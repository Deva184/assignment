import 'dotenv/config';
import crypto from 'crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import fs from 'fs';
import multer from 'multer';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { runGeminiAutoMark } from './server/aiEvaluator.js';
import {
  APPROVED_SUBJECTS,
  fmtNow,
  hashPassword,
  loadDb,
  newId,
  REF_UPLOAD_DIR,
  saveDb,
  SUB_UPLOAD_DIR,
  verifyPassword,
  type Database,
  type Role,
  type StoredFileRef,
  type StoredQuestion,
  type StoredUser,
} from './server/store.js';

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SERVER_START_MS = Date.now();

const ALLOWED_EXTENSIONS = new Set([
  '.jpg',
  '.jpeg',
  '.png',
  '.webp',
  '.bmp',
  '.gif',
  '.tiff',
  '.tif',
  '.pdf',
  '.txt',
  '.csv',
  '.tsv',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.ppt',
  '.pptx',
  '.md',
  '.py',
  '.js',
  '.ts',
  '.java',
]);

function guessMime(filename: string): string {
  const ext = path.extname(filename).toLowerCase();
  const map: Record<string, string> = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.webp': 'image/webp',
    '.bmp': 'image/bmp',
    '.gif': 'image/gif',
    '.tiff': 'image/tiff',
    '.tif': 'image/tiff',
    '.pdf': 'application/pdf',
    '.txt': 'text/plain',
    '.csv': 'text/csv',
    '.tsv': 'text/tab-separated-values',
    '.md': 'text/markdown',
    '.py': 'text/plain',
    '.js': 'text/plain',
    '.ts': 'text/plain',
    '.java': 'text/plain',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  };
  return map[ext] || 'application/octet-stream';
}

// ==================== TOKEN SIGNING ====================
interface TokenPayload {
  uid: string;
  role: Role;
  exp: number;
}

function signToken(user: StoredUser): string {
  const payload: TokenPayload = {
    uid: user.id,
    role: user.role,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function verifyToken(token: string): TokenPayload | null {
  try {
    const [encoded, sig] = token.split('.');
    if (!encoded || !sig) return null;
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8')) as TokenPayload;
    if (!payload.uid || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function toSafeUser(u: StoredUser) {
  return {
    id: u.id,
    name: u.fullName,
    email: u.email,
    role: u.role,
    subjects: u.subjects,
    isActive: u.isActive,
    createdAt: u.createdAt,
  };
}

function addHistory(db: Database, user: StoredUser, action: string, details: string) {
  db.history.unshift({
    id: newId('hist'),
    userId: user.id,
    role: user.role,
    action,
    details,
    createdAt: fmtNow(),
  });
  if (db.history.length > 500) {
    db.history = db.history.slice(0, 500);
  }
}

function addNotification(
  db: Database,
  params: {
    recipientId: string | null;
    targetAudience: 'USER' | 'ALL_STUDENTS' | 'ALL_TEACHERS';
    senderId: string | null;
    senderName: string;
    title: string;
    message: string;
  }
) {
  db.notifications.unshift({
    id: newId('notif'),
    recipientId: params.recipientId,
    targetAudience: params.targetAudience,
    senderId: params.senderId,
    senderName: params.senderName,
    title: params.title,
    message: params.message,
    readByUserIds: [],
    createdAt: fmtNow(),
  });
}

function recordSystemError(
  db: Database,
  params: {
    userId?: string | null;
    userName?: string;
    userEmail?: string;
    userRole?: string;
    errorType: string;
    errorMessage: string;
    pageContext?: string;
  }
) {
  db.systemErrors.unshift({
    id: newId('err'),
    userId: params.userId ?? null,
    userName: params.userName || 'Guest',
    userEmail: params.userEmail || '',
    userRole: params.userRole || '',
    errorType: params.errorType.slice(0, 80),
    errorMessage: params.errorMessage.slice(0, 2000),
    pageContext: (params.pageContext || '').slice(0, 200),
    resolved: false,
    createdAt: fmtNow(),
  });
  if (db.systemErrors.length > 300) {
    db.systemErrors = db.systemErrors.slice(0, 300);
  }
}

// ==================== RATE LIMITER ====================
const rateBuckets = new Map<string, number[]>();
function rateLimit(maxCalls: number, windowMs = 60_000) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${req.path}:${req.ip || 'unknown'}`;
    const now = Date.now();
    const list = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
    if (list.length >= maxCalls) {
      res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
      return;
    }
    list.push(now);
    rateBuckets.set(key, list);
    next();
  };
}

// ==================== MULTER SETUP ====================
function makeUploader(destDir: string) {
  return multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb) => cb(null, destDir),
      filename: (_req, file, cb) => {
        const clean = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
        cb(null, `${crypto.randomBytes(8).toString('hex')}_${clean}`);
      },
    }),
    limits: { fileSize: 10 * 1024 * 1024, files: 8 },
    fileFilter: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      if (!ALLOWED_EXTENSIONS.has(ext)) {
        cb(new Error(`Unsupported file type: ${ext}`));
        return;
      }
      cb(null, true);
    },
  });
}

const uploadRefs = makeUploader(REF_UPLOAD_DIR);
const uploadSubs = makeUploader(SUB_UPLOAD_DIR);

// ==================== AUTH MIDDLEWARE ====================
interface AuthedRequest extends Request {
  authUser?: StoredUser;
}

function getRequestUser(req: Request): StoredUser | null {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!token) return null;
  const payload = verifyToken(token);
  if (!payload) return null;
  const db = loadDb();
  const user = db.users.find((u) => u.id === payload.uid && u.isActive);
  return user || null;
}

function requireAuth(role?: Role | Role[]) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    const user = getRequestUser(req);
    if (!user) {
      res.status(401).json({ error: 'Authentication required. Please sign in.' });
      return;
    }
    if (role) {
      const allowed = Array.isArray(role) ? role : [role];
      if (!allowed.includes(user.role)) {
        res.status(403).json({ error: `${allowed.join(' or ')} access required.` });
        return;
      }
    }
    req.authUser = user;
    next();
  };
}

function safeTimingEqualText(a: string, b: string): boolean {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ==================== EXPRESS APP ====================
async function startServer() {
  const app = express();
  app.use(express.json({ limit: '4mb' }));

  // Health Check
  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      backend: 'express-gemini',
      uptimeSeconds: Math.floor((Date.now() - SERVER_START_MS) / 1000),
      geminiConfigured: Boolean(process.env.GEMINI_API_KEY?.trim()),
    });
  });

  app.get('/api/subjects', (_req, res) => {
    const db = loadDb();
    res.json({ subjects: db.subjects });
  });

  // ==================== AUTH ROUTES ====================
  function getEnvAdminPasscode(): string {
    return (process.env.ADMIN_PASSCODE || process.env.ADMIN || '').trim();
  }

  app.get('/api/auth/admin-status', (_req, res) => {
    const db = loadDb();
    const adminUser = db.users.find((u) => u.role === 'Admin');
    res.json({
      claimed: Boolean(adminUser),
      envPasscodeConfigured: Boolean(getEnvAdminPasscode()),
    });
  });

  app.post('/api/auth/admin-claim', rateLimit(10), (req, res) => {
    const db = loadDb();
    const envPass = getEnvAdminPasscode();
    const name = String(req.body?.name || 'System Admin').trim();
    const email = String(req.body?.email || 'admin@scan2score.com').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (envPass) {
      if (safeTimingEqualText(password, envPass)) {
        let adminUser = db.users.find((u) => u.role === 'Admin');
        if (!adminUser) {
          adminUser = {
            id: newId('usr'),
            fullName: name || 'System Admin',
            email: email || 'admin@scan2score.com',
            passwordHash: hashPassword(envPass),
            role: 'Admin',
            subjects: [],
            isActive: true,
            createdAt: fmtNow(),
          };
          db.users.push(adminUser);
        }
        addHistory(db, adminUser, 'Signed in', 'Admin signed in via configured secret');
        saveDb(db);
        res.json({ token: signToken(adminUser), user: toSafeUser(adminUser) });
        return;
      }
      res.status(401).json({ error: 'Invalid Admin passcode. Please enter the value configured in Secrets.' });
      return;
    }

    const existingAdmin = db.users.find((u) => u.role === 'Admin');
    if (existingAdmin) {
      res.status(409).json({ error: 'Admin account has already been claimed. Please sign in.' });
      return;
    }

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.status(400).json({ error: 'Please enter a valid admin email address.' });
      return;
    }
    if (password.length < 6) {
      res.status(400).json({ error: 'Admin password must be at least 6 characters.' });
      return;
    }
    if (db.users.some((u) => u.email === email)) {
      res.status(409).json({ error: 'This email is already registered under another role.' });
      return;
    }

    const adminUser: StoredUser = {
      id: newId('usr'),
      fullName: name || 'System Admin',
      email,
      passwordHash: hashPassword(password),
      role: 'Admin',
      subjects: [],
      isActive: true,
      createdAt: fmtNow(),
    };
    db.users.push(adminUser);
    addHistory(db, adminUser, 'Admin claimed', 'Initial Admin account configured');
    saveDb(db);

    res.status(201).json({ token: signToken(adminUser), user: toSafeUser(adminUser) });
  });

  app.post('/api/auth/signup', rateLimit(15), (req, res) => {
    const db = loadDb();
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const role = String(req.body?.role || '') as Role;
    const rawSubjects = Array.isArray(req.body?.subjects) ? req.body.subjects : [];

    if (!name) {
      res.status(400).json({ error: 'Please enter your full name.' });
      return;
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }
    if (password.length < 4) {
      res.status(400).json({ error: 'Password must be at least 4 characters.' });
      return;
    }
    if (role !== 'Teacher' && role !== 'Student' && role !== 'Admin') {
      res.status(400).json({ error: 'Role must be Teacher, Student, or Admin.' });
      return;
    }

    if (role === 'Admin') {
      const envPass = getEnvAdminPasscode();
      const suppliedPasscode = String(req.body?.adminPasscode || password || '').trim();
      const existingAdmins = db.users.filter((u) => u.role === 'Admin');

      if (envPass) {
        if (!safeTimingEqualText(suppliedPasscode, envPass)) {
          res.status(401).json({
            error: 'Invalid Admin passcode. Enter your configured ADMIN secret to sign up as Admin.',
          });
          return;
        }
      } else if (existingAdmins.length > 0) {
        const matchesExisting = existingAdmins.some((adm) =>
          verifyPassword(suppliedPasscode, adm.passwordHash)
        );
        if (!matchesExisting) {
          res.status(403).json({
            error: 'An Admin account already exists. Enter the existing Admin passcode to register another Admin.',
          });
          return;
        }
      }
    }

    const cleanSubjects: string[] = Array.from(
      new Set<string>(
        rawSubjects
          .filter((s: unknown): s is string => typeof s === 'string')
          .map((s: string) => s.trim())
          .filter((s: string) => APPROVED_SUBJECTS.includes(s))
      )
    );

    if (role === 'Teacher' && cleanSubjects.length !== 2) {
      res.status(400).json({ error: 'Teachers must select exactly 2 distinct approved subjects.' });
      return;
    }
    if (db.users.some((u) => u.email === email)) {
      res.status(409).json({ error: 'An account with this email already exists. Please Sign In instead.' });
      return;
    }

    const newUser: StoredUser = {
      id: newId('usr'),
      fullName: name,
      email,
      passwordHash: hashPassword(password),
      role,
      subjects: role === 'Teacher' ? cleanSubjects : [],
      isActive: true,
      createdAt: fmtNow(),
    };
    db.users.push(newUser);
    addHistory(
      db,
      newUser,
      'Account registered',
      role === 'Teacher'
        ? `Teacher registered with subjects: ${cleanSubjects.join(' & ')}`
        : role === 'Admin'
          ? 'Admin account registered'
          : 'Student account created'
    );
    saveDb(db);

    res.status(201).json({ token: signToken(newUser), user: toSafeUser(newUser) });
  });

  app.post('/api/auth/signin', rateLimit(15), (req, res) => {
    const db = loadDb();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const expectedRole = req.body?.role ? String(req.body.role) : null;

    // Optional env-configured admin override (supports ADMIN_PASSCODE or ADMIN secret)
    const envAdminPass = getEnvAdminPasscode();
    if (expectedRole === 'Admin' && envAdminPass && safeTimingEqualText(password, envAdminPass)) {
      let adminUser = db.users.find((u) => u.role === 'Admin' && u.email === email);
      if (!adminUser) {
        adminUser = db.users.find((u) => u.role === 'Admin');
      }
      if (!adminUser) {
        adminUser = {
          id: newId('usr'),
          fullName: 'System Admin',
          email: email || 'admin@scan2score.com',
          passwordHash: hashPassword(envAdminPass),
          role: 'Admin',
          subjects: [],
          isActive: true,
          createdAt: fmtNow(),
        };
        db.users.push(adminUser);
      }
      addHistory(db, adminUser, 'Signed in', 'Admin signed into Scan2Score');
      saveDb(db);
      res.json({ token: signToken(adminUser), user: toSafeUser(adminUser) });
      return;
    }

    const user = db.users.find((u) => u.email === email);
    if (!user) {
      if (expectedRole === 'Admin' && envAdminPass) {
        res.status(401).json({
          error: 'Incorrect Admin passcode. Enter your configured ADMIN secret or Sign Up as Admin.',
        });
        return;
      }
      res.status(404).json({ error: 'No account found for this email. Please Sign Up first.' });
      return;
    }
    if (!user.isActive) {
      res.status(403).json({ error: 'Your account has been suspended by an administrator.' });
      return;
    }
    if (!verifyPassword(password, user.passwordHash)) {
      res.status(401).json({ error: 'Incorrect password. Please check and try again.' });
      return;
    }
    if (expectedRole && user.role !== expectedRole) {
      res.status(403).json({
        error: `This email is registered as a ${user.role}. Switch to ${user.role} Sign In.`,
      });
      return;
    }

    addHistory(db, user, 'Signed in', `${user.role} signed into Scan2Score`);
    saveDb(db);

    res.json({ token: signToken(user), user: toSafeUser(user) });
  });

  app.post('/api/auth/signout', requireAuth(), (req: AuthedRequest, res) => {
    const db = loadDb();
    const user = req.authUser!;
    addHistory(db, user, 'Signed out', `${user.role} signed out of Scan2Score`);
    saveDb(db);
    res.json({ ok: true });
  });

  app.get('/api/auth/me', (req, res) => {
    const user = getRequestUser(req);
    res.json({ user: user ? toSafeUser(user) : null });
  });

  // ==================== SECURE UPLOAD SERVING ====================
  app.get('/api/uploads/:folder/:filename', requireAuth(), (req: AuthedRequest, res) => {
    const folder = String(req.params.folder);
    const filename = path.basename(String(req.params.filename));
    if (folder !== 'references' && folder !== 'submissions') {
      res.status(404).json({ error: 'Invalid upload folder.' });
      return;
    }

    const baseDir = folder === 'references' ? REF_UPLOAD_DIR : SUB_UPLOAD_DIR;
    const resolved = path.resolve(baseDir, filename);
    if (!resolved.startsWith(baseDir + path.sep) || !fs.existsSync(resolved)) {
      res.status(404).json({ error: 'File not found.' });
      return;
    }

    const db = loadDb();
    const user = req.authUser!;
    if (folder === 'submissions' && user.role !== 'Admin') {
      const sub = db.submissions.find((s) => s.files.some((f) => f.storedPath === filename));
      if (sub) {
        const asg = db.assignments.find((a) => a.id === sub.assignmentId);
        if (sub.studentId !== user.id && asg?.teacherId !== user.id) {
          res.status(403).json({ error: 'Access denied.' });
          return;
        }
      }
    }

    res.sendFile(resolved);
  });

  // ==================== WORKSPACE SNAPSHOT ====================
  app.get('/api/workspace', requireAuth(), (req: AuthedRequest, res) => {
    const db = loadDb();
    const user = req.authUser!;

    const rawAssignments =
      user.role === 'Teacher'
        ? db.assignments.filter((a) => a.teacherId === user.id)
        : db.assignments;

    const assignments = rawAssignments.map((a) => {
      const teacher = db.users.find((u) => u.id === a.teacherId);
      const firstRef = a.referenceFiles[0];
      return {
        id: a.id,
        title: a.title,
        subject: a.subject,
        chapter: a.chapter,
        deadline: a.deadline,
        description: a.description,
        maxMarks: a.maxMarks,
        teacherId: a.teacherId,
        teacherName: teacher?.fullName || 'Teacher',
        teacherEmail: teacher?.email || '',
        referenceFiles: a.referenceFiles.map((f) => ({
          ...f,
          url: `/api/uploads/references/${f.storedPath}`,
        })),
        fileName: firstRef?.fileName || '',
        fileDataUrl: firstRef ? `/api/uploads/references/${firstRef.storedPath}` : '',
        questions: a.questions.map((q) =>
          user.role === 'Student'
            ? { id: q.id, questionNo: q.questionNo, questionText: q.questionText, maxMarks: q.maxMarks }
            : q
        ),
        createdAt: a.createdAt,
        updatedAt: a.updatedAt,
      };
    });

    const teacherAssignmentIds = new Set(assignments.map((a) => a.id));
    const rawSubmissions =
      user.role === 'Teacher'
        ? db.submissions.filter((s) => teacherAssignmentIds.has(s.assignmentId))
        : user.role === 'Student'
          ? db.submissions.filter((s) => s.studentId === user.id)
          : db.submissions;

    const submissions = rawSubmissions.map((s) => {
      const stu = db.users.find((u) => u.id === s.studentId);
      const chk = s.checkedBy ? db.users.find((u) => u.id === s.checkedBy) : null;
      const firstFile = s.files[0];
      return {
        id: s.id,
        assignmentId: s.assignmentId,
        studentId: s.studentId,
        studentName: stu?.fullName || 'Student',
        studentEmail: stu?.email || '',
        answer: s.answerText,
        files: s.files.map((f) => ({
          ...f,
          url: `/api/uploads/submissions/${f.storedPath}`,
        })),
        fileName: firstFile?.fileName || '',
        fileType: firstFile?.mime || '',
        fileSize: firstFile?.sizeBytes || 0,
        fileDataUrl: firstFile ? `/api/uploads/submissions/${firstFile.storedPath}` : '',
        checked: s.isChecked,
        gradingMode: s.gradingMode,
        marks: s.marks,
        baseMarks: s.baseMarks,
        maxMarks: s.maxMarks,
        feedback: s.feedback,
        submittedAt: s.submittedAt,
        updatedAt: s.updatedAt,
        checkedBy: chk?.fullName || (s.gradingMode === 'auto' ? 'Scan2Score AI' : ''),
        checkedByEmail: chk?.email || '',
        checkedAt: s.checkedAt || '',
        evaluationStatus: s.evaluationStatus,
        aiPlagiarismScore: s.aiPlagiarismScore,
        aiErrorCount: s.aiErrorCount,
        aiPenalty: s.aiPenalty,
        aiAnalysisNote: s.aiAnalysisNote,
        aiDetectedErrors: s.aiDetectedErrors || [],
        questionResults: s.questionResults.map((qr) => {
          if (user.role === 'Student') {
            const { confidence: _c, ...rest } = qr;
            return rest;
          }
          const asg = db.assignments.find((a) => a.id === s.assignmentId);
          const qDef = asg?.questions.find((q) => q.id === qr.questionId);
          return {
            ...qr,
            modelAnswer: qDef?.modelAnswer || '',
            rubric: qDef?.rubric || '',
          };
        }),
      };
    });

    const notifications = db.notifications
      .filter((n) => {
        if (n.recipientId === user.id) return true;
        if (user.role === 'Student' && n.targetAudience === 'ALL_STUDENTS') return true;
        if (user.role === 'Teacher' && n.targetAudience === 'ALL_TEACHERS') return true;
        return false;
      })
      .map((n) => ({
        id: n.id,
        recipient: n.targetAudience === 'USER' ? user.email : n.targetAudience,
        title: n.title,
        message: n.message,
        senderName: n.senderName,
        createdAt: n.createdAt,
        read: n.readByUserIds.includes(user.id),
      }));

    const history = db.history
      .filter((h) => h.userId === user.id || user.role === 'Admin')
      .slice(0, 100)
      .map((h) => {
        const u = db.users.find((usr) => usr.id === h.userId);
        return {
          id: h.id,
          action: h.action,
          details: h.details,
          userName: u?.fullName || 'User',
          userEmail: u?.email || '',
          role: h.role,
          createdAt: h.createdAt,
        };
      });

    res.json({
      user: toSafeUser(user),
      subjects: db.subjects,
      assignments,
      submissions,
      notifications,
      history,
    });
  });

  // ==================== ASSIGNMENTS (CREATE + EDIT + DELETE) ====================
  function parseQuestionsInput(raw: unknown): StoredQuestion[] {
    if (!raw) return [];
    const list = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (!Array.isArray(list)) return [];
    return list
      .filter((q) => q && String(q.questionText || q.question_text || '').trim())
      .map((q, idx) => ({
        id: String(q.id || newId('q')),
        questionNo: idx + 1,
        questionText: String(q.questionText || q.question_text).trim(),
        modelAnswer: String(q.modelAnswer || q.model_answer || '').trim(),
        rubric: String(q.rubric || '').trim(),
        maxMarks: Math.max(1, Math.min(100, Number(q.maxMarks || q.max_marks || 10))),
      }));
  }

  app.post(
    '/api/assignments',
    requireAuth('Teacher'),
    uploadRefs.array('referenceFiles', 8),
    (req: AuthedRequest, res) => {
      const db = loadDb();
      const user = req.authUser!;
      const title = String(req.body?.title || '').trim();
      const subject = String(req.body?.subject || '').trim();
      const chapter = String(req.body?.chapter || '').trim();
      const deadline = String(req.body?.deadline || '').trim();
      const description = String(req.body?.description || '').trim();

      if (!title || !subject || !chapter || !deadline || !description) {
        res.status(400).json({ error: 'All assignment fields are required.' });
        return;
      }
      if (!user.subjects.includes(subject)) {
        res.status(403).json({ error: 'You can only create assignments for your 2 registered subjects.' });
        return;
      }

      let questions: StoredQuestion[] = [];
      try {
        questions = parseQuestionsInput(req.body?.questions);
      } catch {
        res.status(400).json({ error: 'Invalid questions format.' });
        return;
      }

      const uploaded = (req.files as Express.Multer.File[]) || [];
      const referenceFiles: StoredFileRef[] = uploaded.map((f) => ({
        fileName: f.originalname,
        storedPath: f.filename,
        mime: f.mimetype || guessMime(f.originalname),
        sizeBytes: f.size,
      }));

      const requestedMax = Number(req.body?.maxMarks || 10);
      const maxMarks =
        questions.length > 0
          ? questions.reduce((sum, q) => sum + q.maxMarks, 0)
          : Math.max(1, Math.min(100, Number.isFinite(requestedMax) ? requestedMax : 10));

      const now = fmtNow();
      const asgId = newId('asg');
      db.assignments.unshift({
        id: asgId,
        teacherId: user.id,
        subject,
        title,
        chapter,
        deadline,
        description,
        maxMarks,
        referenceFiles,
        questions,
        createdAt: now,
        updatedAt: now,
      });

      addNotification(db, {
        recipientId: null,
        targetAudience: 'ALL_STUDENTS',
        senderId: user.id,
        senderName: user.fullName,
        title: 'New Assignment Published',
        message: `${title} · ${subject} · ${chapter}`,
      });
      addHistory(db, user, 'Assignment published', `${title} · ${subject} · ${chapter}`);
      saveDb(db);

      res.status(201).json({ ok: true, assignmentId: asgId });
    }
  );

  // EDIT ASSIGNMENT (NEW)
  app.put(
    '/api/assignments/:id',
    requireAuth('Teacher'),
    uploadRefs.array('referenceFiles', 8),
    (req: AuthedRequest, res) => {
      const db = loadDb();
      const user = req.authUser!;
      const asg = db.assignments.find((a) => a.id === req.params.id && a.teacherId === user.id);
      if (!asg) {
        res.status(404).json({ error: 'Assignment not found.' });
        return;
      }

      const title = String(req.body?.title || '').trim();
      const subject = String(req.body?.subject || '').trim();
      const chapter = String(req.body?.chapter || '').trim();
      const deadline = String(req.body?.deadline || '').trim();
      const description = String(req.body?.description || '').trim();

      if (!title || !subject || !chapter || !deadline || !description) {
        res.status(400).json({ error: 'All assignment fields are required.' });
        return;
      }
      if (!user.subjects.includes(subject)) {
        res.status(403).json({ error: 'You can only assign one of your 2 registered subjects.' });
        return;
      }

      let questions: StoredQuestion[] = asg.questions;
      if (req.body?.questions !== undefined) {
        try {
          questions = parseQuestionsInput(req.body.questions);
        } catch {
          res.status(400).json({ error: 'Invalid questions format.' });
          return;
        }
      }

      // Keep selected existing reference files + append newly uploaded ones
      let keptRefPaths: string[] | null = null;
      if (req.body?.keepReferencePaths !== undefined) {
        try {
          const parsed = JSON.parse(String(req.body.keepReferencePaths));
          if (Array.isArray(parsed)) keptRefPaths = parsed.map(String);
        } catch {
          keptRefPaths = null;
        }
      }
      const existingRefs = keptRefPaths
        ? asg.referenceFiles.filter((f) => keptRefPaths!.includes(f.storedPath))
        : asg.referenceFiles;

      const uploaded = (req.files as Express.Multer.File[]) || [];
      const newRefs: StoredFileRef[] = uploaded.map((f) => ({
        fileName: f.originalname,
        storedPath: f.filename,
        mime: f.mimetype || guessMime(f.originalname),
        sizeBytes: f.size,
      }));

      const requestedMax = Number(req.body?.maxMarks || asg.maxMarks || 10);
      const maxMarks =
        questions.length > 0
          ? questions.reduce((sum, q) => sum + q.maxMarks, 0)
          : Math.max(1, Math.min(100, Number.isFinite(requestedMax) ? requestedMax : 10));

      asg.title = title;
      asg.subject = subject;
      asg.chapter = chapter;
      asg.deadline = deadline;
      asg.description = description;
      asg.questions = questions;
      asg.maxMarks = maxMarks;
      asg.referenceFiles = [...existingRefs, ...newRefs].slice(0, 8);
      asg.updatedAt = fmtNow();

      // Update maxMarks on pending submissions for consistency
      for (const sub of db.submissions) {
        if (sub.assignmentId === asg.id) {
          sub.maxMarks = maxMarks;
        }
      }

      addNotification(db, {
        recipientId: null,
        targetAudience: 'ALL_STUDENTS',
        senderId: user.id,
        senderName: user.fullName,
        title: 'Assignment Updated',
        message: `${title} · ${subject} · Updated deadline ${deadline}`,
      });
      addHistory(db, user, 'Assignment edited', `${title} · ${subject}`);
      saveDb(db);

      res.json({ ok: true });
    }
  );

  app.delete('/api/assignments/:id', requireAuth('Teacher'), (req: AuthedRequest, res) => {
    const db = loadDb();
    const user = req.authUser!;
    const idx = db.assignments.findIndex((a) => a.id === req.params.id && a.teacherId === user.id);
    if (idx === -1) {
      res.status(404).json({ error: 'Assignment not found.' });
      return;
    }
    const [removed] = db.assignments.splice(idx, 1);
    db.submissions = db.submissions.filter((s) => s.assignmentId !== removed.id);
    addHistory(db, user, 'Assignment deleted', `${removed.title} · ${removed.subject}`);
    saveDb(db);
    res.json({ ok: true });
  });

  // ==================== STUDENT SUBMISSIONS (SUBMIT & EDIT) ====================
  app.post(
    '/api/assignments/:id/submit',
    requireAuth('Student'),
    uploadSubs.array('files', 8),
    (req: AuthedRequest, res) => {
      const db = loadDb();
      const user = req.authUser!;
      const asg = db.assignments.find((a) => a.id === req.params.id);
      if (!asg) {
        res.status(404).json({ error: 'Assignment not found.' });
        return;
      }

      const answerText = String(req.body?.answer || '').trim();
      const keepExisting = req.body?.keepExistingFiles === '1';
      const uploaded = (req.files as Express.Multer.File[]) || [];
      const newFiles: StoredFileRef[] = uploaded.map((f) => ({
        fileName: f.originalname,
        storedPath: f.filename,
        mime: f.mimetype || guessMime(f.originalname),
        sizeBytes: f.size,
      }));

      const existing = db.submissions.find(
        (s) => s.assignmentId === asg.id && s.studentId === user.id
      );

      const mergedFiles =
        keepExisting && existing ? [...existing.files, ...newFiles].slice(0, 8) : newFiles;

      if (!answerText && mergedFiles.length === 0) {
        res.status(400).json({ error: 'Please write an answer or upload at least one file before submitting.' });
        return;
      }

      const now = fmtNow();
      let submissionId: string;
      if (existing) {
        existing.answerText = answerText;
        existing.files = mergedFiles;
        existing.isChecked = false;
        existing.gradingMode = 'pending';
        existing.marks = null;
        existing.baseMarks = null;
        existing.maxMarks = asg.maxMarks;
        existing.feedback = '';
        existing.checkedBy = null;
        existing.checkedAt = null;
        existing.evaluationStatus = 'pending';
        existing.aiPlagiarismScore = null;
        existing.aiErrorCount = null;
        existing.aiPenalty = null;
        existing.aiAnalysisNote = '';
        existing.aiDetectedErrors = [];
        existing.questionResults = [];
        existing.updatedAt = now;
        submissionId = existing.id;
      } else {
        submissionId = newId('sub');
        db.submissions.unshift({
          id: submissionId,
          assignmentId: asg.id,
          studentId: user.id,
          answerText,
          files: mergedFiles,
          isChecked: false,
          gradingMode: 'pending',
          marks: null,
          baseMarks: null,
          maxMarks: asg.maxMarks,
          feedback: '',
          checkedBy: null,
          checkedAt: null,
          evaluationStatus: 'pending',
          aiPlagiarismScore: null,
          aiErrorCount: null,
          aiPenalty: null,
          aiAnalysisNote: '',
          aiDetectedErrors: [],
          questionResults: [],
          submittedAt: now,
          updatedAt: now,
        });
      }

      addNotification(db, {
        recipientId: asg.teacherId,
        targetAudience: 'USER',
        senderId: user.id,
        senderName: user.fullName,
        title: existing ? 'Student Submission Updated' : 'New Student Submission',
        message: `${user.fullName} ${existing ? 'updated' : 'submitted'} ${asg.title}`,
      });
      addHistory(
        db,
        user,
        existing ? 'Submission edited' : 'Assignment submitted',
        `${asg.title} · ${asg.subject}`
      );
      saveDb(db);

      res.status(existing ? 200 : 201).json({ ok: true, submissionId });
    }
  );

  // ==================== AUTO MARK (SINGLE & BATCH) ====================
  app.post('/api/submissions/:id/auto-mark', requireAuth('Teacher'), async (req: AuthedRequest, res) => {
    const db = loadDb();
    const user = req.authUser!;
    const sub = db.submissions.find((s) => s.id === req.params.id);
    if (!sub) {
      res.status(404).json({ error: 'Submission not found.' });
      return;
    }
    const asg = db.assignments.find((a) => a.id === sub.assignmentId && a.teacherId === user.id);
    if (!asg) {
      res.status(403).json({ error: 'Submission does not belong to your assignments.' });
      return;
    }

    const applyImmediately = req.body?.apply !== false;
    const peerAnswers = db.submissions
      .filter((s) => s.assignmentId === asg.id && s.id !== sub.id && s.answerText.trim())
      .map((s) => s.answerText);

    try {
      const result = await runGeminiAutoMark(asg, sub, peerAnswers);
      const now = fmtNow();

      sub.aiPlagiarismScore = result.plagiarismScore;
      sub.aiErrorCount = result.errorCount;
      sub.aiPenalty = result.penalty;
      sub.aiAnalysisNote = result.analysisNote;
      sub.aiDetectedErrors = result.detectedErrors;
      sub.baseMarks = result.baseMarks;
      sub.maxMarks = result.maxMarks;
      sub.questionResults = result.questionResults;

      if (applyImmediately) {
        sub.marks = result.finalMarks;
        sub.feedback = result.feedback;
        sub.gradingMode = 'auto';
        sub.isChecked = true;
        sub.checkedBy = user.id;
        sub.checkedAt = now;
        sub.evaluationStatus = 'ai_evaluated';
        sub.updatedAt = now;

        addNotification(db, {
          recipientId: sub.studentId,
          targetAudience: 'USER',
          senderId: user.id,
          senderName: user.fullName,
          title: 'Assignment Auto-Marked',
          message: `${asg.title} graded automatically: ${result.finalMarks}/${result.maxMarks}${
            result.penalty > 0 ? ` (−${result.penalty} deduction for errors/plagiarism)` : ''
          }`,
        });
        addHistory(
          db,
          user,
          'Auto Mark applied',
          `${asg.title} · ${result.finalMarks}/${result.maxMarks} (Plag: ${result.plagiarismScore}%, Errors: ${result.errorCount})`
        );
      }
      saveDb(db);

      res.json({
        ok: true,
        applied: applyImmediately,
        marks: result.finalMarks,
        baseMarks: result.baseMarks,
        maxMarks: result.maxMarks,
        plagiarismScore: result.plagiarismScore,
        errorCount: result.errorCount,
        penalty: result.penalty,
        detectedErrors: result.detectedErrors,
        analysisNote: result.analysisNote,
        feedback: result.feedback,
        questionResults: result.questionResults,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Auto Mark failed.';
      recordSystemError(db, {
        userId: user.id,
        userName: user.fullName,
        userEmail: user.email,
        userRole: user.role,
        errorType: 'AI_AUTOMARK_ERROR',
        errorMessage: msg,
        pageContext: `/submissions/${sub.id}/auto-mark`,
      });
      saveDb(db);
      res.status(502).json({ error: msg });
    }
  });

  app.post('/api/submissions/auto-mark-pending', requireAuth('Teacher'), async (req: AuthedRequest, res) => {
    const db = loadDb();
    const user = req.authUser!;
    const assignmentId = req.body?.assignmentId ? String(req.body.assignmentId) : null;

    const teacherAssignments = db.assignments.filter(
      (a) => a.teacherId === user.id && (!assignmentId || assignmentId === 'all' || a.id === assignmentId)
    );
    const asgMap = new Map(teacherAssignments.map((a) => [a.id, a]));
    const pendingSubs = db.submissions.filter(
      (s) => asgMap.has(s.assignmentId) && !s.isChecked
    );

    if (pendingSubs.length === 0) {
      res.json({ ok: true, processed: 0, failed: 0, message: 'No pending submissions to auto mark.' });
      return;
    }

    let processed = 0;
    let failed = 0;
    let lastError = '';

    for (const sub of pendingSubs) {
      const asg = asgMap.get(sub.assignmentId)!;
      const peerAnswers = db.submissions
        .filter((s) => s.assignmentId === asg.id && s.id !== sub.id && s.answerText.trim())
        .map((s) => s.answerText);

      try {
        const result = await runGeminiAutoMark(asg, sub, peerAnswers);
        const now = fmtNow();
        sub.aiPlagiarismScore = result.plagiarismScore;
        sub.aiErrorCount = result.errorCount;
        sub.aiPenalty = result.penalty;
        sub.aiAnalysisNote = result.analysisNote;
        sub.aiDetectedErrors = result.detectedErrors;
        sub.baseMarks = result.baseMarks;
        sub.maxMarks = result.maxMarks;
        sub.questionResults = result.questionResults;
        sub.marks = result.finalMarks;
        sub.feedback = result.feedback;
        sub.gradingMode = 'auto';
        sub.isChecked = true;
        sub.checkedBy = user.id;
        sub.checkedAt = now;
        sub.evaluationStatus = 'ai_evaluated';
        sub.updatedAt = now;

        addNotification(db, {
          recipientId: sub.studentId,
          targetAudience: 'USER',
          senderId: user.id,
          senderName: user.fullName,
          title: 'Assignment Auto-Marked',
          message: `${asg.title} graded automatically: ${result.finalMarks}/${result.maxMarks}`,
        });
        processed++;
      } catch (err) {
        failed++;
        lastError = err instanceof Error ? err.message : 'Auto Mark error';
      }
    }

    if (processed > 0) {
      addHistory(db, user, 'Batch Auto Mark', `Auto-marked ${processed} pending submission(s)`);
    }
    if (failed > 0 && lastError) {
      recordSystemError(db, {
        userId: user.id,
        userName: user.fullName,
        userEmail: user.email,
        userRole: user.role,
        errorType: 'AI_BATCH_AUTOMARK_ERROR',
        errorMessage: lastError,
        pageContext: '/submissions/auto-mark-pending',
      });
    }
    saveDb(db);

    if (processed === 0 && failed > 0) {
      res.status(502).json({ error: lastError });
      return;
    }

    res.json({ ok: true, processed, failed, lastError: failed > 0 ? lastError : undefined });
  });

  // ==================== MANUAL GRADING & EDIT GRADE ====================
  app.post('/api/submissions/:id/review', requireAuth('Teacher'), (req: AuthedRequest, res) => {
    const db = loadDb();
    const user = req.authUser!;
    const sub = db.submissions.find((s) => s.id === req.params.id);
    if (!sub) {
      res.status(404).json({ error: 'Submission not found.' });
      return;
    }
    const asg = db.assignments.find((a) => a.id === sub.assignmentId && a.teacherId === user.id);
    if (!asg) {
      res.status(403).json({ error: 'Submission does not belong to your assignments.' });
      return;
    }

    const maxMarks = asg.maxMarks || 10;
    const marksNum = Number(req.body?.marks);
    if (!Number.isFinite(marksNum) || marksNum < 0 || marksNum > maxMarks) {
      res.status(400).json({ error: `Marks must be between 0 and ${maxMarks}.` });
      return;
    }

    const feedback = String(req.body?.feedback || '').trim();
    const isEdit = sub.isChecked;
    const now = fmtNow();

    sub.marks = Math.round(marksNum * 10) / 10;
    sub.baseMarks = sub.baseMarks ?? sub.marks;
    sub.maxMarks = maxMarks;
    sub.feedback = feedback;
    sub.gradingMode = 'manual';
    sub.isChecked = true;
    sub.checkedBy = user.id;
    sub.checkedAt = now;
    sub.evaluationStatus = 'teacher_approved';
    sub.updatedAt = now;

    // Optional per-question manual overrides
    if (Array.isArray(req.body?.questionOverrides)) {
      for (const ov of req.body.questionOverrides) {
        const qr = sub.questionResults.find((item) => item.id === ov.id || item.questionId === ov.questionId);
        if (qr) {
          const m = Math.max(0, Math.min(qr.maxMarks, Number(ov.marks ?? qr.awardedMarks)));
          qr.teacherMarks = Math.round(m * 10) / 10;
          qr.teacherFeedback = String(ov.feedback || '').trim();
          qr.approved = true;
          qr.evaluator = 'teacher';
        }
      }
    }

    const stu = db.users.find((u) => u.id === sub.studentId);
    addNotification(db, {
      recipientId: sub.studentId,
      targetAudience: 'USER',
      senderId: user.id,
      senderName: user.fullName,
      title: isEdit ? 'Grade Updated' : 'Assignment Graded (Manual)',
      message: `${asg.title} reviewed manually. Marks: ${sub.marks}/${maxMarks}`,
    });
    addHistory(
      db,
      user,
      isEdit ? 'Grade edited' : 'Manual grade saved',
      `${stu?.fullName || 'Student'} · ${sub.marks}/${maxMarks} · ${asg.title}`
    );
    saveDb(db);

    res.json({ ok: true, marks: sub.marks });
  });

  app.post('/api/evaluations/:subId/reject', requireAuth('Teacher'), (req: AuthedRequest, res) => {
    const db = loadDb();
    const user = req.authUser!;
    const sub = db.submissions.find((s) => s.id === req.params.subId);
    if (!sub) {
      res.status(404).json({ error: 'Submission not found.' });
      return;
    }
    const asg = db.assignments.find((a) => a.id === sub.assignmentId && a.teacherId === user.id);
    if (!asg) {
      res.status(403).json({ error: 'Access denied.' });
      return;
    }

    const reason = String(req.body?.reason || '').trim();
    if (!reason) {
      res.status(400).json({ error: 'A rejection reason is required.' });
      return;
    }

    sub.evaluationStatus = 'rejected';
    sub.isChecked = true;
    sub.marks = 0;
    sub.feedback = `Rejected: ${reason}`;
    sub.checkedBy = user.id;
    sub.checkedAt = fmtNow();
    sub.updatedAt = fmtNow();

    addNotification(db, {
      recipientId: sub.studentId,
      targetAudience: 'USER',
      senderId: user.id,
      senderName: user.fullName,
      title: 'Submission Rejected',
      message: `${asg.title}: ${reason}`,
    });
    addHistory(db, user, 'Submission rejected', `${asg.title} · ${reason}`);
    saveDb(db);
    res.json({ ok: true });
  });

  // ==================== NOTIFICATIONS ====================
  app.post('/api/notifications/read-all', requireAuth(), (req: AuthedRequest, res) => {
    const db = loadDb();
    const user = req.authUser!;
    for (const n of db.notifications) {
      const visible =
        n.recipientId === user.id ||
        (user.role === 'Student' && n.targetAudience === 'ALL_STUDENTS') ||
        (user.role === 'Teacher' && n.targetAudience === 'ALL_TEACHERS');
      if (visible && !n.readByUserIds.includes(user.id)) {
        n.readByUserIds.push(user.id);
      }
    }
    saveDb(db);
    res.json({ ok: true });
  });

  // ==================== CLIENT ERROR REPORTER ====================
  app.post('/api/errors/report', rateLimit(30), (req, res) => {
    const user = getRequestUser(req);
    const errorType = String(req.body?.type || 'CLIENT_ERROR').trim();
    const errorMessage = String(req.body?.message || '').trim();
    const pageContext = String(req.body?.page || '').trim();

    if (!errorMessage) {
      res.status(400).json({ ok: false });
      return;
    }
    const db = loadDb();
    recordSystemError(db, {
      userId: user?.id ?? null,
      userName: user?.fullName || 'Guest',
      userEmail: user?.email || '',
      userRole: user?.role || '',
      errorType,
      errorMessage,
      pageContext,
    });
    saveDb(db);
    res.json({ ok: true });
  });

  // ==================== ADMIN ROUTES ====================
  app.get('/api/admin/stats', requireAuth('Admin'), (_req, res) => {
    const db = loadDb();
    res.json({
      teachers: db.users.filter((u) => u.role === 'Teacher').length,
      students: db.users.filter((u) => u.role === 'Student').length,
      assignments: db.assignments.length,
      submissions: db.submissions.length,
      openErrors: db.systemErrors.filter((e) => !e.resolved).length,
      uptimeSeconds: Math.floor((Date.now() - SERVER_START_MS) / 1000),
      errors: db.systemErrors.slice(0, 100).map((e) => ({
        id: e.id,
        type: e.errorType,
        message: e.errorMessage,
        page: e.pageContext,
        userName: e.userName,
        userEmail: e.userEmail,
        userRole: e.userRole,
        resolved: e.resolved,
        createdAt: e.createdAt,
      })),
    });
  });

  app.get('/api/admin/users', requireAuth('Admin'), (_req, res) => {
    const db = loadDb();
    const users = db.users
      .filter((u) => u.role !== 'Admin')
      .map((u) => ({
        id: u.id,
        name: u.fullName,
        email: u.email,
        role: u.role,
        isActive: u.isActive,
        subjects: u.subjects.join(', '),
        createdAt: u.createdAt,
      }));
    res.json({ users });
  });

  app.put('/api/admin/users/:id', requireAuth('Admin'), (req: AuthedRequest, res) => {
    const db = loadDb();
    const target = db.users.find((u) => u.id === req.params.id && u.role !== 'Admin');
    if (!target) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }
    const name = String(req.body?.name || target.fullName).trim();
    const isActive = typeof req.body?.isActive === 'boolean' ? req.body.isActive : target.isActive;
    let subjects = target.subjects;
    if (target.role === 'Teacher' && Array.isArray(req.body?.subjects)) {
      const clean: string[] = Array.from(
        new Set<string>(
          (req.body.subjects as unknown[])
            .filter((s): s is string => typeof s === 'string')
            .filter((s) => APPROVED_SUBJECTS.includes(s))
        )
      );
      if (clean.length !== 2) {
        res.status(400).json({ error: 'Teachers must have exactly 2 approved subjects.' });
        return;
      }
      subjects = clean;
    }
    target.fullName = name || target.fullName;
    target.isActive = isActive;
    target.subjects = subjects;
    addHistory(db, req.authUser!, 'Admin edited user', `${target.fullName} (${target.role})`);
    saveDb(db);
    res.json({ ok: true });
  });

  app.post('/api/admin/users/:id/toggle', requireAuth('Admin'), (req: AuthedRequest, res) => {
    const db = loadDb();
    const target = db.users.find((u) => u.id === req.params.id && u.role !== 'Admin');
    if (!target) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }
    target.isActive = !target.isActive;
    addHistory(
      db,
      req.authUser!,
      target.isActive ? 'User activated' : 'User suspended',
      `${target.fullName} (${target.email})`
    );
    saveDb(db);
    res.json({ ok: true, isActive: target.isActive });
  });

  app.delete('/api/admin/users/:id', requireAuth('Admin'), (req: AuthedRequest, res) => {
    const db = loadDb();
    const idx = db.users.findIndex((u) => u.id === req.params.id && u.role !== 'Admin');
    if (idx === -1) {
      res.status(404).json({ error: 'Cannot delete admin or missing user.' });
      return;
    }
    const [removed] = db.users.splice(idx, 1);
    db.submissions = db.submissions.filter((s) => s.studentId !== removed.id);
    if (removed.role === 'Teacher') {
      const removedAsgIds = new Set(
        db.assignments.filter((a) => a.teacherId === removed.id).map((a) => a.id)
      );
      db.assignments = db.assignments.filter((a) => a.teacherId !== removed.id);
      db.submissions = db.submissions.filter((s) => !removedAsgIds.has(s.assignmentId));
    }
    addHistory(db, req.authUser!, 'Admin deleted user', `${removed.fullName} (${removed.email})`);
    saveDb(db);
    res.json({ ok: true });
  });

  app.post('/api/admin/errors/:id/resolve', requireAuth('Admin'), (req: AuthedRequest, res) => {
    const db = loadDb();
    const errItem = db.systemErrors.find((e) => e.id === req.params.id);
    if (!errItem) {
      res.status(404).json({ error: 'Error log entry not found.' });
      return;
    }
    errItem.resolved = true;
    addHistory(db, req.authUser!, 'Error resolved', `${errItem.errorType} · ${errItem.id}`);
    saveDb(db);
    res.json({ ok: true });
  });

  app.post('/api/admin/errors/resolve-all', requireAuth('Admin'), (req: AuthedRequest, res) => {
    const db = loadDb();
    let count = 0;
    for (const e of db.systemErrors) {
      if (!e.resolved) {
        e.resolved = true;
        count++;
      }
    }
    addHistory(db, req.authUser!, 'Resolved all errors', `Marked ${count} error(s) resolved`);
    saveDb(db);
    res.json({ ok: true, count });
  });

  app.get('/api/admin/ai-analysis', requireAuth('Admin'), (_req, res) => {
    const db = loadDb();
    const rows = db.submissions
      .filter(
        (s) =>
          s.aiPlagiarismScore !== null ||
          s.aiErrorCount !== null ||
          s.aiPenalty !== null ||
          s.isChecked
      )
      .map((s) => {
        const stu = db.users.find((u) => u.id === s.studentId);
        const asg = db.assignments.find((a) => a.id === s.assignmentId);
        return {
          id: s.id,
          studentName: stu?.fullName || 'Student',
          assignmentTitle: asg?.title || 'Assignment',
          plagiarismScore: s.aiPlagiarismScore,
          errorCount: s.aiErrorCount,
          penalty: s.aiPenalty,
          analysisNote: s.aiAnalysisNote,
          detectedErrors: s.aiDetectedErrors || [],
          marks: s.marks,
          maxMarks: s.maxMarks,
          gradingMode: s.gradingMode,
          submittedAt: s.submittedAt,
        };
      });
    res.json({ submissions: rows });
  });

  app.post('/api/admin/broadcast', requireAuth('Admin'), (req: AuthedRequest, res) => {
    const db = loadDb();
    const title = String(req.body?.title || '').trim();
    const message = String(req.body?.message || '').trim();
    const audience = req.body?.audience === 'ALL_TEACHERS' ? 'ALL_TEACHERS' : 'ALL_STUDENTS';
    if (!title || !message) {
      res.status(400).json({ error: 'Title and message are required.' });
      return;
    }

    addNotification(db, {
      recipientId: null,
      targetAudience: audience,
      senderId: req.authUser!.id,
      senderName: req.authUser!.fullName,
      title,
      message,
    });
    addHistory(db, req.authUser!, 'Broadcast sent', `${audience}: ${title}`);
    saveDb(db);
    res.json({ ok: true });
  });

  // Global API error handler
  app.use('/api', (err: Error, req: Request, res: Response, _next: NextFunction) => {
    const db = loadDb();
    const user = getRequestUser(req);
    recordSystemError(db, {
      userId: user?.id ?? null,
      userName: user?.fullName || 'Guest',
      userEmail: user?.email || '',
      userRole: user?.role || '',
      errorType: 'SERVER_API_ERROR',
      errorMessage: err.message || 'Unhandled server error',
      pageContext: req.originalUrl,
    });
    saveDb(db);
    res.status(500).json({ error: err.message || 'An unexpected server error occurred.' });
  });

  // ==================== VITE / STATIC SERVING ====================
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Scan2Score server listening on http://localhost:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start Scan2Score server:', err);
  process.exit(1);
});
