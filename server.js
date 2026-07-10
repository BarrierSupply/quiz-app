// ควิซออนไลน์ + ระบบล็อกอิน + สื่อ + ตัวจับเวลา + Part + ตรวจจับการออกจากจอ
// ใช้แค่ Node.js ที่มากับเครื่อง ไม่ต้องติดตั้ง dependency ใด ๆ
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
// รองรับ persistent disk บน Render/Railway ผ่าน env DATA_DIR (เช่น /var/data)
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const MAX_UPLOAD = 25 * 1024 * 1024; // 25MB ต่อไฟล์
const MAX_JSON = 8 * 1024 * 1024;    // 8MB ต่อ request

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// อีเมลที่เป็นแอดมินระบบ
// - แก้ไข/เพิ่มแอดมินถาวรได้ที่ DEFAULT_ADMIN_EMAILS ด้านล่าง
// - หรือเพิ่มผ่าน env ADMIN_EMAIL (คั่นหลายคนด้วยจุลภาค) โดยไม่ต้องแก้โค้ด
const DEFAULT_ADMIN_EMAILS = ['admin12345@teacher.com'];
const ADMIN_EMAILS = [...new Set([
  ...DEFAULT_ADMIN_EMAILS,
  ...String(process.env.ADMIN_EMAIL || '').split(','),
].map((s) => s.trim().toLowerCase()).filter(Boolean))];
function isAdmin(user) { return !!(user && ADMIN_EMAILS.includes(user.email)); }

// ---------- ที่เก็บข้อมูล (ไฟล์ JSON ไฟล์เดียว) ----------
let db = { users: {}, sessions: {}, quizzes: {}, responses: {}, events: {} };
try {
  const loaded = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  db = Object.assign(db, loaded);
  for (const k of ['users', 'sessions', 'quizzes', 'responses', 'events']) db[k] = db[k] || {};
} catch (_) { /* เริ่มใหม่ */ }

let saveTimer = null;
function saveDb() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(DATA_FILE, JSON.stringify(db), () => {});
  }, 40);
}

// ---------- helper ----------
function rid(n = 5) { return crypto.randomBytes(n).toString('hex'); }

function sendJson(res, status, data, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(data));
}

function readJson(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > MAX_JSON) req.destroy(); });
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

function readRaw(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size > max) { req.destroy(); reject(new Error('too big')); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ---------- auth ----------
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const h = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(hash));
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}
const SESSION_TTL = 30 * 24 * 3600 * 1000;
function currentUser(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;
  const s = db.sessions[sid];
  if (!s || Date.now() - s.createdAt > SESSION_TTL) { if (s) delete db.sessions[sid]; return null; }
  return db.users[s.userId] || null;
}
function makeSession(userId) {
  const sid = rid(24);
  db.sessions[sid] = { userId, createdAt: Date.now() };
  return sid;
}
function sessionCookie(sid) {
  return `sid=${sid}; HttpOnly; Path=/; Max-Age=${SESSION_TTL / 1000}; SameSite=Lax`;
}

// ---------- sanitize ควิซ ----------
function sanitizeQuiz(body) {
  const parts = Array.isArray(body.parts) ? body.parts.slice(0, 30) : [];
  const cleanParts = parts.map((pt) => ({
    id: pt.id || rid(3),
    title: String(pt.title || '').slice(0, 200),
    questions: (Array.isArray(pt.questions) ? pt.questions.slice(0, 200) : []).map(sanitizeQuestion)
      .filter((q) => q.text.trim() !== '' || q.media.images.length || q.media.video || q.media.audio),
  })).filter((pt) => pt.questions.length > 0 || pt.title.trim() !== '');
  return {
    title: String(body.title || 'ควิซไม่มีชื่อ').slice(0, 200),
    description: String(body.description || '').slice(0, 2000),
    timeLimitSec: Math.max(0, Math.min(parseInt(body.timeLimitSec, 10) || 0, 24 * 3600)),
    parts: cleanParts,
  };
}
function sanitizeQuestion(q) {
  const type = q.type === 'open' ? 'open' : 'mc';
  let choices = Array.isArray(q.choices) ? q.choices.slice(0, 10).map((c) => String(c).slice(0, 500)) : [];
  if (type === 'mc') { while (choices.length < 2) choices.push(''); } else choices = [];
  let correct = parseInt(q.correct, 10);
  if (!(correct >= 0 && correct < choices.length)) correct = 0;
  const media = q.media || {};
  return {
    id: q.id || rid(3),
    type,
    text: String(q.text || '').slice(0, 3000),
    media: {
      images: (Array.isArray(media.images) ? media.images : []).slice(0, 4).map((s) => String(s).slice(0, 300)),
      video: String(media.video || '').slice(0, 300),
      audio: String(media.audio || '').slice(0, 300),
    },
    choices,
    correct,
    sampleAnswer: String(q.sampleAnswer || '').slice(0, 2000),
  };
}

// จำนวนคำถามทั้งหมดในควิซ
function allQuestions(quiz) {
  return (quiz.parts || []).flatMap((pt) => pt.questions);
}

// เวอร์ชันสำหรับผู้ตอบ (ตัดเฉลย/token/sampleAnswer ออก)
function publicQuiz(quiz) {
  return {
    id: quiz.id,
    title: quiz.title,
    description: quiz.description,
    timeLimitSec: quiz.timeLimitSec || 0,
    parts: (quiz.parts || []).map((pt) => ({
      title: pt.title,
      questions: pt.questions.map((q) => ({
        id: q.id, type: q.type, text: q.text, media: q.media,
        choices: q.type === 'mc' ? q.choices : [],
      })),
    })),
  };
}

// ---------- ไฟล์ static ----------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime',
  '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.ogg': 'audio/ogg', '.m4a': 'audio/mp4',
};

function serveStatic(req, res) {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);

  // เสิร์ฟไฟล์สื่อที่อัปโหลด (อยู่ใน DATA_DIR ไม่ใช่ public)
  if (urlPath.startsWith('/uploads/')) {
    const f = path.join(UPLOAD_DIR, path.normalize(urlPath.slice('/uploads/'.length)).replace(/^(\.\.[/\\])+/, ''));
    if (!f.startsWith(UPLOAD_DIR)) { res.writeHead(403); res.end('Forbidden'); return; }
    return fs.readFile(f, (err, data) => {
      if (err) { res.writeHead(404); res.end('not found'); return; }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(f).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'public, max-age=31536000' });
      res.end(data);
    });
  }

  if (urlPath === '/') urlPath = '/index.html';
  if (urlPath === '/login') urlPath = '/login.html';
  if (urlPath === '/take') urlPath = '/take.html';
  if (urlPath === '/admin') urlPath = '/admin.html';
  if (urlPath === '/users') urlPath = '/admin-users.html';
  const filePath = path.join(PUBLIC_DIR, path.normalize(urlPath).replace(/^(\.\.[/\\])+/, ''));
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('ไม่พบหน้านี้'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------- เซิร์ฟเวอร์ ----------
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;
  if (!p.startsWith('/api/')) return serveStatic(req, res);

  try {
    // ========== AUTH ==========
    if (p === '/api/register' && req.method === 'POST') {
      const b = await readJson(req);
      const email = String(b.email || '').trim().toLowerCase();
      const password = String(b.password || '');
      if (!email || !email.includes('@')) return sendJson(res, 400, { error: 'อีเมลไม่ถูกต้อง' });
      if (password.length < 6) return sendJson(res, 400, { error: 'รหัสผ่านต้องยาวอย่างน้อย 6 ตัว' });
      if (Object.values(db.users).some((x) => x.email === email)) return sendJson(res, 409, { error: 'อีเมลนี้ถูกใช้แล้ว' });
      const id = rid(6);
      const { salt, hash } = hashPassword(password);
      db.users[id] = { id, email, salt, hash, createdAt: Date.now() };
      const sid = makeSession(id);
      saveDb();
      return sendJson(res, 200, { email }, { 'Set-Cookie': sessionCookie(sid) });
    }

    if (p === '/api/login' && req.method === 'POST') {
      const b = await readJson(req);
      const email = String(b.email || '').trim().toLowerCase();
      const user = Object.values(db.users).find((x) => x.email === email);
      if (!user || !verifyPassword(b.password || '', user.salt, user.hash))
        return sendJson(res, 401, { error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
      const sid = makeSession(user.id);
      saveDb();
      return sendJson(res, 200, { email }, { 'Set-Cookie': sessionCookie(sid) });
    }

    if (p === '/api/logout' && req.method === 'POST') {
      const sid = parseCookies(req).sid;
      if (sid) delete db.sessions[sid];
      saveDb();
      return sendJson(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; Path=/; Max-Age=0' });
    }

    if (p === '/api/me' && req.method === 'GET') {
      const me = currentUser(req);
      if (!me) return sendJson(res, 401, { error: 'ยังไม่ได้เข้าสู่ระบบ' });
      return sendJson(res, 200, { email: me.email, isAdmin: isAdmin(me) });
    }

    // ========== แอดมินระบบ: ดู/ลบผู้ใช้ ==========
    if (p === '/api/admin/users' && req.method === 'GET') {
      const me = currentUser(req);
      if (!isAdmin(me)) return sendJson(res, 403, { error: 'เฉพาะแอดมินระบบเท่านั้น' });
      const users = Object.values(db.users).map((usr) => {
        const quizzes = Object.values(db.quizzes).filter((q) => q.ownerId === usr.id);
        const responseCount = quizzes.reduce((s, q) => s + ((db.responses[q.id] || []).length), 0);
        return {
          id: usr.id, email: usr.email, createdAt: usr.createdAt,
          quizCount: quizzes.length,
          enabledCount: quizzes.filter((q) => q.enabled).length,
          responseCount,
          isAdmin: isAdmin(usr),
          isSelf: usr.id === me.id,
        };
      }).sort((a, b) => b.createdAt - a.createdAt);
      return sendJson(res, 200, { users, total: users.length });
    }
    // แอดมิน: ดูข้อมูลผู้ใช้รายคน (ควิซทั้งหมดของเขา)
    const adminUserMatch = p.match(/^\/api\/admin\/users\/([^/]+)$/);
    if (adminUserMatch && req.method === 'GET') {
      const me = currentUser(req);
      if (!isAdmin(me)) return sendJson(res, 403, { error: 'เฉพาะแอดมินระบบเท่านั้น' });
      const usr = db.users[adminUserMatch[1]];
      if (!usr) return sendJson(res, 404, { error: 'ไม่พบผู้ใช้' });
      const quizzes = Object.values(db.quizzes).filter((q) => q.ownerId === usr.id).map((q) => ({
        id: q.id, title: q.title, enabled: !!q.enabled, adminToken: q.adminToken,
        questionCount: allQuestions(q).length, responseCount: (db.responses[q.id] || []).length,
        createdAt: q.createdAt,
      })).sort((a, b) => b.createdAt - a.createdAt);
      return sendJson(res, 200, { user: { id: usr.id, email: usr.email, createdAt: usr.createdAt }, quizzes });
    }

    // แอดมิน: รีเซ็ตรหัสผ่านผู้ใช้ (ตั้งรหัสใหม่ ไม่เห็นรหัสเดิม)
    const resetMatch = p.match(/^\/api\/admin\/users\/([^/]+)\/reset-password$/);
    if (resetMatch && req.method === 'POST') {
      const me = currentUser(req);
      if (!isAdmin(me)) return sendJson(res, 403, { error: 'เฉพาะแอดมินระบบเท่านั้น' });
      const usr = db.users[resetMatch[1]];
      if (!usr) return sendJson(res, 404, { error: 'ไม่พบผู้ใช้' });
      const b = await readJson(req);
      const pw = String(b.password || '');
      if (pw.length < 6) return sendJson(res, 400, { error: 'รหัสผ่านต้องยาวอย่างน้อย 6 ตัว' });
      const { salt, hash } = hashPassword(pw);
      usr.salt = salt; usr.hash = hash;
      // เตะ session เดิมของผู้ใช้นี้ออก (บังคับให้เข้าใหม่ด้วยรหัสใหม่)
      for (const sid of Object.keys(db.sessions)) if (db.sessions[sid].userId === usr.id) delete db.sessions[sid];
      saveDb();
      return sendJson(res, 200, { ok: true });
    }

    if (adminUserMatch && req.method === 'DELETE') {
      const me = currentUser(req);
      if (!isAdmin(me)) return sendJson(res, 403, { error: 'เฉพาะแอดมินระบบเท่านั้น' });
      const uid = adminUserMatch[1];
      if (!db.users[uid]) return sendJson(res, 404, { error: 'ไม่พบผู้ใช้' });
      if (uid === me.id) return sendJson(res, 400, { error: 'ลบบัญชีตัวเองไม่ได้' });
      Object.values(db.quizzes).filter((q) => q.ownerId === uid).forEach((q) => {
        delete db.quizzes[q.id]; delete db.responses[q.id]; delete db.events[q.id];
      });
      for (const sid of Object.keys(db.sessions)) if (db.sessions[sid].userId === uid) delete db.sessions[sid];
      delete db.users[uid];
      saveDb();
      return sendJson(res, 200, { ok: true });
    }

    // ========== UPLOAD สื่อ (ต้องล็อกอิน) ==========
    if (p === '/api/upload' && req.method === 'POST') {
      const me = currentUser(req);
      if (!me) return sendJson(res, 401, { error: 'ต้องเข้าสู่ระบบก่อน' });
      let buf;
      try { buf = await readRaw(req, MAX_UPLOAD); }
      catch { return sendJson(res, 413, { error: 'ไฟล์ใหญ่เกิน 25MB' }); }
      const nameParam = u.searchParams.get('name') || 'file';
      let ext = path.extname(nameParam).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 6);
      if (!MIME[ext]) ext = '';
      const fname = rid(10) + ext;
      fs.writeFileSync(path.join(UPLOAD_DIR, fname), buf);
      return sendJson(res, 200, { url: '/uploads/' + fname });
    }

    // ========== รายการควิซของฉัน (ต้องล็อกอิน) ==========
    if (p === '/api/my-quizzes' && req.method === 'GET') {
      const me = currentUser(req);
      if (!me) return sendJson(res, 401, { error: 'ต้องเข้าสู่ระบบก่อน' });
      const list = Object.values(db.quizzes)
        .filter((q) => q.ownerId === me.id)
        .sort((a, b) => (b.updatedAt || b.createdAt) - (a.updatedAt || a.createdAt))
        .map((q) => ({
          id: q.id, title: q.title, enabled: !!q.enabled,
          questionCount: allQuestions(q).length,
          partCount: (q.parts || []).length,
          responseCount: (db.responses[q.id] || []).length,
          timeLimitSec: q.timeLimitSec || 0,
          adminToken: q.adminToken,
          updatedAt: q.updatedAt || q.createdAt,
        }));
      return sendJson(res, 200, { quizzes: list });
    }

    // ========== สร้างควิซใหม่ (ต้องล็อกอิน) ==========
    if (p === '/api/quizzes' && req.method === 'POST') {
      const me = currentUser(req);
      if (!me) return sendJson(res, 401, { error: 'ต้องเข้าสู่ระบบก่อน' });
      const clean = sanitizeQuiz(await readJson(req));
      if (allQuestions(clean).length === 0) return sendJson(res, 400, { error: 'ต้องมีคำถามอย่างน้อย 1 ข้อ' });
      const qid = rid(4);
      db.quizzes[qid] = {
        id: qid, ownerId: me.id, adminToken: rid(10), enabled: false,
        ...clean, createdAt: Date.now(), updatedAt: Date.now(),
      };
      db.responses[qid] = []; db.events[qid] = [];
      saveDb();
      return sendJson(res, 200, { id: qid });
    }

    // ========== เส้นทางที่อ้างถึงควิซเฉพาะตัว ==========
    const seg = p.split('/').filter(Boolean); // ['api','quizzes',':id', sub]
    if (seg[0] === 'api' && seg[1] === 'quizzes' && seg[2]) {
      const qid = seg[2];
      const quiz = db.quizzes[qid];
      if (!quiz) return sendJson(res, 404, { error: 'ไม่พบควิซนี้' });
      const sub = seg[3];
      const me = currentUser(req);
      const isOwner = me && quiz.ownerId === me.id;

      // -- เจ้าของ: ดึงควิซเต็มไปแก้ไข --
      if (sub === 'edit' && req.method === 'GET') {
        if (!isOwner) return sendJson(res, 403, { error: 'ไม่มีสิทธิ์' });
        return sendJson(res, 200, { quiz });
      }
      // -- เจ้าของ: อัปเดตควิซ --
      if (!sub && req.method === 'PUT') {
        if (!isOwner) return sendJson(res, 403, { error: 'ไม่มีสิทธิ์' });
        const clean = sanitizeQuiz(await readJson(req));
        if (allQuestions(clean).length === 0) return sendJson(res, 400, { error: 'ต้องมีคำถามอย่างน้อย 1 ข้อ' });
        Object.assign(quiz, clean, { updatedAt: Date.now() });
        saveDb();
        return sendJson(res, 200, { ok: true });
      }
      // -- เจ้าของ: ลบควิซ --
      if (!sub && req.method === 'DELETE') {
        if (!isOwner) return sendJson(res, 403, { error: 'ไม่มีสิทธิ์' });
        delete db.quizzes[qid]; delete db.responses[qid]; delete db.events[qid];
        saveDb();
        return sendJson(res, 200, { ok: true });
      }
      // -- เจ้าของ: เปิด/ปิดการใช้งานควิซ --
      if (sub === 'toggle' && req.method === 'POST') {
        if (!isOwner) return sendJson(res, 403, { error: 'ไม่มีสิทธิ์' });
        const b = await readJson(req);
        quiz.enabled = !!b.enabled;
        quiz.updatedAt = Date.now();
        saveDb();
        return sendJson(res, 200, { enabled: quiz.enabled });
      }

      // -- ผู้ตอบ: ดึงควิซ (เฉพาะที่เปิดใช้งาน) --
      if (!sub && req.method === 'GET') {
        if (!quiz.enabled && !isOwner) return sendJson(res, 403, { error: 'ควิซนี้ยังไม่เปิดใช้งาน' });
        return sendJson(res, 200, publicQuiz(quiz));
      }

      // -- ผู้ตอบ: ส่งคำตอบ --
      if (sub === 'responses' && req.method === 'POST') {
        if (!quiz.enabled && !isOwner) return sendJson(res, 403, { error: 'ควิซนี้ยังไม่เปิดใช้งาน' });
        const b = await readJson(req);
        const answers = b.answers && typeof b.answers === 'object' ? b.answers : {}; // { questionId: value }
        const qs = allQuestions(quiz);
        let score = 0, mcTotal = 0;
        const detail = qs.map((q) => {
          const a = answers[q.id];
          if (q.type === 'mc') {
            mcTotal++;
            const correct = a === q.correct;
            if (correct) score++;
            return { id: q.id, type: 'mc', answer: (a ?? -1), correct };
          }
          return { id: q.id, type: 'open', answer: String(a ?? '').slice(0, 5000) };
        });
        db.responses[qid].push({
          sessionId: String(b.sessionId || rid(6)),
          name: String(b.name || 'ไม่ระบุชื่อ').slice(0, 100),
          detail, score, mcTotal,
          durationSec: Math.max(0, parseInt(b.durationSec, 10) || 0),
          submittedAt: Date.now(),
        });
        saveDb();
        return sendJson(res, 200, { ok: true, score, mcTotal });
      }

      // -- ผู้ตอบ: บันทึกออก/กลับเข้าจอ --
      if (sub === 'events' && req.method === 'POST') {
        const b = await readJson(req);
        db.events[qid].push({
          sessionId: String(b.sessionId || '').slice(0, 40),
          name: String(b.name || 'ไม่ระบุชื่อ').slice(0, 100),
          type: b.type === 'return' ? 'return' : 'leave',
          reason: String(b.reason || '').slice(0, 40),
          awayMs: Number(b.awayMs) || 0,
          at: Date.now(),
        });
        if (db.events[qid].length > 20000) db.events[qid].shift();
        saveDb();
        return sendJson(res, 200, { ok: true });
      }

      // -- เจ้าของ/มี token: แดชบอร์ดผล --
      if (sub === 'admin' && req.method === 'GET') {
        const token = u.searchParams.get('token');
        if (!isOwner && !isAdmin(me) && token !== quiz.adminToken) return sendJson(res, 403, { error: 'ไม่มีสิทธิ์เข้าถึง' });
        return sendJson(res, 200, {
          quiz, responses: db.responses[qid] || [], events: db.events[qid] || [],
        });
      }
    }

    return sendJson(res, 404, { error: 'ไม่พบ endpoint นี้' });
  } catch (err) {
    return sendJson(res, 500, { error: 'เซิร์ฟเวอร์ขัดข้อง' });
  }
});

server.listen(PORT, () => {
  console.log(`\n  ควิซออนไลน์กำลังทำงานที่  http://localhost:${PORT}\n`);
});
