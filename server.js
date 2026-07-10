// ควิซออนไลน์ + ระบบตรวจจับการออกจากหน้าจอ
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

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- ที่เก็บข้อมูล (ไฟล์ JSON ไฟล์เดียว) ----------
let db = { quizzes: {}, responses: {}, events: {} };
try {
  db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  db.quizzes = db.quizzes || {};
  db.responses = db.responses || {};
  db.events = db.events || {};
} catch (_) { /* เริ่มใหม่ */ }

let saveTimer = null;
function saveDb() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(DATA_FILE, JSON.stringify(db, null, 2), () => {});
  }, 40);
}

// ---------- helper ----------
function rid(n = 5) { return crypto.randomBytes(n).toString('hex'); }

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

function sanitizeQuestions(input) {
  if (!Array.isArray(input)) return [];
  return input.slice(0, 100).map((q) => {
    const choices = Array.isArray(q.choices) ? q.choices.slice(0, 4) : [];
    while (choices.length < 4) choices.push('');
    let correct = parseInt(q.correct, 10);
    if (!(correct >= 0 && correct <= 3)) correct = 0;
    return {
      text: String(q.text || '').slice(0, 500),
      choices: choices.map((c) => String(c).slice(0, 300)),
      correct,
    };
  }).filter((q) => q.text.trim() !== '');
}

// เวอร์ชันสำหรับผู้ตอบ (ตัดเฉลย + token ออก)
function publicQuiz(quiz) {
  return {
    id: quiz.id,
    title: quiz.title,
    description: quiz.description,
    questions: quiz.questions.map((q) => ({ text: q.text, choices: q.choices })),
  };
}

// ---------- ไฟล์ static ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function serveStatic(req, res) {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);
  if (urlPath === '/') urlPath = '/index.html';
  if (urlPath === '/take') urlPath = '/take.html';
  if (urlPath === '/admin') urlPath = '/admin.html';
  const filePath = path.join(PUBLIC_DIR, path.normalize(urlPath).replace(/^(\.\.[/\\])+/, ''));
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('ไม่พบหน้านี้'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------- เซิร์ฟเวอร์ ----------
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;

  if (!p.startsWith('/api/')) return serveStatic(req, res);

  try {
    // สร้างควิซใหม่
    if (p === '/api/quizzes' && req.method === 'POST') {
      const body = await readBody(req);
      const qid = rid(4);
      const adminToken = rid(10);
      const quiz = {
        id: qid,
        adminToken,
        title: String(body.title || 'ควิซไม่มีชื่อ').slice(0, 200),
        description: String(body.description || '').slice(0, 1000),
        questions: sanitizeQuestions(body.questions),
        createdAt: Date.now(),
      };
      if (quiz.questions.length === 0) return sendJson(res, 400, { error: 'ต้องมีคำถามอย่างน้อย 1 ข้อ' });
      db.quizzes[qid] = quiz;
      db.responses[qid] = [];
      db.events[qid] = [];
      saveDb();
      return sendJson(res, 200, { id: qid, adminToken });
    }

    const parts = p.split('/').filter(Boolean); // ['api','quizzes',':id', ...]
    if (parts[0] === 'api' && parts[1] === 'quizzes' && parts[2]) {
      const qid = parts[2];
      const quiz = db.quizzes[qid];
      if (!quiz) return sendJson(res, 404, { error: 'ไม่พบควิซนี้' });
      const sub = parts[3];

      // ดึงควิซสำหรับผู้ตอบ
      if (!sub && req.method === 'GET') {
        return sendJson(res, 200, publicQuiz(quiz));
      }

      // ส่งคำตอบ
      if (sub === 'responses' && req.method === 'POST') {
        const body = await readBody(req);
        const answers = Array.isArray(body.answers) ? body.answers : [];
        let score = 0;
        quiz.questions.forEach((q, i) => { if (answers[i] === q.correct) score++; });
        const response = {
          sessionId: String(body.sessionId || rid(6)),
          name: String(body.name || 'ไม่ระบุชื่อ').slice(0, 100),
          answers,
          score,
          total: quiz.questions.length,
          submittedAt: Date.now(),
        };
        db.responses[qid].push(response);
        saveDb();
        return sendJson(res, 200, { ok: true, score, total: quiz.questions.length });
      }

      // บันทึกเหตุการณ์ออก/กลับเข้าหน้าจอ (เรียกผ่าน sendBeacon)
      if (sub === 'events' && req.method === 'POST') {
        const body = await readBody(req);
        const ev = {
          sessionId: String(body.sessionId || '').slice(0, 40),
          name: String(body.name || 'ไม่ระบุชื่อ').slice(0, 100),
          type: body.type === 'return' ? 'return' : 'leave',
          reason: String(body.reason || '').slice(0, 40),
          awayMs: Number(body.awayMs) || 0,
          at: Date.now(),
        };
        db.events[qid].push(ev);
        if (db.events[qid].length > 20000) db.events[qid].shift();
        saveDb();
        return sendJson(res, 200, { ok: true });
      }

      // แดชบอร์ดผู้สร้าง (ต้องมี token)
      if (sub === 'admin' && req.method === 'GET') {
        const token = u.searchParams.get('token');
        if (token !== quiz.adminToken) return sendJson(res, 403, { error: 'token ไม่ถูกต้อง' });
        return sendJson(res, 200, {
          quiz: {
            id: quiz.id, title: quiz.title, description: quiz.description,
            questions: quiz.questions, createdAt: quiz.createdAt,
          },
          responses: db.responses[qid] || [],
          events: db.events[qid] || [],
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
