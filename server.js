'use strict';
// Watch backend: Instagram + Facebook + YouTube mix. Zero npm deps. Node 22.13+
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), util = require('util');
const { DatabaseSync } = require('node:sqlite');
const scrypt = util.promisify(crypto.scrypt);
const PORT = +process.env.PORT || 3000;
let DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
let UP = path.join(DATA, 'uploads');
try {
  fs.mkdirSync(UP, { recursive: true });
} catch (e) {
  console.log('Cannot use', DATA, '- falling back to /app/data');
  DATA = path.join(__dirname, 'data');
  UP = path.join(DATA, 'uploads');
  fs.mkdirSync(UP, { recursive: true });
}
fs.mkdirSync(PUB, { recursive: true });

let SECRET = process.env.SECRET;
if (!SECRET) {
  const f = path.join(DATA, 'secret');
  try { SECRET = fs.readFileSync(f, 'utf8'); }
  catch { SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(f, SECRET, { mode: 0o600 }); }
}

const db = new DatabaseSync(path.join(DATA, 'watch.db'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt TEXT, hash TEXT, bio TEXT DEFAULT '', av TEXT);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY AUTOINCREMENT, u TEXT REFERENCES users(name) ON DELETE CASCADE, k TEXT, cap TEXT, file TEXT, ts INTEGER, views INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS likes(pid INTEGER REFERENCES posts(id) ON DELETE CASCADE, u TEXT REFERENCES users(name) ON DELETE CASCADE, PRIMARY KEY(pid,u));
CREATE TABLE IF NOT EXISTS saves(pid INTEGER REFERENCES posts(id) ON DELETE CASCADE, u TEXT REFERENCES users(name) ON DELETE CASCADE, PRIMARY KEY(pid,u));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT, pid INTEGER REFERENCES posts(id) ON DELETE CASCADE, u TEXT REFERENCES users(name) ON DELETE CASCADE, txt TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS follows(a TEXT REFERENCES users(name) ON DELETE CASCADE, b TEXT, PRIMARY KEY(a,b));
CREATE TABLE IF NOT EXISTS blocks(a TEXT REFERENCES users(name) ON DELETE CASCADE, b TEXT, PRIMARY KEY(a,b));
CREATE TABLE IF NOT EXISTS reports(pid INTEGER REFERENCES posts(id) ON DELETE CASCADE, u TEXT, PRIMARY KEY(pid,u));
CREATE TABLE IF NOT EXISTS stories(id INTEGER PRIMARY KEY AUTOINCREMENT, u TEXT REFERENCES users(name) ON DELETE CASCADE, file TEXT, ts INTEGER);
CREATE INDEX IF NOT EXISTS idx_posts_ts ON posts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_stories_ts ON stories(ts DESC);`);

// migrate views if missing
try { db.exec('ALTER TABLE posts ADD COLUMN views INTEGER DEFAULT 0'); } catch(e) {}

const Q = (s) => db.prepare(s);

// ---------- helpers ----------
const hits = new Map();
function limited(key, max, win) {
  const now = Date.now(); let h = hits.get(key);
  if (!h || now > h.r) { h = { n: 0, r: now + win }; hits.set(key, h); }
  return ++h.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (n > v.r) hits.delete(k); }, 60000).unref();

const ip = (req) => (process.env.TRUST_PROXY && req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const NAME = /^[a-z0-9_]{3,20}$/;

function setCookie(req, res, user) {
  const exp = Date.now() + 7 * 864e5, v = `${user}.${exp}`;
  const secure = process.env.INSECURE_COOKIES ? '' : '; Secure';
  res.setHeader('Set-Cookie', `w=${v}.${sign(v)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${7 * 86400}${secure}`);
}
function who(req) {
  const m = /(?:^|; )w=([^;]+)/.exec(req.headers.cookie || ''); if (!m) return null;
  const [u, exp, mac] = m[1].split('.');
  if (!u || !mac || +exp < Date.now() || !safeEq(mac, sign(`${u}.${exp}`))) return null;
  return Q('SELECT name FROM users WHERE name=?').get(u) ? u : null;
}
function send(res, code, obj) {
  const b = JSON.stringify(obj); res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(b);
}
function readBody(req, max) {
  return new Promise((ok, no) => {
    const c = []; let n = 0;
    req.on('data', (d) => { n += d.length; if (n > max) { no(Object.assign(new Error('Too big'), { code: 413 })); req.destroy(); } else c.push(d); });
    req.on('end', () => ok(Buffer.concat(c))); req.on('error', no);
  });
}
const json = async (req) => { try { return JSON.parse((await readBody(req, 10000)).toString() || '{}'); } catch (e) { if (e.code === 413) throw e; throw Object.assign(new Error('Bad JSON'), { code: 400 }); } };
const str = (s, n) => (typeof s === 'string' ? s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, n) : '');

function sniff(b) {
  if (b.length < 12) return null;
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return ['jpg', 'image/jpeg'];
  if (b.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) return ['png', 'image/png'];
  if (b.subarray(0, 4).toString() === 'GIF8') return ['gif', 'image/gif'];
  if (b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP') return ['webp', 'image/webp'];
  if (b.subarray(4, 8).toString() === 'ftyp') return ['mp4', 'video/mp4'];
  if (b.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))) return ['webm', 'video/webm'];
  return null;
}
const MIME = { jpg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', mp4: 'video/mp4', webm: 'video/webm' };
const FILE = /^[a-f0-9]{32}\.(jpg|png|gif|webp|mp4|webm)$/;

function feed(me, explore = false) {
  let sql;
  if (explore) {
    sql = `SELECT p.*, (SELECT COUNT(*) FROM likes WHERE pid=p.id) lc,
      (SELECT COUNT(*) FROM likes WHERE pid=p.id AND u=?) lm, (SELECT COUNT(*) FROM saves WHERE pid=p.id AND u=?) sm
      FROM posts p WHERE p.u NOT IN (SELECT b FROM blocks WHERE a=?) 
      ORDER BY (p.views + lc * 3) DESC, p.id DESC LIMIT 100`;
  } else {
    sql = `SELECT p.*, (SELECT COUNT(*) FROM likes WHERE pid=p.id) lc,
      (SELECT COUNT(*) FROM likes WHERE pid=p.id AND u=?) lm, (SELECT COUNT(*) FROM saves WHERE pid=p.id AND u=?) sm
      FROM posts p WHERE p.u NOT IN (SELECT b FROM blocks WHERE a=?) ORDER BY p.id DESC LIMIT 200`;
  }
  const rows = Q(sql).all(me, me, me);
  const cm = Q('SELECT u,txt FROM (SELECT * FROM comments WHERE pid=? ORDER BY id DESC LIMIT 30) ORDER BY id');
  return rows.map((r) => {
    const ext = r.file ? r.file.split('.')[1] : null, vid = ext === 'mp4' || ext === 'webm';
    return { id: r.id, k: r.k, u: r.u, cap: r.cap, g: r.id % 6, e: { text: '📝', photo: '📷', reel: '🎞', video: '📺' }[r.k] || '✨',
      likes: r.lc - r.lm, liked: !!r.lm, saved: !!r.sm, cm: cm.all(r.id).map((c) => [c.u, c.txt]),
      src: r.file ? '/u/' + r.file : null, t: r.file ? (vid ? 'video' : 'image') : null, 
      views: r.views || 0, dur: vid ? '0:30' : null };
  });
}

function getStories(me) {
  // stories from last 24h, group by user
  const since = Date.now() - 24 * 3600 * 1000;
  const rows = Q(`SELECT s.*, u.av FROM stories s JOIN users u ON u.name=s.u 
    WHERE s.ts > ? AND s.u NOT IN (SELECT b FROM blocks WHERE a=?) 
    ORDER BY s.ts DESC LIMIT 200`).all(since, me);
  const byUser = {};
  for (const r of rows) {
    if (!byUser[r.u]) byUser[r.u] = { u: r.u, av: r.av ? '/u/' + r.av : null, items: [] };
    byUser[r.u].items.push({ id: r.id, src: '/u/' + r.file, ts: r.ts });
  }
  // put "me" first if has stories
  const list = Object.values(byUser);
  list.sort((a, b) => (a.u === me ? -1 : b.u === me ? 1 : 0));
  return list;
}

// ---------- routes ----------
async function api(req, res, url) {
  const m = req.method, p = url.pathname;
  if (m !== 'GET' && req.headers['x-w'] !== '1') return send(res, 403, { error: 'Forbidden' });

  if (m === 'POST' && (p === '/api/signup' || p === '/api/login')) {
    const b = await json(req), u = str(b.u, 20).toLowerCase(), pw = typeof b.p === 'string' ? b.p.slice(0, 64) : '';
    if (limited(`a:${ip(req)}:${u}`, 5, 15 * 60000) || limited(`a:${ip(req)}`, 30, 15 * 60000)) return send(res, 429, { error: 'Ghani vaar prayas. 15 minute pachhi try karo.' });
    if (!NAME.test(u)) return send(res, 400, { error: 'Username 3-20 akshar (a-z, 0-9, _).' });
    if (p === '/api/signup') {
      if (pw.length < 8 || !/[a-z]/i.test(pw) || !/\d/.test(pw)) return send(res, 400, { error: 'Password 8+ akshar, letter ane number joie.' });
      if (Q('SELECT 1 FROM users WHERE name=?').get(u)) return send(res, 409, { error: 'Aa username levayu chhe.' });
      const salt = crypto.randomBytes(16).toString('hex'), hash = (await scrypt(pw, salt, 64)).toString('hex');
      Q('INSERT INTO users(name,salt,hash) VALUES(?,?,?)').run(u, salt, hash);
    } else {
      const r = Q('SELECT salt,hash FROM users WHERE name=?').get(u);
      const h = (await scrypt(pw, r ? r.salt : '0'.repeat(32), 64)).toString('hex');
      if (!r || !safeEq(h, r.hash)) return send(res, 401, { error: 'Username ke password khotu chhe.' });
      hits.delete(`a:${ip(req)}:${u}`);
    }
    setCookie(req, res, u); return send(res, 200, { u });
  }
  if (m === 'POST' && p === '/api/logout') { res.setHeader('Set-Cookie', 'w=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return send(res, 200, {}); }

  const me = who(req); if (!me) return send(res, 401, { error: 'Login karo' });
  if (limited(`w:${me}`, m === 'GET' ? 240 : 60, 60000)) return send(res, 429, { error: 'Thodu dhime…' });

  if (m === 'GET' && p === '/api/me') { const r = Q('SELECT bio,av FROM users WHERE name=?').get(me); return send(res, 200, { u: me, bio: r.bio, av: r.av ? '/u/' + r.av : null }); }
  if (m === 'GET' && p === '/api/posts') {
    const r = Q('SELECT bio,av FROM users WHERE name=?').get(me);
    return send(res, 200, { posts: feed(me), me: { bio: r.bio, av: r.av ? '/u/' + r.av : null },
      fol: Q('SELECT b FROM follows WHERE a=?').all(me).map((x) => x.b), blocked: Q('SELECT b FROM blocks WHERE a=?').all(me).map((x) => x.b),
      stories: getStories(me) });
  }
  if (m === 'GET' && p === '/api/explore') {
    return send(res, 200, { posts: feed(me, true) });
  }
  if (m === 'PUT' && p === '/api/me') {
    const b = await json(req); const bio = str(b.bio, 150);
    if (b.av !== undefined && !(typeof b.av === 'string' && FILE.test(b.av))) return send(res, 400, { error: 'Bad file' });
    Q('UPDATE users SET bio=?, av=COALESCE(?,av) WHERE name=?').run(bio, b.av || null, me); return send(res, 200, {});
  }
  if (m === 'DELETE' && p === '/api/me') { Q('DELETE FROM users WHERE name=?').run(me); res.setHeader('Set-Cookie', 'w=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return send(res, 200, {}); }

  if (m === 'POST' && p === '/api/upload') {
    if (limited(`up:${me}`, 30, 3600000)) return send(res, 429, { error: 'Upload limit' });
    const b = await readBody(req, 50e6), t = sniff(b); if (!t) return send(res, 400, { error: 'Aa file type nathi chalto.' });
    const name = crypto.randomBytes(16).toString('hex') + '.' + t[0]; fs.writeFileSync(path.join(UP, name), b, { mode: 0o640 });
    return send(res, 200, { file: name });
  }
  if (m === 'POST' && p === '/api/posts') {
    const b = await json(req), k = ['text', 'photo', 'reel', 'video'].includes(b.k) ? b.k : null, cap = str(b.cap, 300);
    const file = typeof b.file === 'string' && FILE.test(b.file) && fs.existsSync(path.join(UP, b.file)) ? b.file : null;
    if (!k || (!cap && !file)) return send(res, 400, { error: 'Kai to lakho ke upload karo' });
    const r = Q('INSERT INTO posts(u,k,cap,file,ts,views) VALUES(?,?,?,?,?,0)').run(me, k, cap, file, Date.now());
    return send(res, 200, { id: Number(r.lastInsertRowid) });
  }
  if (m === 'POST' && p === '/api/stories') {
    if (limited(`st:${me}`, 10, 3600000)) return send(res, 429, { error: 'Story limit' });
    const b = await json(req);
    const file = typeof b.file === 'string' && FILE.test(b.file) && fs.existsSync(path.join(UP, b.file)) ? b.file : null;
    if (!file) return send(res, 400, { error: 'File joie' });
    // only image or short video for stories
    const ext = file.split('.')[1];
    if (!['jpg','png','gif','webp','mp4','webm'].includes(ext)) return send(res, 400, { error: 'Bad type' });
    Q('INSERT INTO stories(u,file,ts) VALUES(?,?,?)').run(me, file, Date.now());
    return send(res, 200, {});
  }
  if (m === 'POST' && p === '/api/posts/view') {
    const b = await json(req), id = +b.id;
    if (id) Q('UPDATE posts SET views = views + 1 WHERE id=?').run(id);
    return send(res, 200, {});
  }
  let x;
  if ((x = /^\/api\/posts\/(\d+)\/(like|save|comments|report)$/.exec(p)) && m === 'POST') {
    const id = +x[1]; if (!Q('SELECT 1 FROM posts WHERE id=?').get(id)) return send(res, 404, { error: 'Not found' });
    if (x[2] === 'comments') { const t = str((await json(req)).t, 200); if (!t) return send(res, 400, { error: 'Khali' }); Q('INSERT INTO comments(pid,u,txt,ts) VALUES(?,?,?,?)').run(id, me, t, Date.now()); return send(res, 200, {}); }
    if (x[2] === 'report') { Q('INSERT OR IGNORE INTO reports VALUES(?,?)').run(id, me); return send(res, 200, {}); }
    const tb = x[2] === 'like' ? 'likes' : 'saves';
    if (Q(`DELETE FROM ${tb} WHERE pid=? AND u=?`).run(id, me).changes === 0) Q(`INSERT INTO ${tb} VALUES(?,?)`).run(id, me);
    return send(res, 200, {});
  }
  if ((x = /^\/api\/posts\/(\d+)$/.exec(p)) && m === 'DELETE') {
    const r = Q('SELECT file FROM posts WHERE id=? AND u=?').get(+x[1], me); if (!r) return send(res, 404, { error: 'Not found' });
    Q('DELETE FROM posts WHERE id=?').run(+x[1]); if (r.file) fs.rm(path.join(UP, r.file), () => {}); return send(res, 200, {});
  }
  if ((x = /^\/api\/users\/([a-z0-9_]{3,20})\/(follow|block)$/.exec(p)) && m === 'POST') {
    if (x[1] === me || !Q('SELECT 1 FROM users WHERE name=?').get(x[1])) return send(res, 400, { error: 'Bad user' });
    const tb = x[2] === 'follow' ? 'follows' : 'blocks';
    if (Q(`DELETE FROM ${tb} WHERE a=? AND b=?`).run(me, x[1]).changes === 0) Q(`INSERT INTO ${tb} VALUES(?,?)`).run(me, x[1]);
    return send(res, 200, {});
  }
  return send(res, 404, { error: 'Not found' });
}

function serveFile(req, res, file, type, cache) {
  fs.stat(file, (e, st) => {
    if (e || !st.isFile()) { res.writeHead(404); return res.end(); }
    const h = { 'Content-Type': type, 'Accept-Ranges': 'bytes', 'Cache-Control': cache };
    const r = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (r && (r[1] || r[2])) {
      let s = r[1] ? +r[1] : Math.max(0, st.size - +r[2]), en = r[1] && r[2] ? Math.min(+r[2], st.size - 1) : st.size - 1;
      if (s > en || s >= st.size) { res.writeHead(416, { 'Content-Range': `bytes */${st.size}` }); return res.end(); }
      res.writeHead(206, { ...h, 'Content-Range': `bytes ${s}-${en}/${st.size}`, 'Content-Length': en - s + 1 });
      return fs.createReadStream(file, { start: s, end: en }).pipe(res);
    }
    res.writeHead(200, { ...h, 'Content-Length': st.size }); fs.createReadStream(file).pipe(res);
  });
}

http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  if (req.headers['x-forwarded-proto'] === 'https') res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  try {
    if (limited(`g:${ip(req)}`, 600, 60000)) { res.writeHead(429); return res.end(); }
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    if (url.pathname === '/' || url.pathname === '/index.html') return serveFile(req, res, path.join(PUB, 'index.html'), 'text/html; charset=utf-8', 'no-cache');
    if (url.pathname === '/manifest.json') return serveFile(req, res, path.join(PUB, 'manifest.json'), 'application/manifest+json', 'no-cache');
    if (url.pathname === '/icon.svg') return serveFile(req, res, path.join(PUB, 'icon.svg'), 'image/svg+xml; charset=utf-8', 'public, max-age=86400');
    const f = /^\/u\/([a-f0-9]{32}\.[a-z0-9]{3,4})$/.exec(url.pathname);
    if (f && FILE.test(f[1])) return serveFile(req, res, path.join(UP, f[1]), MIME[f[1].split('.')[1]], 'public, max-age=86400');
    res.writeHead(404); res.end();
  } catch (e) {
    if (!res.headersSent) send(res, e.code === 413 ? 413 : e.code === 400 ? 400 : 500, { error: e.code === 413 ? 'File ghani moti' : e.code === 400 ? 'Bad request' : 'Server error' });
    if (!e.code) console.error(e);
  }
}).listen(PORT, () => console.log('Watch running on :' + PORT));
