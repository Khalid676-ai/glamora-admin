'use strict';
/* Glamora backend: zero-dependency Node server (Node 22.13+). Serves the public site, the admin panel and the JSON APIs. */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
// minimal .env loader (no dependency); real environment variables win
try { for (const line of fs.readFileSync(path.join(ROOT, '.env'), 'utf8').split(/\r?\n/)) { const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, ''); } } catch (_) {}
const PORT = +process.env.PORT || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const UPLOADS = path.join(DATA_DIR, 'uploads');
const SECURE = process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production';
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'glamora.db'));
db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
db.exec(`
CREATE TABLE IF NOT EXISTS admin_users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS collections(id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, description TEXT DEFAULT '', banner TEXT DEFAULT '', thumbnail TEXT DEFAULT '', sort INTEGER DEFAULT 0, status TEXT DEFAULT 'published', seo_title TEXT DEFAULT '', seo_desc TEXT DEFAULT '', created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, description TEXT DEFAULT '', image TEXT DEFAULT '', collection_id INTEGER REFERENCES collections(id) ON DELETE RESTRICT, status TEXT DEFAULT 'published', created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, sku TEXT UNIQUE, name TEXT NOT NULL, short_desc TEXT DEFAULT '', description TEXT DEFAULT '', image TEXT DEFAULT '', images TEXT DEFAULT '[]', category_id INTEGER REFERENCES categories(id) ON DELETE RESTRICT, collection_id INTEGER REFERENCES collections(id) ON DELETE RESTRICT, price REAL NOT NULL, sale_price REAL, sizes TEXT DEFAULT '[]', colors TEXT DEFAULT '[]', stock INTEGER, tags TEXT DEFAULT '[]', featured INTEGER DEFAULT 0, focus INTEGER DEFAULT 20, status TEXT DEFAULT 'draft', seo_title TEXT DEFAULT '', seo_desc TEXT DEFAULT '', created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, title TEXT NOT NULL, excerpt TEXT DEFAULT '', image TEXT DEFAULT '', body TEXT DEFAULT '[]', author TEXT DEFAULT 'Glamora Editorial Team', category TEXT DEFAULT '', tags TEXT DEFAULT '[]', published_at TEXT, seo_title TEXT DEFAULT '', seo_desc TEXT DEFAULT '', og_image TEXT DEFAULT '', featured INTEGER DEFAULT 0, status TEXT DEFAULT 'draft', created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS redirects(old_slug TEXT PRIMARY KEY, new_slug TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS media(id INTEGER PRIMARY KEY, filename TEXT UNIQUE NOT NULL, original TEXT, mime TEXT, size INTEGER, width INTEGER, height INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT, subject TEXT, order_no TEXT, message TEXT, status TEXT DEFAULT 'new', created_at TEXT);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);
const rows = (sql, ...p) => db.prepare(sql).all(...p);
const one = (sql, ...p) => db.prepare(sql).get(...p);
const run = (sql, ...p) => db.prepare(sql).run(...p);
const now = () => new Date().toISOString();

/* ---------- passwords: scrypt (memory-hard, built into Node) ---------- */
const SC = { N: 32768, r: 8, p: 1 };
function hashPw(pw) { const salt = crypto.randomBytes(16); const h = crypto.scryptSync(pw, salt, 64, { ...SC, maxmem: 96 * 1024 * 1024 }); return `scrypt$${SC.N}$${SC.r}$${SC.p}$${salt.toString('base64')}$${h.toString('base64')}`; }
function checkPw(pw, stored) {
  try { const [a, N, r, p, s, h] = stored.split('$'); if (a !== 'scrypt') return false; const want = Buffer.from(h, 'base64'); const got = crypto.scryptSync(pw, Buffer.from(s, 'base64'), want.length, { N: +N, r: +r, p: +p, maxmem: 96 * 1024 * 1024 }); return crypto.timingSafeEqual(got, want); } catch (_) { return false; }
}
const DUMMY = hashPw('not-a-real-password');
function pwProblem(pw) { if (typeof pw !== 'string' || pw.length < 10) return 'Use at least 10 characters.'; if (pw.length > 200) return 'Password is too long.'; if (!/[a-zA-Z]/.test(pw) || !/\d/.test(pw)) return 'Include at least one letter and one number.'; return ''; }

function setAdmin(username, password, allowUpdate) {
  const bad = pwProblem(password); if (bad) throw new Error('ADMIN_PASSWORD: ' + bad);
  if (!/^[A-Za-z0-9._-]{3,40}$/.test(username || '')) throw new Error('ADMIN_USERNAME must be 3-40 characters (letters, numbers, . _ -).');
  const ex = one('select * from admin_users where username=?', username);
  if (ex) { if (!allowUpdate) return 'exists'; run('update admin_users set pass_hash=? where id=?', hashPw(password), ex.id); run('delete from sessions where user_id=?', ex.id); return 'updated'; }
  run('insert into admin_users(username,pass_hash,created_at) values(?,?,?)', username, hashPw(password), now()); return 'created';
}
if (process.argv[2] === 'set-admin') {
  try { const r = setAdmin(process.env.ADMIN_USERNAME, process.env.ADMIN_PASSWORD, true); console.log(r === 'created' ? 'Administrator created.' : 'Administrator password updated. All sessions were signed out.'); process.exit(0); }
  catch (e) { console.error(e.message); process.exit(1); }
}
if (!one('select 1 x from admin_users')) {
  if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) { try { setAdmin(process.env.ADMIN_USERNAME, process.env.ADMIN_PASSWORD, false); console.log('First administrator created from ADMIN_USERNAME / ADMIN_PASSWORD.'); } catch (e) { console.error('Could not create administrator:', e.message); } }
  else console.warn('No administrator exists yet. Set ADMIN_USERNAME and ADMIN_PASSWORD in .env, then run: npm run set-admin');
}
db.prepare('delete from sessions where expires_at<?').run(Date.now());

/* ---------- validation ---------- */
const RX = { slug: /^[a-z0-9]+(?:-[a-z0-9]+)*$/, hex: /^#[0-9a-fA-F]{6}$/, email: /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/, phone: /^\+?[\d\s\-()]{7,20}$/, color: /^(#[0-9a-fA-F]{3,8}|[a-zA-Z]{3,20})$/ };
const BLOG_CATS = ["Women's Fashion", "Men's Fashion", "Kids' Style", 'Styling Tips', 'Fashion Trends', 'Wardrobe Essentials'];
const SUBJECTS = ['General Inquiry', 'Product Information', 'Order Status', 'Shipping and Delivery', 'Returns and Exchanges', 'Sizing Assistance', 'Collaboration', 'Other'];
const str = (v, max) => String(v ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, max);
function field(t, o, v) {
  const empty = v === undefined || v === null || v === '';
  if (empty) { if (o.req) throw 'This field is required.'; return t === 'enum' ? o.list[0] : t === 'b' ? 0 : (t === 'j' || t === 'imgs' || t === 'blocks') ? [] : (t === 'n' || t === 'i') ? null : ''; }
  switch (t) {
    case 's': { const s = str(v, o.max || 200); if (!s && o.req) throw 'This field is required.'; return s; }
    case 't': { const s = str(v, o.max || 20000); if (!s && o.req) throw 'This field is required.'; return s; }
    case 'n': { const n = Number(v); if (!Number.isFinite(n) || n < 0 || n > 1e9) throw 'Enter a valid number (0 or more).'; return Math.round(n * 100) / 100; }
    case 'i': { const n = Number(v); if (!Number.isInteger(n) || n < (o.min ?? 0) || n > (o.maxn ?? 1e9)) throw `Enter a whole number${o.maxn ? ' up to ' + o.maxn : ''}.`; return n; }
    case 'b': return v === true || v === 1 || v === '1' || v === 'true' ? 1 : 0;
    case 'enum': if (!o.list.includes(v)) throw 'Choose a valid option.'; return v;
    case 'slug': { const s = str(v, 120); if (!RX.slug.test(s)) throw 'Use lowercase letters, numbers and single hyphens.'; return s; }
    case 'img': { const s = str(v, 300); if (!/^\/uploads\/[A-Za-z0-9._-]+$/.test(s)) throw 'Choose an image from the media library.'; return s; }
    case 'imgs': { if (!Array.isArray(v) || v.length > 12) throw 'Up to 12 images.'; return v.map(x => field('img', {}, x)); }
    case 'j': { if (!Array.isArray(v) || v.length > (o.count || 30)) throw 'Too many items.'; return v.map(x => str(x, o.item || 60)).filter(Boolean).map(x => { if (o.rx && !o.rx.test(x)) throw o.msg || 'Invalid item.'; return x; }); }
    case 'link': { const s = str(v, 300); if (!/^(\/|#|https?:\/\/)[^\s]*$/.test(s)) throw 'Use a path like /collections or a full https:// link.'; return s; }
    case 'url': { const s = str(v, 300); if (!/^https?:\/\/[^\s]+$/.test(s)) throw 'Enter a full link starting with https://'; return s; }
    case 'hex': { const s = str(v, 7); if (!RX.hex.test(s)) throw 'Use a colour like #B89B72.'; return s; }
    case 'email': { const s = str(v, 200); if (!RX.email.test(s)) throw 'Enter a valid email address.'; return s; }
    case 'phone': { const s = str(v, 30); if (!RX.phone.test(s)) throw 'Enter a valid phone number.'; return s; }
    case 'date': { const d = new Date(v); if (isNaN(d)) throw 'Enter a valid date.'; return d.toISOString(); }
    case 'blocks': {
      if (!Array.isArray(v) || v.length > 200) throw 'Too many blocks.';
      return v.map(b => { const type = b && b.type; if (type === 'h' || type === 'p') return { type, text: str(b.text, 6000) }; if (type === 'ul') return { type, items: (Array.isArray(b.items) ? b.items : []).slice(0, 50).map(x => str(x, 500)).filter(Boolean) }; if (type === 'img') return { type, src: field('img', { req: true }, b.src), alt: str(b.alt, 200) }; throw 'Unknown block type.'; }).filter(b => b.text !== '' && !(b.items && !b.items.length));
    }
  }
  throw 'Unsupported field.';
}
function validate(def, body, partial) {
  const out = {}, err = {};
  for (const [k, [t, o = {}]] of Object.entries(def)) {
    if (body[k] === undefined && (partial || !o.req)) { if (!partial && !o.req) out[k] = field(t, o, undefined); continue; }
    try { out[k] = field(t, o, body[k]); } catch (e) { err[k] = String(e); }
  }
  return { out, err };
}

/* ---------- entity definitions ---------- */
const STATUS = ['draft', 'published', 'archived'];
const ENT = {
  products: {
    json: ['images', 'sizes', 'colors', 'tags'], order: 'p.id desc', search: ['p.name', 'p.sku'], filters: { category_id: 'p.category_id', collection_id: 'p.collection_id', status: 'p.status' },
    base: 'select p.*, c.name category_name, l.name collection_name from products p left join categories c on c.id=p.category_id left join collections l on l.id=p.collection_id', idcol: 'p.id', table: 'products',
    def: { name: ['s', { req: 1, max: 160 }], slug: ['slug', { req: 1 }], sku: ['s', { max: 60 }], short_desc: ['t', { max: 500 }], description: ['t', { max: 10000 }], image: ['img'], images: ['imgs'], category_id: ['i'], collection_id: ['i', { req: 1 }], price: ['n', { req: 1 }], sale_price: ['n'], sizes: ['j', { item: 20, count: 20 }], colors: ['j', { item: 20, count: 20, rx: RX.color, msg: 'Use hex colours like #1F1F1F or simple names like navy.' }], stock: ['i'], tags: ['j', { item: 30 }], featured: ['b'], focus: ['i', { maxn: 100 }], status: ['enum', { list: STATUS }], seo_title: ['s', { max: 70 }], seo_desc: ['t', { max: 200 }] },
  },
  collections: { json: [], order: 'sort, id', search: ['name', 'slug'], filters: { status: 'status' }, base: 'select * from collections', idcol: 'id', table: 'collections', def: { name: ['s', { req: 1, max: 80 }], slug: ['slug', { req: 1 }], description: ['t', { max: 1000 }], banner: ['img'], thumbnail: ['img'], sort: ['i'], status: ['enum', { list: STATUS }], seo_title: ['s', { max: 70 }], seo_desc: ['t', { max: 200 }] } },
  categories: { json: [], order: 'name', search: ['name', 'slug'], filters: { collection_id: 'collection_id', status: 'status' }, base: 'select c.*, l.name collection_name from categories c left join collections l on l.id=c.collection_id', idcol: 'c.id', table: 'categories', def: { name: ['s', { req: 1, max: 80 }], slug: ['slug', { req: 1 }], description: ['t', { max: 500 }], image: ['img'], collection_id: ['i'], status: ['enum', { list: ['published', 'draft'] }] } },
  posts: { json: ['body', 'tags'], order: 'id desc', search: ['title', 'slug'], filters: { category: 'category', status: 'status' }, base: 'select * from posts', idcol: 'id', table: 'posts', def: { title: ['s', { req: 1, max: 200 }], slug: ['slug', { req: 1 }], excerpt: ['t', { max: 400 }], image: ['img'], body: ['blocks'], author: ['s', { max: 80 }], category: ['enum', { list: BLOG_CATS }], tags: ['j', { item: 30 }], published_at: ['date'], seo_title: ['s', { max: 70 }], seo_desc: ['t', { max: 200 }], og_image: ['img'], featured: ['b'], status: ['enum', { list: ['draft', 'published'] }] } },
};
const parseRow = (e, r) => { if (!r) return r; const o = { ...r }; for (const k of e.json) { try { o[k] = JSON.parse(o[k] || '[]'); } catch (_) { o[k] = []; } } return o; };

const KVDEF = {
  homepage: {
    hero_enabled: ['b'], hero_eyebrow: ['s', { max: 80 }], hero_heading: ['s', { max: 160 }], hero_text: ['t', { max: 400 }], hero_primary_label: ['s', { max: 40 }], hero_primary_link: ['link'], hero_secondary_label: ['s', { max: 40 }], hero_secondary_link: ['link'], hero_image: ['img'], hero_align: ['enum', { list: ['left', 'center'] }], hero_overlay: ['i', { maxn: 90 }],
    sec_collections: ['b'], sec_featured: ['b'], sec_story: ['b'], sec_values: ['b'], sec_newsletter: ['b'], story_heading: ['s', { max: 120 }], story_text: ['t', { max: 800 }], story_button: ['s', { max: 40 }], story_image: ['img'], newsletter_heading: ['s', { max: 120 }], newsletter_text: ['t', { max: 300 }],
  },
  about: { hero_image: ['img'], hero_heading: ['s', { max: 160 }], hero_text: ['t', { max: 600 }], story_heading: ['s', { max: 160 }], story_text: ['t', { max: 3000 }], cta_heading: ['s', { max: 160 }], cta_text: ['t', { max: 300 }], seo_title: ['s', { max: 70 }], seo_desc: ['t', { max: 200 }] },
  settings: { site_name: ['s', { max: 60 }], default_seo_title: ['s', { max: 70 }], default_seo_desc: ['t', { max: 200 }], currency: ['s', { max: 6 }], email: ['email'], phone_display: ['s', { max: 30 }], phone_tel: ['phone'], color_primary: ['hex'], color_secondary: ['hex'], color_accent: ['hex'], announcement_text: ['s', { max: 160 }], announcement_visible: ['b'], instagram: ['url'], facebook: ['url'], pinterest: ['url'], tiktok: ['url'], footer_text: ['t', { max: 200 }], copyright: ['s', { max: 120 }], logo: ['img'], favicon: ['img'] },
};
const KVDEFAULT = {
  homepage: { hero_enabled: 1, hero_eyebrow: 'The New Season Edit', hero_heading: 'Style That Speaks. Elegance That Lasts.', hero_text: 'Discover timeless essentials and contemporary fashion designed to make every moment your own.', hero_primary_label: 'Explore Collection', hero_primary_link: '/collections', hero_secondary_label: 'Discover Glamora', hero_secondary_link: '/about', hero_image: '/uploads/family-banner.jpg', hero_align: 'left', hero_overlay: 62, sec_collections: 1, sec_featured: 1, sec_story: 1, sec_values: 1, sec_newsletter: 1, story_heading: 'Fashion Beyond Trends.', story_text: 'At Glamora, style is about more than what you wear. It is about confidence, individuality, and the details that make every look your own.', story_button: 'Our Story', story_image: '/uploads/story-man.jpg', newsletter_heading: 'Stay in Style', newsletter_text: 'Get updates on new collections, fresh arrivals, and fashion inspiration.' },
  about: { hero_image: '/uploads/about-hero.jpg', hero_heading: 'More Than Fashion. A Way of Life.', hero_text: 'At Glamora, we believe that what you wear is an expression of who you are. We bring together contemporary style, timeless inspiration, and everyday versatility to help every generation find its own sense of fashion.', story_heading: 'Style That Brings Us Together.', story_text: 'Glamora was created around a simple idea: fashion should feel personal, inspiring, and effortless. The right outfit can change how you feel, how you express yourself, and how you experience the everyday.\n\nOur collections bring together styles for men, women, and children, making it easier to discover pieces that complement different personalities, occasions, and lifestyles.\n\nWe continue to explore contemporary trends and timeless essentials with a focus on creating an enjoyable fashion experience for every customer.', cta_heading: 'Find Your Kind of Glamora.', cta_text: 'Explore the collections and discover styles that feel like you.', seo_title: 'About Us | Glamora', seo_desc: 'Learn about Glamora: contemporary style and timeless essentials for Men, Women and Children.' },
  settings: { site_name: 'Glamora', default_seo_title: 'Glamora: Style That Speaks', default_seo_desc: 'Fashion for Men, Women and Children.', currency: 'PKR', email: 'khalidsafdar676@gmail.com', phone_display: '0310 0960639', phone_tel: '+923100960639', color_primary: '#1F1F1F', color_secondary: '#EDE5DA', color_accent: '#B89B72', announcement_text: 'Discover Your Style — New Season Collection Now Available', announcement_visible: 1, instagram: '', facebook: '', pinterest: '', tiktok: '', footer_text: 'Fashion for Men, Women, and Children.', copyright: '© 2026 Glamora. All rights reserved.', logo: '', favicon: '' },
};
function kvGet(k) { const r = one('select value from kv where key=?', k); let v = {}; try { v = r ? JSON.parse(r.value) : {}; } catch (_) {} return { ...KVDEFAULT[k], ...v }; }

/* ---------- http helpers ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function headers(res, extra) {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  if (SECURE) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  for (const [k, v] of Object.entries(extra || {})) res.setHeader(k, v);
}
const send = (res, code, body, type, extra) => { headers(res, extra); res.writeHead(code, { 'Content-Type': type || 'application/json' }); res.end(body); };
const json = (res, code, obj, extra) => send(res, code, JSON.stringify(obj), 'application/json', { 'Cache-Control': 'no-store', ...extra });
const fail = (res, code, error, fields) => json(res, code, { error, ...(fields ? { fields } : {}) });
function readBody(req, limit) {
  return new Promise((ok, no) => { const chunks = []; let n = 0; req.on('data', c => { n += c.length; if (n > limit) { no({ code: 413 }); req.destroy(); } else chunks.push(c); }); req.on('end', () => ok(Buffer.concat(chunks))); req.on('error', () => no({ code: 400 })); });
}
async function readJSON(req, limit = 1e6) { const b = await readBody(req, limit); try { const v = JSON.parse(b.toString('utf8') || '{}'); if (v === null || typeof v !== 'object' || Array.isArray(v)) throw 0; return v; } catch (_) { throw { code: 400, msg: 'Invalid request body.' }; } }
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim()).filter(Boolean).map(s => { const i = s.indexOf('='); return [s.slice(0, i), decodeURIComponent(s.slice(i + 1))]; }));
const clientIp = req => req.socket.remoteAddress || 'x';

/* ---------- rate limiting (in memory) ---------- */
const hits = new Map();
function limited(key, max, windowMs) { const t = Date.now(); const h = hits.get(key); if (!h || h.reset < t) return false; return h.n >= max; }
function hit(key, windowMs) { const t = Date.now(); const h = hits.get(key); if (!h || h.reset < t) hits.set(key, { n: 1, reset: t + windowMs }); else h.n++; }
setInterval(() => { const t = Date.now(); for (const [k, v] of hits) if (v.reset < t) hits.delete(k); db.prepare('delete from sessions where expires_at<?').run(t); }, 600000).unref();

/* ---------- sessions ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function newSession(userId, remember) {
  const token = crypto.randomBytes(32).toString('hex'); const ttl = remember ? 30 * 864e5 : 12 * 36e5;
  run('insert into sessions(id,user_id,expires_at,created_at) values(?,?,?,?)', sha(token), userId, Date.now() + ttl, now());
  return `glamora_sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(ttl / 1000)}${SECURE ? '; Secure' : ''}`;
}
function sessionOf(req) {
  const t = cookies(req).glamora_sid; if (!t || !/^[a-f0-9]{64}$/.test(t)) return null;
  const s = one('select s.id sid, s.expires_at, u.id, u.username from sessions s join admin_users u on u.id=s.user_id where s.id=?', sha(t));
  if (!s || s.expires_at < Date.now()) { if (s) run('delete from sessions where id=?', s.sid); return null; }
  return s;
}
const clearCookie = `glamora_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${SECURE ? '; Secure' : ''}`;
function csrfOk(req) {
  if (req.headers['x-requested-with'] !== 'glamora-admin') return false;
  const o = req.headers.origin; if (o) { try { if (new URL(o).host !== req.headers.host) return false; } catch (_) { return false; } }
  return true;
}

/* ---------- media ---------- */
function sniff(b) {
  if (b.length > 12 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return 'jpg';
  if (b.length > 24 && b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return 'png';
  if (b.length > 30 && b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP') return 'webp';
  return null;
}
function dims(b, ext) {
  try {
    if (ext === 'png') return [b.readUInt32BE(16), b.readUInt32BE(20)];
    if (ext === 'jpg') { let i = 2; while (i < b.length) { if (b[i] !== 0xFF) { i++; continue; } const m = b[i + 1]; if (m >= 0xC0 && m <= 0xCF && ![0xC4, 0xC8, 0xCC].includes(m)) return [b.readUInt16BE(i + 7), b.readUInt16BE(i + 5)]; i += 2 + b.readUInt16BE(i + 2); } }
    if (ext === 'webp') { const t = b.slice(12, 16).toString(); if (t === 'VP8 ') return [b.readUInt16LE(26) & 0x3fff, b.readUInt16LE(28) & 0x3fff]; if (t === 'VP8L') { const x = b.readUInt32LE(21); return [(x & 0x3fff) + 1, ((x >> 14) & 0x3fff) + 1]; } if (t === 'VP8X') return [1 + b.readUIntLE(24, 3), 1 + b.readUIntLE(27, 3)]; }
  } catch (_) {}
  return [null, null];
}
const MIMES = { jpg: 'image/jpeg', png: 'image/png', webp: 'image/webp' };
function saveMedia(buf, original, forcedName) {
  const ext = sniff(buf); if (!ext) throw { code: 415, msg: 'Only JPEG, PNG and WebP images are allowed.' };
  const [w, h] = dims(buf, ext);
  const base = str(original || 'image', 80).replace(/\.[^.]*$/, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'image';
  const filename = forcedName || `${base}-${crypto.randomBytes(3).toString('hex')}.${ext}`;
  fs.writeFileSync(path.join(UPLOADS, filename), buf);
  return { filename, ext, w, h };
}
function mediaUsage() {
  const hay = [rows('select image,images,description from products'), rows('select banner,thumbnail from collections'), rows('select image from categories'), rows('select image,body,og_image from posts'), [kvGet('homepage'), kvGet('about'), kvGet('settings')]].map(x => JSON.stringify(x)).join('') + '/uploads/family-banner.jpg';
  return f => hay.includes('/uploads/' + f);
}

/* ---------- public content ---------- */
function publicContent() {
  const cols = rows("select * from collections where status='published' order by sort,id");
  const slugOf = Object.fromEntries(rows('select id,slug from collections').map(c => [c.id, c.slug]));
  const prods = rows("select * from products where status='published' order by id desc").map(r => { const p = parseRow(ENT.products, r); p.collection = slugOf[p.collection_id] || ''; delete p.stock; return p; });
  let order = []; try { order = JSON.parse((one("select value from kv where key='featured_ids'") || { value: '[]' }).value); } catch (_) {}
  const feat = prods.filter(p => p.featured).sort((a, b) => { const x = order.indexOf(a.id), y = order.indexOf(b.id); return (x < 0 ? 999 : x) - (y < 0 ? 999 : y); }).slice(0, 8);
  const posts = rows("select * from posts where status='published' and published_at<=? order by published_at desc", now()).map(r => parseRow(ENT.posts, r));
  return { settings: kvGet('settings'), homepage: kvGet('homepage'), about: kvGet('about'), collections: cols, categories: rows("select id,slug,name,description,image,collection_id from categories where status='published'"), products: prods, featured: feat, posts, redirects: Object.fromEntries(rows('select * from redirects').map(r => [r.old_slug, r.new_slug])) };
}

/* ---------- admin API ---------- */
function listEntity(name, e, u) {
  const where = [], p = [];
  const q = str(u.searchParams.get('q'), 80);
  if (q) { where.push('(' + e.search.map(c => `${c} like ?`).join(' or ') + ')'); e.search.forEach(() => p.push(`%${q}%`)); }
  for (const [k, col] of Object.entries(e.filters)) { const v = u.searchParams.get(k); if (v) { where.push(`${col}=?`); p.push(v); } }
  const w = where.length ? ' where ' + where.join(' and ') : '';
  const ps = Math.min(50, Math.max(1, +u.searchParams.get('ps') || 10)), page = Math.max(1, +u.searchParams.get('page') || 1);
  const total = one(`select count(*) n from (${e.base}${w})`, ...p).n;
  const items = rows(`${e.base}${w} order by ${e.order} limit ${ps} offset ${(page - 1) * ps}`, ...p).map(r => parseRow(e, r));
  return { items, total, page, pages: Math.max(1, Math.ceil(total / ps)) };
}
function dbErr(e, res) {
  const m = String(e.message || '');
  const um = m.match(/UNIQUE constraint failed: \w+\.(\w+)/); if (um) return fail(res, 409, 'That value is already used.', { [um[1]]: 'Already in use. Choose another.' });
  if (/FOREIGN KEY/.test(m)) return fail(res, 409, 'This item is still in use elsewhere.');
  console.error(e); return fail(res, 500, 'Something went wrong. Please try again.');
}
function writeEntity(name, e, body, id, res) {
  const { out, err } = validate(e.def, body, !!id);
  if (out.category_id) { if (!one('select 1 x from categories where id=?', out.category_id)) err.category_id = 'Category not found.'; }
  if (out.collection_id) { if (!one('select 1 x from collections where id=?', out.collection_id)) err.collection_id = 'Collection not found.'; }
  if (name === 'products' && out.sale_price != null && out.price != null && out.sale_price >= out.price) err.sale_price = 'Sale price must be lower than the price.';
  if (name === 'products' && !out.sku && 'sku' in out) out.sku = null;
  if (name === 'products' && 'focus' in out && out.focus == null) out.focus = 20;
  if (name === 'collections' && 'sort' in out && out.sort == null) out.sort = 0;
  if (Object.keys(err).length) return fail(res, 400, 'Please fix the highlighted fields.', err);
  let old; if (id) { old = one(`select * from ${e.table} where id=?`, id); if (!old) return fail(res, 404, 'Not found.'); }
  if (name === 'posts') { if (out.status === 'published' && !out.published_at && !(old && old.published_at)) out.published_at = now(); if ('published_at' in out && !out.published_at) delete out.published_at; }
  const keys = Object.keys(out), vals = keys.map(k => Array.isArray(out[k]) || (typeof out[k] === 'object' && out[k] !== null) ? JSON.stringify(out[k]) : out[k]);
  try {
    db.exec('BEGIN');
    if (id) { run(`update ${e.table} set ${keys.map(k => k + '=?').join(',')}${keys.length ? ',' : ''}updated_at=? where id=?`, ...vals, now(), id); }
    else { id = Number(run(`insert into ${e.table}(${keys.join(',')},created_at,updated_at) values(${keys.map(() => '?').join(',')},?,?)`, ...vals, now(), now()).lastInsertRowid); }
    if (name === 'posts' && old && out.slug && out.slug !== old.slug) { run('insert or replace into redirects(old_slug,new_slug) values(?,?)', old.slug, out.slug); run('delete from redirects where old_slug=?', out.slug); }
    if (name === 'products' && 'featured' in out) { let ids = []; try { ids = JSON.parse((one("select value from kv where key='featured_ids'") || { value: '[]' }).value); } catch (_) {} ids = ids.filter(x => x !== id); if (out.featured) ids.push(id); run("insert or replace into kv(key,value) values('featured_ids',?)", JSON.stringify(ids)); }
    db.exec('COMMIT');
  } catch (er) { try { db.exec('ROLLBACK'); } catch (_) {} return dbErr(er, res); }
  return json(res, old ? 200 : 201, { item: parseRow(e, one(`${e.base} where ${e.idcol}=?`, id)) });
}

async function admin(req, res, u, s) {
  const m = req.method, p = u.pathname;
  let mt;
  if (p === '/api/admin/me') return json(res, 200, { user: { username: s.username } });
  if (p === '/api/admin/stats') {
    const c = x => one(x).n;
    return json(res, 200, { totals: { products: c("select count(*) n from products where status!='archived'"), posts_published: c("select count(*) n from posts where status='published'"), collections: c('select count(*) n from collections'), messages: c('select count(*) n from messages'), products_draft: c("select count(*) n from products where status='draft'"), posts_draft: c("select count(*) n from posts where status='draft'"), messages_new: c("select count(*) n from messages where status='new'") }, recent: { products: rows('select id,name,image,status,created_at from products order by id desc limit 5'), posts: rows('select id,title,image,status,created_at from posts order by id desc limit 5'), messages: rows('select id,name,subject,status,created_at from messages order by id desc limit 5') } });
  }
  if ((mt = p.match(/^\/api\/admin\/(products|collections|categories|posts)(?:\/(\d+))?$/))) {
    const name = mt[1], e = ENT[name], id = mt[2] ? +mt[2] : 0;
    if (m === 'GET') { if (!id) return json(res, 200, listEntity(name, e, u)); const r = one(`${e.base} where ${e.idcol}=?`, id); return r ? json(res, 200, { item: parseRow(e, r) }) : fail(res, 404, 'Not found.'); }
    if (m === 'POST' && !id) return writeEntity(name, e, await readJSON(req, 2e6), 0, res);
    if (m === 'PUT' && id) return writeEntity(name, e, await readJSON(req, 2e6), id, res);
    if (m === 'DELETE' && id) {
      if (name === 'collections') { const n = one('select count(*) n from products where collection_id=?', id).n + one('select count(*) n from categories where collection_id=?', id).n; if (n) return fail(res, 409, `This collection still has ${n} product(s) or categor${n > 1 ? 'ies' : 'y'}. Move or remove them first.`); }
      if (name === 'categories') { const n = one('select count(*) n from products where category_id=?', id).n; if (n) return fail(res, 409, `${n} product(s) use this category. Reassign them to another category first.`); }
      try { run(`delete from ${e.table} where id=?`, id); } catch (er) { return dbErr(er, res); }
      return json(res, 200, { ok: true });
    }
  }
  if ((mt = p.match(/^\/api\/admin\/kv\/(homepage|about|settings)$/))) {
    const k = mt[1];
    if (m === 'GET') return json(res, 200, { value: kvGet(k) });
    if (m === 'PUT') { const { out, err } = validate(KVDEF[k], await readJSON(req), true); if (Object.keys(err).length) return fail(res, 400, 'Please fix the highlighted fields.', err); run('insert or replace into kv(key,value) values(?,?)', k, JSON.stringify({ ...kvGet(k), ...out })); return json(res, 200, { value: kvGet(k) }); }
  }
  if (p === '/api/admin/homepage/featured' && m === 'PUT') {
    const b = await readJSON(req); const ids = (Array.isArray(b.ids) ? b.ids : []).map(Number).filter(Number.isInteger).slice(0, 8);
    db.exec('BEGIN'); run('update products set featured=0'); for (const id of ids) run("update products set featured=1 where id=? and status='published'", id); run("insert or replace into kv(key,value) values('featured_ids',?)", JSON.stringify(ids)); db.exec('COMMIT');
    return json(res, 200, { ok: true });
  }
  if (p === '/api/admin/homepage/featured' && m === 'GET') { let ids = []; try { ids = JSON.parse((one("select value from kv where key='featured_ids'") || { value: '[]' }).value); } catch (_) {} const f = new Set(rows('select id from products where featured=1').map(r => r.id)); return json(res, 200, { ids: ids.filter(i => f.has(i)).concat([...f].filter(i => !ids.includes(i))), products: rows("select id,name,image,price from products where status='published' order by name") }); }
  if (p === '/api/admin/messages' && m === 'GET') {
    const where = [], a = []; const q = str(u.searchParams.get('q'), 80), st = u.searchParams.get('status');
    if (q) { where.push('(name like ? or email like ? or message like ? or subject like ?)'); a.push(...Array(4).fill(`%${q}%`)); } if (st) { where.push('status=?'); a.push(st); }
    const w = where.length ? ' where ' + where.join(' and ') : ''; const ps = 10, page = Math.max(1, +u.searchParams.get('page') || 1);
    const total = one(`select count(*) n from messages${w}`, ...a).n;
    return json(res, 200, { items: rows(`select * from messages${w} order by id desc limit ${ps} offset ${(page - 1) * ps}`, ...a), total, page, pages: Math.max(1, Math.ceil(total / ps)) });
  }
  if ((mt = p.match(/^\/api\/admin\/messages\/(\d+)$/))) {
    const id = +mt[1];
    if (m === 'PUT') { const st = (await readJSON(req)).status; if (!['new', 'read', 'replied', 'archived'].includes(st)) return fail(res, 400, 'Invalid status.'); run('update messages set status=? where id=?', st, id); return json(res, 200, { ok: true }); }
    if (m === 'DELETE') { run('delete from messages where id=?', id); return json(res, 200, { ok: true }); }
  }
  if (p === '/api/admin/media' && m === 'GET') {
    const used = mediaUsage(); const q = str(u.searchParams.get('q'), 60).toLowerCase();
    let items = rows('select * from media order by id desc').map(r => ({ ...r, url: '/uploads/' + r.filename, used: used(r.filename) }));
    if (q) items = items.filter(i => i.filename.includes(q) || (i.original || '').toLowerCase().includes(q));
    return json(res, 200, { items });
  }
  if (p === '/api/admin/media' && m === 'PUT') {
    let buf; try { buf = await readBody(req, 8 * 1024 * 1024); } catch (_) { return fail(res, 413, 'Image is too large (8 MB maximum).'); }
    try { const r = saveMedia(buf, u.searchParams.get('name')); const id = Number(run('insert into media(filename,original,mime,size,width,height,created_at) values(?,?,?,?,?,?,?)', r.filename, str(u.searchParams.get('name'), 120), MIMES[r.ext], buf.length, r.w, r.h, now()).lastInsertRowid); return json(res, 201, { item: { ...one('select * from media where id=?', id), url: '/uploads/' + r.filename, used: false } }); }
    catch (e) { return fail(res, e.code || 500, e.msg || 'Upload failed.'); }
  }
  if ((mt = p.match(/^\/api\/admin\/media\/(\d+)$/))) {
    const id = +mt[1], row = one('select * from media where id=?', id); if (!row) return fail(res, 404, 'Not found.');
    if (m === 'DELETE') { if (mediaUsage()(row.filename)) return fail(res, 409, 'This image is still used on the website. Replace it where it is used first.'); try { fs.unlinkSync(path.join(UPLOADS, row.filename)); } catch (_) {} run('delete from media where id=?', id); return json(res, 200, { ok: true }); }
    if (m === 'PUT') {
      let buf; try { buf = await readBody(req, 8 * 1024 * 1024); } catch (_) { return fail(res, 413, 'Image is too large (8 MB maximum).'); }
      const ext = sniff(buf); if (!ext) return fail(res, 415, 'Only JPEG, PNG and WebP images are allowed.');
      if (ext !== row.filename.split('.').pop().replace('jpeg', 'jpg')) return fail(res, 415, `Replacement must be the same type (.${row.filename.split('.').pop()}).`);
      const [w, h] = dims(buf, ext); fs.writeFileSync(path.join(UPLOADS, row.filename), buf); run('update media set size=?,width=?,height=? where id=?', buf.length, w, h, id); return json(res, 200, { ok: true });
    }
  }
  if (p === '/api/admin/password' && m === 'POST') {
    const b = await readJSON(req); const user = one('select * from admin_users where id=?', s.id);
    if (!checkPw(String(b.current || ''), user.pass_hash)) return fail(res, 400, 'Your current password is not correct.', { current: 'Not correct.' });
    if (b.next !== b.confirm) return fail(res, 400, 'The new passwords do not match.', { confirm: 'Does not match.' });
    const bad = pwProblem(b.next); if (bad) return fail(res, 400, bad, { next: bad });
    run('update admin_users set pass_hash=? where id=?', hashPw(b.next), user.id); run('delete from sessions where user_id=? and id!=?', user.id, s.sid);
    return json(res, 200, { ok: true });
  }
  return fail(res, 404, 'Not found.');
}

/* ---------- static files ---------- */
function serveFile(res, file, type, cache) {
  fs.readFile(file, (err, data) => { if (err) return send(res, 404, 'Not found', 'text/plain'); send(res, 200, data, type, { 'Cache-Control': cache || 'no-cache' }); });
}

/* ---------- main handler ---------- */
const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://localhost'); const p = u.pathname, m = req.method;
    if (p === '/api/health') return json(res, 200, { ok: true });
    if (p === '/api/public/content' && m === 'GET') return json(res, 200, publicContent());
    if (p === '/api/contact' && m === 'POST') {
      const ip = clientIp(req), key = 'contact:' + ip; if (limited(key, 5, 36e5)) return fail(res, 429, 'Too many messages. Please try again later.');
      const b = await readJSON(req, 30000);
      if (b.website) return json(res, 200, { ok: true }); // honeypot
      const { out, err } = validate({ name: ['s', { req: 1, max: 120 }], email: ['email', { req: 1 }], phone: ['s', { max: 30 }], subject: ['enum', { list: SUBJECTS, req: 1 }], order: ['s', { max: 40 }], message: ['t', { req: 1, max: 3000 }] }, b, false);
      if (out.phone && !RX.phone.test(out.phone)) err.phone = 'Enter a valid phone number.';
      if (b.privacy !== 'on' && b.privacy !== true) err.privacy = 'Please confirm the Privacy Policy.';
      if (Object.keys(err).length) return fail(res, 400, 'Please check the form.', err);
      hit(key, 36e5);
      run('insert into messages(name,email,phone,subject,order_no,message,status,created_at) values(?,?,?,?,?,?,?,?)', out.name, out.email, out.phone, out.subject, out.order, out.message, 'new', now());
      return json(res, 200, { ok: true });
    }
    if (p === '/api/admin/login' && m === 'POST') {
      if (!csrfOk(req)) return fail(res, 403, 'Request blocked.');
      const b = await readJSON(req, 5000); const uname = str(b.username, 60), pw = String(b.password || '').slice(0, 300);
      const k1 = 'login:' + clientIp(req) + ':' + uname.toLowerCase(), k2 = 'loginip:' + clientIp(req);
      if (limited(k1, 5, 9e5) || limited(k2, 30, 9e5)) return fail(res, 429, 'Too many attempts. Please wait 15 minutes and try again.');
      if (!uname || !pw) return fail(res, 400, 'Enter your username and password.');
      const user = one('select * from admin_users where username=?', uname);
      const ok = checkPw(pw, user ? user.pass_hash : DUMMY) && !!user;
      if (!ok) { hit(k1, 9e5); hit(k2, 9e5); return fail(res, 401, 'Incorrect username or password.'); }
      hits.delete(k1);
      return json(res, 200, { ok: true }, { 'Set-Cookie': newSession(user.id, !!b.remember) });
    }
    if (p.startsWith('/api/admin/')) {
      const s = sessionOf(req); if (!s) return fail(res, 401, 'Please sign in.');
      if (m !== 'GET') { if (!csrfOk(req)) return fail(res, 403, 'Request blocked.'); }
      if (p === '/api/admin/logout' && m === 'POST') { run('delete from sessions where id=?', s.sid); return json(res, 200, { ok: true }, { 'Set-Cookie': clearCookie }); }
      return await admin(req, res, u, s);
    }
    if (p.startsWith('/api/')) return fail(res, 404, 'Not found.');
    if (p.startsWith('/uploads/')) { const f = p.slice(9); if (!/^[A-Za-z0-9._-]+$/.test(f) || f.includes('..')) return send(res, 404, 'Not found', 'text/plain'); return serveFile(res, path.join(UPLOADS, f), MIME[path.extname(f).toLowerCase()] || 'application/octet-stream', 'no-cache'); }
    if (p === '/admin' || p.startsWith('/admin/')) {
      if (path.extname(p)) return send(res, 404, 'Not found', 'text/plain');
      const s = sessionOf(req);
      if (p === '/admin/login') { if (s) { res.writeHead(302, { Location: '/admin' }); return res.end(); } }
      else if (!s) { res.writeHead(302, { Location: '/admin/login' }); return res.end(); }
      return serveFile(res, path.join(ROOT, 'admin', 'index.html'), MIME['.html'], 'no-store');
    }
    if (m === 'GET' || m === 'HEAD') {
      const f = p === '/' ? 'index.html' : p.slice(1);
      if (!/^[A-Za-z0-9._-]+$/.test(f)) return send(res, 404, 'Not found', 'text/plain');
      return serveFile(res, path.join(ROOT, 'public', f), MIME[path.extname(f).toLowerCase()] || 'application/octet-stream');
    }
    send(res, 405, 'Method not allowed', 'text/plain');
  } catch (e) {
    if (e && e.code === 413) return fail(res, 413, 'Request too large.');
    if (e && e.code === 400) return fail(res, 400, e.msg || 'Bad request.');
    console.error(e); try { fail(res, 500, 'Something went wrong. Please try again.'); } catch (_) {}
  }
});

/* ---------- first-run seed from the existing Glamora content ---------- */
function seed() {
  if (one('select 1 x from collections')) return;
  let S; try { S = JSON.parse(fs.readFileSync(path.join(ROOT, 'seed', 'seed.json'), 'utf8')); } catch (_) { return; }
  const imgDir = path.join(ROOT, 'seed', 'images');
  const U = f => f ? '/uploads/' + f : '';
  db.exec('BEGIN');
  for (const f of fs.existsSync(imgDir) ? fs.readdirSync(imgDir) : []) { const buf = fs.readFileSync(path.join(imgDir, f)); const ext = sniff(buf); if (!ext) continue; fs.writeFileSync(path.join(UPLOADS, f), buf); const [w, h] = dims(buf, ext); run('insert or ignore into media(filename,original,mime,size,width,height,created_at) values(?,?,?,?,?,?,?)', f, f, MIMES[ext], buf.length, w, h, now()); }
  const cid = {}, catid = {};
  for (const c of S.collections) cid[c.slug] = Number(run('insert into collections(slug,name,description,banner,thumbnail,sort,status,created_at,updated_at) values(?,?,?,?,?,?,?,?,?)', c.slug, c.name, c.description, U(c.banner), U(c.thumbnail), c.sort, 'published', now(), now()).lastInsertRowid);
  for (const c of S.categories) catid[c.slug] = Number(run('insert into categories(slug,name,description,collection_id,status,created_at,updated_at) values(?,?,?,?,?,?,?)', c.slug, c.name, c.description || '', c.collection ? cid[c.collection] : null, 'published', now(), now()).lastInsertRowid);
  const featured = [];
  S.products.forEach((p, i) => { const id = Number(run('insert into products(slug,sku,name,short_desc,description,image,images,category_id,collection_id,price,sale_price,sizes,colors,stock,tags,featured,focus,status,created_at,updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', p.slug, p.sku, p.name, p.short_desc, p.description, U(p.image), '[]', catid[p.category] || null, cid[p.collection], p.price, p.sale_price ?? null, JSON.stringify(p.sizes), JSON.stringify(p.colors), null, JSON.stringify(p.tags || []), p.featured ? 1 : 0, p.focus ?? 20, 'published', new Date(Date.now() - i * 60000).toISOString(), now()).lastInsertRowid); if (p.featured) featured.push([p.featured, id]); });
  featured.sort((a, b) => a[0] - b[0]);
  run("insert or replace into kv(key,value) values('featured_ids',?)", JSON.stringify(featured.map(x => x[1])));
  S.posts.forEach((a, i) => run('insert into posts(slug,title,excerpt,body,author,category,tags,published_at,featured,status,created_at,updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?)', a.slug, a.title, a.excerpt, JSON.stringify(a.body), 'Glamora Editorial Team', a.category, '[]', new Date(Date.now() - (i + 1) * 3 * 864e5).toISOString(), a.featured ? 1 : 0, 'published', now(), now()));
  db.exec('COMMIT'); console.log('Seeded the database with the existing Glamora collections, products and articles.');
}
if (process.env.SEED !== 'false') { try { seed(); } catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} console.error('Seed failed:', e.message); } }

server.listen(PORT, () => console.log(`Glamora running on http://localhost:${PORT}  (admin: /admin)`));
