const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');
const D = require('./db'), N = require('./net'), S = require('./security'), BC = require('./bot-core');
const CFG = S.CFG;
const logErr = (w, e) => console.error(`[${new Date().toISOString()}] ${w}:`, (e && e.stack) || e);
process.on('uncaughtException', e => logErr('uncaughtException', e));
process.on('unhandledRejection', e => logErr('unhandledRejection', e));
const PORT = process.env.PORT || 3000;
const PAGE = path.join(__dirname, 'public', 'index.html');
const LOBBY = 'الصالة العامة';

const UP = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'); fs.mkdirSync(UP, { recursive: true });
const MIME = { png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', mp3: 'audio/mpeg', ogg: 'audio/ogg', wav: 'audio/wav', m4a: 'audio/mp4', mp4: 'video/mp4', webm: 'video/webm', pdf: 'application/pdf', txt: 'text/plain; charset=utf-8', zip: 'application/zip', docx: 'application/octet-stream', xlsx: 'application/octet-stream' };
const IMG = ['png', 'jpg', 'gif', 'webp'];
const LIM = { msg: 8e6, post: 5e6, avatar: 1.5e6, emoji: 3e5, banner: 3e6, bg: 1.5e6, frame: 5e5, galbg: 1.5e6, galframe: 5e5, roleicon: 1e6, fakeav: 1.5e6 };
const catOf = ext => IMG.includes(ext) ? 'image' : /^(mp3|ogg|wav|m4a)$/.test(ext) ? 'audio' : /^(mp4|webm)$/.test(ext) ? 'video' : 'file';
const byKey = new Map(); // مفتاح الرفع -> مستخدم متصل
const failIp = new S.Window(CFG.lockMin * 60e3, CFG.authFailIp), failAcct = new S.Window(CFG.lockMin * 60e3, CFG.authFailAcct);
const regWin = new S.Window(3600e3, CFG.regPerHour), connWin = new S.Window(60e3, CFG.connRate), upWin = new S.Window(60e3, 20);
const connIp = new Map();
const FORCE_HTTPS = process.env.FORCE_HTTPS === '1';
const cookieOf = (req, k) => { const m = new RegExp('(?:^|;\\s*)' + k + '=([a-f0-9]{32})').exec(req.headers.cookie || ''); return m ? m[1] : ''; };

const HTML = fs.readFileSync(PAGE, 'utf8'), CSP = S.csp(HTML), FLAGS_PNG = fs.readFileSync(path.join(__dirname, 'public', 'flags.png'));
function route(req, res) {
  const https = N.isHttps(req), base = S.baseHeaders(https);
  const end = (c, h = {}, body) => { res.writeHead(c, { ...base, ...h }); res.end(body); };
  if (FORCE_HTTPS && !https) { const h = String(req.headers.host || ''); return /^[\w.\-:\[\]]+$/.test(h) ? end(308, { Location: 'https://' + h + req.url.replace(/[\r\n]/g, '') }) : end(400); }
  if (req.method !== 'GET' && req.method !== 'HEAD' && !(req.method === 'POST' && req.url.split('?')[0] === '/upload')) return end(405, { Allow: 'GET, HEAD, POST' });
  const url = req.url.split('?')[0];
  if (url === '/') {
    const h = { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': CSP, 'Cache-Control': 'no-store' };
    if (!cookieOf(req, 'sd')) h['Set-Cookie'] = `sd=${crypto.randomBytes(16).toString('hex')}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000${https ? '; Secure' : ''}`;
    return end(200, h, HTML);
  }
  if (url === '/flags.png') return end(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=604800' }, FLAGS_PNG);
  if (url === '/upload') return upload(req, res);
  const f = /^\/u\/([a-f0-9]{24}\.[a-z0-9]{2,4})$/.exec(url);
  if (f) {
    const ext = f[1].split('.')[1], mime = MIME[ext], cat = catOf(ext), fp = path.join(UP, f[1]);
    if (!mime || !fs.existsSync(fp)) return end(404);
    const row = D.upload('/u/' + f[1]);
    res.writeHead(200, { ...base, 'Content-Type': mime, 'Content-Security-Policy': "sandbox; default-src 'none'", 'Cache-Control': 'public, max-age=86400', ...(cat === 'file' ? { 'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent(row?.name || f[1]) } : {}) });
    if (req.method === 'HEAD') return res.end();
    const st = fs.createReadStream(fp); st.on('error', () => res.destroy()); return st.pipe(res);
  }
  end(404);
}
const server = http.createServer((req, res) => {
  try { route(req, res); } catch (e) { logErr('http', e); try { if (!res.headersSent) res.writeHead(500); res.end(); } catch {} }
});
server.headersTimeout = 20000; server.requestTimeout = 120000; server.keepAliveTimeout = 5000; server.maxHeadersCount = 60;
server.on('clientError', (e, sock) => { if (sock.writable) sock.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); else sock.destroy(); });
const wss = new WebSocketServer({
  server, maxPayload: 4096, perMessageDeflate: false,
  verifyClient: ({ req }, cb) => {
    if (!S.sameOrigin(req)) return cb(false, 403, 'Forbidden');
    const ip = N.clientIp(req);
    if (wss.clients.size >= CFG.connTotal) return cb(false, 503, 'Busy');
    if ((connIp.get(ip) || 0) >= CFG.connPerIp || connWin.hit(ip) > CFG.connRate) return cb(false, 429, 'Too Many Requests');
    cb(true);
  },
});
wss.on('error', e => logErr('wss', e));

function upload(req, res) {
  const out = (c, o) => { if (res.headersSent) return; res.writeHead(c, { ...S.baseHeaders(false), 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(o)); };
  if (req.method !== 'POST') return out(405, { err: 'method' });
  if (!S.sameOrigin(req)) return out(403, { err: 'مصدر الطلب غير مسموح' });
  const q = new URL(req.url, 'http://x').searchParams, kind = q.get('k') || 'msg', u = byKey.get(String(req.headers['x-key'] || ''));
  const lim = LIM[kind], ip = N.clientIp(req);
  if (!u) return out(401, { err: 'سجّل الدخول الأول' });
  if (!lim) return out(400, { err: 'نوع غير معروف' });
  if (kind !== 'msg' && kind !== 'banner' && kind !== 'emoji' && !u.uid) return out(403, { err: 'الخاصية دي للأعضاء المسجلين فقط' });
  if (['banner', 'emoji', 'galbg', 'galframe'].includes(kind) && !D.can(u.role, 'assets')) return out(403, { err: 'مفيش صلاحية' });
  if (kind === 'fakeav' && u.role !== 'owner') return out(403, { err: 'مفيش صلاحية' });
  if (kind === 'roleicon' && !D.can(u.role, 'roles') && !D.can(u.role, 'assets')) return out(403, { err: 'مفيش صلاحية' });
  if (Date.now() - (u.lastUp || 0) < 2000 || upWin.hit(ip) > 20) return out(429, { err: 'بالراحة شوية على الرفع' });
  const clen = Number(req.headers['content-length']);
  if (clen > lim) return out(413, { err: `الحجم الأقصى ${Math.round(lim / 1e5) / 10} ميجا` });
  const staff = D.can(u.role, 'assets') || D.can(u.role, 'roles') || u.role === 'owner', quota = u.uid ? CFG.uploadsPerDayMember : CFG.uploadsPerDayGuest;
  if (!staff && D.usedBytes(u.uid ?? -u.id) + (clen || 0) > quota) return out(413, { err: 'وصلت للحد اليومي للرفع، جرّب بكرة' });
  if (D.totalBytes() + (clen || 0) > CFG.storageCap) return out(507, { err: 'مساحة التخزين ممتلئة حاليًا' });
  u.lastUp = Date.now();
  const chunks = []; let size = 0, big = false;
  req.on('data', c => { size += c.length; if (size > lim) { big = true; chunks.length = 0; return; } if (!big) chunks.push(c); });
  req.on('end', () => {
    try {
      if (big) return out(413, { err: `الحجم الأقصى ${Math.round(lim / 1e5) / 10} ميجا` });
      const buf = Buffer.concat(chunks);
      let raw = String(req.headers['x-name'] || 'file'); try { raw = decodeURIComponent(raw); } catch {}
      const name = S.cleanName(raw).replace(/[\\/<>:"|?*]/g, '_').slice(0, 80) || 'file';
      let ext = (/\.([a-z0-9]{2,4})$/i.exec(name)?.[1] || '').toLowerCase().replace('jpeg', 'jpg'), sn = S.imageType(buf);
      if (!buf.length) return out(400, { err: 'ملف فاضي' });
      if (kind !== 'msg' || IMG.includes(ext) || sn) { if (!sn) return out(415, { err: 'الملف مش صورة صالحة (png, jpg, gif, webp)' }); ext = sn; }
      else if (!MIME[ext] || !S.validFile(ext, buf)) return out(415, { err: 'نوع الملف غير مسموح أو محتواه مش مطابق للامتداد' });
      if (/frame$/.test(kind) && !['png', 'webp'].includes(ext)) return out(415, { err: 'الإطار لازم يكون png أو webp بخلفية شفافة' });
      if (!byKey.has(u.upkey)) return out(401, { err: 'انتهت الجلسة' });
      const file = crypto.randomBytes(12).toString('hex') + '.' + ext, url = '/u/' + file, cat = catOf(ext);
      fs.writeFileSync(path.join(UP, file), buf, { mode: 0o600 });
      D.addUpload(url, u.uid ?? -u.id, kind, name, buf.length, cat);
      if (kind === 'avatar') { dropFile(u.avatar); u.avatar = url; D.setCol(u.uid, 'avatar', url); send(u, { t: 'avatar', url }); pushUsers(u.room); }
      if (kind === 'bg' || kind === 'frame') { const k = kind === 'bg' ? 'bg' : 'frame'; if (u[k] && !D.inGallery(k, u[k])) dropFile(u[k]); u[k] = url; D.setCol(u.uid, k, url); send(u, { t: 'looks', frame: u.frame, bg: u.bg }); pushUsers(u.room); }
      if (kind === 'galbg' || kind === 'galframe') { D.addGallery(kind === 'galbg' ? 'bg' : 'frame', url, u.name); D.audit(u.name, 'gallery', null, kind === 'galbg' ? 'خلفية' : 'إطار'); }
      out(200, { url, name, size: buf.length, kind: cat });
    } catch (e) { logErr('upload', e); out(500, { err: 'خطأ داخلي' }); }
  });
  req.on('error', () => {});
}
const dropFile = url => { if (!/^\/u\/[a-f0-9]{24}\.[a-z0-9]{2,4}$/.test(url || '')) return; D.delUpload(url); fs.rm(path.join(UP, url.slice(3)), () => {}); };

D.db.exec('DELETE FROM rooms WHERE permanent = 0');
const rooms = new Map(D.db.prepare('SELECT name, permanent FROM rooms').all().map(r => [r.name, !!r.permanent]));
const users = new Map(), socks = new Set();
let BAD = [], SHORT = {};
const loadFilter = () => { BAD = D.setting('filter_words').split(/[\n,،]+/).map(x => x.trim()).filter(Boolean).map(w => new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'giu')); };
const loadShort = () => { try { SHORT = Object.fromEntries(Object.entries(JSON.parse(D.setting('shortcuts') || '{}')).map(([k, v]) => [S.normDigits(k), v])); } catch { SHORT = {}; } };
loadFilter(); loadShort();
let nextId = 1;

// ===== مسك بوت: عضو افتراضي مجاني (قواعد ردود + كتم مؤقت فقط) =====
const botCore = new BC.Bot({ rules: D.setting('bot_rules') || BC.DEFAULT_RULES, bad: D.setting('bot_bad') });
const botU = { id: nextId++, uid: null, isBot: true, name: BC.NAME, role: 'bot', style: { n: '#7be0c3' }, deco: '', status: 'مساعد الشات 🤖', ws: { readyState: 0, send() {}, close() {} }, room: null, stamps: [], reports: new Set(), mutedUntil: 0, cc: '', avatar: '', frame: '', bg: '', upkey: '', lastUp: 0, token: null, info: { ip: '', did: '', sd: '', ua: '' }, since: Date.now() };
const botOn = () => D.setting('bot_enabled') !== '0';

const hex = v => /^#[0-9a-f]{6}$/i.test(v) ? v : '';
const parseStyle = j => { try { return JSON.parse(j || '{}'); } catch { return {}; } };
const clean = S.cleanText, cname = S.cleanName;
const filter = t => BAD.reduce((x, w) => x.replace(w, '***'), t);
const badWord = t => { const s = String(t ?? ''), c = s.replace(/[\s_.\-]+/g, ''); return filter(s) !== s || filter(c) !== c; };
const toRoomFrom = (r, o, s) => inRoom(r).forEach(x => { if (s.uid && x.ign && x.ign.has(s.uid)) return; send(x, o); });
const expand = t => t.split(/(\s+)/).map(p => { const k = S.normDigits(p); return p.trim() && Object.hasOwn(SHORT, k) ? SHORT[k] : p; }).join('');
const longText = (v, n) => String(v ?? '').normalize('NFC').replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, c => c === '\n' || c === '\u200d' || c === '\u200c' ? c : '').replace(/\p{M}{4,}/gu, m => m.slice(0, 3)).replace(/\n{4,}/g, '\n\n\n').slice(0, n);
const send = (u, o) => { try { u.ws.readyState === 1 && u.ws.send(JSON.stringify(o)); } catch (e) { logErr('send', e); } };
const notice = (u, title, text) => send(u, { t: 'notice', title, text });
const ACTAR = { fakeadd: 'إضافة عضو وهمي', fakeedit: 'تعديل عضو وهمي', fakedel: 'حذف عضو وهمي', repclose: 'إغلاق بلاغ', delmsg: 'حذف رسالة', clearframe: 'إزالة الإطار', clearbg: 'إزالة الغلاف', clearstatus: 'إزالة بنر الحالة', setdeco: 'تغيير الزخرفة', kick: 'طرد', kickroom: 'طرد من الغرفة', mute: 'اسكات', ban: 'باند', tempban: 'باند مؤقت', setrole: 'تغيير الرتبة', move: 'نقل لغرفة', likes: 'تعديل الإيكات' };
const inRoom = r => [...users.values()].filter(u => u.room === r);
const toRoom = (r, o) => inRoom(r).forEach(u => send(u, o));
const toSocks = o => { const s = JSON.stringify(o); socks.forEach(x => { try { x.readyState === 1 && x.send(s); } catch {} }); };
const site = () => ({ t: 'site', name: D.setting('site_name'), welcome: D.setting('welcome'), rules: D.setting('rules'), regOpen: D.setting('reg_open') !== '0', guestOpen: D.setting('guest_open') !== '0', accent: D.setting('accent'), roomsBar: D.setting('rooms_bar') === '1', banner: D.setting('banner'), emojis: D.emojis(), rbanners: rbList() });
const lockedRooms = new Set((() => { try { return JSON.parse(D.setting('locked_rooms') || '[]'); } catch { return []; } })());
const saveLocked = () => D.setSetting('locked_rooms', JSON.stringify([...lockedRooms]));
const pushRooms = () => toSocks({ t: 'rooms', list: [...rooms.keys()].map(n => ({ name: n, count: inRoom(n).length, locked: lockedRooms.has(n), perm: !!rooms.get(n) })) });
const ulist = arr => arr.map(u => ({ id: u.id, uid: u.uid, name: u.name, role: u.role, label: D.label(u.role), color: D.color(u.role), ri: D.icon(u.role), rn: D.rn(u.role), rb: D.rb(u.role), dn: u.deco, status: u.status, style: u.style, av: u.avatar, fr: u.frame, bgi: u.bg, cc: u.cc, member: !!u.uid || !!u.fake, vf: u.verified ? 1 : 0, room: u.room }));
const pushLoose = () => { const L = [...users.values()].filter(x => !x.room && !x.isBot); if (!L.length) return; const o = { t: 'users', list: ulist([...users.values()].slice(0, 300)), all: 1 }; L.forEach(x => send(x, o)); };
const pushUsers = r => { if (r) toRoom(r, { t: 'users', list: ulist(inRoom(r)) }); pushLoose(); };
const pushOnline = () => toSocks({ t: 'online', count: users.size, ids: [...users.keys()], list: [...users.values()].slice(-30).reverse().map(u => ({ id: u.id, uid: u.uid, name: u.name, dn: u.deco, room: u.room, cc: u.cc })) });
const tooFast = u => { const n = Date.now(); u.stamps = u.stamps.filter(t => n - t < 3000); u.stamps.push(n); return u.stamps.length > 5; };

const pushNotif = (uid, kind, text, from) => {
  if (!uid) return; const n = D.notify(uid, kind, text, from), t = [...users.values()].find(x => x.uid === uid);
  if (t) send(t, { t: 'notif', n: { ...n, read: 0 }, unread: D.unread(uid) });
};
function mentions(u, text) {
  const low = text.toLowerCase();
  users.forEach(x => { if (x !== u && x.uid && !(u.uid && x.ign && x.ign.has(u.uid)) && low.includes('@' + x.name.toLowerCase())) pushNotif(x.uid, 'mention', `${u.name} أشار إليك في غرفة "${u.room}"`, u.name); });
}
const repSeen = new Map(), repWin = new S.Window(3600e3, 10), alertWin = new S.Window(60e3, 6), alertLast = new Map();
const SINCE = { day: 1, week: 7, month: 30 };
function sendWall(u) {
  send(u, { t: 'wall', canMod: D.can(u.role, 'wallmod'), list: D.posts(u.uid).map(p => ({ id: p.id, uid: p.uid, name: p.name, dn: p.deco || '', text: p.text, img: p.img, ts: p.ts, av: p.av || '', fr: p.fr || '', label: D.label(p.role), color: D.color(p.role), nc: parseStyle(p.style).n || '', likes: p.likes, cc: p.cc, liked: !!p.liked, mine: p.uid === u.uid })) });
}
function sendComments(u, id) {
  send(u, { t: 'comments', id, canMod: D.can(u.role, 'wallmod'), list: D.comments(id).map(c => ({ ...c, mine: c.uid === u.uid })) });
}
function restart() {
  wss.clients.forEach(c => c.close(1012)); server.close();
  if (!process.env.SUPERVISED) require('child_process').spawn(process.argv[0], process.argv.slice(1), { detached: true, stdio: 'inherit', env: { ...process.env, RESTART_DELAY: '1500' } }).unref();
  setTimeout(() => process.exit(0), 300);
}

const evOf = (u, r, text, ev) => ({ t: 'sys', ev, text, id: u.id, name: u.name, dn: u.deco, av: u.avatar, fr: u.frame, room: r });
const roomEv = (u, r, text, ev) => { toRoom(r, evOf(u, r, text, ev)); try { D.logSys(r, text, u.uid, u.name, { ev, room: r }); } catch (e) { logErr('logSys', e); } };
function sendInbox(u) { if (!u.uid) return; const on = new Map([...users.values()].filter(x => x.uid).map(x => [x.uid, x.id])); send(u, { t: 'inbox', list: D.pmInbox(u.uid).map(r => ({ uid: r.other, name: r.name, dn: r.deco || '', av: r.av || '', fr: r.fr || '', text: r.text || (r.file ? 'مرفق' : ''), ts: r.ts, mine: r.a === u.uid, unread: r.unread, sid: on.get(r.other) ?? null })) }); }
function leave(u, why) {
  const old = u.room; if (!old) return;
  u.room = null; why = u.leaveWhy || why || 'غادر الغرفة'; u.leaveWhy = '';
  if (!u.isBot) { roomEv(u, old, why, 'leave'); send(u, evOf(u, old, why, 'leave')); }
  if (!rooms.get(old) && !inRoom(old).length) { rooms.delete(old); D.delRoom(old); }
  pushUsers(old);
}
function botSync() { // يدخل/يخرج البوت حسب الإعداد
  if (botOn() && !users.has(botU.id)) { users.set(botU.id, botU); botU.room = LOBBY; pushUsers(LOBBY); pushRooms(); pushOnline(); }
  else if (!botOn() && users.has(botU.id)) { const r = botU.room; users.delete(botU.id); botU.room = null; pushUsers(r); pushRooms(); pushOnline(); }
}
const botSay = (room, text, delay) => setTimeout(() => { if (!users.has(botU.id)) return; const mid = D.logMsg(room, null, botU.name, text, null); toRoom(room, { t: 'msg', mid, id: botU.id, name: botU.name, dn: '', text, style: botU.style, av: '', fr: '', bgi: '', file: null }); D.logMsg(room, null, botU.name, text, null); }, delay ?? 700 + Math.random() * 900);
function botOnMsg(u, text) {
  if (!users.has(botU.id) || u === botU || u.room !== botU.room) return;
  const r = botCore.reply(text, u.deco || u.name, Date.now(), 'u' + u.id); if (r) botSay(u.room, r);
}
// ===== بوتات وأعضاء وهميين يضيفهم المالك من لوحة التحكم =====
const fakeUsers = new Map(); // fid -> كائن المستخدم الافتراضي
const fakeRoom = r => (r && rooms.has(r) ? r : LOBBY);
function fakeObj(f) {
  const o = { id: nextId++, uid: null, fake: f.id, kind: f.kind, isBot: false, name: f.name, role: f.role, style: f.color ? { n: f.color } : {}, deco: f.deco || '', status: f.status || '', likesN: f.likes || 0, welcomed: true,
    ws: { readyState: 0, send() {}, close() { fakeOff(o, o.leaveWhy || 'غادر الدردشة'); } }, room: null, stamps: [], reports: new Set(), mutedUntil: 0, cc: '', avatar: f.av || '', frame: '', bg: '', upkey: '', lastUp: 0, token: null, info: { ip: '', did: '', sd: '', ua: '' }, since: Date.now(), leaveWhy: '' };
  if (f.kind === 'bot') o.core = new BC.Bot({ name: f.name, rules: f.rules && f.rules.trim() ? f.rules : BC.DEFAULT_RULES, bad: '' });
  return o;
}
function fakeOn(f) { // يدخل الموجود في DB للدردشة
  if (fakeUsers.has(f.id)) return;
  const o = fakeObj(f); fakeUsers.set(f.id, o); users.set(o.id, o); join(o, fakeRoom(f.room)); pushOnline();
}
function fakeOff(o, why) { // يطلعه من الدردشة (الطرد/الباند/الإيقاف)
  if (!users.has(o.id)) return; const r = o.room; if (r) { o.leaveWhy = why; leave(o, why); } users.delete(o.id); fakeUsers.delete(o.fake); D.fakeSet(o.fake, { active: 0 }); pushUsers(r); pushRooms(); pushOnline();
}
function fakesInit() { D.fakes().forEach(f => f.active && fakeOn(f)); }
function fakeOnMsg(u, text) {
  fakeUsers.forEach(f => { if (f.kind !== 'bot' || f === u || u.fake || f.room !== u.room || f.mutedUntil > Date.now()) return;
    const r = f.core.reply(text, u.deco || u.name, Date.now(), 'u' + u.id); if (!r) return;
    setTimeout(() => { if (!users.has(f.id) || f.room !== u.room) return; const mid = D.logMsg(f.room, null, f.name, r, null); toRoom(f.room, { t: 'msg', mid, id: f.id, name: f.name, ri: D.icon(f.role), rn: D.rn(f.role), rb: D.rb(f.role), dn: f.deco, text: r, style: f.style, av: f.avatar, fr: '', bgi: '', file: null }); }, 700 + Math.random() * 800); });
}
const fakesMsg = () => ({ t: 'fakes', max: 20, rooms: [...rooms.keys()], roles: D.rolesList().filter(r => r.name !== 'bot').map(r => ({ name: r.name, label: r.label })), list: D.fakes().map(f => ({ ...f, online: fakeUsers.has(f.id), curRoom: fakeUsers.get(f.id)?.room || '' })) });
function fakeAdmin(u, op, m) {
  if (u.role !== 'owner') return;
  const all = D.fakes();
  if (op === 'fakeget') return send(u, fakesMsg());
  if (op === 'fakeadd' || op === 'fakeedit') {
    const cur = op === 'fakeedit' ? all.find(x => x.id === Number(m.id)) : null; if (op === 'fakeedit' && !cur) return;
    const name = cname(m.name).slice(0, 20), kind = m.kind === 'bot' ? 'bot' : 'member', role = String(m.role || 'member');
    if (name.length < 2) return send(u, { t: 'err', text: 'الاسم قصير' });
    if (badWord(name)) return send(u, { t: 'err', text: 'الاسم فيه كلمة ممنوعة' });
    if (!D.roleExists(role) || role === 'bot') return send(u, { t: 'err', text: 'رتبة غير صالحة' });
    if (op === 'fakeadd' && all.length >= 20) return send(u, { t: 'err', text: 'وصلنا للحد الأقصى (20)' });
    const sk = S.skeleton(name);
    if (name === BC.NAME || D.userByName(name) || all.some(x => x.id !== cur?.id && S.skeleton(x.name) === sk) || [...users.values()].some(x => !x.fake && !x.isBot && S.skeleton(x.name) === sk)) return send(u, { t: 'err', text: 'الاسم ده مستخدم أو شبه اسم تاني' });
    const av = String(m.av || ''); if (!okIcon(av)) return send(u, { t: 'err', text: 'الصورة غير صالحة' });
    const o = { name, kind, role, room: cname(m.room).slice(0, 30), deco: cname(m.deco).slice(0, 24), status: clean(m.status).slice(0, 60), color: hex(m.color), av, rules: longText(m.rules, 6000), likes: Math.min(Math.max(Math.floor(Number(m.likes)) || 0, 0), 1e9) };
    if (o.deco && badWord(o.deco)) return send(u, { t: 'err', text: 'الزخرفة فيها كلمة ممنوعة' });
    if (op === 'fakeadd') { const id = D.fakeAdd(o); D.audit(u.name, 'fakeadd', name, kind); const f = D.fakes().find(x => x.id === id); fakeOn(f); }
    else {
      const old = fakeUsers.get(cur.id); if (cur.av && cur.av !== av) dropFile(cur.av);
      D.fakeSet(cur.id, o); D.audit(u.name, 'fakeedit', name, kind);
      if (old) { fakeOff(old, 'غادر الدردشة'); D.fakeSet(cur.id, { active: 1 }); fakeOn(D.fakes().find(x => x.id === cur.id)); }
    }
    return send(u, fakesMsg());
  }
  const f = all.find(x => x.id === Number(m.id)); if (!f) return;
  if (op === 'fakedel') { const o = fakeUsers.get(f.id); if (o) fakeOff(o, 'غادر الدردشة'); if (f.av) dropFile(f.av); D.fakeDel(f.id); D.audit(u.name, 'fakedel', f.name, ''); }
  if (op === 'fakepower') { const o = fakeUsers.get(f.id); if (o) fakeOff(o, 'غادر الدردشة'); else { D.fakeSet(f.id, { active: 1 }); fakeOn(D.fakes().find(x => x.id === f.id)); } }
  if (op === 'fakesay') {
    const o = fakeUsers.get(f.id), text = clean(m.text).slice(0, 300); if (!o || !o.room || !text) return send(u, { t: 'err', text: 'العضو الوهمي مش داخل الدردشة' });
    if (o.mutedUntil > Date.now()) return send(u, { t: 'err', text: 'العضو الوهمي مكتوم دلوقتي' });
    const mid = D.logMsg(o.room, null, o.name, text, null); toRoom(o.room, { t: 'msg', mid, id: o.id, name: o.name, ri: D.icon(o.role), rn: D.rn(o.role), rb: D.rb(o.role), dn: o.deco, text, style: o.style, av: o.avatar, fr: '', bgi: '', file: null });
  }
  return send(u, fakesMsg());
}
function botModerate(u, text) { // يرجع true لو الرسالة اتمنعت
  if (!users.has(botU.id) || D.setting('bot_mod') === '0' || D.level(u.role) >= D.level(botU.role)) return false;
  const c = botCore.check(text, 'u' + u.id); if (!c) return false;
  u.mutedUntil = Date.now() + c.mins * 60e3; if (u.uid) D.setCol(u.uid, 'muted_until', u.mutedUntil);
  D.audit(botU.name, 'mute', u.name, c.mins + 'د - ' + c.why);
  notice(u, 'تم إسكاتك مؤقتًا', `قام ${botU.name} بإسكاتك ${c.mins} دقائق (${c.why}).`);
  botSay(u.room, `تم إسكات ${u.name} لمدة ${c.mins} دقائق (${c.why}) 🤖`, 300); return true;
}
function join(u, r) {
  if (!rooms.has(r) || u.room === r) return;
  leave(u); u.room = r;
  send(u, { t: 'joined', room: r, rw: D.roomWelcome(r) });
  send(u, { t: 'history', list: D.history(r).map(x => ({ ...x, ri: x.role ? D.icon(x.role) : '', rn: x.role ? D.rn(x.role) : '', rb: x.role ? D.rb(x.role) : '', role: undefined })) });
  roomEv(u, r, 'دخل الغرفة', 'enter');
  pushRooms(); pushUsers(r); pushOnline();
  if (r === LOBBY && !u.isBot && users.has(botU.id) && u.welcomed !== true) { u.welcomed = true; botSay(r, botCore.welcome(u.deco || u.name)); }
}

const PERMOF = { clearframe: 'members', clearbg: 'members', clearstatus: 'members', setdeco: 'members', kick: 'kick', kickroom: 'kickroom', mute: 'mute', ban: 'ban', tempban: 'tempban', setrole: 'setrole', move: 'moverooms', likes: 'editlikes' };
const rolesInfo = u => ({ catalog: D.PERMS, mine: D.level(u.role), list: D.rolesList().filter(r => (r.name === 'owner' ? u.role === 'owner' : r.level < D.level(u.role))) });
const rbList = () => { try { const l = JSON.parse(D.setting('role_banners') || '[]'); return Array.isArray(l) ? l : []; } catch { return []; } };
const iconUsed = i => !!i && (rbList().includes(i) || D.rolesList().some(r => r.icon === i));
const okIcon = i => i === '' || (/^\/u\/[a-f0-9]{24}\.(png|jpg|gif|webp)$/.test(i) && fs.existsSync(path.join(UP, i.slice(3))));
function whois(u, v) {
  const st = v.uid ? D.stats(v.uid) : { points: 0, likes: 0 };
  send(u, { t: 'whois', id: v.id, uid: v.uid, name: v.name, dn: v.deco, real: D.perms(u.role).length && v.deco ? v.name : undefined, role: v.role, label: D.label(v.role), color: D.color(v.role), ri: D.icon(v.role), rn: D.rn(v.role), rb: D.rb(v.role), av: v.avatar, fr: v.frame, bgi: v.bg, cc: v.cc, online: true, room: v.room, status: v.status, style: v.style, points: st.points, likes: v.fake ? v.likesN : st.likes, member: !!v.uid || !!v.fake, vf: v.verified ? 1 : 0, views: v.uid ? D.views(v.uid) : 0, low: D.level(v.role) < D.level(u.role), same: D.level(v.role) <= D.level(u.role), isbot: !!v.isBot, ignored: !!(u.ign && v.uid && u.ign.has(v.uid)) });
}

function admin(u, m) {
  const op = m.op;
  const owner = u.role === 'owner', ok = (t, x) => notice(u, t, x);
  if (op === 'setting') {
    const k = String(m.key); let val = clean(m.value).slice(0, 500);
    const allowed = ['site_name', 'reg_open', 'guest_open', 'accent', 'rooms_bar'].includes(k) ? owner : k === 'welcome' ? D.can(u.role, 'welcome') || D.can(u.role, 'settings') : k === 'rules' ? D.can(u.role, 'settings') : k === 'banner' ? D.can(u.role, 'assets') : false;
    if (!allowed) return send(u, { t: 'err', text: 'مفيش صلاحية على الإعداد ده' });
    if (k === 'reg_open' || k === 'guest_open' || k === 'rooms_bar') val = val === '0' ? '0' : '1';
    if (k === 'accent' && val && !hex(val)) return send(u, { t: 'err', text: 'لون غير صالح' });
    if (k === 'site_name' && val.length < 2) return send(u, { t: 'err', text: 'اسم الموقع قصير' });
    if (k === 'banner' && val) { const up = D.upload(val); if (!up || up.kind !== 'banner') return; }
    if (k === 'banner') dropFile(D.setting('banner'));
    D.setSetting(k, val); D.audit(u.name, 'setting', null, k + (k === 'banner' || k === 'accent' ? '' : ': ' + val.slice(0, 40)));
    return toSocks(site());
  }
  if (op === 'reports' || op === 'repact') {
    if (!D.can(u.role, 'reports')) return;
    if (op === 'repact') {
      const r = D.reportGet(Number(m.id)), act = String(m.act); if (!r) return;
      if (['close', 'dismiss'].includes(act)) { D.reportSet(r.id, act === 'close' ? 'done' : 'dismissed', u.name); D.audit(u.name, 'repclose', r.target, act); }
      else if (['mute', 'ban'].includes(act)) {
        const row = D.userByName(r.target), live = [...users.values()].find(x => x.name === r.target);
        const lvl = live ? D.level(live.role) : row ? D.level(row.role) : 0;
        if (live?.isBot || lvl >= D.level(u.role)) return send(u, { t: 'err', text: 'مفيش صلاحية على العضو ده' });
        if (!D.can(u.role, act)) return send(u, { t: 'err', text: 'مفيش صلاحية على الإجراء ده' });
        if (act === 'mute') { const until = Date.now() + 10 * 60e3; if (live) { live.mutedUntil = until; notice(live, 'تم إسكاتك', `قام ${u.name} بإسكاتك 10 دقايق بسبب بلاغ.`); } if (row) D.setCol(row.id, 'muted_until', until); }
        else { const until = Date.now() + 3650 * 864e5; if (row) D.setCol(row.id, 'banned_until', until); if (live) { D.addBlock('device', live.info.did, u.name, until); D.addBlock('device', live.info.sd, u.name, until); if (!live.uid) D.addBlock('ip', live.info.ip, u.name, until); else D.addBlock('reg', live.info.ip, u.name, until); if (!live.verified) { live.leaveWhy = 'تم حظره من الدردشة'; notice(live, 'تم حظرك', `قام ${u.name} بحظرك بشكل دائم.`); live.ws.close(); } } }
        D.reportSet(r.id, 'done', u.name); D.audit(u.name, act === 'mute' ? 'mute' : 'ban', r.target, 'من بلاغ #' + r.id);
        notice(u, 'تم التنفيذ', act === 'mute' ? `تم إسكات "${r.target}" 10 دقايق وإغلاق البلاغ.` : `تم حظر "${r.target}" وإغلاق البلاغ.`);
      } else return;
    }
    const off = Math.max(0, Math.floor(Number(m.off)) || 0), st = m.status === 'all' ? 'all' : 'open';
    return send(u, { t: 'reports', status: st, off, open: D.reportsOpen(), list: D.reportsList(st, off).map(r => ({ ...r, online: [...users.values()].some(x => x.name === r.target) })) });
  }
  if (op === 'members') {
    if (!D.can(u.role, 'members')) return;
    const off = Math.max(0, Math.floor(Number(m.off)) || 0), r = D.members(clean(m.q).slice(0, 30), off, 25), on = new Set([...users.values()].filter(x => x.uid).map(x => x.uid));
    return send(u, { t: 'members', q: clean(m.q).slice(0, 30), off, total: r.total, list: r.list.map(x => ({ id: x.id, name: x.username, dn: x.deco || '', role: x.role, label: D.label(x.role), color: D.color(x.role), av: x.avatar || '', fr: x.frame || '', created: x.created_at, last: x.last_login, banned: x.banned_until > Date.now() ? x.banned_until : 0, muted: x.muted_until > Date.now() ? x.muted_until : 0, vf: x.verified ? 1 : 0, vip: x.vip ? 1 : 0, online: on.has(x.id), low: D.level(x.role) < D.level(u.role) })), roles: D.rolesList().filter(x => x.name !== 'bot' && x.level < D.level(u.role)).map(x => ({ name: x.name, label: x.label })) });
  }
  if (op === 'mem') {
    if (!D.can(u.role, 'members')) return;
    const t = D.memberRow(Number(m.id)), act = String(m.act), ow = u.role === 'owner';
    if (!t || t.id === u.uid) return send(u, { t: 'err', text: 'عضو غير صالح' });
    if (D.level(t.role) >= D.level(u.role)) return send(u, { t: 'err', text: 'مفيش صلاحية على العضو ده' });
    const live = [...users.values()].find(x => x.uid === t.id), who = `"${t.username}"`; let said = '', det = '';
    const PM = { role: 'setrole', ban: 'ban', tempban: 'tempban', unban: 'ban' };
    if (PM[act] && !D.can(u.role, PM[act])) return send(u, { t: 'err', text: 'مفيش صلاحية على الإجراء ده' });
    if (act === 'role') {
      const r = String(m.role);
      if (r === 'bot' || !D.roleExists(r) || D.level(r) >= D.level(u.role)) return send(u, { t: 'err', text: 'رتبة غير صالحة' });
      D.setCol(t.id, 'role', r); if (live) { live.role = r; send(live, { t: 'perms', role: r, perms: D.perms(r) }); notice(live, 'تغيرت رتبتك', `قام ${u.name} بتغيير رتبتك إلى ${D.label(r)}.`); pushUsers(live.room); }
      said = `تم تغيير رتبة ${who} إلى ${D.label(r)}.`; det = r;
    } else if (act === 'ban' || act === 'tempban') {
      const mins = act === 'ban' ? 0 : Math.min(Math.max(Math.floor(Number(m.mins)) || 0, 1), 525600), until = Date.now() + (act === 'ban' ? 3650 * 864e5 : mins * 60e3);
      D.setCol(t.id, 'banned_until', until); if (live) { D.addBlock('device', live.info.did, u.name, until); D.addBlock('device', live.info.sd, u.name, until); D.addBlock('reg', live.info.ip, u.name, until); }
      if (live && !live.verified) { live.leaveWhy = 'تم حظره من الدردشة'; notice(live, 'تم حظرك', `قام ${u.name} بحظرك ${act === 'ban' ? 'بشكل دائم' : 'لمدة ' + mins + ' دقيقة'}.`); live.ws.close(); }
      said = `تم حظر ${who} ${act === 'ban' ? 'بشكل دائم' : 'لمدة ' + mins + ' دقيقة'}.${t.verified ? ' (العضو موثّق، فهو يقدر يدخل رغم الحظر)' : ''}`; det = act === 'ban' ? 'دائم' : mins + 'د';
    } else if (act === 'unban') { D.unbanUser(t.id); said = `تم فك الحظر عن ${who}.`; }
    else if (['verify', 'unverify', 'vip', 'unvip'].includes(act)) {
      if (!ow) return send(u, { t: 'err', text: 'التوثيق والدخول المميز للمالك بس' });
      const col = act.endsWith('vip') ? 'vip' : 'verified', on = !act.startsWith('un');
      D.setCol(t.id, col, on ? 1 : 0); if (live) { live[col] = on; pushUsers(live.room); }
      said = col === 'vip' ? (on ? `${who} بقى له دخول مميز.` : `تم إلغاء الدخول المميز عن ${who}.`) : (on ? `${who} بقى عضو موثّق، يدخل حتى لو متحظور.` : `تم إلغاء توثيق ${who}.`);
    } else return;
    D.audit(u.name, act === 'role' ? 'setrole' : act, t.username, det);
    notice(u, 'تم التنفيذ', said);
    return admin(u, { op: 'members', q: m.q, off: m.off });
  }
  if (op.startsWith('fake')) return fakeAdmin(u, op, m);
  if (op === 'botget' || op === 'botcfg') {
    if (!owner) return;
    if (op === 'botcfg') {
      D.setSetting('bot_enabled', m.enabled ? '1' : '0'); D.setSetting('bot_mod', m.mod ? '1' : '0');
      D.setSetting('bot_rules', longText(m.rules, 6000).trim() === BC.DEFAULT_RULES.trim() ? '' : longText(m.rules, 6000)); D.setSetting('bot_bad', longText(m.bad, 2000));
      botCore.setRules(D.setting('bot_rules') || BC.DEFAULT_RULES); botCore.setBad(D.setting('bot_bad')); botSync(); D.audit(u.name, 'botcfg', null, (m.enabled ? 'يعمل' : 'متوقف') + ' - ' + botCore.rules.length + ' قاعدة');
      ok('تم حفظ إعدادات البوت', `القواعد: ${botCore.rules.length} - المراقبة: ${m.mod ? 'شغالة' : 'متوقفة'}`);
    }
    return send(u, { t: 'botcfg', enabled: botOn(), mod: D.setting('bot_mod') !== '0', rules: D.setting('bot_rules') || BC.DEFAULT_RULES, bad: D.setting('bot_bad'), name: BC.NAME, defaults: BC.DEFAULT_RULES });
  }
  if (op === 'filter') {
    if (!D.can(u.role, 'filter')) return;
    D.setSetting('filter_words', longText(m.value, 2000)); loadFilter(); D.audit(u.name, 'filter', null, BAD.length + ' كلمة');
    return ok('تم حفظ الفلتر', `الكلمات الممنوعة دلوقتي: ${BAD.length}`);
  }
  if (op === 'shortcuts') {
    if (!D.can(u.role, 'shortcuts') || !Array.isArray(m.list)) return;
    const o = {}; m.list.slice(0, 40).forEach(p => { const a = S.normDigits(clean(p?.[0])).replace(/\s/g, '').slice(0, 12), b = clean(p?.[1]).slice(0, 300); if (a && b) o[a] = b; });
    D.setSetting('shortcuts', JSON.stringify(o)); loadShort(); D.audit(u.name, 'shortcuts', null, Object.keys(o).length + ' اختصار');
    return ok('تم حفظ الاختصارات', `عدد الاختصارات: ${Object.keys(o).length}`);
  }
  if (op === 'roomwelcome') {
    const r = cname(m.room); if (!(D.can(u.role, 'welcome') || D.can(u.role, 'roomadmin')) || !rooms.has(r)) return;
    D.setRoomWelcome(r, clean(m.text).slice(0, 300)); D.audit(u.name, 'roomwelcome', null, r);
    return ok('تم حفظ الترحيب', `ترحيب غرفة "${r}" اتحفظ.`);
  }
  if (op === 'mkrole' || op === 'editrole') {
    if (!D.can(u.role, 'roles')) return;
    const hasIcon = m.icon !== undefined, icon = hasIcon ? String(m.icon || '') : undefined;
    if (hasIcon && !okIcon(icon)) return send(u, { t: 'err', text: 'صورة البنر غير صالحة' });
    if (op === 'editrole' && m.role === 'owner' && u.role === 'owner' && hasIcon) { const old = D.icon('owner'); D.setRoleIcon('owner', icon); if (old && old !== icon && !iconUsed(old)) dropFile(old); D.audit(u.name, 'editrole', 'owner', 'بنر'); users.forEach(x => pushUsers(x.room)); return send(u, { t: 'roles', ...rolesInfo(u) }); }
    const label = clean(m.label).slice(0, 20), color = hex(m.color);
    if (label.length < 2) return send(u, { t: 'err', text: 'اسم الرتبة قصير' });
    if (op === 'mkrole') {
      const lvl = Math.floor(Number(m.level));
      if (D.rolesList().length >= 20) return send(u, { t: 'err', text: 'وصلنا للحد الأقصى للرتب' });
      if (!(lvl >= 1 && lvl < D.level(u.role))) return send(u, { t: 'err', text: 'مستوى الرتبة لازم يكون أقل من مستواك' });
      D.addRole('r' + Date.now().toString(36), lvl, label, color, icon || ''); D.audit(u.name, 'mkrole', null, label);
    } else {
      const r = String(m.role); if (!D.roleExists(r) || r === 'owner' || D.level(r) >= D.level(u.role)) return;
      const oldI = D.icon(r); D.editRole(r, label, color, icon); if (hasIcon && oldI && oldI !== icon && !iconUsed(oldI)) dropFile(oldI); D.audit(u.name, 'editrole', r, label);
    }
    users.forEach(x => pushUsers(x.room)); return send(u, { t: 'roles', ...rolesInfo(u) });
  }
  if (op === 'delrole') {
    const r = String(m.role);
    if (!D.can(u.role, 'roles') || !D.roleExists(r) || ['owner', 'admin', 'mod', 'member', 'bot'].includes(r) || D.level(r) >= D.level(u.role)) return send(u, { t: 'err', text: 'مينفعش تحذف الرتبة دي' });
    if (D.roleUsers(r) || [...users.values()].some(x => x.role === r)) return send(u, { t: 'err', text: 'فيه أعضاء بالرتبة دي، انقلهم لرتبة تانية الأول' });
    const oi = D.icon(r); D.delRole(r); if (oi && !iconUsed(oi)) dropFile(oi); D.audit(u.name, 'delrole', r); return send(u, { t: 'roles', ...rolesInfo(u) });
  }
  if (op === 'rolestyle') {
    const r = String(m.role); if (!D.can(u.role, 'roles') || !D.roleExists(r) || r === 'bot') return;
    if (r === 'owner' ? u.role !== 'owner' : D.level(r) >= D.level(u.role)) return;
    D.setRoleStyle(r, hex(m.n), hex(m.b)); D.audit(u.name, 'editrole', r, 'ألوان'); users.forEach(x => pushUsers(x.room)); return send(u, { t: 'roles', ...rolesInfo(u) });
  }
  if (op === 'rbadd' || op === 'rbdel') {
    if (!D.can(u.role, 'assets')) return;
    const url = String(m.url || ''), L = rbList();
    if (op === 'rbadd') { const up = D.upload(url); if (!up || up.kind !== 'roleicon' || !okIcon(url) || L.includes(url)) return; if (L.length >= 40) return send(u, { t: 'err', text: 'مكتبة البنرات ممتلئة (40)' }); L.push(url); D.audit(u.name, 'setting', null, 'بنر رتبة'); }
    else { if (!L.includes(url)) return; if (D.rolesList().some(r => r.icon === url)) return send(u, { t: 'err', text: 'البنر ده مستخدم في رتبة، شيله منها الأول' }); L.splice(L.indexOf(url), 1); D.setSetting('role_banners', JSON.stringify(L)); dropFile(url); return toSocks(site()); }
    D.setSetting('role_banners', JSON.stringify(L)); return toSocks(site());
  }
  if (op === 'emoji' || op === 'delemoji') {
    if (!D.can(u.role, 'assets')) return;
    let n = S.normDigits(clean(m.name));
    if (!n && op === 'emoji') { const used = new Set(D.emojis().map(e => e.name)); let i = 1; while (used.has('ف' + i)) i++; n = 'ف' + i; } // ترقيم تلقائي
    if (!/^[\p{L}\p{N}_]{1,16}$/u.test(n)) return send(u, { t: 'err', text: 'اختصار الإيموجي حروف وأرقام فقط (حتى 16)' });
    if (op === 'emoji') { const up = D.upload(String(m.url)); if (!up || up.kind !== 'emoji') return; D.addEmoji(n, up.url); D.audit(u.name, 'emoji', null, n); }
    else { const e = D.emojis().find(x => x.name === n); if (e) dropFile(e.url); D.delEmoji(n); D.audit(u.name, 'delemoji', null, n); }
    return toSocks(site());
  }
  if (op === 'roomclear' || op === 'roomlock' || op === 'roomdel') {
    const r = cname(m.room); if (!D.can(u.role, 'roomadmin') || !rooms.has(r)) return send(u, { t: 'err', text: 'مفيش صلاحية أو الغرفة مش موجودة' });
    if (op === 'roomclear') { D.clearRoom(r); D.audit(u.name, 'roomclear', null, r); toRoom(r, { t: 'history', list: [], replace: true }); toRoom(r, { t: 'sys', text: `${u.name} مسح رسائل الغرفة` }); return ok('تم مسح الرسائل', `اتمسحت كل رسائل غرفة "${r}".`); }
    if (op === 'roomlock') {
      const lock = !lockedRooms.has(r); lock ? lockedRooms.add(r) : lockedRooms.delete(r); saveLocked(); D.audit(u.name, 'roomlock', null, r + (lock ? ' (قفل)' : ' (فتح)'));
      toRoom(r, { t: 'sys', text: lock ? `${u.name} قفل الغرفة، المشرفين بس اللي يكتبوا` : `${u.name} فتح الغرفة للكتابة` }); pushRooms();
      return ok(lock ? 'تم قفل الغرفة' : 'تم فتح الغرفة', `غرفة "${r}" ${lock ? 'بقت للقراءة فقط لغير المشرفين' : 'اتفتحت للكل'}.`);
    }
    if (rooms.get(r) || r === LOBBY) return send(u, { t: 'err', text: 'الغرف الأساسية مينفعش تتحذف' });
    inRoom(r).forEach(x => { notice(x, 'تم حذف الغرفة', `قام ${u.name} بحذف غرفة "${r}" ونقلك للصالة العامة.`); join(x, LOBBY); });
    rooms.delete(r); D.delRoom(r); lockedRooms.delete(r); saveLocked(); D.audit(u.name, 'roomdel', null, r); pushRooms();
    return ok('تم حذف الغرفة', `غرفة "${r}" اتحذفت.`);
  }
  if (op === 'restart') {
    if (!owner) return;
    D.audit(u.name, 'restart'); toSocks({ t: 'restarting' }); setTimeout(restart, 400); return;
  }
  if (op === 'setperms') {
    const r = String(m.role);
    if (!D.can(u.role, 'roles') || !D.roleExists(r) || r === 'owner' || D.level(r) >= D.level(u.role)) return;
    D.setPerms(r, Array.isArray(m.perms) ? m.perms.map(String) : []); D.audit(u.name, 'setperms', r, D.perms(r).join('، '));
    users.forEach(x => x.role === r && send(x, { t: 'perms', role: r, perms: D.perms(r) }));
    return send(u, { t: 'roles', ...rolesInfo(u) });
  }
  const v = users.get(Number(m.target));
  if (!v || v === u || !PERMOF[op] || !D.can(u.role, PERMOF[op])) return;
  if (v.isBot) return send(u, { t: 'err', text: 'ده مسك بوت، تتحكم فيه من لوحة التحكم ← مسك بوت' });
  // الزخرفة وتعديل الإيكات متاحين على نفس المستوى (مش على الأعلى)، وباقي الأوامر الإدارية على الأقل رتبة بس
  if (['likes', 'setdeco'].includes(op) ? D.level(v.role) > D.level(u.role) : D.level(v.role) >= D.level(u.role)) return send(u, { t: 'err', text: 'مفيش صلاحية على العضو ده' });
  const mins = Math.min(Math.max(Math.floor(Number(m.mins)) || 0, 0), 525600);
  let det = { mute: mins ? mins + 'د' : 'فك', tempban: mins + 'د', ban: 'دائم', move: cname(m.room), likes: String(m.value), setrole: String(m.role) }[op] || '';
  const who = `"${v.name}"`;
  let said = '';
  if (op === 'kick') { v.leaveWhy = 'تم طرده من الدردشة'; notice(v, 'تم طردك', `قام ${u.name} بطردك من الدردشة.`); v.ws.close(); said = `تم طرد ${who} من الدردشة وفصله عن الموقع.`; }
  if (op === 'kickroom') {
    if (v.room === LOBBY) return notice(u, 'ملحوظة', `${who} موجود في الصالة العامة أصلًا.`);
    notice(v, 'تم طردك من الغرفة', `قام ${u.name} بنقلك إلى الصالة العامة.`); v.leaveWhy = 'تم طرده من الغرفة'; join(v, LOBBY);
    said = `تم طرد ${who} من الغرفة ونقله إلى الصالة العامة.`;
  }
  if (op === 'mute') {
    v.mutedUntil = mins ? Date.now() + mins * 60e3 : 0; if (v.uid) D.setCol(v.uid, 'muted_until', v.mutedUntil);
    notice(v, mins ? 'تم إسكاتك' : 'تم فك الإسكات', mins ? `قام ${u.name} بإسكاتك ${mins} دقيقة، ومش هتقدر تكتب رسايل لحد ما المدة تخلص.` : `قام ${u.name} بفك الإسكات عنك، تقدر تكتب تاني.`);
    said = mins ? `تم إسكات ${who} لمدة ${mins} دقيقة. مش هيقدر يكتب رسايل خلال المدة دي.` : `تم فك الإسكات عن ${who} وبقى يقدر يكتب.`;
  }
  if (op === 'ban' || op === 'tempban') {
    const until = Date.now() + (op === 'ban' ? 3650 * 864e5 : Math.max(mins, 1) * 60e3);
    const how = op === 'ban' ? 'بشكل دائم' : `لمدة ${Math.max(mins, 1)} دقيقة`;
    if (v.uid) D.setCol(v.uid, 'banned_until', until);
    if (!v.fake) { D.addBlock('device', v.info.did, u.name, until); D.addBlock('device', v.info.sd, u.name, until); if (!v.uid) D.addBlock('ip', v.info.ip, u.name, until); else D.addBlock('reg', v.info.ip, u.name, until); }
    notice(v, 'تم حظرك', `قام ${u.name} بحظرك ${how}.`); v.leaveWhy = 'تم حظره من الدردشة'; v.ws.close();
    said = `تم حظر ${who} ${how} (${v.uid ? 'الحساب والجهاز' : 'الجهاز والايبي'}). تقدر تفك الحظر من لوحة التحكم ← المحظورين.`;
  }
  if (op === 'move') {
    const r = cname(m.room); if (!rooms.has(r)) return;
    notice(v, 'تم نقلك', `قام ${u.name} بنقلك إلى غرفة "${r}".`); v.leaveWhy = `تم نقله إلى غرفة "${r}"`; join(v, r); said = `تم نقل ${who} إلى غرفة "${r}".`;
  }
  if (op === 'likes') {
    const n = Math.floor(Number(m.value));
    if ((!v.uid && !v.fake) || !(n >= 0 && n <= 1e9)) return send(u, { t: 'err', text: 'قيمة غير صالحة' });
    if (v.fake) { v.likesN = n; D.fakeSet(v.fake, { likes: n }); } else D.setCol(v.uid, 'likes', n); said = `تم تعديل إيكات ${who} إلى ${n}.`;
  }
  if (op === 'setrole') {
    const r = String(m.role);
    if ((!v.uid && !v.fake) || r === 'bot' || !D.roleExists(r) || D.level(r) >= D.level(u.role)) return send(u, { t: 'err', text: 'رتبة غير صالحة' });
    if (v.fake) { v.role = r; D.fakeSet(v.fake, { role: r }); pushUsers(v.room); notice(u, 'تم تنفيذ: ' + ACTAR[op], `تم تغيير رتبة "${v.name}" إلى ${D.label(r)}.\nتم تسجيل الإجراء في الحالات.`); return D.audit(u.name, op, v.name, r); }
    const days = Math.min(Math.max(Math.floor(Number(m.days)) || 0, 0), 3650);
    if (days && D.level(v.role) < 100) { { const cur = D.memberRow(v.uid); D.setCol(v.uid, 'role_prev', cur && cur.role_until > 0 && cur.role_prev ? cur.role_prev : (v.role === r ? 'member' : v.role)); } D.setCol(v.uid, 'role_until', Date.now() + days * 864e5); } else { D.setCol(v.uid, 'role_until', 0); D.setCol(v.uid, 'role_prev', ''); }
    D.setCol(v.uid, 'role', r); v.role = r;
    send(v, { t: 'perms', role: r, perms: D.perms(r) }); pushUsers(v.room);
    notice(v, 'تغيرت رتبتك', `قام ${u.name} بتغيير رتبتك إلى ${D.label(r)}.`); said = `تم تغيير رتبة ${who} إلى ${D.label(r)}.`;
  }
  if (['clearframe', 'clearbg', 'clearstatus'].includes(op)) {
    if (!v.uid) return send(u, { t: 'err', text: v.fake ? 'ده عضو وهمي' : 'العضو ده زائر' });
    if (op === 'clearframe') { dropFile(v.frame); v.frame = ''; D.setCol(v.uid, 'frame', ''); said = `تم إزالة إطار ${who}.`; }
    if (op === 'clearbg') { v.bg = ''; D.setCol(v.uid, 'bg', ''); said = `تم إزالة غلاف ${who}.`; }
    if (op === 'clearstatus') { v.status = ''; D.setCol(v.uid, 'status_msg', ''); said = `تم إزالة بنر الحالة عن ${who}.`; }
    pushUsers(v.room);
  }
  if (op === 'setdeco') {
    if (!v.uid && !v.fake) return send(u, { t: 'err', text: 'العضو ده زائر' });
    if (v.fake) { const d = cname(m.value).slice(0, 24); if (d && badWord(d)) return send(u, { t: 'err', text: 'الزخرفة فيها كلمة ممنوعة' }); v.deco = d; D.fakeSet(v.fake, { deco: d }); pushUsers(v.room); notice(u, 'تم تنفيذ: ' + ACTAR[op], `تم تغيير زخرفة "${v.name}".\nتم تسجيل الإجراء في الحالات.`); return D.audit(u.name, op, v.name, d); }
    const d = cname(m.value).slice(0, 24), sk = S.skeleton(d).replace(/[^\p{L}\p{N}]/gu, '');
    if (d && (badWord(d) || !/[\p{L}\p{N}]/u.test(d) || D.decoTaken(v.uid, sk))) return send(u, { t: 'err', text: 'الزخرفة دي مستخدمة أو شبه اسم عضو تاني أو فيها كلمة ممنوعة' });
    v.deco = d; D.setCol(v.uid, 'deco', d); D.setCol(v.uid, 'deco_skel', d ? sk : ''); pushUsers(v.room); said = d ? `تم تغيير زخرفة ${who} إلى "${d}".` : `تم مسح زخرفة ${who}.`; det = d;
  }
  D.audit(u.name, op, v.name, det);
  notice(u, 'تم تنفيذ: ' + ACTAR[op], said + '\nتم تسجيل الإجراء في الحالات.');
}

async function changePass(u, m) {
  const k = 'pw|' + u.uid;
  if (failAcct.full(k)) return send(u, { t: 'err', text: 'محاولات كتير، استنى شوية وجرّب تاني' });
  const np = String(m.np ?? '');
  if (!(await D.checkPass(u.uid, String(m.old ?? '')))) { failAcct.hit(k); return send(u, { t: 'err', text: 'كلمة المرور الحالية غلط' }); }
  const bad = S.badPassword(np, u.name); if (bad) return send(u, { t: 'err', text: bad });
  const c = await D.newCred(np); D.setPassHash(u.uid, c.h, c.salt);
  users.forEach(x => { if (x !== u && x.uid === u.uid) { send(x, { t: 'err', text: 'تم تغيير كلمة المرور من جهاز تاني' }); x.ws.close(); } });
  u.token = D.newSession(u.uid); failAcct.reset(k);
  send(u, { t: 'token', token: u.token });
  notice(u, 'تم تغيير كلمة المرور', 'كلمة مرورك اتغيرت، وجلسات الأجهزة التانية اتقفلت.');
}
const NAME_OK = (n, min) => new RegExp(`^[\\p{L}\\p{N}_ ]{${min},20}$`, 'u').test(n) && /[\p{L}\p{N}]/u.test(n);
const lockMsg = w => `محاولات كتير غلط. جرّب بعد ${Math.ceil(w / 60)} دقيقة`;
let authBusy = 0;

wss.on('connection', (ws, req) => {
  ws.on('error', e => logErr('ws', e));
  let u = null, fails = 0, abuse = 0, pending = false;
  const ip = N.clientIp(req), dq = new URL(req.url, 'http://x').searchParams.get('d') || '';
  const info = { ip, country: N.clientCountry(req, ip), ...N.parseUA(req.headers['user-agent']), lang: String(req.headers['accept-language'] || '').split(',')[0].slice(0, 12), did: /^[\w-]{8,64}$/.test(dq) ? dq : '', sd: cookieOf(req, 'sd') };
  connIp.set(ip, (connIp.get(ip) || 0) + 1);
  ws.isAlive = true; ws.on('pong', () => { ws.isAlive = true; });
  const allow = S.bucket(CFG.burst, CFG.perSec);
  const authTimer = setTimeout(() => { if (!u) ws.close(4008); }, CFG.authTimeout);
  socks.add(ws); try { ws.send(JSON.stringify(site())); } catch {} pushOnline();
  const raw1 = o => { try { ws.readyState === 1 && ws.send(JSON.stringify(o)); } catch {} };
  const err = x => { raw1({ t: 'err', text: x }); if (++fails >= 8) ws.close(); };
  const online = n => { const k = S.skeleton(n); return [...users.values()].some(x => S.skeleton(x.name) === k); };
  const enter = (row, name, token) => {
    if (ws.readyState !== 1) return;
    if (row?.role !== 'owner' && !row?.verified && D.blockedBy(info.ip, info.did, info.sd)) { raw1({ t: 'err', text: 'تم حظر الدخول من جهازك أو شبكتك' }); return ws.close(); }
    if (row) { const dup = [...users.values()].find(x => x.uid === row.id); if (dup) { send(dup, { t: 'err', text: 'دخلت من جهاز تاني' }); dup.ws.close(); } }
    u = { id: nextId++, uid: row?.id ?? null, name, role: row?.role ?? 'guest', style: parseStyle(row?.style), ign: new Set(row ? D.ignoreList(row.id).map(x => x.uid) : []), mids: new Set(), deco: row?.deco || '', verified: !!row?.verified, vip: !!row?.vip, status: row?.status_msg || '', ws, room: null, stamps: [], reports: new Set(), mutedUntil: row?.muted_until || 0, cc: info.country || '', avatar: row?.avatar || '', frame: row?.frame || '', bg: row?.bg || '', upkey: crypto.randomBytes(16).toString('hex'), lastUp: 0, token: token || null };
    byKey.set(u.upkey, u);
    users.set(u.id, u); u.info = info; u.since = Date.now(); u.visit = D.visit(u, info);
    send(u, { t: 'welcome', id: u.id, name, role: u.role, perms: D.perms(u.role), token, upkey: u.upkey, av: u.avatar, fr: u.frame, bgi: u.bg, unread: u.uid ? D.unread(u.uid) : 0, pmUnread: u.uid ? D.pmUnread(u.uid) : 0 });
    if (u.uid) { sendInbox(u); send(u, { t: 'ignores', list: D.ignoreList(u.uid) }); }
    join(u, LOBBY);
    if (u.vip) { toRoom(LOBBY, { t: 'vipin', id: u.id, name: u.name, dn: u.deco }); roomEv(u, LOBBY, 'دخل دخولًا مميزًا', 'vip'); }
  };

  async function auth(m) {
    if (m.t === 'resume') {
      const row = D.sessionUser(String(m.token ?? ''));
      if (!row) return raw1({ t: 'badtoken' });
      if (row.banned_until > Date.now() && !row.verified) return err('الحساب محظور مؤقتًا');
      D.touch(row.id); return enter(row, row.username, String(m.token));
    }
    const name = cname(m.name).slice(0, 20), key = S.skeleton(name);
    if (m.t === 'login' && m.pass !== undefined) {
      const ak = ip + '|' + key;
      if (failIp.full(ip) || failAcct.full(ak)) return err(lockMsg(Math.max(failIp.retry(ip), failAcct.retry(ak))));
      if (authBusy >= 16) return err('السيرفر مشغول، جرّب كمان لحظات');
      authBusy++; let row; try { row = await D.loginAsync(name, String(m.pass).slice(0, 200)); } finally { authBusy--; }
      if (!row) { failIp.hit(ip); failAcct.hit(ak); return err('الاسم أو كلمة المرور غلط'); }
      failAcct.reset(ak);
      if (row.banned_until > Date.now() && !row.verified) return err('الحساب محظور مؤقتًا');
      D.touch(row.id); return enter(row, row.username, D.newSession(row.id));
    }
    if (m.t === 'login') {
      if (D.setting('guest_open') === '0') return err('دخول الزوار متوقف حاليًا، سجّل دخول كعضو');
      if (!NAME_OK(name, 2)) return err('الاسم 2 إلى 20 حرف (حروف وأرقام ومسافة وشرطة سفلية فقط)');
      if (D.regBlocked(ip)) return err('الدخول كزائر غير متاح من شبكتك حاليًا');
      if (badWord(name)) return err('الاسم فيه كلمة ممنوعة');
      if (D.userExists(name)) return err('الاسم ده لعضو مسجّل، سجّل دخول بكلمة المرور');
      if (online(name)) return err('الاسم مستخدم، اختار اسم تاني');
      return enter(null, name);
    }
    if (m.t === 'register') {
      if (D.setting('reg_open') === '0') return err('التسجيل الجديد متوقف حاليًا');
      const pass = String(m.pass ?? '');
      if (!NAME_OK(name, 3)) return err('الاسم 3 إلى 20 حرف (حروف وأرقام فقط)');
      if (D.regBlocked(ip)) return err('إنشاء حساب جديد غير متاح من شبكتك حاليًا');
      if (badWord(name)) return err('الاسم فيه كلمة ممنوعة');
      const bad = S.badPassword(pass, name); if (bad) return err(bad);
      if (regWin.full(ip)) return err('تم الوصول للحد الأقصى لإنشاء الحسابات من شبكتك، جرّب بعد ساعة');
      if (D.userExists(name) || online(name) || D.fakes().some(f => S.skeleton(f.name) === S.skeleton(name))) return err('الاسم مستخدم، اختار اسم تاني');
      if (authBusy >= 16) return err('السيرفر مشغول، جرّب كمان لحظات');
      regWin.hit(ip);
      authBusy++; let c; try { c = await D.newCred(pass); } finally { authBusy--; }
      if (D.userExists(name)) return err('الاسم مستخدم، اختار اسم تاني');
      let row; try { row = D.createUserWith(name, c.h, c.salt); } catch { return err('الاسم مستخدم، اختار اسم تاني'); }
      return enter(row, row.username, D.newSession(row.id));
    }
  }

  const onMsg = raw => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (!m || typeof m !== 'object' || Array.isArray(m)) return;

    if (!u) {
      if (pending) return;
      pending = true;
      auth(m).catch(e => { logErr('auth', e); err('خطأ مؤقت، حاول تاني'); }).finally(() => { pending = false; });
      return;
    }
    if (m.t === 'logout') { if (u.token) D.delSession(u.token); u.token = null; u.leaveWhy = 'سجّل خروج'; return; }

    if (m.t === 'join') return join(u, cname(m.room));
    if (m.t === 'leave') { if (!u.room) return; leave(u); send(u, { t: 'left' }); pushRooms(); pushOnline(); pushLoose(); return; }
    if (m.t === 'mkroom') {
      const r = cname(m.name).slice(0, 24);
      if (badWord(r)) return send(u, { t: 'err', text: 'اسم الغرفة فيه كلمة ممنوعة' });
      if (tooFast(u) || r.length < 2 || !/[\p{L}\p{N}]/u.test(r) || rooms.has(r) || rooms.size >= 30) return send(u, { t: 'err', text: 'تعذّر إنشاء الغرفة: الاسم قصير أو موجود، أو وصلنا للحد الأقصى' });
      rooms.set(r, false); D.addRoom(r, u.uid); return join(u, r);
    }
    if (m.t === 'msg' || m.t === 'pm') {
      let file = null;
      if (m.file && typeof m.file === 'object') {
        const up = D.upload(String(m.file.url));
        if (!up || up.kind !== 'msg' || up.user_id !== (u.uid ?? -u.id)) return send(u, { t: 'err', text: 'الملف غير صالح' });
        file = { url: up.url, name: up.name, size: up.size, kind: up.mime };
      }
      const text = filter(expand(clean(m.text).slice(0, 300)).slice(0, 600)); if (!text && !file) return;
      if (Date.now() < u.mutedUntil) return send(u, { t: 'err', text: 'أنت مكتوم مؤقتًا' });
      if (tooFast(u)) return send(u, { t: 'err', text: 'بالراحة شوية، الرسايل بتتبعت بسرعة' });
      if (m.t === 'msg') {
        if (!u.room) return;
        if (lockedRooms.has(u.room) && !D.can(u.role, 'roomadmin') && D.level(u.role) < 50) return send(u, { t: 'err', text: 'الغرفة مقفولة حاليًا، المشرفين بس اللي يكتبوا' });
        if (botModerate(u, text)) return;
        const mid = D.logMsg(u.room, u.uid, u.name, text, file); if (!u.uid) { u.mids.add(mid); if (u.mids.size > 60) u.mids.delete(u.mids.values().next().value); }
        toRoomFrom(u.room, { t: 'msg', mid, id: u.id, name: u.name, ri: D.icon(u.role), rn: D.rn(u.role), rb: D.rb(u.role), dn: u.deco, vf: u.verified ? 1 : 0, text, style: u.style, av: u.avatar, fr: u.frame, bgi: u.bg, file }, u);
        mentions(u, text); botOnMsg(u, text); fakeOnMsg(u, text);
        if (u.uid) { D.addPoint(u.uid); D.bump(u.uid, 'msgs'); } return;
      }
      const byUid = m.touid != null ? Number(m.touid) : null;
      let to = byUid ? [...users.values()].find(x => x.uid === byUid) : users.get(Number(m.to));
      if (to === u) return;
      const toUid = byUid || (to && to.uid) || null, trow = toUid ? D.memberRow(toUid) : null;
      if (!to && !trow) return send(u, { t: 'err', text: 'العضو ده مش موجود' });
      if (!to && !u.uid) return send(u, { t: 'err', text: 'العضو ده مش متصل دلوقتي' });
      if (toUid && !to?.isBot && !to?.fake && D.isIgnoring(toUid, u.uid || -1)) return send(u, { t: 'err', text: 'العضو ده مش بيستقبل رسايل منك' });
      if (u.uid && toUid && u.ign.has(toUid) && !to?.isBot && !to?.fake) return send(u, { t: 'err', text: 'انت متجاهل العضو ده، شيل التجاهل الأول' });
      const pid = u.uid && toUid && !to?.isBot && !to?.fake ? D.pmAdd(u.uid, toUid, text, file) : 0;
      const o = { t: 'pm', pid, from: u.id, fromUid: u.uid, fromName: u.name, fromDn: u.deco, to: to ? to.id : null, toUid, toName: to ? to.name : trow.username, toDn: to ? to.deco : (trow.deco || ''), text, file, fromAv: u.avatar, toAv: to ? to.avatar : '' };
      send(u, o);
      if (to && to.isBot) { const rp = botCore.pm(text, u.deco || u.name); setTimeout(() => send(u, { t: 'pm', from: botU.id, fromUid: null, fromName: botU.name, to: u.id, toUid: u.uid, toName: u.name, text: rp, file: null, fromAv: '', toAv: u.avatar }), 600 + Math.random() * 700); return; }
      if (to && to.fake) { if (to.kind === 'bot' && !(to.mutedUntil > Date.now())) { const rp = to.core.pm(text, u.deco || u.name); setTimeout(() => send(u, { t: 'pm', from: to.id, fromUid: null, fromName: to.name, fromDn: to.deco, to: u.id, toUid: u.uid, toName: u.name, text: rp, file: null, fromAv: to.avatar, toAv: u.avatar }), 600 + Math.random() * 700); } return; }
      if (to) { send(to, o); return; }
      pushNotif(toUid, 'pm', `${u.deco || u.name} بعتلك رسالة خاصة`, u.name); return;
    }
    if (m.t === 'profile' && u.uid) {
      u.style = { n: hex(m.n), t: hex(m.tx), b: hex(m.b), s: hex(m.s) };
      if ('deco' in m) {
        const d = cname(m.deco).slice(0, 24), sk = S.skeleton(d).replace(/[^\p{L}\p{N}]/gu, '');
        if (d && badWord(d)) send(u, { t: 'err', text: 'الزخرفة فيها كلمة ممنوعة' });
        else if (d && (!/[\p{L}\p{N}]/u.test(d) || D.decoTaken(u.uid, sk))) send(u, { t: 'err', text: 'الزخرفة دي مستخدمة أو شبه اسم عضو تاني، اختار غيرها' });
        else { u.deco = d; D.setCol(u.uid, 'deco', d); D.setCol(u.uid, 'deco_skel', d ? sk : ''); }
      }
      u.status = clean(m.status).slice(0, 60); if (badWord(u.status)) { u.status = ''; send(u, { t: 'err', text: 'الحالة فيها كلمة ممنوعة' }); }
      D.setCol(u.uid, 'style', JSON.stringify(u.style)); D.setCol(u.uid, 'status_msg', u.status);
      return pushUsers(u.room);
    }
    if (m.t === 'passwd' && u.uid) { changePass(u, m).catch(e => { logErr('passwd', e); send(u, { t: 'err', text: 'خطأ مؤقت، حاول تاني' }); }); return; }
    if (m.t === 'reveal') {
      const v = users.get(Number(m.id)); if (!v || v === u || !D.can(u.role, 'reveal')) return;
      if (D.level(v.role) > D.level(u.role)) return send(u, { t: 'err', text: 'مفيش صلاحية على العضو ده' });
      if (v.isBot || v.fake) return send(u, { t: 'err', text: 'ده ' + (v.fake ? 'عضو وهمي' : 'مسك بوت') + '، مفيش ليه ايبي أو جهاز' });
      D.audit(u.name, 'reveal', v.name);
      const i = v.info;
      return send(u, { t: 'reveal', id: v.id, name: v.name, dn: v.deco, member: !!v.uid, devType: i.devType, os: i.os, model: i.model, bname: i.bname, bver: i.bver, lang: i.lang, ip: i.ip, country: i.country, countryName: N.countryName(i.country), device: i.device, browser: i.browser, since: v.since, same: D.sameDevice(i.did, v.name) });
    }
    if (m.t === 'logs') {
      const need = { visits: 'viewlog', cases: 'viewcases', blocks: 'ban' }[m.kind];
      if (!need || !D.can(u.role, need)) return;
      let rows = m.kind === 'visits' ? D.visits() : m.kind === 'cases' ? D.cases() : D.blocks();
      if (m.kind === 'visits') rows = rows.map(r => { const h = D.level(r.role) >= D.level(u.role) && r.name !== u.name; return { ...r, label: D.label(r.role), ip: h ? 'مخفي' : r.ip, device: h ? '' : r.device, browser: h ? '' : r.browser, countryName: N.countryName(r.country) }; });
      return send(u, { t: 'logs', kind: m.kind, rows });
    }
    if (m.t === 'unblock' && D.can(u.role, 'ban')) {
      D.delBlock(Number(m.id)); D.audit(u.name, 'unblock', null, String(m.id));
      return send(u, { t: 'logs', kind: 'blocks', rows: D.blocks() });
    }
    if (m.t === 'whois') {
      const v = m.id != null ? users.get(Number(m.id)) : [...users.values()].find(x => x.name === cname(m.name));
      if (v) { if (u.uid && v.uid) D.addVisit(v.uid, u.uid); return whois(u, v); }
      const r = D.userByName(cname(m.name)); if (r && u.uid) D.addVisit(r.id, u.uid);
      if (!r) return notice(u, 'غير متصل', 'العضو ده زائر وخرج من الدردشة، فمفيش بروفايل ليه.');
      return send(u, { t: 'whois', id: null, uid: r.id, name: r.username, dn: r.deco || '', real: D.perms(u.role).length && r.deco ? r.username : undefined, role: r.role, label: D.label(r.role), color: D.color(r.role), av: r.avatar, fr: r.frame, bgi: r.bg, cc: D.lastCountry(r.id), room: null, status: r.status_msg, style: parseStyle(r.style), points: r.points, likes: r.likes, member: true, vf: r.verified ? 1 : 0, views: D.views(r.id), low: D.level(r.role) < D.level(u.role), same: D.level(r.role) <= D.level(u.role), offline: true });
    }
    if (m.t === 'like') {
      const v = users.get(Number(m.id)); if (!v || !v.uid || !u.uid || v === u) return;
      const before = D.stats(v.uid).likes; D.like(u.uid, v.uid);
      if (D.stats(v.uid).likes > before) pushNotif(v.uid, 'like', `${u.name} أعجب بملفك الشخصي`, u.name);
      return whois(u, v);
    }
    if (m.t === 'alert') {
      const v = users.get(Number(m.id)), text = filter(clean(m.text).slice(0, 200));
      if (!v || v === u || v.isBot || !text || tooFast(u)) return;
      if (Date.now() < u.mutedUntil) return send(u, { t: 'err', text: 'أنت مكتوم مؤقتًا' });
      const ak = u.id + '>' + v.id;
      if (alertWin.full(u.id) || alertLast.get(ak) > Date.now() - 15e3) return send(u, { t: 'err', text: 'استنى شوية قبل ما تبعت تنبيه تاني' });
      alertWin.hit(u.id); alertLast.set(ak, Date.now()); if (alertLast.size > 3000) alertLast.clear();
      if (u.uid && v.ign && v.ign.has(u.uid)) return notice(u, 'تم إرسال التنبيه', `وصلت رسالتك إلى "${v.deco || v.name}".`);
      send(v, { t: 'alert', fromName: u.name, dn: u.deco, text }); return notice(u, 'تم إرسال التنبيه', `وصلت رسالتك إلى "${v.deco || v.name}".`);
    }
    if (m.t === 'avdel' && u.uid) { dropFile(u.avatar); u.avatar = ''; D.setCol(u.uid, 'avatar', ''); send(u, { t: 'avatar', url: '' }); return pushUsers(u.room); }
    if (m.t === 'cfg') {
      const o = { t: 'cfg' };
      if (D.can(u.role, 'filter')) o.filter = D.setting('filter_words');
      if (D.can(u.role, 'shortcuts')) o.shortcuts = SHORT;
      if (D.can(u.role, 'welcome')) o.welcomes = D.roomWelcomes();
      return send(u, o);
    }
    if (m.t === 'stats') {
      if (!D.can(u.role, 'stats')) return;
      let bytes = 0; try { fs.readdirSync(UP).forEach(f => { bytes += fs.statSync(path.join(UP, f)).size; }); } catch {}
      return send(u, { t: 'stats', ...D.counts(), online: users.size, onlineMembers: [...users.values()].filter(x => x.uid).length, liveRooms: rooms.size, up: Math.floor(process.uptime()), bytes });
    }
    // الإشعارات والمظهر والترتيبات
    if (m.t === 'notifs') { if (!u.uid) return send(u, { t: 'notifs', list: [] }); send(u, { t: 'notifs', list: D.notifs(u.uid) }); return D.readAll(u.uid); }
    if (m.t === 'notifclear' && u.uid) { D.clearNotifs(u.uid); return send(u, { t: 'notifs', list: [] }); }
    if (m.t === 'gallery') return send(u, { t: 'gallery', frames: D.gallery('frame'), bgs: D.gallery('bg'), frame: u.frame, bg: u.bg, canAdd: D.can(u.role, 'assets') });
    if (m.t === 'setlook' && u.uid) {
      for (const [k, key] of [['frame', 'frame'], ['bg', 'bg']]) {
        if (!(k in m)) continue;
        const url = String(m[k] || '');
        if (url && !D.inGallery(key, url)) { const up = D.upload(url); if (!up || up.user_id !== u.uid || up.kind !== key) continue; }
        if (u[key] && u[key] !== url && !D.inGallery(key, u[key])) dropFile(u[key]);
        u[key] = url; D.setCol(u.uid, key, url);
      }
      send(u, { t: 'looks', frame: u.frame, bg: u.bg }); return pushUsers(u.room);
    }
    if (m.t === 'galdel') {
      if (!D.can(u.role, 'assets')) return; const g = D.delGallery(Number(m.id)); if (!g) return;
      D.audit(u.name, 'galdel', null, g.kind === 'bg' ? 'خلفية' : 'إطار'); dropFile(g.url);
      users.forEach(x => { if (x.frame === g.url) x.frame = ''; if (x.bg === g.url) x.bg = ''; });
      users.forEach(x => pushUsers(x.room)); return send(u, { t: 'gallery', frames: D.gallery('frame'), bgs: D.gallery('bg'), frame: u.frame, bg: u.bg, canAdd: true });
    }
    if (m.t === 'rank') {
      const kind = String(m.kind), period = SINCE[m.period] ? m.period : 'day', d = SINCE[period], o = { t: 'rank', kind, period };
      if (kind === 'trend') o.lists = { posts: D.rank('posts', d), comments: D.rank('comments', d) };
      else if (kind === 'creator') o.lists = { likes: D.rank('likes', d) };
      else if (kind === 'stars') o.lists = { msgs: D.rank('msgs', d) };
      else if (kind === 'visits') o.lists = { top: D.topVisited(Date.now() - d * 864e5), recent: u.uid ? D.myVisitors(u.uid) : [] };
      else return;
      return send(u, o);
    }
    // الحائط
    if (m.t === 'wall') return sendWall(u);
    if (m.t === 'post') {
      if (!u.uid) return send(u, { t: 'err', text: 'النشر للأعضاء المسجلين فقط' });
      if (Date.now() < u.mutedUntil) return send(u, { t: 'err', text: 'أنت مكتوم مؤقتًا' });
      if (tooFast(u)) return send(u, { t: 'err', text: 'بالراحة شوية' });
      let img = '';
      if (m.img) { const up = D.upload(String(m.img)); if (!up || up.kind !== 'post' || up.user_id !== u.uid) return send(u, { t: 'err', text: 'الصورة غير صالحة' }); img = up.url; }
      const text = filter(longText(m.text, 500).trim()); if (!text && !img) return;
      D.addPost(u.uid, u.name, text, img); D.addPoint(u.uid); D.bump(u.uid, 'posts');
      sendWall(u); return users.forEach(x => x !== u && send(x, { t: 'wallnew' }));
    }
    if (m.t === 'plike') {
      const p = D.post(Number(m.id)); if (!u.uid || !p) return;
      const had = !!D.db.prepare('SELECT 1 x FROM post_likes WHERE post_id = ? AND user_id = ?').get(p.id, u.uid);
      D.postLike(p.id, u.uid); D.bump(p.user_id, 'likes', had ? -1 : 1);
      if (!had && p.user_id !== u.uid) pushNotif(p.user_id, 'wall', `${u.name} أعجب بمنشورك`, u.name);
      return sendWall(u);
    }
    if (m.t === 'comments') return sendComments(u, Number(m.id));
    if (m.t === 'comment') {
      const p = D.post(Number(m.id)), text = filter(clean(m.text).slice(0, 200));
      if (!u.uid || !p || !text) return;
      if (Date.now() < u.mutedUntil || tooFast(u)) return send(u, { t: 'err', text: 'استنى شوية' });
      D.addComment(p.id, u.uid, u.name, text); D.bump(u.uid, 'comments'); if (p.user_id !== u.uid) pushNotif(p.user_id, 'wall', `${u.name} علّق على منشورك: ${text.slice(0, 40)}`, u.name);
      sendComments(u, p.id); sendWall(u); return users.forEach(x => x !== u && send(x, { t: 'wallnew' }));
    }
    if (m.t === 'delpost') {
      const p = D.post(Number(m.id)); if (!p) return;
      if (p.user_id !== u.uid && !D.can(u.role, 'wallmod')) return;
      if (p.user_id !== u.uid) D.audit(u.name, 'delpost', p.name);
      dropFile(p.img); D.delPost(p.id); sendWall(u); return users.forEach(x => x !== u && send(x, { t: 'wallnew' }));
    }
    if (m.t === 'delcomment') {
      const c = D.comment(Number(m.id)); if (!c) return;
      if (c.user_id !== u.uid && !D.can(u.role, 'wallmod')) return;
      D.delComment(c.id); sendComments(u, c.post_id); return sendWall(u);
    }
    if (m.t === 'rolesinfo') return (D.can(u.role, 'roles') || D.can(u.role, 'setrole')) && send(u, { t: 'roles', ...rolesInfo(u) });
    if (m.t === 'admin') return admin(u, m);
    if (m.t === 'report') {
      const v = users.get(Number(m.id)); if (!v || v === u || v.isBot) return;
      if (tooFast(u)) return;
      const rk = u.uid ? 'u' + u.uid : 'i' + u.info.ip, dk = rk + '>' + v.name;
      if (repSeen.get(dk) > Date.now() - 600e3) return notice(u, 'تم إرسال البلاغ', `بلاغك على "${v.name}" وصل قبل كده وبيتراجع.`);
      if (repWin.full(rk)) return send(u, { t: 'err', text: 'بلاغات كتير في ساعة، استنى شوية' });
      repWin.hit(rk); repSeen.set(dk, Date.now()); if (repSeen.size > 2000) repSeen.clear();
      const reason = filter(clean(m.reason).slice(0, 200)), ctx = D.lastMsgsBy(v.room || '', v.name, 5).join('\n').slice(0, 800);
      D.report(u.name, v.name, reason, ctx, v.room || '');
      users.forEach(x => { if (x.uid && D.can(x.role, 'reports')) send(x, { t: 'repnew', n: D.reportsOpen(), from: u.name, target: v.name }); });
      v.reports.add(rk);
      if (v.reports.size >= 3 && D.level(v.role) < 50) { v.mutedUntil = Date.now() + 300e3; v.reports.clear(); notice(v, 'تم إسكاتك مؤقتًا', 'وصلت عليك 3 بلاغات من أعضاء مختلفين، فتم إسكاتك 5 دقايق تلقائيًا.'); }
      notice(u, 'تم إرسال البلاغ', `تم تسجيل بلاغك على "${v.name}" وهيتراجع من الإدارة. لو وصلت 3 بلاغات من أعضاء مختلفين بيتم إسكاته 5 دقايق تلقائيًا.`);
    }
    if (m.t === 'ignore' && u.uid) {
      const v = users.get(Number(m.id)); if (!v || !v.uid || v === u || v.isBot) return;
      if (m.on && D.level(v.role) >= 50) return send(u, { t: 'err', text: 'مينفعش تتجاهل الإدارة' });
      if (!D.ignoreSet(u.uid, v.uid, !!m.on)) return send(u, { t: 'err', text: 'وصلت للحد الأقصى لقايمة التجاهل' });
      m.on ? u.ign.add(v.uid) : u.ign.delete(v.uid);
      send(u, { t: 'ignores', list: D.ignoreList(u.uid) }); return whois(u, v);
    }
    if (m.t === 'unignore' && u.uid) { const t = Number(m.uid); D.ignoreSet(u.uid, t, false); u.ign.delete(t); return send(u, { t: 'ignores', list: D.ignoreList(u.uid) }); }
    if (m.t === 'inbox' && u.uid) return sendInbox(u);
    if (m.t === 'pmthread' && u.uid) {
      const o = Number(m.uid), r = D.memberRow(o); if (!r) return;
      D.pmRead(u.uid, o); const on = [...users.values()].find(x => x.uid === o);
      send(u, { t: 'pmthread', uid: o, name: r.username, dn: r.deco || '', sid: on ? on.id : null, list: D.pmThread(u.uid, o) }); return sendInbox(u);
    }
    if (m.t === 'delmsg') {
      const row = D.msgById(Number(m.mid)); if (!row || row.room !== u.room) return;
      const own = u.uid ? row.user_id === u.uid : u.mids.has(row.id);
      const staff = D.can(u.role, 'delmsg') && (row.user_id ? D.level(row.role) < D.level(u.role) : true);
      if (!own && !staff) return send(u, { t: 'err', text: 'مفيش صلاحية تحذف الرسالة دي' });
      D.delMsg(row.id); try { const f = row.file ? JSON.parse(row.file) : null; if (f && f.url) dropFile(f.url); } catch {}
      toRoom(row.room, { t: 'delmsg', mid: row.id });
      if (!own) D.audit(u.name, 'delmsg', row.name, String(row.text).slice(0, 60));
      return;
    }
  };
  ws.on('message', (raw, isBinary) => {
    if (isBinary) return;
    if (!allow()) { if (++abuse > 30) ws.close(1008, 'rate'); return; }
    try { onMsg(raw); } catch (e) { logErr('ws message', e); raw1({ t: 'err', text: 'حصل خطأ، جرّب تاني' }); }
  });
  ws.on('close', () => {
    clearTimeout(authTimer);
    const c = (connIp.get(ip) || 1) - 1; c > 0 ? connIp.set(ip, c) : connIp.delete(ip);
    socks.delete(ws);
    if (!u) return;
    byKey.delete(u.upkey);
    D.leaveVisit(u.visit); leave(u, 'غادر الدردشة'); users.delete(u.id); pushRooms(); pushOnline(); pushLoose();
  });
});

const unlinkUp = url => { if (/^\/u\/[a-f0-9]{24}\.[a-z0-9]{2,4}$/.test(url || '')) fs.rm(path.join(UP, url.slice(3)), () => {}); };
setInterval(() => { try { D.prune().forEach(unlinkUp); } catch (e) { logErr('prune', e); } [failIp, failAcct, regWin, connWin, upWin].forEach(w => w.sweep()); }, 36e5).unref();
setInterval(() => { try { D.expireRoles().forEach(x => { const l = [...users.values()].find(y => y.uid === x.id); if (l) { l.role = x.role; send(l, { t: 'perms', role: x.role, perms: D.perms(x.role) }); notice(l, 'انتهت مدة رتبتك', `رجعت رتبتك ${D.label(x.role)}.`); pushUsers(l.room); } }); } catch (e) { logErr('expire', e); } }, 60e3).unref();
setInterval(() => wss.clients.forEach(c => { if (c.isAlive === false) return c.terminate(); c.isAlive = false; try { c.ping(); } catch {} }), 30e3).unref();
let closing = false;
const shutdown = sig => { if (closing) return; closing = true; console.log(sig + ': إغلاق هادئ'); wss.clients.forEach(c => c.close(1001)); server.close(); setTimeout(() => { try { D.db.close(); } catch {} process.exit(0); }, 400); };
['SIGTERM', 'SIGINT'].forEach(sg => process.on(sg, () => shutdown(sg)));
if (!D.hasOwner()) console.warn(process.env.OWNER_NAME ? `تنبيه: لا يوجد مالك بعد. الحساب "${process.env.OWNER_NAME}" هو الوحيد الذي سيصبح مالكًا عند تسجيله.` : 'تنبيه أمني: لا يوجد مالك بعد، أول حساب يتسجل هيبقى المالك. اضبط OWNER_NAME لتحديد اسم المالك مسبقًا.');
server.on('error', e => { logErr('server', e); if (e.code === 'EADDRINUSE') process.exit(1); });
botSync(); fakesInit();
setTimeout(() => server.listen(PORT, () => console.log(`http://localhost:${PORT}`)), Number(process.env.RESTART_DELAY) || 0);
