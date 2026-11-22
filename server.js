require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { GEMINI_API_KEY: KEY, MONGODB_URI, JWT_SECRET, ADMIN_KEY } = process.env;
const MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
const SYSTEM = 'أنت DARK AI، مساعد ذكاء اصطناعي مستقل بشخصية هادئة وذكية وغامضة قليلًا. رد بنفس لغة المستخدم (افتراضيًا العربية بلهجة بسيطة وواضحة)، وكن مفيدًا ودقيقًا ومختصرًا. استخدم ``` للأكواد. لا تساعد في أي شيء ضار أو غير قانوني.';

if (!MONGODB_URI || !JWT_SECRET) { console.error('MONGODB_URI و JWT_SECRET مطلوبين'); process.exit(1); }
mongoose.connect(MONGODB_URI).then(() => console.log('DB connected')).catch(e => { console.error(e); process.exit(1); });

const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  hash: { type: String, required: true },
  net: { type: Boolean, default: false }
}));
const Chat = mongoose.model('Chat', new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, index: true, required: true },
  title: String,
  messages: [{ role: String, content: String, _id: false }],
  updatedAt: { type: Date, default: Date.now }
}));

const Device = mongoose.model('Device', new mongoose.Schema({
  serial: { type: String, unique: true, required: true },
  name: String,
  addedBy: mongoose.Schema.Types.ObjectId,
  enabled: { type: Boolean, default: true },
  codeHash: String,
  tokenHash: String,
  activatedAt: Date,
  lastSeen: Date,
  createdAt: { type: Date, default: Date.now }
}));

const Net = mongoose.model('Net', new mongoose.Schema({
  cidr: { type: String, unique: true, required: true },
  label: String,
  createdAt: { type: Date, default: Date.now }
}));

const app = express();
app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS || 1));
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public'));

// حد الطلبات لكل IP
const hits = new Map();
const limit = (name, max) => (req, res, next) => {
  const k = name + req.ip, now = Date.now();
  const a = (hits.get(k) || []).filter(t => now - t < 60000);
  if (a.length >= max) return res.status(429).json({ error: 'rate_limited' });
  a.push(now); hits.set(k, a); next();
};
setInterval(() => hits.clear(), 10 * 60 * 1000);

const sign = (u, exp = '30d') => jwt.sign({ id: u._id }, JWT_SECRET, { expiresIn: exp });
function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    req.uid = jwt.verify(t, JWT_SECRET).id; next();
  } catch { res.status(401).json({ error: 'unauthorized' }); }
}
const validOk = (u, p) => /^[a-zA-Z0-9_]{3,20}$/.test(u || '') && typeof p === 'string' && p.length >= 6 && p.length <= 100;

app.post('/api/register', limit('auth', 10), async (req, res) => {
  const username = String(req.body.username || '').toLowerCase(), { password } = req.body;
  if (!validOk(username, password)) return res.status(400).json({ error: 'invalid_input' });
  try {
    const u = await User.create({ username, hash: await bcrypt.hash(password, 10) });
    res.json({ token: sign(u), username });
  } catch (e) { res.status(e.code === 11000 ? 409 : 500).json({ error: e.code === 11000 ? 'taken' : 'server' }); }
});

app.post('/api/login', limit('auth', 10), async (req, res) => {
  const username = String(req.body.username || '').toLowerCase();
  const u = await User.findOne({ username });
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.hash))) return res.status(401).json({ error: 'bad_login' });
  res.json({ token: sign(u), username });
});

app.get('/api/chats', auth, async (req, res) => {
  res.json(await Chat.find({ user: req.uid }, 'title updatedAt').sort({ updatedAt: -1 }).limit(100));
});
app.get('/api/chats/:id', auth, async (req, res) => {
  const c = await Chat.findOne({ _id: req.params.id, user: req.uid }).catch(() => null);
  c ? res.json(c) : res.status(404).json({ error: 'not_found' });
});
app.delete('/api/chats/:id', auth, async (req, res) => {
  await Chat.deleteOne({ _id: req.params.id, user: req.uid }).catch(() => {});
  res.json({ ok: true });
});

app.post('/api/chat', auth, limit('chat', 20), async (req, res) => {
  const message = String(req.body.message || '').slice(0, 8000).trim();
  if (!message || !KEY) return res.status(KEY ? 400 : 500).json({ error: KEY ? 'bad_request' : 'missing_key' });
  if (process.env.REQUIRE_DEVICE === '1' && !(await deviceOk(req))) return res.status(403).json({ error: 'device_blocked' });
  let chat = req.body.chatId ? await Chat.findOne({ _id: req.body.chatId, user: req.uid }).catch(() => null) : null;
  if (!chat) chat = new Chat({ user: req.uid, title: message.slice(0, 40), messages: [] });
  const contents = [...chat.messages.slice(-20), { role: 'user', content: message }].map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }]
  }));
  try {
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': KEY },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: SYSTEM }] }, contents })
    });
    const data = await r.json();
    if (!r.ok) {
      console.error('Gemini error:', JSON.stringify(data));
      return res.status(r.status === 429 ? 429 : 502).json({ error: r.status === 429 ? 'rate_limited' : 'provider_error' });
    }
    const text = (data.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('') || 'مفيش رد، جرّب تاني.';
    chat.messages.push({ role: 'user', content: message }, { role: 'assistant', content: text });
    chat.updatedAt = new Date();
    await chat.save();
    res.json({ chatId: chat._id, title: chat.title, text });
  } catch (e) { console.error(e); res.status(502).json({ error: 'provider_error' }); }
});

// ---------- الأجهزة: الإدارة بمفتاح التحكم، والتفعيل بكود لمرة واحدة ----------
const sha = v => crypto.createHash('sha256').update(String(v)).digest();
const shaHex = v => sha(v).toString('hex');
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const newCode = () => crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{4}/g).join('-');
const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

function adminOnly(req, res, next) {
  if (!ADMIN_KEY) return res.status(503).json({ error: 'no_admin' });
  if (!same(req.headers['x-admin-key'] || '', ADMIN_KEY)) return res.status(403).json({ error: 'bad_key' });
  next();
}
async function deviceOk(req) {
  if (await onTrustedNet(req)) return true;
  const t = req.headers['x-device-token'];
  if (!t) return false;
  const d = await Device.findOne({ tokenHash: shaHex(t), enabled: true });
  if (!d) return false;
  d.lastSeen = new Date(); d.save().catch(() => {});
  return true;
}
// ---------- الشبكات الموثوقة (تابعة لنظام الأجهزة) ----------
const v4 = s => { const p = String(s).split('.'); if (p.length !== 4 || !p.every(x => /^\d{1,3}$/.test(x) && +x <= 255)) return null; return p.reduce((a, x) => a * 256 + +x, 0); };
function ipInRule(ip, rule) {
  const [base, m] = rule.split('/');
  const a = v4(ip), b = v4(base);
  if (a === null || b === null) return m === undefined && ip.toLowerCase() === base.toLowerCase();
  const size = 2 ** (32 - (m === undefined ? 32 : Number(m)));
  return Math.floor(a / size) === Math.floor(b / size);
}
const clientIp = req => String(req.ip || '').replace(/^::ffff:/, '');
let netCache = { t: 0, list: [] };
async function getNets() {
  if (Date.now() - netCache.t > 30000) netCache = { t: Date.now(), list: [...(await Net.find({}, 'cidr').lean()).map(n => n.cidr), ...String(process.env.TRUSTED_NETS || '').split(/[\s,]+/).filter(Boolean).filter(validRule)] };
  return netCache.list;
}
async function onTrustedNet(req) { const ip = clientIp(req); return (await getNets()).some(r => ipInRule(ip, r)); }
function validRule(r) {
  const [base, m] = String(r).split('/');
  if (v4(base) !== null) return m === undefined || (/^\d{1,2}$/.test(m) && +m >= 16 && +m <= 32);   // ممنوع النطاقات الواسعة
  return m === undefined && /^[0-9a-f:]{3,45}$/i.test(base) && (base.match(/:/g) || []).length >= 2;
}

const adm = [auth, limit('adm', 20), adminOnly];
const admKey = [limit('adm', 20), adminOnly];   // بمفتاح التحكم فقط (للشاشة الأولى قبل تسجيل الدخول)

app.get('/api/devices', ...adm, async (req, res) => {
  res.json(await Device.find({}, 'serial name enabled activatedAt lastSeen createdAt').sort({ createdAt: -1 }));
});
app.post('/api/devices', ...adm, async (req, res) => {
  const serial = String(req.body.serial || '').trim().toUpperCase();
  if (!/^[A-Z0-9-]{4,40}$/.test(serial)) return res.status(400).json({ error: 'bad_serial' });
  const code = newCode();
  try {
    const d = await Device.create({ serial, name: String(req.body.name || '').slice(0, 40), addedBy: req.uid, codeHash: shaHex(normCode(code)) });
    res.json({ _id: d._id, serial: d.serial, code });
  } catch (e) { res.status(e.code === 11000 ? 409 : 500).json({ error: e.code === 11000 ? 'dup' : 'server' }); }
});
app.patch('/api/devices/:id', ...adm, async (req, res) => {
  await Device.updateOne({ _id: req.params.id }, { enabled: !!req.body.enabled }).catch(() => {});
  res.json({ ok: true });
});
app.post('/api/devices/:id/code', ...adm, async (req, res) => {
  const code = newCode();
  const r = await Device.updateOne({ _id: req.params.id }, { codeHash: shaHex(normCode(code)), tokenHash: null, activatedAt: null }).catch(() => null);
  r && r.matchedCount ? res.json({ code }) : res.status(404).json({ error: 'not_found' });
});
app.delete('/api/devices/:id', ...adm, async (req, res) => {
  await Device.deleteOne({ _id: req.params.id }).catch(() => {});
  res.json({ ok: true });
});

app.get('/api/nets', ...admKey, async (req, res) => {
  res.json({ yourIp: clientIp(req), list: await Net.find({}, 'cidr label createdAt').sort({ createdAt: -1 }) });
});
app.post('/api/nets', ...admKey, async (req, res) => {
  const cidr = String(req.body.cidr || '').trim();
  if (!validRule(cidr)) return res.status(400).json({ error: 'bad_net' });
  try {
    const n = await Net.create({ cidr, label: String(req.body.label || '').slice(0, 40) });
    netCache.t = 0; res.json({ _id: n._id });
  } catch (e) { res.status(e.code === 11000 ? 409 : 500).json({ error: e.code === 11000 ? 'dup' : 'server' }); }
});
app.delete('/api/nets/:id', ...admKey, async (req, res) => {
  await Net.deleteOne({ _id: req.params.id }).catch(() => {}); netCache.t = 0; res.json({ ok: true });
});

app.get('/api/myip', limit('ip', 30), (req, res) => res.json({ ip: clientIp(req) }));

// دخول تلقائي لأجهزة الشبكة الموثوقة: بدون تفعيل ولا أكواد ولا خروج
app.post('/api/net/login', limit('net', 30), async (req, res) => {
  if (!(await onTrustedNet(req))) return res.status(403).json({ error: 'not_on_network' });
  const u = await User.create({ username: 'net-' + crypto.randomBytes(5).toString('hex'), hash: await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 4), net: true });
  res.json({ token: sign(u, '365d') });
});

// تفعيل الكمبيوتر: الرقم التسلسلي + الكود اللي أصدره المسؤول (يُستخدم مرة واحدة)
app.post('/api/device/activate', limit('act', 10), async (req, res) => {
  const serial = String(req.body.serial || '').trim().toUpperCase();
  const d = await Device.findOne({ serial });
  const ok = d && d.codeHash && same(shaHex(normCode(req.body.code)), d.codeHash);
  if (!ok) return res.status(403).json({ error: 'bad_activation' });
  const token = crypto.randomBytes(32).toString('hex');
  d.tokenHash = shaHex(token); d.codeHash = null; d.activatedAt = new Date();
  await d.save();
  res.json({ token, name: d.name });
});

app.listen(process.env.PORT || 3000, () => console.log('DARK AI is running'));
