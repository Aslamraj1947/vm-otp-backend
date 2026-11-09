/* Vande Mataram OTP backend - Fast2SMS. Zero dependencies, Node 18+.
   The Fast2SMS key lives ONLY here (env var FAST2SMS_API_KEY), never in the app files.
   POST /api/otp/send   {mobile}      -> {ok,msg}
   POST /api/otp/verify {mobile,otp}  -> {ok,msg}
   GET  /health                       -> {ok:true} */
'use strict';
const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');

/* tiny .env loader (real environment variables win) */
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
    const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/); if (!m || l.trim().startsWith('#')) return;
    if (process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch (e) { /* no .env file: use real env vars */ }

const KEY = process.env.FAST2SMS_API_KEY || '';
const PORT = +process.env.PORT || 8787;
const ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
const F2S_URL = process.env.F2S_URL || 'https://www.fast2sms.com/dev/bulkV2';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const COOL_MS = 60 * 1000;            /* min gap between SMS to one number */
const TTL_MS = 5 * 60 * 1000;         /* OTP validity */
const MAX_TRIES = 5;                  /* wrong guesses per OTP */
const PER_NUMBER_HOUR = 5, PER_IP_HOUR = 10;
const DAILY_CAP = +process.env.DAILY_SMS_CAP || 500;   /* hard ceiling on SMS credits per day */
const SECRET = process.env.OTP_SECRET || crypto.randomBytes(32).toString('hex');
if (!KEY) console.warn('WARNING: FAST2SMS_API_KEY is not set - OTP sending will fail.');

const otps = new Map();               /* mobile -> {h,exp,tries,sentAt} */
const hits = new Map();               /* "n:"+mobile / "i:"+ip -> [timestamps] */
let day = new Date().toDateString(), dayCount = 0;

const hash = (m, o) => crypto.createHmac('sha256', SECRET).update(m + ':' + o).digest('hex');
const ipOf = req => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
function bump(k, limit, win) {
  const now = Date.now(), a = (hits.get(k) || []).filter(t => now - t < win);
  if (a.length >= limit) { hits.set(k, a); return false; }
  a.push(now); hits.set(k, a); return true;
}
function cors(req, res) {
  const o = req.headers.origin;
  if (ORIGINS.includes('*')) res.setHeader('Access-Control-Allow-Origin', '*');
  else if (o && ORIGINS.includes(o)) { res.setHeader('Access-Control-Allow-Origin', o); res.setHeader('Vary', 'Origin'); }
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
}
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const body = req => new Promise(r => { let s = ''; req.on('data', c => { s += c; if (s.length > 2048) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(s || '{}')); } catch (e) { r({}); } }); req.on('error', () => r({})); });

async function sendSms(mobile, code) {
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 10000);
  try {
    const r = await fetch(F2S_URL, {
      method: 'POST', signal: ctl.signal,
      headers: { authorization: KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ route: 'otp', variables_values: code, numbers: mobile, flash: 0 })
    });
    const j = await r.json().catch(() => ({}));
    if (!(j && j.return === true)) console.warn('Fast2SMS rejected:', r.status, JSON.stringify(j).slice(0, 200));
    return !!(j && j.return === true);
  } catch (e) { console.warn('Fast2SMS error:', e.message); return false; }
  finally { clearTimeout(t); }
}

http.createServer(async (req, res) => {
  cors(req, res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const url = (req.url || '').split('?')[0];
  if (req.method === 'GET' && url === '/health') return send(res, 200, { ok: true });
  if (req.method !== 'POST') return send(res, 404, { ok: false, msg: 'Not found.' });

  if (url === '/api/otp/send') {
    const { mobile } = await body(req), m = String(mobile || '');
    if (!/^[6-9]\d{9}$/.test(m)) return send(res, 400, { ok: false, msg: 'Enter a valid 10-digit mobile number.' });
    if (!KEY) return send(res, 503, { ok: false, msg: 'OTP service is not configured.' });
    const now = Date.now(), cur = otps.get(m);
    if (cur && now - cur.sentAt < COOL_MS) return send(res, 429, { ok: false, msg: 'Please wait ' + Math.ceil((COOL_MS - (now - cur.sentAt)) / 1000) + ' seconds before requesting a new OTP.' });
    if (new Date().toDateString() !== day) { day = new Date().toDateString(); dayCount = 0; }
    if (dayCount >= DAILY_CAP) return send(res, 503, { ok: false, msg: 'OTP service is busy. Please try again later.' });
    if (!bump('i:' + ipOf(req), PER_IP_HOUR, 3600e3)) return send(res, 429, { ok: false, msg: 'Too many OTP requests. Please try again later.' });
    if (!bump('n:' + m, PER_NUMBER_HOUR, 3600e3)) return send(res, 429, { ok: false, msg: 'Too many OTP requests for this number. Try again in an hour.' });
    const code = String(crypto.randomInt(100000, 1000000));
    otps.set(m, { h: hash(m, code), exp: now + TTL_MS, tries: 0, sentAt: now });   /* set first: blocks parallel double-sends */
    if (!await sendSms(m, code)) { otps.delete(m); return send(res, 502, { ok: false, msg: 'Could not send the SMS right now. Please try again.' }); }
    dayCount++;
    return send(res, 200, { ok: true, msg: 'OTP sent.' });
  }

  if (url === '/api/otp/verify') {
    const { mobile, otp } = await body(req), m = String(mobile || ''), o = String(otp || '');
    const cur = otps.get(m);
    if (!/^\d{6}$/.test(o)) return send(res, 400, { ok: false, msg: 'Enter the 6-digit OTP.' });
    if (!cur) return send(res, 400, { ok: false, msg: 'Request an OTP first.' });
    if (Date.now() > cur.exp) { otps.delete(m); return send(res, 400, { ok: false, msg: 'OTP expired. Request a new one.' }); }
    if (cur.tries >= MAX_TRIES) { otps.delete(m); return send(res, 429, { ok: false, msg: 'Too many wrong attempts. Request a new OTP.' }); }
    cur.tries++;
    const a = Buffer.from(hash(m, o)), b = Buffer.from(cur.h);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) { otps.delete(m); return send(res, 200, { ok: true, msg: 'Verified.' }); }
    return send(res, 400, { ok: false, msg: 'Incorrect OTP.' });
  }
  send(res, 404, { ok: false, msg: 'Not found.' });
}).listen(PORT, () => console.log('OTP server on :' + PORT));

setInterval(() => { const n = Date.now(); otps.forEach((v, k) => { if (n > v.exp + 60000) otps.delete(k); }); hits.forEach((a, k) => { const f = a.filter(t => n - t < 3600e3); f.length ? hits.set(k, f) : hits.delete(k); }); }, 60000).unref();
