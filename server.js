'use strict';
const crypto = require('crypto');
const http = require('http');
const fs   = require('fs');
const path = require('path');
const os   = require('os');

// Request telemetry (in-memory, resets on restart)
let _reqTotal = 0;
const _reqLog = []; // {ts, path, ms, ip}

// ── IP RATE LIMITER ───────────────────────────────────────
// risk levels: low | medium | high
// bypass: true = skip all rate limiting
// forcedRisk: 'low'|'medium'|'high'|null = admin override
const _ipTracker = new Map();
const IP_RESET_MS = 2 * 60 * 60 * 1000; // 2 hours
let _ipKVLoaded = false;

async function ensureIPKVLoaded() {
  if (_ipKVLoaded) return;
  _ipKVLoaded = true;
  try {
    const stored = await kvRead('ip_tracker', {});
    for (const [ip, rec] of Object.entries(stored)) {
      if (!_ipTracker.has(ip)) _ipTracker.set(ip, { ...rec, reloads: [] });
    }
  } catch(e) {}
}

function persistIPTracker() {
  const obj = {};
  const now = Date.now();
  _ipTracker.forEach((rec, ip) => {
    // Drop entries inactive for 2h+ with no active cooldown, bypass, or forcedRisk
    if (!rec.bypass && !rec.forcedRisk && rec.cooldownUntil < now && (now - rec.lastSeen) > IP_RESET_MS) return;
    obj[ip] = { risk: rec.risk, violations: rec.violations, cooldownUntil: rec.cooldownUntil, firstSeen: rec.firstSeen, lastSeen: rec.lastSeen, bypass: rec.bypass || false, forcedRisk: rec.forcedRisk || null };
  });
  kvWrite('ip_tracker', obj).catch(e => console.error('[IP persist]', e.message));
}

function getIPRecord(ip) {
  const now = Date.now();
  if (!_ipTracker.has(ip)) {
    _ipTracker.set(ip, { risk:'low', reloads:[], cooldownUntil:0, violations:0, firstSeen:now, lastSeen:now, bypass:false, forcedRisk:null });
  }
  const rec = _ipTracker.get(ip);
  // Auto-reset if 2h inactive, no cooldown, bypass, or forced risk
  if (!rec.bypass && !rec.forcedRisk && rec.cooldownUntil < now && (now - rec.lastSeen) > IP_RESET_MS) {
    rec.risk = 'low'; rec.reloads = []; rec.violations = 0;
  }
  return rec;
}

async function checkAndRecordVisit(ip) {
  await ensureIPKVLoaded();
  const now = Date.now();
  const rec = getIPRecord(ip);
  rec.lastSeen = now;
  // Bypassed IPs skip all rate limiting
  if (rec.bypass) return { risk: 'bypass', cooldown: 0 };
  // Active cooldown
  if (rec.cooldownUntil > now) {
    return { risk: rec.forcedRisk || rec.risk, cooldown: Math.ceil((rec.cooldownUntil - now) / 1000) };
  }
  rec.reloads.push(now);
  rec.reloads = rec.reloads.filter(t => now - t < 120000);
  // High: >20 reloads in 60s → 5 min cooldown
  if (rec.reloads.filter(t => now - t < 60000).length > 20) {
    rec.violations++; rec.risk = 'high';
    rec.cooldownUntil = now + 300000;
    persistIPTracker();
    return { risk: rec.forcedRisk || 'high', cooldown: 300 };
  }
  // Medium: >10 reloads in 30s → 1 min cooldown
  if (rec.reloads.filter(t => now - t < 30000).length > 10) {
    rec.violations++; rec.risk = 'medium';
    rec.cooldownUntil = now + 60000;
    persistIPTracker();
    return { risk: rec.forcedRisk || 'medium', cooldown: 60 };
  }
  return { risk: rec.forcedRisk || rec.risk, cooldown: 0 };
}

const PORT = process.env.PORT || 4000;
const DIR  = __dirname;
const DATA_DIR = os.tmpdir(); // writable on Vercel Lambda; use KV for true persistence

// In-memory data cache — survives within a Lambda invocation, falls back to KV/file on cold start
const _cache = {};

// Parse .env file
(function loadEnv() {
  try {
    const raw = fs.readFileSync(path.join(DIR, '.env'), 'utf8');
    raw.split(/\r?\n/).forEach(line => {
      const m = line.match(/^([^=\s]+)\s*=\s*(.*)$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
    });
  } catch(e) {}
})();

// Stripe setup
let stripe;
const STRIPE_SECRET = process.env.STRIPE_SECRET || '';
const STRIPE_PUB    = process.env.STRIPE_PUB    || '';
const GOOGLE_CLIENT = process.env.GOOGLE_CLIENT_ID || '';
const PRIMARY_ADMIN = 'precisionworkz9@gmail.com';
// CO_OWNER_EMAIL is set via Vercel env var — never hardcoded here
const CO_OWNER_EMAIL = (process.env.CO_OWNER_EMAIL || '').toLowerCase().trim();

// reCAPTCHA Enterprise server-side assessment
const RECAPTCHA_API_KEY    = process.env.RECAPTCHA_API_KEY    || '';
const RECAPTCHA_PROJECT_ID = process.env.RECAPTCHA_PROJECT_ID || '';
const RECAPTCHA_SITE_KEY   = '6Lft7NYsAAAAAEianu0W1CoaV42ABKro6ignxv3h';

async function verifyRecaptchaToken(token) {
  if (!RECAPTCHA_API_KEY || !RECAPTCHA_PROJECT_ID || !token) return true; // fail open if not configured
  try {
    const r = await fetch(
      'https://recaptchaenterprise.googleapis.com/v1/projects/' + RECAPTCHA_PROJECT_ID + '/assessments?key=' + RECAPTCHA_API_KEY,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event: { token, siteKey: RECAPTCHA_SITE_KEY, expectedAction: 'visit' } }),
      }
    );
    if (!r.ok) { console.warn('[reCAPTCHA] assess HTTP', r.status); return true; }
    const d = await r.json();
    const valid = !d.tokenProperties || d.tokenProperties.valid !== false;
    const score = (d.riskAnalysis && d.riskAnalysis.score != null) ? d.riskAnalysis.score : 0.5;
    console.log('[reCAPTCHA] valid:', valid, 'score:', score);
    return valid && score >= 0.5;
  } catch(e) {
    console.warn('[reCAPTCHA] assess error:', e.message);
    return true; // fail open on any error
  }
}

try { stripe = require('stripe')(STRIPE_SECRET); }
catch(e) { console.warn('stripe module not found — run: npm install stripe'); }

// Nodemailer setup
let nodemailer;
try { nodemailer = require('nodemailer'); } catch(e) { console.warn('nodemailer not found — npm install nodemailer'); }
const GMAIL_USER = process.env.GMAIL_USER || '';
const GMAIL_PASS = process.env.GMAIL_PASS || '';
const SITE_URL   = process.env.SITE_URL   || 'http://localhost:4000';

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.xml': 'application/xml',
  '.txt': 'text/plain',
};

const PRICES = {
  'basic-monthly': null,
  'basic-annual':  null,
  'gold-monthly':  null,
  'gold-annual':   null,
};

const OWNER_EMAIL = 'precizionworkz@gmail.com';

// ── PERSISTENT STORAGE (Vercel KV with local file fallback) ─
// Checks all env var naming variants Vercel creates depending on the storage prefix chosen
function _pickKVURL() {
  const candidates = [
    process.env.KV_REST_API_URL,
    process.env.UPSTASH_REDIS_REST_URL,
    process.env.STORAGE_REST_API_URL,
    process.env.STORAGE_URL,
  ].filter(Boolean);
  // Must be an HTTPS REST endpoint — skip redis:// connection strings
  return candidates.find(u => u.startsWith('https://')) || '';
}
function _pickKVToken() {
  return process.env.KV_REST_API_TOKEN
    || process.env.UPSTASH_REDIS_REST_TOKEN
    || process.env.STORAGE_REST_API_TOKEN
    || process.env.STORAGE_TOKEN
    || '';
}
const KV_URL   = _pickKVURL();
const KV_TOKEN = _pickKVToken();

async function kvRead(key, fallback) {
  // Serve from in-memory cache if available
  if (_cache[key] !== undefined) return _cache[key];
  if (KV_URL && KV_TOKEN) {
    try {
      const r = await fetch(KV_URL + '/get/' + encodeURIComponent(key), {
        headers: { Authorization: 'Bearer ' + KV_TOKEN },
      });
      if (!r.ok) throw new Error('KV HTTP ' + r.status);
      const d = await r.json();
      let val = fallback;
      if (d.result !== null && d.result !== undefined) {
        if (typeof d.result === 'string') {
          // Upstash returns stored strings already JSON-encoded in the result field.
          // Our kvWrite double-encodes, so one parse gets us back to the object.
          try { val = JSON.parse(d.result); } catch(e) { val = d.result; }
          // If still a string (triple-encoded edge case), parse once more
          if (typeof val === 'string') { try { val = JSON.parse(val); } catch(e) {} }
        } else {
          val = d.result; // Already a JS object/array/number
        }
      }
      _cache[key] = val;
      return val;
    } catch(e) { console.error('[KV read]', key, e.message); }
  }
  // File fallback — DATA_DIR is writable on Lambda (tmpdir); DIR is read-only
  try {
    const val = JSON.parse(fs.readFileSync(path.join(DATA_DIR, key + '.json'), 'utf8'));
    _cache[key] = val;
    return val;
  } catch(e) {}
  // Dev fallback: try project root too
  try { return JSON.parse(fs.readFileSync(path.join(DIR, key + '.json'), 'utf8')); }
  catch(e) { return fallback; }
}

async function kvWrite(key, value) {
  _cache[key] = value; // Always update in-memory cache immediately
  if (KV_URL && KV_TOKEN) {
    const r = await fetch(KV_URL + '/set/' + encodeURIComponent(key), {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + KV_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify(JSON.stringify(value)),
    });
    if (!r.ok) {
      const msg = 'KV write failed: HTTP ' + r.status;
      console.error('[KV write]', key, msg);
      throw new Error(msg);
    }
    // Upstash can return HTTP 200 with {"error":"..."} for Redis-level errors
    const body = await r.json().catch(() => ({}));
    if (body && body.error) {
      console.error('[KV write]', key, 'Upstash error:', body.error);
      throw new Error('KV Redis error: ' + body.error);
    }
    return;
  }
  // File fallback — try DATA_DIR (tmpdir, writable on Lambda) then project root (dev)
  try { fs.writeFileSync(path.join(DATA_DIR, key + '.json'), JSON.stringify(value, null, 2)); return; }
  catch(e) { console.warn('[KV fallback tmpdir write] failed —', e.code || e.message); }
  try { fs.writeFileSync(path.join(DIR, key + '.json'), JSON.stringify(value, null, 2)); }
  catch(e) {
    console.error('[KV fallback write] all methods failed for', key, '—', e.code || e.message);
    throw new Error('Persistence unavailable — configure KV_REST_API_URL and KV_REST_API_TOKEN in Vercel settings');
  }
}

function _parseKV(raw, fallback) {
  // If KV returned a string (double-encoded), parse it again
  if (typeof raw === 'string') { try { raw = JSON.parse(raw); } catch(e) { return fallback; } }
  return (raw === null || raw === undefined) ? fallback : raw;
}

async function readAdmins() {
  const raw = _parseKV(await kvRead('admins', [PRIMARY_ADMIN]), [PRIMARY_ADMIN]);
  return Array.isArray(raw) ? raw : [PRIMARY_ADMIN];
}

async function readRequests() {
  const raw = _parseKV(await kvRead('requests', []), []);
  return Array.isArray(raw) ? raw : [];
}

async function readReports() {
  const raw = _parseKV(await kvRead('reports', []), []);
  return Array.isArray(raw) ? raw : [];
}

const _emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
async function readClients() {
  let raw = _parseKV(await kvRead('clients', {}), {});
  if (Array.isArray(raw)) {
    const obj = {};
    raw.forEach(c => { if (c && c.email && _emailRe.test(c.email)) obj[c.email.toLowerCase()] = c; });
    raw = obj;
  }
  if (!raw || typeof raw !== 'object') raw = {};
  for (const k of Object.keys(raw)) { if (!_emailRe.test(k)) delete raw[k]; }
  return raw;
}
async function readUsers() {
  const raw = _parseKV(await kvRead('users', {}), {});
  return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
}
const writeAdmins   = (v) => kvWrite('admins',   v);
const writeClients  = (v) => kvWrite('clients',  v);
const writeRequests = (v) => kvWrite('requests', v);
const writeReports  = (v) => kvWrite('reports',  v);
const writeUsers    = (v) => kvWrite('users',    v);

async function isAdmin(email) {
  if (!email) return false;
  const e = email.toLowerCase().trim();
  if (e === PRIMARY_ADMIN.toLowerCase()) return true;
  if (CO_OWNER_EMAIL && e === CO_OWNER_EMAIL) return true;
  const admins = await readAdmins();
  return admins.map(a => a.toLowerCase()).includes(e);
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err);
      else resolve(salt + ':' + key.toString('hex'));
    });
  });
}
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const [salt, key] = stored.split(':');
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(crypto.timingSafeEqual(Buffer.from(key, 'hex'), derivedKey));
    });
  });
}

function sendVerificationEmail(toEmail, token) {
  if (!nodemailer || !GMAIL_USER || !GMAIL_PASS) {
    console.warn('[Email] GMAIL_USER/GMAIL_PASS not set — cannot send verification email');
    return Promise.resolve();
  }
  const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: GMAIL_USER, pass: GMAIL_PASS } });
  const link = SITE_URL + '/verify-email?token=' + token;
  return transporter.sendMail({
    from: '"Precision Workz" <' + GMAIL_USER + '>',
    to: toEmail,
    subject: 'Verify your Precision Workz account',
    text: 'Verify your Precision Workz email\n\nClick the link below to verify your email and set your password. This link expires in 24 hours.\n\n' + link + '\n\nIf you did not request this, ignore this email.',
    html: [
      '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#ffffff;border-radius:12px;border:1px solid #e2e8f0">',
      '<h2 style="font-size:1.4rem;font-weight:800;color:#0f172a;margin:0 0 12px">Verify your email</h2>',
      '<p style="color:#475569;line-height:1.7;margin:0 0 28px;font-size:.92rem">Click the button below to verify your email and set your password. This link expires in 24 hours.</p>',
      '<table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:24px">',
      '<tr><td style="background:#7c3aed;border-radius:10px;padding:0">',
      '<a href="' + link + '" style="display:inline-block;padding:14px 28px;color:#ffffff;font-weight:700;font-size:.95rem;text-decoration:none;border-radius:10px;font-family:Arial,sans-serif">Verify Email &amp; Set Password &#8594;</a>',
      '</td></tr></table>',
      '<p style="color:#64748b;font-size:.8rem;margin:0 0 8px">Button not working? Copy and paste this link into your browser:</p>',
      '<p style="margin:0"><a href="' + link + '" style="color:#7c3aed;font-size:.78rem;word-break:break-all">' + link + '</a></p>',
      '<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">',
      '<p style="color:#94a3b8;font-size:.75rem;margin:0">If you did not request this, ignore this email.</p>',
      '</div>'
    ].join('')
  });
}

async function sendEmail(to, subject, html) {
  if (!nodemailer || !GMAIL_USER || !GMAIL_PASS) return;
  const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: GMAIL_USER, pass: GMAIL_PASS } });
  const recipients = Array.isArray(to) ? to.filter(Boolean).join(',') : to;
  await transporter.sendMail({ from: '"Precision Workz" <' + GMAIL_USER + '>', to: recipients, subject, html });
}

function serveVerifyPage(res, token, user) {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Set Password — Precision Workz</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Inter,system-ui,sans-serif;background:#04040d;color:#f1f5f9;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}.box{background:linear-gradient(145deg,#0d0d26,#121232);border:1px solid rgba(124,58,237,.35);border-radius:24px;padding:40px 36px;max-width:420px;width:100%}h2{font-size:1.6rem;font-weight:800;margin-bottom:8px}p{color:#94a3b8;font-size:.88rem;line-height:1.7;margin-bottom:24px}label{display:block;font-size:.78rem;font-weight:600;color:#94a3b8;margin-bottom:6px}input{width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:10px;color:#f1f5f9;padding:12px 14px;font-size:.9rem;outline:none;margin-bottom:16px;font-family:inherit}input:focus{border-color:rgba(124,58,237,.5)}button{width:100%;padding:14px;border-radius:12px;background:linear-gradient(135deg,#7c3aed,#06b6d4);color:#fff;font-weight:700;font-size:.95rem;border:none;cursor:pointer;font-family:inherit}.msg{margin-top:12px;font-size:.85rem;text-align:center}.ok{color:#4ade80}.err{color:#f87171}</style></head><body><div class="box"><h2>Set Your Password</h2><p>Creating account for <strong style="color:#22d3ee">' + user.email + '</strong></p><label>Password</label><input type="password" id="pw1" placeholder="At least 8 characters"><label>Confirm Password</label><input type="password" id="pw2" placeholder="Repeat password"><button onclick="go()">Create Account →</button><div class="msg" id="m"></div></div><script>async function go(){var p1=document.getElementById("pw1").value,p2=document.getElementById("pw2").value,m=document.getElementById("m");if(p1.length<8){m.className="msg err";m.textContent="Password must be at least 8 characters.";return}if(p1!==p2){m.className="msg err";m.textContent="Passwords do not match.";return}m.className="msg";m.textContent="Setting up...";var r=await fetch("/api/set-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:"' + token + '",password:p1})});var d=await r.json();if(d.ok){m.className="msg ok";m.textContent="Account created! Redirecting...";setTimeout(function(){window.location="/"},1800);}else{m.className="msg err";m.textContent=d.error||"Something went wrong.";}}</script></body></html>');
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch(e) { reject(e); } });
    req.on('error', reject);
  });
}

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

// ── API HANDLER ────────────────────────────────────────────
async function handleAPI(req, res, urlPath) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST,GET,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' });
    res.end(); return;
  }

  if (urlPath === '/api/pub-key') return json(res, 200, { key: STRIPE_PUB });
  if (urlPath === '/api/config')  return json(res, 200, { stripeKey: STRIPE_PUB, googleClientId: GOOGLE_CLIENT });

  if (urlPath === '/api/gate-check' && req.method === 'POST') {
    return json(res, 200, await checkAndRecordVisit(req.realIP));
  }

  if (urlPath === '/api/verify-captcha' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const passed = await verifyRecaptchaToken(body.token);
      return json(res, 200, { ok: passed });
    } catch(e) {
      return json(res, 200, { ok: true }); // fail open
    }
  }

  if (urlPath === '/api/report' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { category, description, replyEmail } = body;
      if (!category || !description || description.trim().length < 20) {
        return json(res, 400, { error: 'Category and a description of at least 20 characters are required.' });
      }
      const report = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        category, description: description.trim(),
        replyEmail: (replyEmail || '').trim() || null,
        ip: req.realIP, createdAt: new Date().toISOString(), read: false,
      };
      const reports = await readReports();
      reports.unshift(report);
      if (reports.length > 500) reports.length = 500;
      await writeReports(reports);
      console.log('[Report submitted]', report.category, 'from', report.replyEmail || report.ip);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/request' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email, name, type, details, sub, phone, service, promoCode } = body;
      if (!email || !details) return json(res, 400, { error: 'Missing fields' });
      const newReq = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        email, name: name || email, type: type || 'general', details,
        phone: phone || null, service: service || null, promoCode: promoCode || null,
        sub: sub || null, status: 'open', createdAt: new Date().toISOString(),
      };
      const reqs = await readRequests();
      reqs.unshift(newReq);
      await writeRequests(reqs);
      console.log('[Request submitted]', newReq.type, 'from', newReq.email);
      // Email notification to admins
      const typeLabel = newReq.type === 'quote' ? 'Quote Request' : newReq.type.replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      const adminRecipients = [GMAIL_USER, CO_OWNER_EMAIL].filter(Boolean);
      const adminHtml = '<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px 24px;background:#04040d;color:#f1f5f9;border-radius:16px">'
        + '<div style="font-size:.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#94a3b8;margin-bottom:16px">Precision Workz</div>'
        + '<h2 style="font-size:1.3rem;font-weight:800;margin:0 0 6px">New ' + typeLabel + '</h2>'
        + '<p style="color:#94a3b8;font-size:.85rem;margin:0 0 24px">' + new Date().toLocaleString() + '</p>'
        + '<table style="width:100%;border-collapse:collapse;margin-bottom:20px">'
        + '<tr><td style="padding:8px 0;color:#64748b;font-size:.82rem;width:100px">From</td><td style="padding:8px 0;font-weight:600">' + (newReq.name || '') + '</td></tr>'
        + '<tr><td style="padding:8px 0;color:#64748b;font-size:.82rem">Email</td><td style="padding:8px 0"><a href="mailto:' + newReq.email + '" style="color:#22d3ee">' + newReq.email + '</a></td></tr>'
        + (newReq.phone ? '<tr><td style="padding:8px 0;color:#64748b;font-size:.82rem">Phone</td><td style="padding:8px 0;color:#22d3ee">' + newReq.phone + '</td></tr>' : '')
        + (newReq.service ? '<tr><td style="padding:8px 0;color:#64748b;font-size:.82rem">Package</td><td style="padding:8px 0">' + newReq.service + '</td></tr>' : '')
        + (newReq.promoCode ? '<tr><td style="padding:8px 0;color:#64748b;font-size:.82rem">Promo</td><td style="padding:8px 0">' + newReq.promoCode + '</td></tr>' : '')
        + '</table>'
        + '<div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:16px;font-size:.88rem;color:#cbd5e1;white-space:pre-wrap;word-break:break-word">' + newReq.details + '</div>'
        + '<p style="margin-top:24px;font-size:.75rem;color:#475569">Reply directly to this email to respond to the client, or log in to the admin panel.</p>'
        + '</div>';
      sendEmail(adminRecipients, 'New ' + typeLabel + ' — ' + (newReq.name || newReq.email), adminHtml).catch(e => console.warn('[Email notify]', e.message));
      return json(res, 200, { ok: true, id: newReq.id });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/client-status') {
    const qs = new URLSearchParams(req.url.split('?')[1] || '');
    const email = (qs.get('email') || '').toLowerCase().trim();
    if (!email) return json(res, 400, { error: 'email required' });
    const clients = await readClients();
    return json(res, 200, { client: clients[email] || null });
  }

  if (urlPath === '/api/client-requests') {
    const qs = new URLSearchParams(req.url.split('?')[1] || '');
    const email = (qs.get('email') || '').toLowerCase().trim();
    if (!email) return json(res, 400, { error: 'email required' });
    const reqs = await readRequests();
    return json(res, 200, { requests: reqs.filter(r => r.email && r.email.toLowerCase() === email && !r.deletedByClient) });
  }

  if (urlPath === '/api/client-reply' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email, id, text } = body;
      if (!email || !id || !text) return json(res, 400, { error: 'Missing fields' });
      const reqs = await readRequests();
      const idx = reqs.findIndex(r => r.id === id && r.email && r.email.toLowerCase() === email.toLowerCase());
      if (idx < 0) return json(res, 404, { error: 'Request not found' });
      if (!reqs[idx].replies) reqs[idx].replies = [];
      reqs[idx].replies.push({ text, from: 'client', createdAt: new Date().toISOString() });
      await writeRequests(reqs);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/client-request' && req.method === 'DELETE') {
    try {
      const body = await parseBody(req);
      const { email, id } = body;
      if (!email || !id) return json(res, 400, { error: 'Missing fields' });
      const reqs = await readRequests();
      const idx = reqs.findIndex(r => r.id === id && r.email && r.email.toLowerCase() === email.toLowerCase());
      if (idx < 0) return json(res, 404, { error: 'Request not found' });
      reqs[idx].deletedByClient = true;
      await writeRequests(reqs);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  // Admin routes
  if (urlPath.startsWith('/api/admin/')) {
    let body = {};
    if (req.method === 'POST') {
      try { body = await parseBody(req); } catch(e) { return json(res, 400, { error: 'invalid json' }); }
    } else {
      const qs = new URLSearchParams(req.url.split('?')[1] || '');
      body = { adminEmail: qs.get('adminEmail') };
    }

    if (!await isAdmin(body.adminEmail)) return json(res, 403, { error: 'Forbidden' });

    if (urlPath === '/api/admin/data') {
      const [clients, admins] = await Promise.all([readClients(), readAdmins()]);
      // Build full admin list including permanent co-owner (never removable via UI)
      const allAdmins = [...new Set([PRIMARY_ADMIN, ...(CO_OWNER_EMAIL ? [CO_OWNER_EMAIL] : []), ...admins.filter(a => a.toLowerCase() !== PRIMARY_ADMIN.toLowerCase() && a.toLowerCase() !== CO_OWNER_EMAIL)])];
      return json(res, 200, { clients, admins: allAdmins, primaryAdmin: PRIMARY_ADMIN, coOwner: CO_OWNER_EMAIL || null });
    }

    if (urlPath === '/api/admin/requests') {
      return json(res, 200, { requests: await readRequests(), ownerEmail: OWNER_EMAIL });
    }

    if (urlPath === '/api/admin/reports') {
      return json(res, 200, { reports: await readReports() });
    }

    if (urlPath === '/api/admin/report-read' && req.method === 'POST') {
      try {
        const { id } = body;
        const reports = await readReports();
        const idx = reports.findIndex(r => r.id === id);
        if (idx >= 0) { reports[idx].read = true; await writeReports(reports); }
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/report-delete' && req.method === 'POST') {
      try {
        const { id } = body;
        const reports = (await readReports()).filter(r => r.id !== id);
        await writeReports(reports);
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/update-request' && req.method === 'POST') {
      try {
        const { id, status } = body;
        const reqs = await readRequests();
        const idx = reqs.findIndex(r => r.id === id);
        if (idx >= 0) { reqs[idx].status = status; reqs[idx].updatedAt = new Date().toISOString(); await writeRequests(reqs); }
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/delete-request' && req.method === 'POST') {
      try {
        const { id } = body;
        if (!id) return json(res, 400, { error: 'id required' });
        const reqs = (await readRequests()).filter(r => r.id !== id);
        await writeRequests(reqs);
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/reply-request' && req.method === 'POST') {
      try {
      const { id, replyText } = body;
      if (!id || !replyText) return json(res, 400, { error: 'Missing fields' });
      const reqs = await readRequests();
      const idx = reqs.findIndex(r => r.id === id);
      if (idx < 0) return json(res, 404, { error: 'Request not found' });
      if (!reqs[idx].replies) reqs[idx].replies = [];
      reqs[idx].replies.push({ text: replyText, from: 'admin', createdAt: new Date().toISOString() });
      await writeRequests(reqs);
      // Email client + notify co-owner
      const clientEmail = reqs[idx].email;
      const clientName = reqs[idx].name || clientEmail;
      const replyHtml = '<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px 24px;background:#04040d;color:#f1f5f9;border-radius:16px">'
        + '<div style="font-size:.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#94a3b8;margin-bottom:16px">Precision Workz</div>'
        + '<h2 style="font-size:1.3rem;font-weight:800;margin:0 0 8px">We replied to your request</h2>'
        + '<p style="color:#94a3b8;font-size:.85rem;margin:0 0 24px">Hi ' + clientName.split(' ')[0] + ', here\'s our response:</p>'
        + '<div style="background:rgba(255,255,255,.04);border:1px solid rgba(6,182,212,.2);border-radius:10px;padding:16px;font-size:.88rem;color:#cbd5e1;white-space:pre-wrap;word-break:break-word">' + replyText + '</div>'
        + '<p style="margin-top:24px;font-size:.82rem;color:#94a3b8">You can reply to this email or visit <a href="' + SITE_URL + '" style="color:#22d3ee">your dashboard</a> to view the full thread.</p>'
        + '<p style="margin-top:8px;font-size:.75rem;color:#475569">— Precision Workz · Tucson, AZ</p>'
        + '</div>';
      sendEmail(clientEmail, 'Reply from Precision Workz', replyHtml).catch(e => console.warn('[Email reply]', e.message));
      if (CO_OWNER_EMAIL) sendEmail(CO_OWNER_EMAIL, 'Reply sent to ' + clientEmail, replyHtml).catch(e => console.warn('[Email co-owner]', e.message));
      return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/clean-clients' && req.method === 'POST') {
      try {
        let clients = await readClients();
        // If stored as array, convert to object
        if (Array.isArray(clients)) {
          const obj = {};
          clients.forEach(c => { if (c && c.email) obj[c.email.toLowerCase()] = c; });
          clients = obj;
        }
        if (typeof clients !== 'object' || clients === null) clients = {};
        const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const before = Object.keys(clients).length;
        for (const k of Object.keys(clients)) {
          if (!emailRe.test(k)) delete clients[k];
        }
        const removed = before - Object.keys(clients).length;
        await writeClients(clients);
        return json(res, 200, { ok: true, removed, remaining: Object.keys(clients).length });
      } catch(e) {
        console.error('[clean-clients]', e.message);
        return json(res, 500, { error: e.message });
      }
    }

    if (urlPath === '/api/admin/raw-clients' && req.method === 'GET') {
      try {
        const raw = await readClients();
        const type = Array.isArray(raw) ? 'array' : typeof raw;
        const keys = type === 'object' && raw ? Object.keys(raw).slice(0, 20) : [];
        return json(res, 200, { type, keyCount: type === 'object' && raw ? Object.keys(raw).length : (Array.isArray(raw) ? raw.length : 0), sampleKeys: keys, cacheHas: !!_cache['clients'] });
      } catch(e) {
        return json(res, 500, { error: e.message });
      }
    }

    if (urlPath === '/api/admin/set-client' && req.method === 'POST') {
      try {
        const { targetEmail, name, sub, billing, packageType, notes } = body;
        if (!targetEmail) return json(res, 400, { error: 'targetEmail required' });
        const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRe.test(targetEmail.trim())) return json(res, 400, { error: 'Invalid email address' });
        let clients = await readClients();
        if (!clients || typeof clients !== 'object' || Array.isArray(clients)) clients = {};
        const key = targetEmail.toLowerCase().trim();
        const existing = clients[key] || {};
        clients[key] = {
          name:        name        || existing.name || '',
          email:       key,
          sub:         sub         !== undefined ? sub         : (existing.sub || null),
          billing:     billing     !== undefined ? billing     : (existing.billing || 'monthly'),
          packageType: packageType !== undefined ? packageType : (existing.packageType || null),
          notes:       notes       !== undefined ? notes       : (existing.notes || ''),
          updatedAt:   new Date().toISOString(),
          addedAt:     existing.addedAt || new Date().toISOString(),
        };
        if (existing.progress) clients[key].progress = existing.progress;
        await writeClients(clients);
        return json(res, 200, { ok: true, client: clients[key] });
      } catch(e) {
        console.error('[set-client]', e.message);
        return json(res, 500, { error: 'Save failed: ' + e.message });
      }
    }

    if (urlPath === '/api/admin/set-progress' && req.method === 'POST') {
      try {
        const { targetEmail, stages, currentTask } = body;
        if (!targetEmail) return json(res, 400, { error: 'targetEmail required' });
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(targetEmail.trim())) return json(res, 400, { error: 'Invalid email' });
        let clients = await readClients();
        if (!clients || typeof clients !== 'object' || Array.isArray(clients)) clients = {};
        const key = targetEmail.toLowerCase().trim();
        if (!clients[key]) clients[key] = { email: key, name: key, addedAt: new Date().toISOString() };
        clients[key].progress = {
          stages: (stages || []).map(s => ({ name: String(s.name||''), pct: Math.min(100, Math.max(0, parseInt(s.pct)||0)), status: ['pending','active','complete'].includes(s.status) ? s.status : 'pending' })),
          currentTask: (currentTask || '').trim() || null,
          lastUpdated: new Date().toISOString(),
        };
        await writeClients(clients);
        return json(res, 200, { ok: true });
      } catch(e) {
        console.error('[set-progress]', e.message);
        return json(res, 500, { error: 'Save failed: ' + e.message });
      }
    }

    if (urlPath === '/api/admin/remove-client' && req.method === 'POST') {
      try {
        const { targetEmail } = body;
        if (!targetEmail) return json(res, 400, { error: 'targetEmail required' });
        let clients = await readClients();
        if (!clients || typeof clients !== 'object' || Array.isArray(clients)) clients = {};
        delete clients[targetEmail.toLowerCase().trim()];
        await writeClients(clients);
        return json(res, 200, { ok: true });
      } catch(e) {
        console.error('[remove-client]', e.message);
        return json(res, 500, { error: 'Remove failed: ' + e.message });
      }
    }

    if (urlPath === '/api/admin/add-admin' && req.method === 'POST') {
      try {
        if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) {
          return json(res, 403, { error: 'Only the primary admin can add developers' });
        }
        const { newEmail } = body;
        if (!newEmail) return json(res, 400, { error: 'newEmail required' });
        const admins = await readAdmins();
        const key = newEmail.toLowerCase().trim();
        if (!admins.map(e => e.toLowerCase()).includes(key)) {
          admins.push(newEmail.trim());
          await writeAdmins(admins);
        }
        return json(res, 200, { ok: true, admins });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/remove-admin' && req.method === 'POST') {
      try {
        if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) {
          return json(res, 403, { error: 'Only the primary admin can remove developers' });
        }
        const { targetEmail } = body;
        const admins = (await readAdmins()).filter(e =>
          e.toLowerCase() !== (targetEmail||'').toLowerCase() && e.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()
        );
        admins.unshift(PRIMARY_ADMIN);
        await writeAdmins(admins);
        return json(res, 200, { ok: true, admins });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    // IP management endpoints
    if (urlPath === '/api/admin/ip-bypass' && req.method === 'POST') {
      const { targetIP, bypass } = body;
      if (!targetIP) return json(res, 400, { error: 'targetIP required' });
      await ensureIPKVLoaded();
      const rec = getIPRecord(targetIP);
      rec.bypass = !!bypass;
      persistIPTracker();
      return json(res, 200, { ok: true });
    }

    if (urlPath === '/api/admin/ip-force' && req.method === 'POST') {
      const { targetIP, risk } = body;
      if (!targetIP) return json(res, 400, { error: 'targetIP required' });
      await ensureIPKVLoaded();
      const rec = getIPRecord(targetIP);
      rec.forcedRisk = ['low','medium','high'].includes(risk) ? risk : null;
      if (rec.forcedRisk) rec.risk = rec.forcedRisk;
      persistIPTracker();
      return json(res, 200, { ok: true });
    }

    if (urlPath === '/api/admin/ip-reset' && req.method === 'POST') {
      const { targetIP } = body;
      if (!targetIP) return json(res, 400, { error: 'targetIP required' });
      await ensureIPKVLoaded();
      const rec = getIPRecord(targetIP);
      rec.risk = 'low'; rec.reloads = []; rec.violations = 0;
      rec.cooldownUntil = 0; rec.bypass = false; rec.forcedRisk = null;
      persistIPTracker();
      return json(res, 200, { ok: true });
    }

    if (urlPath === '/api/admin/kv-status') {
      const configured = !!(KV_URL && KV_TOKEN);
      let kvWorking = false;
      let kvError = null;
      if (configured) {
        try {
          const testKey = '_kv_health_check';
          const testVal = { ts: Date.now() };
          const wr = await fetch(KV_URL + '/set/' + encodeURIComponent(testKey), {
            method: 'POST',
            headers: { Authorization: 'Bearer ' + KV_TOKEN, 'Content-Type': 'application/json' },
            body: JSON.stringify(JSON.stringify(testVal)),
          });
          if (!wr.ok) throw new Error('write HTTP ' + wr.status);
          const rr = await fetch(KV_URL + '/get/' + encodeURIComponent(testKey), {
            headers: { Authorization: 'Bearer ' + KV_TOKEN },
          });
          if (!rr.ok) throw new Error('read HTTP ' + rr.status);
          kvWorking = true;
        } catch(e) { kvError = e.message; }
      }
      const clientCount = Object.keys(_cache['clients'] || {}).length;
      return json(res, 200, { configured, kvWorking, kvError, cacheKeys: Object.keys(_cache), clientsInCache: clientCount, KV_URL: KV_URL ? KV_URL.slice(0,40)+'…' : null });
    }

    if (urlPath === '/api/admin/metrics') {
      await ensureIPKVLoaded();
      const mem = process.memoryUsage();
      const now = Date.now();
      const ipList = [];
      _ipTracker.forEach(function(rec, ip) {
        ipList.push({
          ip, risk: rec.forcedRisk || rec.risk,
          reloads: rec.reloads.length, violations: rec.violations,
          cooldownLeft: rec.cooldownUntil > now ? Math.ceil((rec.cooldownUntil - now) / 1000) : 0,
          firstSeen: rec.firstSeen, lastSeen: rec.lastSeen,
          bypass: rec.bypass || false, forcedRisk: rec.forcedRisk || null,
        });
      });
      ipList.sort((a, b) => b.lastSeen - a.lastSeen);
      return json(res, 200, {
        uptime:           process.uptime(),
        memory:           { heapUsed: mem.heapUsed, heapTotal: mem.heapTotal, rss: mem.rss },
        osMemTotal:       os.totalmem(),
        osMemFree:        os.freemem(),
        loadAvg:          os.loadavg(),
        cpuCount:         os.cpus().length,
        nodeVersion:      process.version,
        reqTotal:         _reqTotal,
        reqLog:           _reqLog.slice(-30),
        behindCloudflare: !!req.headers['cf-connecting-ip'],
        ips:              ipList.slice(0, 100),
      });
    }

    return json(res, 404, { error: 'admin route not found' });
  }

  // Stripe checkout
  if (urlPath === '/api/create-checkout' && req.method === 'POST') {
    if (!stripe) return json(res, 503, { error: 'Stripe not configured' });
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { plan, email } = JSON.parse(body);
        const priceId = PRICES[plan];
        if (!priceId) return json(res, 402, { error: 'setup_required', message: 'Add price IDs to server.js PRICES object.' });
        const session = await stripe.checkout.sessions.create({
          mode: 'subscription', payment_method_types: ['card'],
          customer_email: email || undefined,
          line_items: [{ price: priceId, quantity: 1 }],
          success_url: SITE_URL + '/?checkout=success',
          cancel_url:  SITE_URL + '/?checkout=cancel',
        });
        return json(res, 200, { url: session.url });
      } catch(err) { return json(res, 500, { error: err.message }); }
    });
    return;
  }

  // Demo booking
  if (urlPath === '/api/demo' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { const data = JSON.parse(body); console.log('[Demo Request]', data); return json(res, 200, { ok: true }); }
      catch(e) { return json(res, 400, { error: 'invalid json' }); }
    });
    return;
  }

  if (urlPath === '/api/register' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email } = body;
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, 400, { error: 'Valid email required' });
      const key = email.toLowerCase().trim();
      const users = await readUsers();
      const token = crypto.randomBytes(32).toString('hex');
      users[key] = Object.assign(users[key] || {}, { email: key, verified: false, verifyToken: token, tokenExpiry: Date.now() + 86400000, createdAt: (users[key] || {}).createdAt || new Date().toISOString() });
      await writeUsers(users);
      await sendVerificationEmail(key, token);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/resend-verify' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email } = body;
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, 400, { error: 'Valid email required' });
      const key = email.toLowerCase().trim();
      const users = await readUsers();
      if (users[key] && users[key].verified) return json(res, 400, { error: 'Email already verified — please log in.' });
      const token = crypto.randomBytes(32).toString('hex');
      users[key] = Object.assign(users[key] || {}, { email: key, verified: false, verifyToken: token, tokenExpiry: Date.now() + 86400000 });
      await writeUsers(users);
      await sendVerificationEmail(key, token);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/set-password' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { token, password } = body;
      if (!token || !password || password.length < 8) return json(res, 400, { error: 'Invalid request' });
      const users = await readUsers();
      const key = Object.keys(users).find(k => users[k].verifyToken === token);
      if (!key) return json(res, 400, { error: 'Invalid or expired link' });
      if (Date.now() > users[key].tokenExpiry) return json(res, 400, { error: 'Link expired — please register again' });
      users[key].password = await hashPassword(password);
      users[key].verified = true;
      users[key].verifyToken = null;
      users[key].tokenExpiry = null;
      await writeUsers(users);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/login' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email, password } = body;
      if (!email || !password) return json(res, 400, { error: 'Email and password required' });
      const key = email.toLowerCase().trim();
      const users = await readUsers();
      const user = users[key];
      if (!user || !user.verified || !user.password) return json(res, 401, { error: 'Invalid email or password' });
      const ok = await verifyPassword(password, user.password);
      if (!ok) return json(res, 401, { error: 'Invalid email or password' });
      return json(res, 200, { ok: true, user: { email: key, name: key.split('@')[0] } });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  return json(res, 404, { error: 'not found' });
}

// ── REQUEST HANDLER ────────────────────────────────────────
async function handler(req, res) {
  const _t0 = Date.now();
  _reqTotal++;
  req.realIP = req.headers['cf-connecting-ip']
    || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress
    || 'unknown';
  const _origEnd = res.end.bind(res);
  res.end = function() {
    _reqLog.push({ ts: Date.now(), path: req.url.split('?')[0], ms: Date.now() - _t0, ip: req.realIP });
    if (_reqLog.length > 120) _reqLog.shift();
    res.end = _origEnd;
    return _origEnd.apply(res, arguments);
  };

  let urlPath = req.url.split('?')[0];
  if (urlPath.startsWith('/api/')) {
    handleAPI(req, res, urlPath).catch(e => {
      console.error('[API error]', urlPath, e.message);
      if (!res.headersSent) json(res, 500, { error: 'Internal server error' });
    });
    return;
  }

  if (urlPath === '/verify-email') {
    const qs = new URLSearchParams(req.url.split('?')[1] || '');
    const token = qs.get('token') || '';
    const users = await readUsers();
    const user = Object.values(users).find(u => u.verifyToken === token);
    if (!user || !token || Date.now() > (user.tokenExpiry || 0)) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Precision Workz</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Arial,sans-serif;background:#04040d;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}.box{background:#0d0d26;border:1px solid rgba(124,58,237,.3);border-radius:16px;padding:36px;max-width:400px;width:100%;text-align:center}h2{font-size:1.3rem;margin-bottom:10px;color:#f1f5f9}p{color:#94a3b8;font-size:.88rem;line-height:1.6;margin-bottom:24px}label{display:block;font-size:.78rem;color:#94a3b8;text-align:left;margin-bottom:6px;font-weight:600}input{width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#f1f5f9;padding:11px 14px;font-size:.9rem;outline:none;margin-bottom:14px;font-family:Arial,sans-serif}button{width:100%;padding:13px;border-radius:8px;background:#7c3aed;color:#fff;font-weight:700;font-size:.9rem;border:none;cursor:pointer;font-family:Arial,sans-serif}.msg{margin-top:12px;font-size:.83rem;min-height:18px}.ok{color:#4ade80}.err{color:#f87171}.back{display:block;margin-top:18px;color:#22d3ee;font-size:.83rem;text-decoration:none}</style></head><body><div class="box"><h2>Link expired or invalid</h2><p>This verification link has expired or already been used. Enter your email below to get a fresh one.</p><label>Your Email Address</label><input type="email" id="em" placeholder="you@example.com"><button onclick="resend()">Resend Verification Email</button><div class="msg" id="msg"></div><a class="back" href="/">← Back to site</a></div><script>async function resend(){var e=document.getElementById("em").value.trim(),m=document.getElementById("msg");if(!e){m.className="msg err";m.textContent="Enter your email address.";return}m.className="msg";m.textContent="Sending...";try{var r=await fetch("/api/resend-verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:e})});var d=await r.json();if(d.ok){m.className="msg ok";m.textContent="✓ New link sent — check your inbox!";}else{m.className="msg err";m.textContent=d.error||"Something went wrong.";}}catch(x){m.className="msg err";m.textContent="Network error — try again.";}}</script></body></html>');
      return;
    }
    serveVerifyPage(res, token, user);
    return;
  }

  if (urlPath === '/sitemap.xml') {
    res.writeHead(200, { 'Content-Type': 'application/xml' });
    res.end(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://precisionworkz.net/</loc>
    <lastmod>2026-05-03</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`);
    return;
  }

  if (urlPath === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`User-agent: *\nAllow: /\n\nUser-agent: GPTBot\nAllow: /\n\nUser-agent: OAI-SearchBot\nAllow: /\n\nUser-agent: PerplexityBot\nAllow: /\n\nUser-agent: ClaudeBot\nAllow: /\n\nUser-agent: CCBot\nDisallow: /\n\nSitemap: https://precisionworkz.net/sitemap.xml`);
    return;
  }

  if (urlPath === '/' || urlPath === '') urlPath = '/index.html';
  const filePath = path.join(DIR, urlPath);
  const mime = MIME[path.extname(filePath)] || 'text/plain';
  fs.readFile(filePath, function(err, data) {
    if (err) {
      fs.readFile(path.join(DIR, 'index.html'), function(e2, d2) {
        if (e2) { res.writeHead(404); res.end('Not found'); return; }
        res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(d2);
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': mime }); res.end(data);
  });
}

// Run as standalone server locally; export handler for Vercel
if (require.main === module) {
  http.createServer(handler).listen(PORT, function() {
    console.log('Precision Workz running on http://localhost:' + PORT);
  });
}

module.exports = handler;
