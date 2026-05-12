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
const SITE_URL   = process.env.SITE_URL   || 'https://precisionworkz.net';

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

// ── PROFANITY FILTER ──────────────────────────────────────
const _PW_WORDS = ['nigger','nigga','faggot','kike','chink','spic','wetback','coon','beaner','gook','cunt','twat','motherfucker','fuck','shit','bitch','asshole','retard','whore','slut','dickhead','prick','bastard'];
const _PW_PATTERNS = _PW_WORDS.map(w => new RegExp(w.split('').map(c => c + '+').join('[^a-z]*'), 'i'));
function containsProfanity(text) {
  if (!text) return false;
  const lo = text.toLowerCase()
    .replace(/4/g,'a').replace(/@/g,'a').replace(/3/g,'e')
    .replace(/1/g,'i').replace(/!/g,'i').replace(/0/g,'o')
    .replace(/\$/g,'s').replace(/5/g,'s').replace(/7/g,'t');
  return _PW_PATTERNS.some(re => re.test(lo));
}

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
async function readCoMessages() {
  const raw = _parseKV(await kvRead('co-messages', []), []);
  return Array.isArray(raw) ? raw : [];
}
const writeCoMessages = (v) => kvWrite('co-messages', v);
async function readAdminLevels() {
  const raw = _parseKV(await kvRead('admin-levels', {}), {});
  return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
}
const writeAdminLevels = (v) => kvWrite('admin-levels', v);
async function readAdminNames() {
  const raw = _parseKV(await kvRead('admin-names', {}), {});
  return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
}
const writeAdminNames  = (v) => kvWrite('admin-names', v);
async function readSiteStatus() {
  const raw = _parseKV(await kvRead('site-status', {}), {});
  return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
}
const writeSiteStatus = (v) => kvWrite('site-status', v);
async function readProjects() {
  const raw = _parseKV(await kvRead('projects', {}), {});
  return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
}
const writeProjects = (v) => kvWrite('projects', v);
async function readAnalytics() {
  const raw = _parseKV(await kvRead('analytics', {}), {});
  return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
}
const writeAnalytics = (v) => kvWrite('analytics', v);
async function getAdminLevel(email) {
  if (!email) return null;
  const e = email.toLowerCase().trim();
  if (e === PRIMARY_ADMIN.toLowerCase()) return 'primary';
  if (CO_OWNER_EMAIL && e === CO_OWNER_EMAIL.toLowerCase()) return 'co-owner';
  const lvls = await readAdminLevels();
  return lvls[e] || 'low';
}
const _LVL = { low: 0, medium: 1, max: 2, 'co-owner': 1, primary: 99 };
function levelAtLeast(userLevel, minLevel) {
  return (_LVL[userLevel] || 0) >= (_LVL[minLevel] || 0);
}
function isCoOwnerOrPrimary(email) {
  const e = (email || '').toLowerCase().trim();
  return e === PRIMARY_ADMIN.toLowerCase() || !!(CO_OWNER_EMAIL && e === CO_OWNER_EMAIL.toLowerCase());
}

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

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function emailHeader(title, subtitle) {
  return '<div style="font-family:Arial,sans-serif;max-width:580px;margin:0 auto;background:#09090f;border-radius:20px;overflow:hidden;border:1px solid #1e293b">'
    + '<div style="background:linear-gradient(135deg,#7c3aed 0%,#0891b2 100%);padding:28px 32px">'
    + '<div style="font-size:10px;font-weight:800;letter-spacing:4px;text-transform:uppercase;color:rgba(255,255,255,.55);margin-bottom:10px">PRECISION WORKZ</div>'
    + '<div style="font-size:22px;font-weight:800;color:#ffffff;line-height:1.2">' + title + '</div>'
    + (subtitle ? '<div style="font-size:12px;color:rgba(255,255,255,.55);margin-top:5px">' + subtitle + '</div>' : '')
    + '</div>';
}
function emailFooter() {
  return '<div style="padding:14px 32px;border-top:1px solid #1e293b">'
    + '<p style="color:#334155;font-size:11px;margin:0">Precision Workz &middot; Tucson, AZ &middot; precisionworkz.net</p>'
    + '</div></div>';
}
function emailBtn(href, label) {
  return '<table role="presentation" cellpadding="0" cellspacing="0"><tr>'
    + '<td style="border-radius:12px;background:linear-gradient(135deg,#7c3aed,#0891b2)">'
    + '<a href="' + href + '" style="display:inline-block;padding:14px 28px;color:#ffffff;font-weight:700;font-size:14px;text-decoration:none;font-family:Arial,sans-serif">' + label + '</a>'
    + '</td></tr></table>';
}

function sendVerificationEmail(toEmail, token) {
  if (!nodemailer || !GMAIL_USER || !GMAIL_PASS) {
    console.warn('[Email] GMAIL_USER/GMAIL_PASS not set — cannot send verification email');
    return Promise.resolve();
  }
  const transporter = nodemailer.createTransport({ host: 'smtp.gmail.com', port: 587, secure: false, auth: { user: GMAIL_USER, pass: GMAIL_PASS } });
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

function sendWelcomeEmail(toEmail, name) {
  if (!nodemailer || !GMAIL_USER || !GMAIL_PASS) return Promise.resolve();
  const firstName = (name || toEmail.split('@')[0]).split(' ')[0];
  const transporter = nodemailer.createTransport({ host: 'smtp.gmail.com', port: 587, secure: false, auth: { user: GMAIL_USER, pass: GMAIL_PASS } });
  return transporter.sendMail({
    from: '"Precision Workz" <' + GMAIL_USER + '>',
    to: toEmail,
    subject: 'Welcome to Precision Workz',
    text: 'Hey ' + firstName + ',\n\nThanks for joining Precision Workz. We build custom websites, security infrastructure, and full-stack systems for businesses in Tucson, AZ and beyond — no templates, no shortcuts.\n\nIf you have any questions or want to kick off a project, just reply to this email or visit us at ' + SITE_URL + '\n\n— The Precision Workz Team',
    html: [
      '<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #e2e8f0">',
      '<div style="background:#04040d;padding:28px 32px;text-align:center">',
      '<span style="font-size:1.25rem;font-weight:900;letter-spacing:1px;color:#ffffff">PRECISION <span style="color:#f59e0b">WORKZ</span></span>',
      '</div>',
      '<div style="padding:36px 32px">',
      '<h2 style="margin:0 0 10px;font-size:1.4rem;font-weight:800;color:#0f172a">Hey ' + firstName + ', welcome aboard.</h2>',
      '<p style="color:#475569;line-height:1.75;margin:0 0 20px;font-size:.93rem">Thanks for joining Precision Workz. We build custom websites, security infrastructure, and full-stack systems — no templates, no shortcuts, no fluff. Just clean, fast, and secure work built to last.</p>',
      '<p style="color:#475569;line-height:1.75;margin:0 0 28px;font-size:.93rem">Here\'s a quick look at what we do:</p>',
      '<table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:28px;width:100%">',
      '<tr><td style="padding:10px 0;border-bottom:1px solid #f1f5f9;font-size:.88rem;color:#334155"><strong style="color:#7c3aed">&#9656;</strong>&nbsp; Custom web design &amp; development</td></tr>',
      '<tr><td style="padding:10px 0;border-bottom:1px solid #f1f5f9;font-size:.88rem;color:#334155"><strong style="color:#06b6d4">&#9656;</strong>&nbsp; Security infrastructure &amp; threat protection</td></tr>',
      '<tr><td style="padding:10px 0;border-bottom:1px solid #f1f5f9;font-size:.88rem;color:#334155"><strong style="color:#f59e0b">&#9656;</strong>&nbsp; Full-stack systems, APIs &amp; automation</td></tr>',
      '<tr><td style="padding:10px 0;font-size:.88rem;color:#334155"><strong style="color:#a3e635">&#9656;</strong>&nbsp; Ongoing support &amp; managed plans</td></tr>',
      '</table>',
      '<table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:28px">',
      '<tr><td style="background:#7c3aed;border-radius:10px;padding:0">',
      '<a href="' + SITE_URL + '" style="display:inline-block;padding:13px 28px;color:#ffffff;font-weight:700;font-size:.92rem;text-decoration:none;border-radius:10px;font-family:Arial,sans-serif">Visit Our Site &#8594;</a>',
      '</td></tr></table>',
      '<p style="color:#475569;font-size:.88rem;line-height:1.7;margin:0">Have a project in mind or a question? Just reply to this email — we\'re real people and we respond fast.</p>',
      '</div>',
      '<div style="background:#f8fafc;padding:18px 32px;border-top:1px solid #e2e8f0;text-align:center">',
      '<p style="color:#94a3b8;font-size:.75rem;margin:0">Precision Workz &bull; Tucson, AZ &bull; <a href="' + SITE_URL + '" style="color:#7c3aed;text-decoration:none">' + SITE_URL.replace('https://','') + '</a></p>',
      '</div>',
      '</div>'
    ].join('')
  }).catch(function(e){ console.error('[Email] Welcome email failed for', toEmail, '—', e.message); });
}

function sendPasswordResetEmail(toEmail, token) {
  if (!nodemailer || !GMAIL_USER || !GMAIL_PASS) return Promise.resolve();
  const link = SITE_URL + '/reset-password?token=' + token;
  const transporter = nodemailer.createTransport({ host: 'smtp.gmail.com', port: 587, secure: false, auth: { user: GMAIL_USER, pass: GMAIL_PASS } });
  return transporter.sendMail({
    from: '"Precision Workz" <' + GMAIL_USER + '>',
    to: toEmail,
    subject: 'Reset your Precision Workz password',
    text: 'Click the link below to reset your password. This link expires in 1 hour.\n\n' + link + '\n\nIf you did not request this, ignore this email.',
    html: [
      '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#ffffff;border-radius:12px;border:1px solid #e2e8f0">',
      '<h2 style="font-size:1.3rem;font-weight:800;color:#0f172a;margin:0 0 10px">Reset your password</h2>',
      '<p style="color:#475569;line-height:1.7;margin:0 0 24px;font-size:.92rem">Click the button below to set a new password. This link expires in <strong>1 hour</strong>.</p>',
      '<table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:24px"><tr><td style="background:#7c3aed;border-radius:10px">',
      '<a href="' + link + '" style="display:inline-block;padding:13px 28px;color:#fff;font-weight:700;font-size:.92rem;text-decoration:none;border-radius:10px">Reset Password &#8594;</a>',
      '</td></tr></table>',
      '<p style="color:#64748b;font-size:.8rem;margin:0 0 8px">Button not working? Copy this link:</p>',
      '<p style="margin:0"><a href="' + link + '" style="color:#7c3aed;font-size:.78rem;word-break:break-all">' + link + '</a></p>',
      '<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">',
      '<p style="color:#94a3b8;font-size:.75rem;margin:0">If you did not request a password reset, ignore this email — your password will not change.</p>',
      '</div>'
    ].join('')
  }).catch(function(e){ console.error('[Email] Reset email failed for', toEmail, e.message); });
}

function serveResetPage(res, token, user) {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reset Password — Precision Workz</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Inter,system-ui,sans-serif;background:#04040d;color:#f1f5f9;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}.box{background:linear-gradient(145deg,#0d0d26,#121232);border:1px solid rgba(124,58,237,.35);border-radius:24px;padding:40px 36px;max-width:420px;width:100%}h2{font-size:1.5rem;font-weight:800;margin-bottom:8px}p{color:#94a3b8;font-size:.88rem;line-height:1.7;margin-bottom:22px}label{display:block;font-size:.78rem;font-weight:600;color:#94a3b8;margin-bottom:6px}input{width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:10px;color:#f1f5f9;padding:12px 14px;font-size:.9rem;outline:none;margin-bottom:14px;font-family:inherit}input:focus{border-color:rgba(124,58,237,.5)}button{width:100%;padding:13px;border-radius:12px;background:linear-gradient(135deg,#7c3aed,#06b6d4);color:#fff;font-weight:700;font-size:.92rem;border:none;cursor:pointer;font-family:inherit}.msg{margin-top:12px;font-size:.84rem;text-align:center}.ok{color:#4ade80}.err{color:#f87171}.back{display:block;margin-top:18px;text-align:center;color:#22d3ee;font-size:.82rem;text-decoration:none}</style></head><body><div class="box"><h2>Set New Password</h2><p>For <strong style="color:#22d3ee">' + user.email + '</strong></p><label>New Password</label><input type="password" id="pw1" placeholder="At least 8 characters"><label>Confirm Password</label><input type="password" id="pw2" placeholder="Repeat password"><button onclick="go()">Save New Password →</button><div class="msg" id="m"></div><a class="back" href="/">← Back to site</a></div><script>async function go(){var p1=document.getElementById("pw1").value,p2=document.getElementById("pw2").value,m=document.getElementById("m");if(p1.length<8){m.className="msg err";m.textContent="Password must be at least 8 characters.";return}if(p1!==p2){m.className="msg err";m.textContent="Passwords do not match.";return}m.className="msg";m.textContent="Saving...";var r=await fetch("/api/reset-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:"' + token + '",password:p1})});var d=await r.json();if(d.ok){m.className="msg ok";m.textContent="Password updated! Redirecting...";setTimeout(function(){window.location="/"},1800);}else{m.className="msg err";m.textContent=d.error||"Something went wrong.";}}</script></body></html>');
}

function buildMaintenancePage(opts) {
  const msg = (typeof opts === 'string' ? opts : (opts && opts.message)) || "We're making some improvements. Check back in a few minutes.";
  const endTime = (opts && opts.endTime) || 0;
  const isScheduled = (opts && opts.isScheduled) || false;
  const safeMsg = msg.replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const cdBlock = endTime ? `<div id="maint-cd-wrap" style="margin:28px auto;display:inline-flex;gap:0;border:1px solid rgba(245,158,11,.25);border-radius:14px;overflow:hidden;background:rgba(245,158,11,.04)"><div class="cd-unit" id="maint-h" style="display:none"><span class="cd-num" id="maint-hv">00</span><span class="cd-lbl">hours</span></div><div class="cd-unit"><span class="cd-num" id="maint-mv">--</span><span class="cd-lbl">minutes</span></div><div class="cd-unit" style="border-right:none"><span class="cd-num" id="maint-sv">--</span><span class="cd-lbl">seconds</span></div></div>` : '';
  const cdScript = endTime ? `var _mEnd=${endTime};function _mTick(){var d=Math.max(0,_mEnd-Date.now());if(!d){location.reload();return;}var h=Math.floor(d/3600000),m=Math.floor(d%3600000/60000),s=Math.floor(d%60000/1000);var hEl=document.getElementById('maint-hv'),mEl=document.getElementById('maint-mv'),sEl=document.getElementById('maint-sv'),hWrap=document.getElementById('maint-h');if(hEl)hEl.textContent=String(h).padStart(2,'0');if(mEl)mEl.textContent=String(m).padStart(2,'0');if(sEl)sEl.textContent=String(s).padStart(2,'0');if(hWrap)hWrap.style.display=h?'':'none';}setInterval(_mTick,1000);_mTick();` : '';
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Back Soon — Precision Workz</title><link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0}:root{--gold:#f59e0b;--purple:#7c3aed;--cyan:#06b6d4;--bg:#04040d;--text:#f1f5f9;--muted:#94a3b8;--dim:rgba(255,255,255,.28);--border:rgba(255,255,255,.08)}html,body{min-height:100vh;background:var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}body{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 24px;position:relative;overflow-x:hidden}body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% 0%,rgba(124,58,237,.12),transparent),radial-gradient(ellipse 60% 40% at 80% 80%,rgba(6,182,212,.07),transparent);pointer-events:none;z-index:0}body::after{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(255,255,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.015) 1px,transparent 1px);background-size:60px 60px;pointer-events:none;z-index:0}.wrap{position:relative;z-index:1;max-width:560px;width:100%;text-align:center}.logo{font-family:Orbitron,monospace;font-weight:900;font-size:1.45rem;letter-spacing:3px;text-transform:uppercase;background:linear-gradient(90deg,#f59e0b,#fbbf24,#d97706,#fbbf24,#f59e0b);background-size:300% auto;-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;animation:gold-wave 3s ease infinite;margin-bottom:6px}.logo-sub{font-size:.6rem;letter-spacing:4px;color:rgba(255,255,255,.3);text-transform:uppercase;font-weight:600;margin-bottom:36px}@keyframes gold-wave{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}.badge{display:inline-flex;align-items:center;gap:8px;padding:6px 16px;border:1px solid rgba(245,158,11,.3);border-radius:999px;background:rgba(245,158,11,.07);font-size:.72rem;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:rgba(245,158,11,.9);margin-bottom:28px}.badge-dot{width:7px;height:7px;border-radius:50%;background:#f59e0b;animation:pulse-dot 1.8s ease infinite}.badge-dot.blue{background:var(--cyan);animation:pulse-dot-b 1.8s ease infinite}@keyframes pulse-dot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}@keyframes pulse-dot-b{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}.title{font-size:2.6rem;font-weight:900;letter-spacing:-1.5px;line-height:1.1;margin-bottom:16px;background:linear-gradient(135deg,#f1f5f9 30%,#94a3b8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}.msg-card{background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.09);border-left:3px solid rgba(245,158,11,.45);border-radius:16px;padding:22px 26px;margin-bottom:24px;font-size:1rem;color:rgba(255,255,255,.72);line-height:1.8;font-weight:400;letter-spacing:.01em}.cd-unit{display:flex;flex-direction:column;align-items:center;padding:16px 20px;border-right:1px solid rgba(245,158,11,.18)}.cd-num{font-family:Orbitron,monospace;font-size:2rem;font-weight:900;color:#fbbf24;line-height:1}.cd-lbl{font-size:.55rem;letter-spacing:1.5px;text-transform:uppercase;color:rgba(245,158,11,.5);margin-top:4px;font-weight:600}.footer{margin-top:48px;display:flex;align-items:center;justify-content:center;gap:4px;flex-wrap:wrap}.footer-link{background:none;border:none;color:rgba(255,255,255,.35);font-size:.75rem;cursor:pointer;font-family:inherit;padding:6px 10px;border-radius:6px;transition:color .2s}.footer-link:hover{color:rgba(255,255,255,.7)}.sep{color:rgba(255,255,255,.12);font-size:.7rem}.modal-wrap{display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.7);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);align-items:center;justify-content:center;padding:24px}.modal-wrap.open{display:flex}.modal-box{background:linear-gradient(145deg,#0d0d26,#121232);border:1px solid rgba(124,58,237,.3);border-radius:20px;max-width:540px;width:100%;max-height:85vh;overflow-y:auto;padding:36px 32px;position:relative}.modal-close{position:absolute;top:16px;right:16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:var(--dim);border-radius:8px;padding:6px 12px;cursor:pointer;font-family:inherit;font-size:.8rem}.modal-box h2{font-size:1.4rem;font-weight:800;color:var(--text);margin:0 0 6px}.modal-date{font-size:.72rem;color:var(--dim);margin-bottom:24px}.modal-box h3{font-size:.85rem;font-weight:700;color:var(--text);margin:20px 0 6px}.modal-box p{font-size:.84rem;color:var(--muted);line-height:1.72;margin-bottom:8px}.modal-box a{color:#22d3ee;text-decoration:none}.modal-footer{margin-top:28px;padding-top:16px;border-top:1px solid var(--border);display:flex;gap:12px;flex-wrap:wrap}.modal-footer button{background:none;border:none;color:rgba(255,255,255,.4);font-size:.78rem;cursor:pointer;font-family:inherit;padding:4px 0}.modal-footer button:hover{color:var(--cyan)}.rep-form{margin-top:12px;display:flex;flex-direction:column;gap:10px}.rep-inp{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:10px;color:var(--text);padding:11px 14px;font-size:.88rem;outline:none;font-family:inherit;width:100%}.rep-inp:focus{border-color:rgba(124,58,237,.5)}.rep-textarea{resize:none;min-height:90px}.rep-btn{padding:12px;border-radius:10px;background:linear-gradient(135deg,var(--purple),var(--cyan));color:#fff;font-weight:700;font-size:.88rem;border:none;cursor:pointer;font-family:inherit}.rep-msg{font-size:.8rem;min-height:16px;margin-top:4px}.rep-ok{color:#4ade80}.rep-err{color:#f87171}</style></head><body><div class="wrap"><div class="logo">Precision Workz</div><div class="logo-sub">Tucson, AZ &nbsp;·&nbsp; precisionworkz.net</div><div class="badge"><span class="badge-dot${isScheduled?'':' blue'}"></span>${isScheduled?'Scheduled Maintenance':'Under Maintenance'}</div><div class="title">Back Soon</div><div class="msg-card">${safeMsg}</div>${cdBlock}<div class="footer"><button class="footer-link" onclick="openM('privacy')">Privacy Policy</button><span class="sep">·</span><button class="footer-link" onclick="openM('cookies')">Cookie Policy</button><span class="sep">·</span><button class="footer-link" onclick="openM('terms')">Terms of Service</button><span class="sep">·</span><button class="footer-link" onclick="openM('report')">Report a Problem</button></div></div><div class="modal-wrap" id="m-privacy"><div class="modal-box"><button class="modal-close" onclick="closeM('privacy')">✕ Close</button><h2>Privacy Policy</h2><div class="modal-date">Effective: January 1, 2026</div><h3>1. Information We Collect</h3><p>When you contact us, we collect your name, email, and project details. No payment information is collected through this site.</p><h3>2. How We Use It</h3><p>Solely to respond to your inquiry and provide the services you engage us for.</p><h3>3. Information Sharing</h3><p>We do not sell or transfer your information to third parties.</p><h3>4. Data Retention</h3><p>Retained as long as necessary to provide services and for reasonable business records thereafter.</p><h3>5. Cookies</h3><p>We use only essential cookies for basic functionality — no advertising or tracking cookies.</p><h3>6. Security</h3><p>We implement industry-standard security practices. No internet transmission is 100% secure.</p><h3>7. Your Rights</h3><p>Request access, correction, or deletion at <a href="mailto:precizionworkz@gmail.com">precizionworkz@gmail.com</a>.</p><div class="modal-footer"><button onclick="closeM('privacy');openM('cookies')">Cookie Policy</button><button onclick="closeM('privacy');openM('terms')">Terms of Service</button></div></div></div><div class="modal-wrap" id="m-cookies"><div class="modal-box"><button class="modal-close" onclick="closeM('cookies')">✕ Close</button><h2>Cookie Policy</h2><div class="modal-date">Effective: January 1, 2026</div><h3>1. What Are Cookies</h3><p>Small text files stored on your device to make websites work efficiently.</p><h3>2. How We Use Cookies</h3><p>Only essential cookies for basic functionality. No advertising, tracking, or third-party analytics cookies.</p><h3>3. Essential Cookies</h3><p>May store preferences during your visit. Removed when you close your browser.</p><h3>4. Managing Cookies</h3><p>Control through your browser settings. Disabling cookies will not prevent site use.</p><div class="modal-footer"><button onclick="closeM('cookies');openM('privacy')">Privacy Policy</button><button onclick="closeM('cookies');openM('terms')">Terms of Service</button></div></div></div><div class="modal-wrap" id="m-terms"><div class="modal-box"><button class="modal-close" onclick="closeM('terms')">✕ Close</button><h2>Terms of Service</h2><div class="modal-date">Effective: January 1, 2026</div><h3>1. Services</h3><p>All project scope, deliverables, timelines, and pricing are agreed upon in writing before work begins.</p><h3>2. Payment</h3><p>A 50% deposit is required before work begins. Remaining balance due upon completion.</p><h3>3. Intellectual Property</h3><p>Upon full payment, the client owns all custom code and designs. Precision Workz retains portfolio rights unless otherwise agreed.</p><h3>4. Revisions</h3><p>Each package includes defined revision rounds. Additional revisions are billed at an agreed hourly rate.</p><h3>5. Warranties</h3><p>We build to the highest standards but cannot guarantee specific business outcomes.</p><h3>6. Governing Law</h3><p>Governed by the laws of the State of Arizona.</p><div class="modal-footer"><button onclick="closeM('terms');openM('privacy')">Privacy Policy</button><button onclick="closeM('terms');openM('cookies')">Cookie Policy</button></div></div></div><div class="modal-wrap" id="m-report"><div class="modal-box"><button class="modal-close" onclick="closeM('report')">✕ Close</button><h2>Report a Problem</h2><div class="modal-date">We'll look into it as soon as we're back.</div><div class="rep-form"><input class="rep-inp" id="rep-email" type="email" placeholder="Your email address"><input class="rep-inp" id="rep-name" type="text" placeholder="Your name (optional)"><textarea class="rep-inp rep-textarea" id="rep-msg" placeholder="Describe the issue…"></textarea><button class="rep-btn" onclick="submitReport()">Send Report</button><div class="rep-msg" id="rep-status"></div></div></div></div><script>function openM(id){var el=document.getElementById('m-'+id);if(el){el.classList.add('open');document.body.style.overflow='hidden';}}function closeM(id){var el=document.getElementById('m-'+id);if(el){el.classList.remove('open');document.body.style.overflow='';}}document.querySelectorAll('.modal-wrap').forEach(function(w){w.addEventListener('click',function(e){if(e.target===w){var id=w.id.replace('m-','');closeM(id);}});});async function submitReport(){var email=document.getElementById('rep-email').value.trim(),name=document.getElementById('rep-name').value.trim(),msg=document.getElementById('rep-msg').value.trim(),st=document.getElementById('rep-status');if(!email||!msg){st.className='rep-msg rep-err';st.textContent='Email and message are required.';return;}st.className='rep-msg';st.textContent='Sending…';try{var r=await fetch('/api/submit-request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name||email,email:email,message:msg,service:'maintenance-report',details:'[Maintenance Report] '+msg,type:'general'})});if(r.ok){st.className='rep-msg rep-ok';st.textContent='✓ Report sent — thank you!';document.getElementById('rep-msg').value='';document.getElementById('rep-email').value='';}else{throw new Error();}}catch(e){st.className='rep-msg rep-err';st.textContent='Could not send — email us at precizionworkz@gmail.com';}}function openDP(){var o=document.getElementById('dv-ov');o.style.display='flex';document.body.style.overflow='hidden';setTimeout(function(){document.getElementById('dv-em').focus();},80);document.getElementById('dv-ms').textContent='';document.getElementById('dv-em').value='';document.getElementById('dv-pw').value='';}function closeDP(){document.getElementById('dv-ov').style.display='none';document.body.style.overflow='';}async function dpSub(){var e=(document.getElementById('dv-em').value||'').trim().toLowerCase(),p=document.getElementById('dv-pw').value,m=document.getElementById('dv-ms'),b=document.getElementById('dv-sb');if(!e||!p){m.textContent='Email and password required.';return;}b.textContent='Verifying…';b.style.opacity='.6';b.disabled=true;m.textContent='';try{var r=await fetch('/api/dev-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:e,password:p})});var d=await r.json();b.textContent='Access Panel';b.style.opacity='1';b.disabled=false;if(!d.ok){m.textContent=d.error||'Access denied.';return;}if(!d.canBypass){m.textContent='Your access level cannot bypass maintenance mode.';return;}try{sessionStorage.setItem('_devSession',JSON.stringify({email:e,level:d.level}));}catch(x){}window.location.href='/';}catch(x){b.textContent='Access Panel';b.style.opacity='1';b.disabled=false;m.textContent='Connection error.';}}${cdScript}</script><button onclick="openDP()" style="position:fixed;bottom:24px;left:24px;z-index:99990;width:38px;height:38px;border-radius:50%;background:rgba(14,14,24,.92);border:1px solid rgba(255,255,255,.18);color:rgba(255,255,255,.45);font-family:Orbitron,monospace;font-size:.6rem;font-weight:800;cursor:pointer;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(10px);box-shadow:0 2px 12px rgba(0,0,0,.5);transition:all .22s" onmouseover="this.style.borderColor='rgba(245,158,11,.6)';this.style.color='rgba(245,158,11,.9)';this.style.background='rgba(24,14,0,.95)'" onmouseout="this.style.borderColor='rgba(255,255,255,.18)';this.style.color='rgba(255,255,255,.45)';this.style.background='rgba(14,14,24,.92)'" title="Developer Access">PW</button><div id="dv-ov" style="display:none;position:fixed;inset:0;z-index:99991;background:rgba(0,0,0,.88);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);align-items:center;justify-content:center" onclick="if(event.target===this)closeDP()"><div style="background:rgba(8,8,16,.97);border:1px solid rgba(255,255,255,.07);border-radius:18px;padding:40px 36px;width:100%;max-width:380px;margin:0 16px;position:relative;box-shadow:0 32px 80px rgba(0,0,0,.7)"><button onclick="closeDP()" style="position:absolute;top:14px;right:16px;background:none;border:none;color:rgba(255,255,255,.25);font-size:1.2rem;cursor:pointer;padding:4px 8px;border-radius:6px">✕</button><div style="font-family:Orbitron,monospace;font-size:.55rem;letter-spacing:3px;color:rgba(245,158,11,.6);text-transform:uppercase;margin-bottom:6px">Developer Portal</div><div style="font-size:1.15rem;font-weight:800;color:#fff;margin-bottom:4px">Precision Workz</div><div style="font-size:.8rem;color:rgba(255,255,255,.3);margin-bottom:28px">Restricted access. Authorized personnel only.</div><div style="display:flex;flex-direction:column;gap:12px"><input id="dv-em" type="email" placeholder="Developer email" autocomplete="email" onkeydown="if(event.key==='Enter')document.getElementById('dv-pw').focus()" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:12px 14px;color:#fff;font-size:.88rem;font-family:inherit;outline:none;width:100%;box-sizing:border-box" onfocus="this.style.borderColor='rgba(245,158,11,.4)'" onblur="this.style.borderColor='rgba(255,255,255,.1)'"><input id="dv-pw" type="password" placeholder="Password" autocomplete="current-password" onkeydown="if(event.key==='Enter')dpSub()" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:12px 14px;color:#fff;font-size:.88rem;font-family:inherit;outline:none;width:100%;box-sizing:border-box" onfocus="this.style.borderColor='rgba(245,158,11,.4)'" onblur="this.style.borderColor='rgba(255,255,255,.1)'"></div><div id="dv-ms" style="font-size:.8rem;color:#f87171;margin-top:10px;min-height:18px;text-align:center"></div><button id="dv-sb" onclick="dpSub()" style="margin-top:16px;width:100%;padding:13px;background:linear-gradient(135deg,#f59e0b,#d97706);border:none;border-radius:10px;color:#000;font-weight:800;font-size:.88rem;letter-spacing:.5px;cursor:pointer;font-family:inherit">Access Panel</button></div></div></body></html>`;
}

async function sendEmail(to, subject, html) {
  if (!nodemailer || !GMAIL_USER || !GMAIL_PASS) {
    console.warn('[Email] Skipped — GMAIL_USER or GMAIL_PASS not configured');
    return;
  }
  const transporter = nodemailer.createTransport({ host: 'smtp.gmail.com', port: 587, secure: false, auth: { user: GMAIL_USER, pass: GMAIL_PASS } });
  const recipients = Array.isArray(to) ? to.filter(Boolean).join(',') : to;
  try {
    await transporter.sendMail({ from: '"Precision Workz" <' + GMAIL_USER + '>', to: recipients, subject, html });
    console.log('[Email] Sent to', recipients, '| Subject:', subject);
  } catch (e) {
    console.error('[Email] Failed to send to', recipients, '—', e.message);
  }
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
      if (containsProfanity(description)) {
        return json(res, 400, { error: 'Your report contains language we do not allow. Please revise and try again.' });
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
      if (containsProfanity(details)) {
        return json(res, 400, { error: 'Your message contains language we do not allow. Please revise and try again.' });
      }
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
      const reqLink = SITE_URL + '/?req=' + newReq.id;
      const hasBorder = (newReq.phone||newReq.service||newReq.promoCode) ? '1px solid #1e293b' : 'none';
      const adminHtml = emailHeader('New ' + typeLabel, new Date().toLocaleString('en-US',{weekday:'short',month:'short',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit'}))
        + '<div style="padding:28px 32px">'
        + '<table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:22px;background:rgba(255,255,255,.03);border-radius:10px;border:1px solid #1e293b">'
        + '<tr><td style="padding:11px 16px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#64748b;width:80px;border-bottom:1px solid #1e293b">From</td>'
        + '<td style="padding:11px 16px;color:#f1f5f9;font-weight:700;border-bottom:1px solid #1e293b">' + esc(newReq.name || '') + '</td></tr>'
        + '<tr><td style="padding:11px 16px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#64748b;border-bottom:' + hasBorder + '">Email</td>'
        + '<td style="padding:11px 16px;border-bottom:' + hasBorder + '"><a href="mailto:' + esc(newReq.email) + '" style="color:#22d3ee;text-decoration:none;font-weight:600">' + esc(newReq.email) + '</a></td></tr>'
        + (newReq.phone ? '<tr><td style="padding:11px 16px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#64748b;border-bottom:' + (newReq.service||newReq.promoCode?'1px solid #1e293b':'none') + '">Phone</td><td style="padding:11px 16px;color:#22d3ee;font-weight:600;border-bottom:' + (newReq.service||newReq.promoCode?'1px solid #1e293b':'none') + '">' + esc(newReq.phone) + '</td></tr>' : '')
        + (newReq.service ? '<tr><td style="padding:11px 16px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#64748b;border-bottom:' + (newReq.promoCode?'1px solid #1e293b':'none') + '">Package</td><td style="padding:11px 16px;color:#a78bfa;font-weight:600;border-bottom:' + (newReq.promoCode?'1px solid #1e293b':'none') + '">' + esc(newReq.service) + '</td></tr>' : '')
        + (newReq.promoCode ? '<tr><td style="padding:11px 16px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#64748b">Promo</td><td style="padding:11px 16px;color:#fbbf24;font-weight:600">' + esc(newReq.promoCode) + '</td></tr>' : '')
        + '</table>'
        + '<div style="font-size:10px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#475569;margin-bottom:8px">Message</div>'
        + '<div style="background:rgba(255,255,255,.04);border:1px solid #1e293b;border-radius:10px;padding:16px;font-size:14px;color:#cbd5e1;white-space:pre-wrap;word-break:break-word;line-height:1.7;margin-bottom:28px">' + esc(newReq.details) + '</div>'
        + emailBtn(reqLink, 'View &amp; Reply in Admin Panel &#8594;')
        + '</div>'
        + emailFooter();
      await sendEmail(adminRecipients, 'New ' + typeLabel + ' — ' + (newReq.name || newReq.email), adminHtml);
      // Confirmation email to client
      const clientFirst = esc((newReq.name || newReq.email).split(' ')[0].split('@')[0]);
      const clientConfirmHtml = emailHeader('We got your request!', '')
        + '<div style="padding:28px 32px">'
        + '<p style="color:#94a3b8;font-size:15px;line-height:1.7;margin:0 0 22px">Hey ' + clientFirst + ', thanks for reaching out. We\'ve received your message and will get back to you shortly.</p>'
        + '<div style="font-size:10px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#475569;margin-bottom:8px">What you submitted</div>'
        + '<div style="background:rgba(255,255,255,.04);border:1px solid #1e293b;border-radius:10px;padding:16px;font-size:13px;color:#cbd5e1;white-space:pre-wrap;word-break:break-word;line-height:1.7;margin-bottom:28px">' + esc(newReq.details) + '</div>'
        + emailBtn(SITE_URL, 'Track on Dashboard &#8594;')
        + '</div>'
        + emailFooter();
      await sendEmail(newReq.email, 'We received your request — Precision Workz', clientConfirmHtml);
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

  // Co-owner → send message / request to primary admin
  if (urlPath === '/api/track' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { event, label } = body;
      if (!event || !label) return json(res, 200, { ok: false });
      const analytics = await readAnalytics();
      if (!analytics.events) analytics.events = {};
      const key = String(event + ':' + label).slice(0, 100);
      analytics.events[key] = (analytics.events[key] || 0) + 1;
      if (event === 'pageview') analytics.totalPageviews = (analytics.totalPageviews || 0) + 1;
      analytics.lastUpdated = Date.now();
      await writeAnalytics(analytics);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 200, { ok: false }); }
  }

  if (urlPath === '/api/co-message' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { coOwnerEmail, type, message, devEmail } = body;
      const senderEmail = (coOwnerEmail || '').toLowerCase().trim();
      if (!senderEmail || !type || !message) return json(res, 400, { error: 'Missing fields' });
      if (!await isAdmin(senderEmail)) return json(res, 403, { error: 'Forbidden' });
      const msgs = await readCoMessages();
      const newMsg = { id: Date.now().toString(36) + Math.random().toString(36).slice(2,6), type, message, devEmail: devEmail||null, from: senderEmail, status: 'open', createdAt: new Date().toISOString(), replies: [] };
      msgs.unshift(newMsg);
      await writeCoMessages(msgs);
      const isCoO = CO_OWNER_EMAIL && senderEmail === CO_OWNER_EMAIL.toLowerCase();
      const typeLabel = type==='add-dev'?'Add Developer Request':type==='remove-dev'?'Remove Developer Request':(isCoO?'Message from Co-Owner':'Message from Dev: '+senderEmail);
      const adminHtml = emailHeader(typeLabel, new Date().toLocaleString())
        + '<div style="padding:28px 32px">'
        + '<div style="font-size:10px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#475569;margin-bottom:8px">From</div><div style="background:rgba(124,58,237,.08);border:1px solid rgba(124,58,237,.2);border-radius:8px;padding:8px 14px;font-size:13px;color:var(--purple2,#a78bfa);margin-bottom:16px">'+esc(senderEmail)+'</div>'
        + (devEmail?'<div style="font-size:10px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#475569;margin-bottom:8px">Developer Email</div><div style="background:rgba(6,182,212,.08);border:1px solid rgba(6,182,212,.2);border-radius:8px;padding:10px 14px;font-size:14px;color:#22d3ee;margin-bottom:16px">'+esc(devEmail)+'</div>':'')
        + '<div style="font-size:10px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#475569;margin-bottom:8px">Message</div>'
        + '<div style="background:rgba(255,255,255,.04);border:1px solid #1e293b;border-radius:10px;padding:16px;font-size:14px;color:#cbd5e1;white-space:pre-wrap;word-break:break-word;line-height:1.7;margin-bottom:28px">'+esc(message)+'</div>'
        + emailBtn(SITE_URL+'/?coMsg='+newMsg.id,'View &amp; Reply in Admin Panel &#8594;')
        + '</div>'+emailFooter();
      await sendEmail(GMAIL_USER, typeLabel, adminHtml);
      return json(res, 200, { ok: true, id: newMsg.id });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  // Any admin → get own sent messages (to see replies)
  if (urlPath === '/api/co-messages/mine' && req.method === 'GET') {
    const qs = new URLSearchParams(req.url.split('?')[1]||'');
    const senderEmail = (qs.get('coOwnerEmail')||'').toLowerCase().trim();
    if (!senderEmail || !await isAdmin(senderEmail)) return json(res, 403, { error: 'Forbidden' });
    const all = await readCoMessages();
    const mine = all.filter(m => (m.from||'').toLowerCase() === senderEmail);
    return json(res, 200, { messages: mine });
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
      const [clients, admins, adminLevels, adminNames, projects] = await Promise.all([readClients(), readAdmins(), readAdminLevels(), readAdminNames(), readProjects()]);
      const coLow = (CO_OWNER_EMAIL || '').toLowerCase();
      const allAdmins = [...new Set([PRIMARY_ADMIN, ...(CO_OWNER_EMAIL ? [CO_OWNER_EMAIL] : []), ...admins.filter(a => a.toLowerCase() !== PRIMARY_ADMIN.toLowerCase() && a.toLowerCase() !== coLow)])];
      const myLevel = await getAdminLevel(body.adminEmail);
      return json(res, 200, { clients, admins: allAdmins, primaryAdmin: PRIMARY_ADMIN, coOwner: CO_OWNER_EMAIL || null, adminLevels, adminNames, myLevel, projects });
    }

    if (urlPath === '/api/admin/requests') {
      return json(res, 200, { requests: await readRequests(), ownerEmail: OWNER_EMAIL });
    }

    if (urlPath === '/api/admin/co-messages') {
      if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) return json(res, 403, { error: 'Forbidden' });
      return json(res, 200, { messages: await readCoMessages() });
    }

    if (urlPath === '/api/admin/co-message-reply' && req.method === 'POST') {
      if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) return json(res, 403, { error: 'Forbidden' });
      try {
        const { id, replyText } = body;
        if (!id || !replyText) return json(res, 400, { error: 'Missing fields' });
        const msgs = await readCoMessages();
        const idx = msgs.findIndex(m => m.id === id);
        if (idx < 0) return json(res, 404, { error: 'Not found' });
        if (!msgs[idx].replies) msgs[idx].replies = [];
        msgs[idx].replies.push({ text: replyText, from: 'admin', createdAt: new Date().toISOString() });
        msgs[idx].status = 'resolved';
        await writeCoMessages(msgs);
        if (CO_OWNER_EMAIL) {
          const typeLabel = msgs[idx].type==='add-dev'?'Add Developer Request':msgs[idx].type==='remove-dev'?'Remove Developer Request':'Your Message';
          const replyHtml = emailHeader('Reply from the Owner', '')
            + '<div style="padding:28px 32px">'
            + '<p style="color:#94a3b8;font-size:15px;line-height:1.7;margin:0 0 20px">Hi Oscar, here\'s a reply to your <b style="color:#f1f5f9">'+typeLabel+'</b>:</p>'
            + '<div style="background:rgba(6,182,212,.06);border:1px solid rgba(6,182,212,.2);border-radius:10px;padding:18px;font-size:14px;color:#cbd5e1;white-space:pre-wrap;word-break:break-word;line-height:1.7;margin-bottom:28px">'+esc(replyText)+'</div>'
            + emailBtn(SITE_URL,'Open Co-Owner Panel &#8594;')
            + '</div>'+emailFooter();
          await sendEmail(CO_OWNER_EMAIL, 'Reply from owner — Precision Workz', replyHtml);
        }
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/co-message-delete' && req.method === 'POST') {
      if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) return json(res, 403, { error: 'Forbidden' });
      try {
        const { id } = body;
        if (!id) return json(res, 400, { error: 'id required' });
        const msgs = (await readCoMessages()).filter(m => m.id !== id);
        await writeCoMessages(msgs);
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/co-message-resolve' && req.method === 'POST') {
      if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) return json(res, 403, { error: 'Forbidden' });
      try {
        const { id, status } = body;
        const msgs = await readCoMessages();
        const idx = msgs.findIndex(m => m.id === id);
        if (idx >= 0) { msgs[idx].status = status || 'resolved'; await writeCoMessages(msgs); }
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/reports') {
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'medium')) return json(res, 403, { error: 'Medium access or higher required', permissionDenied: true });
      return json(res, 200, { reports: await readReports() });
    }

    if (urlPath === '/api/admin/report-read' && req.method === 'POST') {
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'medium')) return json(res, 403, { error: 'Medium access or higher required', permissionDenied: true });
      try {
        const { id } = body;
        const reports = await readReports();
        const idx = reports.findIndex(r => r.id === id);
        if (idx >= 0) { reports[idx].read = true; await writeReports(reports); }
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/report-delete' && req.method === 'POST') {
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'max')) return json(res, 403, { error: 'Max access or higher required', permissionDenied: true });
      try {
        const { id } = body;
        const reports = (await readReports()).filter(r => r.id !== id);
        await writeReports(reports);
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/update-request' && req.method === 'POST') {
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'medium')) return json(res, 403, { error: 'Medium access or higher required', permissionDenied: true });
      try {
        const { id, status } = body;
        const reqs = await readRequests();
        const idx = reqs.findIndex(r => r.id === id);
        if (idx >= 0) { reqs[idx].status = status; reqs[idx].updatedAt = new Date().toISOString(); await writeRequests(reqs); }
        return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/delete-request' && req.method === 'POST') {
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'max')) return json(res, 403, { error: 'Max access or higher required', permissionDenied: true });
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
      const clientFirst = esc((reqs[idx].name || clientEmail).split(' ')[0].split('@')[0]);
      const replyHtml = emailHeader('You have a reply!', '')
        + '<div style="padding:28px 32px">'
        + '<p style="color:#94a3b8;font-size:15px;line-height:1.7;margin:0 0 20px">Hi ' + clientFirst + ', here\'s our response to your request:</p>'
        + '<div style="background:rgba(6,182,212,.06);border:1px solid rgba(6,182,212,.2);border-radius:10px;padding:18px;font-size:14px;color:#cbd5e1;white-space:pre-wrap;word-break:break-word;line-height:1.7;margin-bottom:28px">' + esc(replyText) + '</div>'
        + emailBtn(SITE_URL, 'View Full Thread on Dashboard &#8594;')
        + '</div>'
        + emailFooter();
      await sendEmail(clientEmail, 'Reply from Precision Workz', replyHtml);
      if (CO_OWNER_EMAIL) await sendEmail(CO_OWNER_EMAIL, 'Reply sent to ' + clientEmail, replyHtml);
      return json(res, 200, { ok: true });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    if (urlPath === '/api/admin/clean-clients' && req.method === 'POST') {
      if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) return json(res, 403, { error: 'Primary admin only' });
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
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'medium')) return json(res, 403, { error: 'Medium access or higher required', permissionDenied: true });
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
      if (!isCoOwnerOrPrimary(body.adminEmail)) return json(res, 403, { error: 'Co-owner or primary admin access required', permissionDenied: true });
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
      if (!isCoOwnerOrPrimary(body.adminEmail)) return json(res, 403, { error: 'Co-owner or primary admin access required', permissionDenied: true });
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
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'max')) return json(res, 403, { error: 'Max access or higher required', permissionDenied: true });
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
        const { newEmail, level } = body;
        if (!newEmail) return json(res, 400, { error: 'newEmail required' });
        const admins = await readAdmins();
        const key = newEmail.toLowerCase().trim();
        if (!admins.map(e => e.toLowerCase()).includes(key)) {
          admins.push(newEmail.trim());
          await writeAdmins(admins);
        }
        if (level && ['low','medium','max'].includes(level)) {
          const levels = await readAdminLevels();
          levels[key] = level;
          await writeAdminLevels(levels);
        }
        if (body.name && typeof body.name === 'string') {
          const names = await readAdminNames();
          names[key] = body.name.trim().slice(0, 60);
          await writeAdminNames(names);
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
        const key = (targetEmail||'').toLowerCase();
        const admins = (await readAdmins()).filter(e =>
          e.toLowerCase() !== key && e.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()
        );
        admins.unshift(PRIMARY_ADMIN);
        await writeAdmins(admins);
        const names = await readAdminNames();
        delete names[key];
        await writeAdminNames(names);
        return json(res, 200, { ok: true, admins });
      } catch(e) { return json(res, 500, { error: e.message }); }
    }

    // Project management endpoints
    if (urlPath === '/api/admin/add-project' && req.method === 'POST') {
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'medium')) return json(res, 403, { error: 'Medium access or higher required', permissionDenied: true });
      const { name, clientEmail, notes } = body;
      if (!name) return json(res, 400, { error: 'Project name required' });
      const id = 'proj_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      const projects = await readProjects();
      projects[id] = { id, name: name.trim(), clientEmail: (clientEmail||'').trim(), notes: (notes||'').trim(), created: Date.now(), createdBy: body.adminEmail, locked: false, status: 'active' };
      await writeProjects(projects);
      return json(res, 200, { ok: true, project: projects[id], projects });
    }

    if (urlPath === '/api/admin/update-project' && req.method === 'POST') {
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'medium')) return json(res, 403, { error: 'Medium access or higher required', permissionDenied: true });
      const { id, name, clientEmail, notes, status } = body;
      if (!id) return json(res, 400, { error: 'Project ID required' });
      const projects = await readProjects();
      if (!projects[id]) return json(res, 404, { error: 'Project not found' });
      if (projects[id].locked && body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) {
        return json(res, 403, { error: 'Project is locked — only the primary admin can edit' });
      }
      if (name !== undefined) projects[id].name = name.trim();
      if (clientEmail !== undefined) projects[id].clientEmail = clientEmail.trim();
      if (notes !== undefined) projects[id].notes = notes.trim();
      if (status) projects[id].status = status;
      projects[id].updatedAt = Date.now();
      projects[id].updatedBy = body.adminEmail;
      await writeProjects(projects);
      return json(res, 200, { ok: true, project: projects[id], projects });
    }

    if (urlPath === '/api/admin/lock-project' && req.method === 'POST') {
      if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) return json(res, 403, { error: 'Only the primary admin can lock/unlock projects' });
      const { id, locked } = body;
      if (!id) return json(res, 400, { error: 'Project ID required' });
      const projects = await readProjects();
      if (!projects[id]) return json(res, 404, { error: 'Project not found' });
      projects[id].locked = !!locked;
      projects[id].lockedAt = locked ? Date.now() : null;
      await writeProjects(projects);
      return json(res, 200, { ok: true, project: projects[id], projects });
    }

    if (urlPath === '/api/admin/delete-project' && req.method === 'POST') {
      if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) return json(res, 403, { error: 'Only the primary admin can delete projects' });
      const { id } = body;
      if (!id) return json(res, 400, { error: 'Project ID required' });
      const projects = await readProjects();
      if (!projects[id]) return json(res, 404, { error: 'Project not found' });
      delete projects[id];
      await writeProjects(projects);
      return json(res, 200, { ok: true, projects });
    }

    // IP management endpoints
    if (urlPath === '/api/admin/ip-bypass' && req.method === 'POST') {
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'max')) return json(res, 403, { error: 'Max access or higher required', permissionDenied: true });
      const { targetIP, bypass } = body;
      if (!targetIP) return json(res, 400, { error: 'targetIP required' });
      await ensureIPKVLoaded();
      const rec = getIPRecord(targetIP);
      rec.bypass = !!bypass;
      persistIPTracker();
      return json(res, 200, { ok: true });
    }

    if (urlPath === '/api/admin/ip-force' && req.method === 'POST') {
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'max')) return json(res, 403, { error: 'Max access or higher required', permissionDenied: true });
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
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'max')) return json(res, 403, { error: 'Max access or higher required', permissionDenied: true });
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
      if (!levelAtLeast(await getAdminLevel(body.adminEmail), 'medium')) return json(res, 403, { error: 'Medium access or higher required', permissionDenied: true });
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
      const analytics = await readAnalytics();
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
        platform:         process.platform,
        ips:              ipList.slice(0, 100),
        analytics:        { events: analytics.events || {}, totalPageviews: analytics.totalPageviews || 0, lastUpdated: analytics.lastUpdated || null },
        siteStatus:       await readSiteStatus(),
      });
    }

    if (urlPath === '/api/admin/analytics-reset' && req.method === 'POST') {
      if (!isCoOwnerOrPrimary(body.adminEmail)) return json(res, 403, { error: 'Co-owner or primary admin access required' });
      await writeAnalytics({});
      return json(res, 200, { ok: true });
    }

    if (urlPath === '/api/admin/site-control' && req.method === 'POST') {
      if (!isCoOwnerOrPrimary(body.adminEmail)) return json(res, 403, { error: 'Owner or Co-Owner access required' });
      const { maintenance, message, scheduledStart, scheduledDuration, clearSchedule } = body;
      const current = await readSiteStatus();
      const updated = Object.assign({}, current, {
        maintenance:       typeof maintenance === 'boolean' ? maintenance : current.maintenance,
        message:           (message !== undefined ? message : current.message || '').slice(0, 200),
        scheduledStart:    clearSchedule ? null : (scheduledStart !== undefined ? scheduledStart : current.scheduledStart),
        scheduledDuration: clearSchedule ? null : (scheduledDuration !== undefined ? scheduledDuration : current.scheduledDuration),
        updatedAt:         new Date().toISOString(),
        updatedBy:         body.adminEmail,
      });
      await writeSiteStatus(updated);
      if (maintenance !== undefined) console.log('[Site Control] Maintenance', maintenance ? 'ENABLED' : 'DISABLED', 'by', body.adminEmail);
      if (scheduledStart) console.log('[Site Control] Scheduled shutdown at', scheduledStart, 'for', scheduledDuration, 'min by', body.adminEmail);
      return json(res, 200, { ok: true, status: updated });
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
      const alreadyWelcomed = !!users[key].welcomeSent;
      users[key].welcomeSent = true;
      await writeUsers(users);
      if (!alreadyWelcomed) sendWelcomeEmail(key, users[key].name || '').catch(function(){});
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

  if (urlPath === '/api/dev-login' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email, password } = body;
      if (!email || !password) return json(res, 400, { error: 'Email and password required.' });
      const key = email.toLowerCase().trim();
      const [admins, adminLevels, users] = await Promise.all([readAdmins(), readAdminLevels(), readUsers()]);
      if (!admins.includes(key)) return json(res, 403, { error: 'Not a registered developer.' });
      const user = users[key];
      if (!user || !user.password) return json(res, 403, { error: 'No account found for this email.' });
      const ok = await verifyPassword(password, user.password);
      if (!ok) return json(res, 401, { error: 'Incorrect password.' });
      const level = adminLevels[key] || 'low';
      const siteStatus = await readSiteStatus();
      const isCoOwner = !!(siteStatus.coOwner && siteStatus.coOwner.toLowerCase() === key);
      const isPrimOwner = key === PRIMARY_ADMIN.toLowerCase();
      const canBypass = isPrimOwner || isCoOwner || level === 'max';
      if (canBypass) res.setHeader('Set-Cookie', 'devAccess=1; HttpOnly; Max-Age=7200; Path=/; SameSite=Strict');
      return json(res, 200, { ok: true, level, canBypass });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/welcome-new-user' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email, name } = body;
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, 400, { error: 'Valid email required' });
      const key = email.toLowerCase().trim();
      const users = await readUsers();
      if (users[key] && users[key].welcomeSent) return json(res, 200, { ok: true, skipped: true });
      users[key] = Object.assign(users[key] || { email: key }, { welcomeSent: true });
      await writeUsers(users);
      sendWelcomeEmail(key, name || '').catch(function(){});
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/client-project') {
    const qs = new URLSearchParams(req.url.split('?')[1] || '');
    const email = (qs.get('email') || '').toLowerCase().trim();
    if (!email) return json(res, 400, { error: 'email required' });
    const projects = await readProjects();
    const project = Object.values(projects).find(p => p.clientEmail && p.clientEmail.toLowerCase() === email) || null;
    return json(res, 200, { project });
  }

  if (urlPath === '/api/forgot-password' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const key = ((body.email) || '').toLowerCase().trim();
      if (key) {
        const users = await readUsers();
        if (users[key] && users[key].verified) {
          const token = crypto.randomBytes(32).toString('hex');
          users[key].resetToken = token;
          users[key].resetExpiry = Date.now() + 3600000;
          await writeUsers(users);
          sendPasswordResetEmail(key, token).catch(function(){});
        }
      }
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/reset-password' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { token, password } = body;
      if (!token || !password || password.length < 8) return json(res, 400, { error: 'Invalid request' });
      const users = await readUsers();
      const key = Object.keys(users).find(k => users[k].resetToken === token);
      if (!key) return json(res, 400, { error: 'Invalid or expired link' });
      if (Date.now() > (users[key].resetExpiry || 0)) return json(res, 400, { error: 'Link expired — request a new one' });
      users[key].password = await hashPassword(password);
      users[key].resetToken = null;
      users[key].resetExpiry = null;
      await writeUsers(users);
      return json(res, 200, { ok: true });
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

  if (urlPath === '/reset-password') {
    const qs = new URLSearchParams(req.url.split('?')[1] || '');
    const token = qs.get('token') || '';
    const users = await readUsers();
    const key = Object.keys(users).find(k => users[k].resetToken === token);
    if (!key || !token || Date.now() > (users[key].resetExpiry || 0)) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Precision Workz</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Inter,sans-serif;background:#04040d;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}.box{background:#0d0d26;border:1px solid rgba(124,58,237,.3);border-radius:16px;padding:36px;max-width:400px;width:100%;text-align:center}h2{margin-bottom:10px}p{color:#94a3b8;font-size:.88rem;line-height:1.6;margin-bottom:20px}a{color:#22d3ee;font-size:.85rem;text-decoration:none}</style></head><body><div class="box"><h2>Link Expired</h2><p>This password reset link has expired or already been used. Return to the site and request a new one.</p><a href="/">← Back to site</a></div></body></html>');
      return;
    }
    serveResetPage(res, token, users[key]);
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

  // Maintenance mode — blocks HTML pages, allows assets/API
  let _clearDevCookie = false;
  if (!path.extname(urlPath) || urlPath === '/' || urlPath === '') {
    try {
      const status = await readSiteStatus();
      const now = Date.now();
      const schedStart = status.scheduledStart ? new Date(status.scheduledStart).getTime() : 0;
      const schedDur   = (status.scheduledDuration || 0) * 60000;
      const schedEnd   = schedStart + schedDur;
      const isScheduled = schedStart && now >= schedStart && now <= schedEnd;
      const isManual    = status.maintenance;
      const cookies = req.headers.cookie || '';
      const hasDevAccess = cookies.split(';').some(c => c.trim() === 'devAccess=1');
      if (!hasDevAccess && (isManual || isScheduled)) {
        res.writeHead(503, { 'Content-Type': 'text/html' });
        res.end(buildMaintenancePage({ message: status.message, endTime: isScheduled ? schedEnd : 0, isScheduled }));
        return;
      }
      // Cookie is valid — clear it immediately so reload returns to maintenance
      if (hasDevAccess) _clearDevCookie = true;
    } catch(e) {}
  }

  if (urlPath === '/' || urlPath === '') urlPath = '/index.html';
  const filePath = path.join(DIR, urlPath);
  const mime = MIME[path.extname(filePath)] || 'text/plain';
  fs.readFile(filePath, function(err, data) {
    if (err) {
      fs.readFile(path.join(DIR, 'index.html'), function(e2, d2) {
        if (e2) { res.writeHead(404); res.end('Not found'); return; }
        const hdrs = { 'Content-Type': 'text/html' };
        if (_clearDevCookie) hdrs['Set-Cookie'] = 'devAccess=; Max-Age=0; Path=/; SameSite=Strict';
        res.writeHead(200, hdrs); res.end(d2);
      });
      return;
    }
    const hdrs = { 'Content-Type': mime };
    if (_clearDevCookie) hdrs['Set-Cookie'] = 'devAccess=; Max-Age=0; Path=/; SameSite=Strict';
    res.writeHead(200, hdrs); res.end(data);
  });
}

// Run as standalone server locally; export handler for Vercel
if (require.main === module) {
  http.createServer(handler).listen(PORT, function() {
    console.log('Precision Workz running on http://localhost:' + PORT);
  });
}

module.exports = handler;
