'use strict';
const crypto = require('crypto');
const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT = process.env.PORT || 4000;
const DIR  = __dirname;

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
  '.ico': 'image/x-icon', '.woff2': 'font/woff2',
};

const PRICES = {
  'basic-monthly': null,
  'basic-annual':  null,
  'gold-monthly':  null,
  'gold-annual':   null,
};

// ── ADMIN DATABASE ─────────────────────────────────────────
const ADMINS_PATH    = path.join(DIR, 'admins.json');
const CLIENTS_PATH   = path.join(DIR, 'clients.json');
const REQUESTS_PATH  = path.join(DIR, 'requests.json');
const OWNER_EMAIL    = 'precizionworkz@gmail.com';

function readAdmins() {
  try { return JSON.parse(fs.readFileSync(ADMINS_PATH, 'utf8')); }
  catch(e) { return [PRIMARY_ADMIN]; }
}
function writeAdmins(list) {
  fs.writeFileSync(ADMINS_PATH, JSON.stringify(list, null, 2));
}
function readClients() {
  try { return JSON.parse(fs.readFileSync(CLIENTS_PATH, 'utf8')); }
  catch(e) { return {}; }
}
function writeClients(data) {
  fs.writeFileSync(CLIENTS_PATH, JSON.stringify(data, null, 2));
}
function readRequests() {
  try { return JSON.parse(fs.readFileSync(REQUESTS_PATH, 'utf8')); }
  catch(e) { return []; }
}
function writeRequests(data) { fs.writeFileSync(REQUESTS_PATH, JSON.stringify(data, null, 2)); }

// ── USER AUTH ───────────────────────────────────────────────
const USERS_PATH = path.join(DIR, 'users.json');
function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_PATH, 'utf8')); }
  catch(e) { return {}; }
}
function writeUsers(data) { fs.writeFileSync(USERS_PATH, JSON.stringify(data, null, 2)); }

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
    html: '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#04040d;color:#f1f5f9;border-radius:16px"><h2 style="font-size:1.5rem;font-weight:800;margin-bottom:12px">Verify your email</h2><p style="color:#94a3b8;line-height:1.7;margin-bottom:24px">Click the button below to verify your email and set your password. This link expires in 24 hours.</p><a href="' + link + '" style="display:inline-block;padding:14px 28px;background:linear-gradient(135deg,#7c3aed,#06b6d4);color:#fff;font-weight:700;border-radius:10px;text-decoration:none">Verify Email & Set Password →</a><p style="color:#475569;font-size:.8rem;margin-top:24px">If you did not request this, ignore this email.</p></div>'
  });
}

function serveVerifyPage(res, token, user) {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Set Password — Precision Workz</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Inter,system-ui,sans-serif;background:#04040d;color:#f1f5f9;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}.box{background:linear-gradient(145deg,#0d0d26,#121232);border:1px solid rgba(124,58,237,.35);border-radius:24px;padding:40px 36px;max-width:420px;width:100%}h2{font-size:1.6rem;font-weight:800;margin-bottom:8px}p{color:#94a3b8;font-size:.88rem;line-height:1.7;margin-bottom:24px}label{display:block;font-size:.78rem;font-weight:600;color:#94a3b8;margin-bottom:6px}input{width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:10px;color:#f1f5f9;padding:12px 14px;font-size:.9rem;outline:none;margin-bottom:16px;font-family:inherit}input:focus{border-color:rgba(124,58,237,.5)}button{width:100%;padding:14px;border-radius:12px;background:linear-gradient(135deg,#7c3aed,#06b6d4);color:#fff;font-weight:700;font-size:.95rem;border:none;cursor:pointer;font-family:inherit}.msg{margin-top:12px;font-size:.85rem;text-align:center}.ok{color:#4ade80}.err{color:#f87171}</style></head><body><div class="box"><h2>Set Your Password</h2><p>Creating account for <strong style="color:#22d3ee">' + user.email + '</strong></p><label>Password</label><input type="password" id="pw1" placeholder="At least 8 characters"><label>Confirm Password</label><input type="password" id="pw2" placeholder="Repeat password"><button onclick="go()">Create Account →</button><div class="msg" id="m"></div></div><script>async function go(){var p1=document.getElementById("pw1").value,p2=document.getElementById("pw2").value,m=document.getElementById("m");if(p1.length<8){m.className="msg err";m.textContent="Password must be at least 8 characters.";return}if(p1!==p2){m.className="msg err";m.textContent="Passwords do not match.";return}m.className="msg";m.textContent="Setting up...";var r=await fetch("/api/set-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:"' + token + '",password:p1})});var d=await r.json();if(d.ok){m.className="msg ok";m.textContent="Account created! Redirecting...";setTimeout(function(){window.location="/"},1800);}else{m.className="msg err";m.textContent=d.error||"Something went wrong.";}}</script></body></html>');
}

function isAdmin(email) {
  if (!email) return false;
  return readAdmins().map(e => e.toLowerCase()).includes(email.toLowerCase().trim());
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch(e) { reject(e); } });
    req.on('error', reject);
  });
}

// ── JSON RESPONSE ──────────────────────────────────────────
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

  // Public routes
  if (urlPath === '/api/pub-key') return json(res, 200, { key: STRIPE_PUB });
  if (urlPath === '/api/config')  return json(res, 200, { stripeKey: STRIPE_PUB, googleClientId: GOOGLE_CLIENT });

  // Public request submission
  if (urlPath === '/api/request' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email, name, type, details, sub } = body;
      if (!email || !details) return json(res, 400, { error: 'Missing fields' });
      const newReq = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        email, name: name || email, type: type || 'general', details, sub: sub || null,
        status: 'open', createdAt: new Date().toISOString(),
      };
      const reqs = readRequests();
      reqs.unshift(newReq);
      writeRequests(reqs);
      console.log('[Request submitted]', newReq.type, 'from', newReq.email);
      return json(res, 200, { ok: true, id: newReq.id });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  if (urlPath === '/api/client-status') {
    const qs = new URLSearchParams(req.url.split('?')[1] || '');
    const email = (qs.get('email') || '').toLowerCase().trim();
    if (!email) return json(res, 400, { error: 'email required' });
    const clients = readClients();
    return json(res, 200, { client: clients[email] || null });
  }

  // Client: fetch their own requests (with replies)
  if (urlPath === '/api/client-requests') {
    const qs = new URLSearchParams(req.url.split('?')[1] || '');
    const email = (qs.get('email') || '').toLowerCase().trim();
    if (!email) return json(res, 400, { error: 'email required' });
    const reqs = readRequests();
    const clientReqs = reqs.filter(r =>
      r.email && r.email.toLowerCase() === email && !r.deletedByClient
    );
    return json(res, 200, { requests: clientReqs });
  }

  // Client: add a reply to their own request
  if (urlPath === '/api/client-reply' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email, id, text } = body;
      if (!email || !id || !text) return json(res, 400, { error: 'Missing fields' });
      const reqs = readRequests();
      const idx = reqs.findIndex(r => r.id === id && r.email && r.email.toLowerCase() === email.toLowerCase());
      if (idx < 0) return json(res, 404, { error: 'Request not found' });
      if (!reqs[idx].replies) reqs[idx].replies = [];
      reqs[idx].replies.push({ text, from: 'client', createdAt: new Date().toISOString() });
      writeRequests(reqs);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  // Client: soft-delete their request
  if (urlPath === '/api/client-request' && req.method === 'DELETE') {
    try {
      const body = await parseBody(req);
      const { email, id } = body;
      if (!email || !id) return json(res, 400, { error: 'Missing fields' });
      const reqs = readRequests();
      const idx = reqs.findIndex(r => r.id === id && r.email && r.email.toLowerCase() === email.toLowerCase());
      if (idx < 0) return json(res, 404, { error: 'Request not found' });
      reqs[idx].deletedByClient = true;
      writeRequests(reqs);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  // Admin routes — all require adminEmail in body or query
  if (urlPath.startsWith('/api/admin/')) {
    let body = {};
    if (req.method === 'POST') {
      try { body = await parseBody(req); } catch(e) { return json(res, 400, { error: 'invalid json' }); }
    } else {
      const qs = new URLSearchParams(req.url.split('?')[1] || '');
      body = { adminEmail: qs.get('adminEmail') };
    }

    if (!isAdmin(body.adminEmail)) return json(res, 403, { error: 'Forbidden' });

    // GET /api/admin/data — return all clients + admin list
    if (urlPath === '/api/admin/data') {
      return json(res, 200, { clients: readClients(), admins: readAdmins(), primaryAdmin: PRIMARY_ADMIN });
    }

    // GET /api/admin/requests
    if (urlPath === '/api/admin/requests') {
      return json(res, 200, { requests: readRequests(), ownerEmail: OWNER_EMAIL });
    }

    // POST /api/admin/update-request
    if (urlPath === '/api/admin/update-request' && req.method === 'POST') {
      const { id, status } = body;
      const reqs = readRequests();
      const idx = reqs.findIndex(r => r.id === id);
      if (idx >= 0) { reqs[idx].status = status; reqs[idx].updatedAt = new Date().toISOString(); writeRequests(reqs); }
      return json(res, 200, { ok: true });
    }

    // POST /api/admin/reply-request — send in-app reply to client
    if (urlPath === '/api/admin/reply-request' && req.method === 'POST') {
      const { id, replyText } = body;
      if (!id || !replyText) return json(res, 400, { error: 'Missing fields' });
      const reqs = readRequests();
      const idx = reqs.findIndex(r => r.id === id);
      if (idx < 0) return json(res, 404, { error: 'Request not found' });
      if (!reqs[idx].replies) reqs[idx].replies = [];
      reqs[idx].replies.push({ text: replyText, from: 'admin', createdAt: new Date().toISOString() });
      writeRequests(reqs);
      return json(res, 200, { ok: true });
    }

    // POST /api/admin/set-client — add or update a client
    if (urlPath === '/api/admin/set-client' && req.method === 'POST') {
      const { targetEmail, name, sub, billing, packageType, notes } = body;
      if (!targetEmail) return json(res, 400, { error: 'targetEmail required' });
      const clients = readClients();
      const key = targetEmail.toLowerCase().trim();
      clients[key] = {
        name:        name        || clients[key]?.name || '',
        email:       key,
        sub:         sub         !== undefined ? sub         : (clients[key]?.sub || null),
        billing:     billing     !== undefined ? billing     : (clients[key]?.billing || 'monthly'),
        packageType: packageType !== undefined ? packageType : (clients[key]?.packageType || null),
        notes:       notes       !== undefined ? notes       : (clients[key]?.notes || ''),
        updatedAt:   new Date().toISOString(),
        addedAt:     clients[key]?.addedAt || new Date().toISOString(),
      };
      writeClients(clients);
      return json(res, 200, { ok: true, client: clients[key] });
    }

    // POST /api/admin/remove-client
    if (urlPath === '/api/admin/remove-client' && req.method === 'POST') {
      const { targetEmail } = body;
      if (!targetEmail) return json(res, 400, { error: 'targetEmail required' });
      const clients = readClients();
      delete clients[targetEmail.toLowerCase().trim()];
      writeClients(clients);
      return json(res, 200, { ok: true });
    }

    // POST /api/admin/add-admin — only primary admin can add admins
    if (urlPath === '/api/admin/add-admin' && req.method === 'POST') {
      if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) {
        return json(res, 403, { error: 'Only the primary admin can add developers' });
      }
      const { newEmail } = body;
      if (!newEmail) return json(res, 400, { error: 'newEmail required' });
      const admins = readAdmins();
      const key = newEmail.toLowerCase().trim();
      if (!admins.map(e => e.toLowerCase()).includes(key)) {
        admins.push(newEmail.trim());
        writeAdmins(admins);
      }
      return json(res, 200, { ok: true, admins });
    }

    // POST /api/admin/remove-admin
    if (urlPath === '/api/admin/remove-admin' && req.method === 'POST') {
      if (body.adminEmail.toLowerCase() !== PRIMARY_ADMIN.toLowerCase()) {
        return json(res, 403, { error: 'Only the primary admin can remove developers' });
      }
      const { targetEmail } = body;
      const admins = readAdmins().filter(e => e.toLowerCase() !== (targetEmail||'').toLowerCase() && e.toLowerCase() !== PRIMARY_ADMIN.toLowerCase());
      admins.unshift(PRIMARY_ADMIN);
      writeAdmins(admins);
      return json(res, 200, { ok: true, admins });
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
          success_url: 'http://localhost:' + PORT + '/?checkout=success',
          cancel_url:  'http://localhost:' + PORT + '/?checkout=cancel',
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

  // POST /api/register
  if (urlPath === '/api/register' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email } = body;
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, 400, { error: 'Valid email required' });
      const key = email.toLowerCase().trim();
      const users = readUsers();
      const token = crypto.randomBytes(32).toString('hex');
      users[key] = Object.assign(users[key] || {}, { email: key, verified: false, verifyToken: token, tokenExpiry: Date.now() + 86400000, createdAt: (users[key] || {}).createdAt || new Date().toISOString() });
      writeUsers(users);
      await sendVerificationEmail(key, token);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  // POST /api/set-password
  if (urlPath === '/api/set-password' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { token, password } = body;
      if (!token || !password || password.length < 8) return json(res, 400, { error: 'Invalid request' });
      const users = readUsers();
      const key = Object.keys(users).find(k => users[k].verifyToken === token);
      if (!key) return json(res, 400, { error: 'Invalid or expired link' });
      if (Date.now() > users[key].tokenExpiry) return json(res, 400, { error: 'Link expired — please register again' });
      users[key].password = await hashPassword(password);
      users[key].verified = true;
      users[key].verifyToken = null;
      users[key].tokenExpiry = null;
      writeUsers(users);
      return json(res, 200, { ok: true });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  // POST /api/login
  if (urlPath === '/api/login' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const { email, password } = body;
      if (!email || !password) return json(res, 400, { error: 'Email and password required' });
      const key = email.toLowerCase().trim();
      const users = readUsers();
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
function handler(req, res) {
  let urlPath = req.url.split('?')[0];
  if (urlPath.startsWith('/api/')) { handleAPI(req, res, urlPath); return; }
  if (urlPath === '/verify-email') {
    const qs = new URLSearchParams(req.url.split('?')[1] || '');
    const token = qs.get('token') || '';
    const users = readUsers();
    const user = Object.values(users).find(u => u.verifyToken === token);
    if (!user || !token || Date.now() > (user.tokenExpiry || 0)) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><head><title>Precision Workz</title></head><body style="font-family:sans-serif;background:#04040d;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0"><div style="text-align:center"><h2 style="margin-bottom:16px">Invalid or expired link.</h2><a href="/" style="color:#22d3ee">← Back to site</a></div></body></html>');
      return;
    }
    serveVerifyPage(res, token, user);
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
