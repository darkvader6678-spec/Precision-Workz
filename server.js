'use strict';
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

  return json(res, 404, { error: 'not found' });
}

// ── HTTP SERVER ────────────────────────────────────────────
http.createServer(function(req, res) {
  let urlPath = req.url.split('?')[0];
  if (urlPath.startsWith('/api/')) { handleAPI(req, res, urlPath); return; }
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
}).listen(PORT, function() {
  console.log('Precision Workz running on http://localhost:' + PORT);
});
