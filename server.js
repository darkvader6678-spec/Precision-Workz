'use strict';
const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT = process.env.PORT || 4000;
const DIR  = __dirname;

const MIME = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.woff2':'font/woff2',
};

http.createServer(function(req, res) {
  let urlPath = req.url.split('?')[0];
  if (urlPath === '/' || urlPath === '') urlPath = '/index.html';

  const filePath = path.join(DIR, urlPath);
  const ext      = path.extname(filePath);
  const mime     = MIME[ext] || 'text/plain';

  fs.readFile(filePath, function(err, data) {
    if (err) {
      fs.readFile(path.join(DIR, 'index.html'), function(e2, d2) {
        if (e2) { res.writeHead(404); res.end('Not found'); return; }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(d2);
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}).listen(PORT, function() {
  console.log('Precision Workz running on port ' + PORT);
});
