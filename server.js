'use strict';

const http = require('node:http');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const zlib = require('node:zlib');

const { getConfig } = require('./lib/config');
const { ProxyError, parseTarget } = require('./lib/netguard');
const { fetchSafe, decodeBody } = require('./lib/fetcher');
const { rewriteHtml, rewriteCss, escapeHtml } = require('./lib/rewrite');
const { RateLimiter, ConcurrencyGate } = require('./lib/ratelimit');
const auth = require('./lib/auth');

const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};
const COMPRESSIBLE = new Set(['.html', '.css', '.js', '.svg', '.json', '.webmanifest']);

// CSP for the app itself, and a much stricter one for anything that came from upstream.
const APP_CSP =
  "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; " +
  "frame-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const UPSTREAM_CSP =
  "sandbox; default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
  "font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'";

function createApp(cfg = getConfig()) {
  const generalLimiter = new RateLimiter({ limit: cfg.generalPerMin, windowMs: 60_000 });
  const proxyLimiter = new RateLimiter({ limit: cfg.proxyUnitsPerMin, windowMs: 60_000 });
  const loginLimiter = new RateLimiter({ limit: cfg.loginAttempts, windowMs: 10 * 60_000 });
  const gate = new ConcurrencyGate({ perKey: cfg.maxInFlightPerIp, global: cfg.maxInFlightGlobal });
  const gzipCache = new Map();

  // ---------- helpers ----------
  function clientIp(req) {
    if (cfg.trustProxyHops > 0) {
      const xff = String(req.headers['x-forwarded-for'] || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const candidate = xff[xff.length - cfg.trustProxyHops];
      if (candidate && net.isIP(candidate)) return candidate;
    }
    return req.socket.remoteAddress || 'unknown';
  }

  function isSecure(req) {
    return cfg.isProd || (cfg.trustProxyHops > 0 && req.headers['x-forwarded-proto'] === 'https');
  }

  function baseHeaders(extra = {}) {
    return {
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Cross-Origin-Opener-Policy': 'same-origin',
      ...extra,
    };
  }

  function sendJson(res, status, body, extra = {}) {
    const data = JSON.stringify(body);
    res.writeHead(
      status,
      baseHeaders({
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(data),
        'Cache-Control': 'no-store',
        'Content-Security-Policy': APP_CSP,
        ...extra,
      }),
    );
    res.end(data);
  }

  function readJson(req) {
    return new Promise((resolve, reject) => {
      if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) {
        return reject(new ProxyError(415, 'Expected JSON.', 'bad_type'));
      }
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > 4096) {
          req.destroy();
          reject(new ProxyError(413, 'Request too large.', 'too_large'));
        } else chunks.push(c);
      });
      req.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
        } catch {
          reject(new ProxyError(400, 'Invalid JSON.', 'bad_json'));
        }
      });
      req.on('error', () => reject(new ProxyError(400, 'Request aborted.', 'aborted')));
    });
  }

  /** CSRF defence for state-changing calls: custom header + same-origin Origin. */
  function assertSameOrigin(req) {
    if (req.headers['x-requested-with'] !== 'gorransproxy') {
      throw new ProxyError(403, 'Missing request header.', 'csrf');
    }
    const origin = req.headers.origin;
    if (origin) {
      let host;
      try {
        host = new URL(origin).host;
      } catch {
        host = '';
      }
      if (host !== req.headers.host) throw new ProxyError(403, 'Cross-origin request refused.', 'csrf');
    }
  }

  function isAuthed(req) {
    const token = auth.parseCookies(req.headers.cookie).gp_session;
    return auth.verifySession(cfg.secret, token);
  }

  function signedPath(kind, absUrl) {
    return auth.signProxyPath(cfg.secret, kind, absUrl, cfg.signedUrlTtlMs);
  }

  /** Used by the HTML rewriter: only allowlisted destinations get a signed URL. */
  function signIfAllowed(kind, absUrl) {
    try {
      parseTarget(absUrl, cfg);
    } catch {
      return null;
    }
    return signedPath(kind, absUrl);
  }

  function logProxy(kind, target, status, startedAt) {
    let host = '-';
    try {
      host = new URL(target).hostname;
    } catch {
      /* ignore */
    }
    console.log(`${new Date().toISOString()} ${kind} ${host} ${status} ${Date.now() - startedAt}ms`);
  }

  function errorPage(res, status, message) {
    const html =
      '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<style>body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f4f5f7;color:#1d2330}' +
      'main{max-width:30rem;margin:1rem;padding:1.5rem 1.75rem;background:#fff;border:1px solid #e3e5e9;border-top:4px solid #dc143c;border-radius:12px}' +
      'h1{margin:0 0 .5rem;font-size:1.25rem}p{margin:0;color:#555}</style>' +
      `<main><h1>Bobr says no 🦫</h1><p>${escapeHtml(message)}</p></main>`;
    res.writeHead(
      status,
      baseHeaders({
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Content-Security-Policy': UPSTREAM_CSP,
      }),
    );
    res.end(html);
  }

  // ---------- API ----------
  async function handleApi(req, res, url, ip) {
    const route = `${req.method} ${url.pathname}`;

    if (route === 'GET /api/config') {
      return sendJson(res, 200, {
        proxyEnabled: cfg.accessCodes.length > 0,
        authenticated: isAuthed(req),
        allowedHosts: cfg.allowedHosts,
      });
    }

    if (route === 'POST /api/login') {
      assertSameOrigin(req);
      if (cfg.accessCodes.length === 0) {
        throw new ProxyError(503, 'Proxy Mode is not configured on this server.', 'disabled');
      }
      const limit = loginLimiter.hit(ip);
      if (!limit.allowed) {
        throw Object.assign(new ProxyError(429, 'Too many attempts. Try again later.', 'rate_limited'), {
          retryAfterSec: limit.retryAfterSec,
        });
      }
      const body = await readJson(req);
      if (!auth.checkAccessCode(body.code, cfg.accessCodes)) {
        throw new ProxyError(401, 'That access code is not correct.', 'bad_code');
      }
      const token = auth.issueSession(cfg.secret, cfg.sessionTtlMs);
      return sendJson(
        res,
        200,
        { ok: true },
        {
          'Set-Cookie': auth.sessionCookie(token, {
            maxAgeSec: Math.floor(cfg.sessionTtlMs / 1000),
            secure: isSecure(req),
          }),
        },
      );
    }

    if (route === 'POST /api/logout') {
      assertSameOrigin(req);
      return sendJson(
        res,
        200,
        { ok: true },
        { 'Set-Cookie': auth.sessionCookie('', { maxAgeSec: 0, secure: isSecure(req) }) },
      );
    }

    if (route === 'POST /api/proxy/open') {
      assertSameOrigin(req);
      if (cfg.accessCodes.length === 0) {
        throw new ProxyError(503, 'Proxy Mode is not configured on this server.', 'disabled');
      }
      if (!isAuthed(req)) throw new ProxyError(401, 'Please sign in first.', 'auth_required');
      const limit = proxyLimiter.hit(ip, 1);
      if (!limit.allowed) {
        throw Object.assign(new ProxyError(429, 'Slow down a little.', 'rate_limited'), {
          retryAfterSec: limit.retryAfterSec,
        });
      }
      const body = await readJson(req);
      const target = parseTarget(body.url, cfg); // validates scheme, port, SSRF rules, allowlist
      return sendJson(res, 200, { viewUrl: signedPath('v', target.href), target: target.href });
    }

    throw new ProxyError(404, 'Not found.', 'not_found');
  }

  // ---------- Proxy output ----------
  async function handleProxy(req, res, url, ip) {
    const kind = url.pathname === '/p/v' ? 'v' : url.pathname === '/p/a' ? 'a' : null;
    if (!kind || req.method !== 'GET') return errorPage(res, 404, 'Not found.');

    const target = auth.verifyProxyParams(cfg.secret, kind, url.searchParams);
    if (!target) return errorPage(res, 403, 'This link has expired. Open the page again from the home screen.');

    const limit = proxyLimiter.hit(ip, kind === 'v' ? 6 : 1);
    if (!limit.allowed) {
      res.setHeader('Retry-After', String(limit.retryAfterSec));
      return errorPage(res, 429, 'Too many requests. Please wait a moment.');
    }
    const release = gate.enter(ip);
    if (!release) return errorPage(res, 429, 'Too many pages are loading at once.');

    const startedAt = Date.now();
    try {
      if (kind === 'v') {
        const r = await fetchSafe(target, cfg, {
          accept: 'text/html,application/xhtml+xml,text/plain;q=0.8',
          types: [/^text\/html$/, /^application\/xhtml\+xml$/, /^text\/plain$/],
        });
        const text = decodeBody(r.body, r.contentType);
        const html =
          r.type === 'text/plain'
            ? `<!doctype html><meta charset="utf-8"><pre style="white-space:pre-wrap">${escapeHtml(text)}</pre>`
            : rewriteHtml(text, r.url.href, signIfAllowed);
        res.writeHead(
          200,
          baseHeaders({
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Security-Policy': UPSTREAM_CSP,
            'Cache-Control': 'private, no-store',
            'X-Robots-Tag': 'noindex',
          }),
        );
        res.end(html);
        return logProxy('view', target, 200, startedAt);
      }

      const r = await fetchSafe(target, cfg, {
        accept: 'image/*,text/css,font/*,*/*;q=0.1',
        types: [/^image\/(png|jpe?g|gif|webp|avif|svg\+xml|x-icon|vnd\.microsoft\.icon)$/, /^text\/css$/, /^font\//, /^application\/(font-woff2?|x-font-(woff|ttf|otf)|vnd\.ms-fontobject)$/],
      });
      let body = r.body;
      if (r.type === 'text/css') {
        body = Buffer.from(rewriteCss(decodeBody(r.body, r.contentType), r.url.href, signIfAllowed), 'utf8');
      }
      res.writeHead(
        200,
        baseHeaders({
          'Content-Type': r.type === 'text/css' ? 'text/css; charset=utf-8' : r.type,
          'Content-Length': body.length,
          'Content-Security-Policy': UPSTREAM_CSP,
          'Cache-Control': 'private, max-age=300',
          'Access-Control-Allow-Origin': '*',
          'Cross-Origin-Resource-Policy': 'cross-origin',
        }),
      );
      res.end(body);
      return logProxy('asset', target, 200, startedAt);
    } catch (err) {
      const status = err instanceof ProxyError ? err.status : 502;
      const message = err instanceof ProxyError ? err.message : 'Something went wrong fetching that page.';
      logProxy(kind === 'v' ? 'view' : 'asset', target, status, startedAt);
      if (kind === 'a') {
        res.writeHead(status, baseHeaders({ 'Content-Type': 'text/plain; charset=utf-8', 'Content-Security-Policy': UPSTREAM_CSP }));
        return res.end(message);
      }
      return errorPage(res, status, message);
    } finally {
      release();
    }
  }

  // ---------- Static files ----------
  function serveStatic(req, res, url) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, baseHeaders({ Allow: 'GET, HEAD' }));
      return res.end();
    }
    let rel;
    try {
      rel = decodeURIComponent(url.pathname);
    } catch {
      res.writeHead(400, baseHeaders());
      return res.end();
    }
    if (rel.endsWith('/')) rel += 'index.html';
    const file = path.normalize(path.join(PUBLIC_DIR, rel));
    if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep)) {
      res.writeHead(403, baseHeaders());
      return res.end();
    }
    fs.stat(file, (err, stat) => {
      if (err || !stat.isFile()) {
        res.writeHead(404, baseHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }));
        return res.end('Nie ma takiej strony - 404');
      }
      const ext = path.extname(file).toLowerCase();
      const type = MIME[ext] || 'application/octet-stream';
      const isHtml = ext === '.html';
      const headers = baseHeaders({
        'Content-Type': type,
        'Cache-Control': isHtml ? 'no-cache' : 'public, max-age=3600',
        'Content-Security-Policy': APP_CSP,
        Vary: 'Accept-Encoding',
      });
      const wantsGzip = COMPRESSIBLE.has(ext) && /\bgzip\b/.test(req.headers['accept-encoding'] || '');
      if (!wantsGzip) {
        headers['Content-Length'] = stat.size;
        res.writeHead(200, headers);
        return req.method === 'HEAD' ? res.end() : fs.createReadStream(file).pipe(res);
      }
      const key = `${file}:${stat.mtimeMs}`;
      let gz = gzipCache.get(key);
      if (!gz) {
        gz = zlib.gzipSync(fs.readFileSync(file), { level: 9 });
        gzipCache.set(key, gz);
      }
      headers['Content-Encoding'] = 'gzip';
      headers['Content-Length'] = gz.length;
      res.writeHead(200, headers);
      return res.end(req.method === 'HEAD' ? undefined : gz);
    });
  }

  // ---------- Router ----------
  const server = http.createServer(async (req, res) => {
    const ip = clientIp(req);
    try {
      const url = new URL(req.url, 'http://localhost');

      if (url.pathname === '/healthz') return sendJson(res, 200, { ok: true });

      const general = generalLimiter.hit(ip);
      if (!general.allowed) {
        res.setHeader('Retry-After', String(general.retryAfterSec));
        return sendJson(res, 429, { error: 'Too many requests.', code: 'rate_limited' });
      }

      if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url, ip);
      if (url.pathname.startsWith('/p/')) return await handleProxy(req, res, url, ip);
      return serveStatic(req, res, url);
    } catch (err) {
      const known = err instanceof ProxyError;
      if (!known) console.error(err);
      if (res.headersSent) return res.destroy();
      const extra = err.retryAfterSec ? { 'Retry-After': String(err.retryAfterSec) } : {};
      return sendJson(
        res,
        known ? err.status : 500,
        { error: known ? err.message : 'Internal error.', code: known ? err.code : 'internal' },
        extra,
      );
    }
  });

  server.requestTimeout = 20_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  server.on('close', () => {
    generalLimiter.close();
    proxyLimiter.close();
    loginLimiter.close();
  });
  return server;
}

module.exports = { createApp };

if (require.main === module) {
  const cfg = getConfig();
  const server = createApp(cfg);
  server.listen(cfg.port, cfg.host, () => {
    console.log(`Gorransproxy listening on http://localhost:${cfg.port}`);
    if (cfg.accessCodes.length === 0) {
      console.warn('! ACCESS_CODES is empty: Proxy Mode is disabled until you set it (see README).');
    }
    if (cfg.secretIsEphemeral) {
      console.warn('! SESSION_SECRET missing/short: using a temporary secret; sign-ins reset on restart.');
    }
    console.log(`Allowed destinations: ${cfg.allowedHosts.join(', ')}`);
  });
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
