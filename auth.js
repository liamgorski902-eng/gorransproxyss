'use strict';

const crypto = require('node:crypto');

const hmac = (secret, data) => crypto.createHmac('sha256', secret).update(data).digest('base64url');

/** Constant-time comparison that also hides length differences. */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function checkAccessCode(input, codes) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 200) return false;
  let ok = false;
  for (const code of codes) {
    if (safeEqual(input, code)) ok = true; // no early exit: constant work per code
  }
  return ok;
}

// ---- Sessions (stateless, HMAC-signed, stored in an HttpOnly cookie) ----

function issueSession(secret, ttlMs) {
  const payload = Buffer.from(
    JSON.stringify({ exp: Date.now() + ttlMs, n: crypto.randomBytes(8).toString('hex') }),
  ).toString('base64url');
  return `${payload}.${hmac(secret, 'session.' + payload)}`;
}

function verifySession(secret, token) {
  if (typeof token !== 'string') return false;
  const [payload, sig] = token.split('.');
  if (!payload || !sig || !safeEqual(sig, hmac(secret, 'session.' + payload))) return false;
  try {
    const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return typeof exp === 'number' && exp > Date.now();
  } catch {
    return false;
  }
}

// ---- Signed proxy URLs (so the sandboxed viewer needs no cookies) ----

/** kind: "v" (page view) or "a" (asset). Returns a same-origin path. */
function signProxyPath(secret, kind, targetUrl, ttlMs) {
  const exp = Date.now() + ttlMs;
  const sig = hmac(secret, `${kind}|${exp}|${targetUrl}`);
  const q = new URLSearchParams({ u: targetUrl, e: String(exp), s: sig });
  return `/p/${kind}?${q}`;
}

/** Returns the target URL string if the signature is valid and fresh, else null. */
function verifyProxyParams(secret, kind, params) {
  const u = params.get('u');
  const e = params.get('e');
  const s = params.get('s');
  if (!u || !e || !s || u.length > 2048) return null;
  const exp = Number(e);
  if (!Number.isFinite(exp) || exp < Date.now()) return null;
  return safeEqual(s, hmac(secret, `${kind}|${exp}|${u}`)) ? u : null;
}

// ---- Cookies ----

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function sessionCookie(token, { maxAgeSec, secure }) {
  return [
    `gp_session=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSec}`,
    secure ? 'Secure' : '',
  ]
    .filter(Boolean)
    .join('; ');
}

module.exports = {
  checkAccessCode,
  issueSession,
  verifySession,
  signProxyPath,
  verifyProxyParams,
  parseCookies,
  sessionCookie,
};
