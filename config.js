'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Tiny .env loader so the project needs no dependencies.
function loadDotEnv(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return;
  }
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*(#|$)/.test(line)) continue;
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m) continue;
    let value = m[2];
    if (/^(["']).*\1$/.test(value)) value = value.slice(1, -1);
    if (process.env[m[1]] === undefined) process.env[m[1]] = value;
  }
}
loadDotEnv(path.join(__dirname, '..', '.env'));

const DEFAULT_ALLOWED_HOSTS = [
  'wikipedia.org',
  'wikimedia.org',
  'wikisource.org',
  'wolnelektury.pl',
  'gutenberg.org',
  'gov.pl',
  'example.com',
  'example.org',
];

const toList = (value, fallback) =>
  String(value ?? fallback)
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

const toInt = (value, fallback, min, max) => {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
};

let ephemeralSecret = null;

function getConfig(env = process.env) {
  let secret = env.SESSION_SECRET || '';
  let secretIsEphemeral = false;
  if (secret.length < 32) {
    // Sessions will not survive a restart, but we never run with a weak secret.
    ephemeralSecret ??= crypto.randomBytes(32).toString('hex');
    secret = ephemeralSecret;
    secretIsEphemeral = true;
  }

  const allowedHosts = toList(env.ALLOWED_HOSTS, DEFAULT_ALLOWED_HOSTS.join(','))
    // Must look like a real domain: no wildcards, no bare TLDs, no IPs-with-ports.
    .filter((h) => h !== '*' && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h));

  return {
    port: toInt(env.PORT, 3000, 1, 65535),
    host: env.HOST || '0.0.0.0',
    isProd: env.NODE_ENV === 'production',
    secret,
    secretIsEphemeral,
    accessCodes: String(env.ACCESS_CODES || '')
      .split(',')
      .map((s) => s.trim())
      .filter((c) => c.length >= 8),
    allowedHosts,
    trustProxyHops: toInt(env.TRUST_PROXY_HOPS, 0, 0, 5),
    proxyUnitsPerMin: toInt(env.PROXY_UNITS_PER_MIN, 240, 20, 5000),
    loginAttempts: toInt(env.LOGIN_ATTEMPTS_PER_10_MIN, 8, 3, 100),
    generalPerMin: 300,
    maxInFlightPerIp: 6,
    maxInFlightGlobal: 40,
    maxBytes: 5 * 1024 * 1024,
    timeoutMs: 10_000,
    maxRedirects: 5,
    signedUrlTtlMs: 30 * 60 * 1000,
    sessionTtlMs: 12 * 60 * 60 * 1000,
  };
}

module.exports = { getConfig, DEFAULT_ALLOWED_HOSTS };
