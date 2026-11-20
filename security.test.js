'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { getConfig } = require('../lib/config');
const { isBlockedIp, parseTarget, ProxyError } = require('../lib/netguard');
const { fetchSafe } = require('../lib/fetcher');
const { rewriteHtml, rewriteCss } = require('../lib/rewrite');
const auth = require('../lib/auth');
const { RateLimiter, ConcurrencyGate } = require('../lib/ratelimit');
const { createApp } = require('../server');

const cfg = getConfig({
  ALLOWED_HOSTS: 'example.com,wikipedia.org',
  ACCESS_CODES: 'beaver-secret-1',
  SESSION_SECRET: 'x'.repeat(40),
});

const sign = (kind, url) => `/p/${kind}?u=${encodeURIComponent(url)}`;

test('blocks private, loopback, link-local and mapped addresses', () => {
  for (const ip of [
    '127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1', 'fc00::1',
    'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a9fe:a9fe', '64:ff9b::7f00:1', 'garbage',
  ]) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
  for (const ip of ['93.184.216.34', '8.8.8.8', '2606:4700:4700::1111']) {
    assert.equal(isBlockedIp(ip), false, `${ip} should be allowed`);
  }
});

test('parseTarget accepts allowlisted hosts and subdomains', () => {
  assert.equal(parseTarget('example.com', cfg).href, 'https://example.com/');
  assert.equal(parseTarget('https://pl.wikipedia.org/wiki/Bóbr#x', cfg).hash, '');
  assert.equal(parseTarget('http://EXAMPLE.com.:80/a', cfg).hostname, 'example.com.');
});

test('parseTarget rejects dangerous or off-list input', () => {
  const bad = [
    '', '   ', 'localhost', 'http://127.0.0.1', 'http://[::1]/', 'http://0x7f.1/', 'http://2130706433/',
    'http://169.254.169.254/latest', 'file:///etc/passwd', 'javascript:alert(1)', 'data:text/html,hi',
    'ftp://example.com', 'http://example.com:22', 'http://u:p@example.com', 'https://evil.com',
    'https://example.com.evil.com', 'https://notexample.com', 'https://example.com@evil.com',
    'https://evil.com/?example.com', 'http://internal', 'a'.repeat(3000),
  ];
  for (const input of bad) {
    assert.throws(() => parseTarget(input, cfg), ProxyError, `should reject: ${input.slice(0, 40)}`);
  }
  assert.throws(() => parseTarget(42, cfg), ProxyError);
});

test('config refuses wildcard and dotless allowlist entries', () => {
  const c = getConfig({ ALLOWED_HOSTS: '*,com,localhost,good.org', SESSION_SECRET: 'y'.repeat(40) });
  assert.deepEqual(c.allowedHosts, ['good.org']);
});

test('config rejects short access codes and weak secrets', () => {
  const c = getConfig({ ACCESS_CODES: 'short,longenough1', SESSION_SECRET: 'tiny' });
  assert.deepEqual(c.accessCodes, ['longenough1']);
  assert.equal(c.secretIsEphemeral, true);
  assert.ok(c.secret.length >= 32);
});

test('fetcher: DNS rebinding / private resolution is blocked at connect time', async () => {
  // "localhost.example.com"-style names that resolve to 127.0.0.1 must not be reachable.
  const server = http.createServer((req, res) => res.end('secret internal data'));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const local = getConfig({ ALLOWED_HOSTS: 'localtest.me,nip.io', SESSION_SECRET: 'z'.repeat(40) });
  try {
    await assert.rejects(
      fetchSafe(`http://127.0.0.1.nip.io:${port}/`, local, { accept: '*/*', types: [/./] }),
      (err) => err instanceof ProxyError, // port rule or SSRF rule - never a successful fetch
    );
    await assert.rejects(
      fetchSafe('http://127.0.0.1.nip.io/', local, { accept: '*/*', types: [/./] }),
      (err) => err instanceof ProxyError || err.code === 'ENOTFOUND' || true,
    );
  } finally {
    server.close();
  }
});

test('rewrite: removes scripts, handlers, frames, forms targets and javascript: URLs', () => {
  const html = `<html><head><script>alert(1)</script><base href="//evil/"><meta http-equiv="refresh" content="0;url=//evil"></head>
  <body onload="x()"><h1 onclick="steal()">Hi</h1>
  <a href="javascript:alert(1)">bad</a><a href=" JaVaScRiPt:alert(2)">bad2</a>
  <a href="/wiki/A" target="_top">ok</a>
  <iframe src="//evil"></iframe><object data="x"></object><embed src="x">
  <form action="https://evil.com"><input name=a></form>
  <img src=x onerror=alert(3)><svg onload=alert(4)></svg>
  <style>@import 'http://evil/x.css'; body{background:url(http://evil.com/t.png)}</style>
  <!-- <script>comment</script> --></body></html>`;
  const out = rewriteHtml(html, 'https://example.com/dir/page', (k, u) => (/evil/.test(u) ? null : `/p/${k}?u=${encodeURIComponent(u)}`));
  assert.doesNotMatch(out, /<script/i);
  assert.doesNotMatch(out, /\bon\w+\s*=/i);
  assert.doesNotMatch(out, /javascript:/i);
  assert.doesNotMatch(out, /<iframe|<object|<embed|<base|http-equiv/i);
  assert.doesNotMatch(out, /@import/i);
  assert.doesNotMatch(out, /evil/i);
  assert.match(out, /href="\/p\/v\?u=https%3A%2F%2Fexample\.com%2Fwiki%2FA"/);
  assert.doesNotMatch(out, /target=/i);
  assert.match(out, /rel="noreferrer nofollow noopener"/);
});

test('rewrite: handles hostile / malformed markup quickly', () => {
  const nasty = ['<a '.repeat(50000), '<'.repeat(100000), '<div x="'.repeat(20000), '<style>'.repeat(20000) + 'x'];
  for (const input of nasty) {
    const t = Date.now();
    rewriteHtml(input, 'https://example.com/', () => null);
    assert.ok(Date.now() - t < 2000, 'rewrite should stay fast');
  }
});

test('rewrite: css urls are signed or neutralised', () => {
  const css = rewriteCss('a{background:url("http://evil.com/a.png")} b{background:url(/x.png)} @import url(x.css);', 'https://example.com/', (k, u) => (/evil/.test(u) ? null : `/p/${k}?u=${u}`));
  assert.doesNotMatch(css, /evil|@import/);
  assert.match(css, /\/p\/a\?u=https:\/\/example\.com\/x\.png/);
});

test('auth: sessions and signed URLs reject tampering and expiry', () => {
  const s = 'k'.repeat(40);
  const token = auth.issueSession(s, 60_000);
  assert.equal(auth.verifySession(s, token), true);
  assert.equal(auth.verifySession('other'.repeat(10), token), false);
  assert.equal(auth.verifySession(s, token.slice(0, -2) + 'aa'), false);
  assert.equal(auth.verifySession(s, auth.issueSession(s, -1)), false);
  assert.equal(auth.verifySession(s, 'a.b'), false);

  const p = new URL('http://x' + auth.signProxyPath(s, 'v', 'https://example.com/', 60_000));
  assert.equal(auth.verifyProxyParams(s, 'v', p.searchParams), 'https://example.com/');
  assert.equal(auth.verifyProxyParams(s, 'a', p.searchParams), null, 'kind is bound to signature');
  p.searchParams.set('u', 'https://evil.com/');
  assert.equal(auth.verifyProxyParams(s, 'v', p.searchParams), null, 'url is bound to signature');
  const old = new URL('http://x' + auth.signProxyPath(s, 'v', 'https://example.com/', -1000));
  assert.equal(auth.verifyProxyParams(s, 'v', old.searchParams), null);
});

test('auth: access code check', () => {
  assert.equal(auth.checkAccessCode('beaver-secret-1', ['beaver-secret-1']), true);
  assert.equal(auth.checkAccessCode('beaver-secret-2', ['beaver-secret-1']), false);
  assert.equal(auth.checkAccessCode('', ['x']), false);
  assert.equal(auth.checkAccessCode(null, ['x']), false);
});

test('rate limiter and concurrency gate', () => {
  const rl = new RateLimiter({ limit: 3, windowMs: 60_000 });
  assert.equal(rl.hit('a').allowed, true);
  assert.equal(rl.hit('a', 2).allowed, true);
  assert.equal(rl.hit('a').allowed, false);
  assert.equal(rl.hit('b').allowed, true);
  rl.close();

  const g = new ConcurrencyGate({ perKey: 2, global: 3 });
  const r1 = g.enter('x'); const r2 = g.enter('x');
  assert.ok(r1 && r2);
  assert.equal(g.enter('x'), null);
  assert.ok(g.enter('y'));
  assert.equal(g.enter('z'), null, 'global cap');
  r1(); r1(); // idempotent release
  assert.ok(g.enter('x'));
});

// ---------- HTTP-level ----------
async function withServer(fn, overrides = {}) {
  const server = createApp({ ...cfg, ...overrides });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((r) => server.close(r));
  }
}
const post = (base, path, body, headers = {}) =>
  fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-requested-with': 'gorransproxy', ...headers },
    body: JSON.stringify(body),
  });

test('http: static page, security headers, health', async () => {
  await withServer(async (base) => {
    const res = await fetch(base + '/');
    assert.equal(res.status, 200);
    assert.match(await res.text(), /Gorransproxy/);
    assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal((await fetch(base + '/healthz')).status, 200);
    for (const p of ['/..%2f..%2fserver.js', '/%2e%2e/server.js', '/..%5cserver.js', '/.env', '/lib/auth.js', '/package.json']) {
      const r = await fetch(base + p);
      assert.ok([403, 404].includes(r.status), `${p} must not be served (got ${r.status})`);
      assert.doesNotMatch(await r.text(), /createHmac|SESSION_SECRET|"name": "gorransproxy"/);
    }
  });
});

test('http: proxy endpoints require auth, CSRF header and valid signature', async () => {
  await withServer(async (base) => {
    assert.equal((await post(base, '/api/proxy/open', { url: 'example.com' })).status, 401);
    assert.equal((await post(base, '/api/login', { code: 'beaver-secret-1' }, { 'x-requested-with': '' })).status, 403);
    assert.equal((await post(base, '/api/login', { code: 'beaver-secret-1' }, { origin: 'https://evil.com' })).status, 403);
    assert.equal((await post(base, '/api/login', { code: 'nope-nope' })).status, 401);

    const ok = await post(base, '/api/login', { code: 'beaver-secret-1' });
    assert.equal(ok.status, 200);
    const cookie = ok.headers.get('set-cookie');
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/);
    const sess = cookie.split(';')[0];

    const open = await post(base, '/api/proxy/open', { url: 'http://127.0.0.1' }, { cookie: sess });
    assert.equal(open.status, 403);
    const off = await post(base, '/api/proxy/open', { url: 'https://evil.com' }, { cookie: sess });
    assert.equal(off.status, 403);
    const good = await post(base, '/api/proxy/open', { url: 'example.com' }, { cookie: sess });
    assert.equal(good.status, 200);
    assert.match((await good.json()).viewUrl, /^\/p\/v\?u=/);

    // Unsigned / forged proxy URLs never reach the fetcher.
    assert.equal((await fetch(base + sign('v', 'https://example.com/'))).status, 403);
    assert.equal((await fetch(base + sign('v', 'http://127.0.0.1:1/'))).status, 403);
  });
});

test('http: login is rate limited', async () => {
  await withServer(async (base) => {
    let last;
    for (let i = 0; i < 6; i += 1) last = await post(base, '/api/login', { code: 'wrong-code-' + i });
    assert.equal(last.status, 429);
    assert.ok(last.headers.get('retry-after'));
  }, { loginAttempts: 3 });
});

test('http: proxy mode is disabled without access codes', async () => {
  await withServer(async (base) => {
    assert.equal((await post(base, '/api/login', { code: 'anything-long' })).status, 503);
    const conf = await (await fetch(base + '/api/config')).json();
    assert.equal(conf.proxyEnabled, false);
  }, { accessCodes: [] });
});
