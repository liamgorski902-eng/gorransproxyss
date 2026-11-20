'use strict';

const http = require('node:http');
const https = require('node:https');
const { ProxyError, safeLookup, parseTarget } = require('./netguard');

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

function requestOnce(url, cfg, accept) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || undefined,
        path: url.pathname + url.search,
        method: 'GET',
        lookup: safeLookup, // SSRF guard: validates the IP we actually connect to
        agent: false,
        timeout: cfg.timeoutMs,
        headers: {
          'user-agent': 'Gorransproxy/1.0 (+beaver)',
          accept,
          'accept-encoding': 'identity',
          'accept-language': 'en,pl;q=0.8',
          connection: 'close',
          // Deliberately NOT forwarded: cookies, authorization, referer, client IP.
        },
      },
      resolve,
    );
    req.on('timeout', () =>
      req.destroy(new ProxyError(504, 'The site took too long to respond.', 'timeout')),
    );
    req.on('error', (err) => {
      if (err instanceof ProxyError) return reject(err);
      if (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
        return reject(new ProxyError(502, 'That site could not be found.', 'dns'));
      }
      return reject(new ProxyError(502, 'Could not connect to that site.', 'connect'));
    });
    req.end();
  });
}

function readBody(res, maxBytes) {
  return new Promise((resolve, reject) => {
    const declared = Number(res.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      res.destroy();
      return reject(new ProxyError(413, 'That page is too large.', 'too_large'));
    }
    const chunks = [];
    let size = 0;
    const deadline = setTimeout(() => {
      res.destroy();
      reject(new ProxyError(504, 'The site took too long to send the page.', 'timeout'));
    }, 20_000);
    res.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        clearTimeout(deadline);
        res.destroy();
        return reject(new ProxyError(413, 'That page is too large.', 'too_large'));
      }
      chunks.push(chunk);
    });
    res.on('end', () => {
      clearTimeout(deadline);
      resolve(Buffer.concat(chunks));
    });
    res.on('error', () => {
      clearTimeout(deadline);
      reject(new ProxyError(502, 'The connection was interrupted.', 'connect'));
    });
  });
}

/**
 * GETs a URL with all protections applied. Redirects are followed manually so that every
 * hop is re-validated. `opts.accept` is the Accept header; `opts.types` is a list of
 * RegExps the response Content-Type must match.
 */
async function fetchSafe(rawUrl, cfg, opts) {
  let url = parseTarget(rawUrl, cfg);

  for (let hop = 0; hop <= cfg.maxRedirects; hop += 1) {
    const res = await requestOnce(url, cfg, opts.accept);
    const status = res.statusCode;

    if (REDIRECTS.has(status)) {
      res.resume();
      const location = res.headers.location;
      if (!location) throw new ProxyError(502, 'The site sent a broken redirect.', 'redirect');
      let next;
      try {
        next = new URL(location, url);
      } catch {
        throw new ProxyError(502, 'The site sent a broken redirect.', 'redirect');
      }
      url = parseTarget(next.href, cfg); // re-validate every hop
      continue;
    }

    if (status >= 400) {
      res.resume();
      throw new ProxyError(502, `The site responded with HTTP ${status}.`, 'upstream_status');
    }

    const contentType = String(res.headers['content-type'] || '');
    const type = contentType.split(';')[0].trim().toLowerCase();
    if (!opts.types.some((re) => re.test(type))) {
      res.resume();
      throw new ProxyError(415, 'This kind of content cannot be shown in the viewer.', 'bad_type');
    }
    const encoding = String(res.headers['content-encoding'] || 'identity').toLowerCase();
    if (encoding !== 'identity') {
      res.resume();
      throw new ProxyError(502, 'The site sent compressed data we cannot read.', 'encoding');
    }

    const body = await readBody(res, cfg.maxBytes);
    return { status, type, contentType, body, url };
  }
  throw new ProxyError(508, 'Too many redirects.', 'redirect');
}

function decodeBody(buffer, contentType) {
  let label = (/charset\s*=\s*["']?([\w-]+)/i.exec(contentType || '') || [])[1];
  if (!label) {
    const head = buffer.subarray(0, 2048).toString('latin1');
    label = (/<meta[^>]+charset\s*=\s*["']?([\w-]+)/i.exec(head) || [])[1] || 'utf-8';
  }
  try {
    return new TextDecoder(label).decode(buffer);
  } catch {
    return new TextDecoder('utf-8').decode(buffer);
  }
}

module.exports = { fetchSafe, decodeBody };
