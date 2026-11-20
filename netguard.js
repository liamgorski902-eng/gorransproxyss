'use strict';

/**
 * SSRF protection.
 *
 * Three independent layers:
 *  1. parseTarget():  scheme, port, credentials, IP-literal and allowlist checks.
 *  2. safeLookup():   every DNS answer is checked against private/reserved ranges at
 *                     connection time. Because the socket connects to the very address
 *                     we validated, DNS rebinding cannot swap in an internal IP.
 *  3. fetcher.js:     every redirect hop goes through layers 1 and 2 again.
 */

const net = require('node:net');
const dns = require('node:dns');

class ProxyError extends Error {
  constructor(status, message, code = 'proxy_error') {
    super(message);
    this.name = 'ProxyError';
    this.status = status;
    this.code = code;
  }
}

const blocked = new net.BlockList();
const V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];
const V6 = [
  ['::', 96], ['64:ff9b::', 96], ['100::', 64], ['2001::', 32], ['2001:db8::', 32],
  ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
];
for (const [addr, prefix] of V4) blocked.addSubnet(addr, prefix, 'ipv4');
for (const [addr, prefix] of V6) blocked.addSubnet(addr, prefix, 'ipv6');

/** True when the address must never be contacted. Anything unparseable counts as blocked. */
function isBlockedIp(ip) {
  let addr = String(ip);
  const zone = addr.indexOf('%');
  if (zone !== -1) addr = addr.slice(0, zone);

  const kind = net.isIP(addr);
  if (kind === 0) return true;
  if (kind === 4) return blocked.check(addr, 'ipv4');

  // IPv4-mapped IPv6 (::ffff:1.2.3.4 or ::ffff:0102:0304): judge the embedded IPv4.
  const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (dotted) return isBlockedIp(dotted[1]);
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(addr);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return isBlockedIp(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  }
  return blocked.check(addr, 'ipv6');
}

/** Drop-in replacement for dns.lookup used by http(s).request. */
function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
    if (err) return callback(err);
    if (!addresses.length || addresses.some((a) => isBlockedIp(a.address))) {
      return callback(
        new ProxyError(403, 'That address resolves to a private or reserved network.', 'ssrf_blocked'),
      );
    }
    if (options && options.all) return callback(null, addresses);
    return callback(null, addresses[0].address, addresses[0].family);
  });
}

function hostAllowed(hostname, allowedHosts) {
  return allowedHosts.some((d) => hostname === d || hostname.endsWith('.' + d));
}

/**
 * Normalises and validates a user-supplied address. Returns a URL or throws ProxyError.
 */
function parseTarget(raw, cfg) {
  if (typeof raw !== 'string' || raw.trim() === '' || raw.length > 2048) {
    throw new ProxyError(400, 'Enter a valid web address.', 'bad_url');
  }
  let text = raw.trim();
  if (!/^[a-z][a-z0-9+.-]*:/i.test(text)) text = 'https://' + text;

  let url;
  try {
    url = new URL(text);
  } catch {
    throw new ProxyError(400, 'That does not look like a valid web address.', 'bad_url');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ProxyError(400, 'Only http and https addresses are supported.', 'bad_scheme');
  }
  if (url.username || url.password) {
    throw new ProxyError(400, 'Addresses with embedded credentials are not allowed.', 'bad_url');
  }
  if (url.port && url.port !== '80' && url.port !== '443') {
    throw new ProxyError(400, 'Only the standard web ports (80 and 443) are allowed.', 'bad_port');
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[') || net.isIP(host) !== 0) {
    throw new ProxyError(403, 'IP addresses are not allowed - use a domain name.', 'ip_literal');
  }
  if (!host.includes('.')) {
    throw new ProxyError(403, 'Internal host names are not allowed.', 'internal_host');
  }
  if (!hostAllowed(host, cfg.allowedHosts)) {
    throw new ProxyError(403, `${host} is not on this server's allowlist.`, 'host_not_allowed');
  }
  url.hash = '';
  return url;
}

module.exports = { ProxyError, isBlockedIp, safeLookup, hostAllowed, parseTarget };
