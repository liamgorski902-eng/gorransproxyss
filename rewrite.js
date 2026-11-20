'use strict';

/**
 * Turns an untrusted upstream HTML page into an inert, read-only copy:
 *  - scripts, frames, plugins and event handlers are removed;
 *  - links and images are rewritten to signed Gorransproxy URLs (or neutralised);
 *  - the server additionally serves it with a sandboxing Content-Security-Policy.
 *
 * It uses a linear-time tokenizer (no backtracking regexes) so hostile markup cannot
 * trigger catastrophic slowdowns. The CSP is the real safety net; this makes pages usable.
 */

const NAMED = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, e) => {
    if (e[0] === '#') {
      const cp = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try {
        return String.fromCodePoint(cp);
      } catch {
        return '';
      }
    }
    return NAMED[e.toLowerCase()] ?? match;
  });
}

const escapeAttr = (s) =>
  s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const escapeHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Resolves to an absolute http(s) URL string, or null (fragments, mailto:, javascript:, ...). */
function resolveHttp(value, base) {
  const cleaned = decodeEntities(String(value)).trim();
  if (!cleaned || cleaned.startsWith('#')) return null;
  try {
    const u = new URL(cleaned, base);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

const SAFE_DATA_IMG = /^data:image\/(png|jpe?g|gif|webp);base64,[a-z0-9+/=\s]+$/i;

function rewriteCss(css, base, sign) {
  return css
    .replace(/@import[^;]*;?/gi, '')
    .replace(/expression\s*\(/gi, '(')
    .replace(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)'"\s]*))\s*\)/gi, (match, a, b, c) => {
      const raw = (a ?? b ?? c ?? '').trim();
      if (SAFE_DATA_IMG.test(raw)) return match;
      const abs = resolveHttp(raw, base);
      const signed = abs ? sign('a', abs) : null;
      return signed ? `url("${signed}")` : 'url("data:,")';
    });
}

// Elements removed together with everything inside them.
const DROP_WITH_CONTENT = new Set(['script', 'iframe', 'noembed', 'noframes', 'xmp', 'template']);
// Elements whose tags are removed but whose fallback content stays.
const DROP_TAG_ONLY = new Set([
  'object', 'embed', 'applet', 'frame', 'frameset', 'audio', 'video', 'canvas', 'base', 'meta', 'source', 'track',
]);

const URL_ATTRS = new Set([
  'href', 'src', 'srcset', 'action', 'formaction', 'xlink:href', 'data', 'poster', 'background', 'ping',
  'manifest', 'codebase', 'usemap', 'longdesc', 'profile', 'archive', 'classid', 'icon', 'lowsrc',
  'dynsrc', 'srcdoc',
]);
const DROP_ATTRS = new Set([
  'target', 'download', 'integrity', 'crossorigin', 'nonce', 'is', 'contenteditable', 'autofocus',
  'accesskey', 'sandbox', 'allow', 'referrerpolicy', 'imagesrcset', 'imagesizes', 'method', 'enctype',
]);

/** Linear-time start-tag parser. Returns null for unterminated/malformed tags. */
function parseStartTag(html, start) {
  const n = html.length;
  let i = start + 1;
  let nameEnd = i;
  while (nameEnd < n && !/[\s/>]/.test(html[nameEnd])) nameEnd += 1;
  const name = html.slice(i, nameEnd).toLowerCase();
  i = nameEnd;
  const attrs = [];
  let selfClose = false;

  while (i < n) {
    while (i < n && /\s/.test(html[i])) i += 1;
    if (i >= n) return null;
    if (html[i] === '>') return { name, attrs, selfClose, end: i + 1 };
    if (html[i] === '/') {
      if (html[i + 1] === '>') return { name, attrs, selfClose: true, end: i + 2 };
      i += 1;
      continue;
    }
    let keyEnd = i;
    while (keyEnd < n && !/[\s=/>]/.test(html[keyEnd])) keyEnd += 1;
    if (keyEnd === i) {
      i += 1; // stray '=' etc.
      continue;
    }
    const key = html.slice(i, keyEnd);
    i = keyEnd;
    let j = i;
    while (j < n && /\s/.test(html[j])) j += 1;
    let value = null;
    if (html[j] === '=') {
      j += 1;
      while (j < n && /\s/.test(html[j])) j += 1;
      const q = html[j];
      if (q === '"' || q === "'") {
        const close = html.indexOf(q, j + 1);
        if (close === -1) return null;
        value = html.slice(j + 1, close);
        i = close + 1;
      } else {
        let vEnd = j;
        while (vEnd < n && !/[\s>]/.test(html[vEnd])) vEnd += 1;
        value = html.slice(j, vEnd);
        i = vEnd;
      }
    }
    attrs.push([key, value]);
  }
  return null;
}

function buildStartTag(tag, base, sign) {
  const { name, attrs, selfClose } = tag;
  const get = (k) => {
    const found = attrs.find(([key]) => key.toLowerCase() === k);
    return found ? found[1] : null;
  };

  // <link>: keep stylesheets only.
  let linkHref = null;
  if (name === 'link') {
    if (!/\bstylesheet\b/i.test(get('rel') || '')) return '';
    const abs = resolveHttp(get('href') || '', base);
    linkHref = abs ? sign('a', abs) : null;
    if (!linkHref) return '';
  }

  const out = [];
  for (const [rawKey, rawValue] of attrs) {
    const key = rawKey.toLowerCase();
    if (!/^[a-z_:][a-z0-9_:.-]*$/.test(key)) continue;
    if (key.startsWith('on') || DROP_ATTRS.has(key)) continue;

    if (URL_ATTRS.has(key)) {
      let safe = null;
      if ((name === 'a' || name === 'area') && key === 'href') {
        const abs = resolveHttp(rawValue || '', base);
        if (abs) safe = sign('v', abs) || '#';
        else if ((rawValue || '').trim().startsWith('#')) safe = decodeEntities(rawValue.trim());
        else safe = '#';
      } else if (name === 'img' && key === 'src') {
        const raw = decodeEntities(rawValue || '').trim();
        if (SAFE_DATA_IMG.test(raw)) safe = raw;
        else {
          const abs = resolveHttp(raw, base);
          safe = abs ? sign('a', abs) : null;
        }
      } else if (name === 'link' && key === 'href') {
        safe = linkHref;
      }
      if (safe) out.push(`${key}="${escapeAttr(safe)}"`);
      continue;
    }

    out.push(rawValue === null ? key : `${key}="${escapeAttr(decodeEntities(rawValue))}"`);
  }

  if (name === 'a' || name === 'area') out.push('rel="noreferrer nofollow noopener"');
  if (name === 'img') out.push('referrerpolicy="no-referrer"');
  return `<${name}${out.length ? ' ' + out.join(' ') : ''}${selfClose ? ' /' : ''}>`;
}

/**
 * @param {string} html     upstream document
 * @param {string} baseUrl  absolute URL of the document (for resolving relative links)
 * @param {(kind:'v'|'a', absUrl:string)=>string|null} sign  returns a signed local URL or null
 */
function rewriteHtml(html, baseUrl, sign) {
  let out =
    '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="referrer" content="no-referrer"><style>img{max-width:100%;height:auto}</style>';
  const n = html.length;
  let i = 0;

  while (i < n) {
    const lt = html.indexOf('<', i);
    if (lt === -1) {
      out += html.slice(i);
      break;
    }
    out += html.slice(i, lt);
    const next = html[lt + 1] || '';

    if (next === '!' || next === '?') {
      if (html.startsWith('<!--', lt)) {
        const end = html.indexOf('-->', lt + 4);
        i = end === -1 ? n : end + 3;
      } else {
        const end = html.indexOf('>', lt);
        i = end === -1 ? n : end + 1; // doctype, CDATA, processing instructions: dropped
      }
      continue;
    }

    if (next === '/') {
      const end = html.indexOf('>', lt);
      const raw = html.slice(lt + 2, end === -1 ? n : end);
      const name = ((/^[a-zA-Z][a-zA-Z0-9:-]*/.exec(raw) || [''])[0] || '').toLowerCase();
      i = end === -1 ? n : end + 1;
      if (name && !DROP_WITH_CONTENT.has(name) && !DROP_TAG_ONLY.has(name)) out += `</${name}>`;
      continue;
    }

    if (!/[a-zA-Z]/.test(next)) {
      out += '&lt;';
      i = lt + 1;
      continue;
    }

    const tag = parseStartTag(html, lt);
    if (!tag) {
      // Malformed or unterminated tag: discard the rest rather than guess.
      break;
    }
    i = tag.end;

    if (DROP_WITH_CONTENT.has(tag.name)) {
      const closer = new RegExp(`</${tag.name}\\b[^>]*>`, 'ig');
      closer.lastIndex = i;
      const m = closer.exec(html);
      i = m ? m.index + m[0].length : n;
      continue;
    }
    if (DROP_TAG_ONLY.has(tag.name)) continue;

    if (tag.name === 'style') {
      const closer = /<\/style\b[^>]*>/gi;
      closer.lastIndex = i;
      const m = closer.exec(html);
      const cssEnd = m ? m.index : n;
      out += `<style>${rewriteCss(html.slice(i, cssEnd), baseUrl, sign)}</style>`;
      i = m ? m.index + m[0].length : n;
      continue;
    }

    out += buildStartTag(tag, baseUrl, sign);
  }
  return out;
}

module.exports = { rewriteHtml, rewriteCss, escapeHtml, resolveHttp };
