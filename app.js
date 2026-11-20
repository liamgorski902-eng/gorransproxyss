(function () {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const dict = window.GP_I18N;
  const safe = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
  };

  // ---------- i18n ----------
  let lang = 'en';
  const t = (key) => (dict[lang] && dict[lang][key]) || dict.en[key] || key;

  function applyLang(next) {
    lang = dict[next] ? next : 'en';
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    $('#lang').value = lang;
    safe.set('gp_lang', lang);
    renderFilters();
    renderShortcuts();
    renderAuth();
  }

  // ---------- Shortcuts ----------
  const G = 'https://www.google.com/';
  const SHORTCUTS = [
    { n: 'Google', d: 'Search the web', u: G, c: 'search', col: '#4285f4', i: 'G' },
    { n: 'Google Maps', d: 'Maps and directions', u: 'https://maps.google.com/', c: 'search', col: '#34a853', i: 'M' },
    { n: 'Wikipedia', d: 'Free encyclopedia', u: 'https://pl.wikipedia.org/', c: 'tools', col: '#3b3b3b', i: 'W' },
    { n: 'YouTube', d: 'Videos and music', u: 'https://www.youtube.com/', c: 'video', col: '#ff0000', i: '▶' },
    { n: 'TikTok', d: 'Short videos', u: 'https://www.tiktok.com/', c: 'social', col: '#111111', i: '♪' },
    { n: 'Snapchat', d: 'Snaps and stories', u: 'https://www.snapchat.com/', c: 'social', col: '#f7c600', i: '👻' },
    { n: 'Google Translate', d: 'PL ⇄ EN ⇄ SV', u: 'https://translate.google.com/', c: 'tools', col: '#4285f4', i: 'T' },
    { n: 'Wolne Lektury', d: 'Free Polish books', u: 'https://wolnelektury.pl/', c: 'tools', col: '#dc143c', i: 'L' },
    { n: 'Poki', d: 'Free browser games', u: 'https://poki.com/', c: 'games', col: '#2a6fff', i: 'P' },
    { n: 'CrazyGames', d: 'Browser games', u: 'https://www.crazygames.com/', c: 'games', col: '#6c3df2', i: 'C' },
    { n: 'Chess.com', d: 'Play chess online', u: 'https://www.chess.com/play/online', c: 'games', col: '#5d8a3a', i: '♞' },
    { n: 'Lichess', d: 'Free open chess', u: 'https://lichess.org/', c: 'games', col: '#262421', i: '♘' },
    { n: 'Pogoda', d: 'Weather (IMGW)', u: 'https://pogoda.interia.pl/', c: 'tools', col: '#e08a00', i: '☀' },
    { n: 'Allegro', d: 'Polish marketplace', u: 'https://allegro.pl/', c: 'tools', col: '#ff5a00', i: 'a' },
  ];
  const QUICK = ['Google', 'YouTube', 'TikTok', 'Snapchat', 'Poki', 'Wikipedia'];
  const FILTERS = ['all', 'search', 'social', 'video', 'games', 'tools'];
  let filter = 'all';

  function tile(s, compact) {
    const li = document.createElement('li');
    li.className = 'tile';
    const a = document.createElement('a');
    a.href = s.u; a.target = '_blank'; a.rel = 'noopener noreferrer';
    const ico = document.createElement('span');
    ico.className = 'ico'; ico.style.background = s.col; ico.textContent = s.i; ico.setAttribute('aria-hidden', 'true');
    if (s.col === '#f7c600') ico.style.color = '#111';
    const name = document.createElement('span');
    name.className = 'name'; name.textContent = s.n;
    a.append(ico, name);
    if (!compact) {
      const d = document.createElement('span');
      d.className = 'desc'; d.textContent = s.d;
      a.append(d);
    }
    li.append(a);
    return li;
  }

  function renderShortcuts() {
    const grid = $('#shortcut-grid');
    grid.replaceChildren(...SHORTCUTS.filter((s) => filter === 'all' || s.c === filter).map((s) => tile(s, false)));
    $('#quick-grid').replaceChildren(...QUICK.map((n) => tile(SHORTCUTS.find((s) => s.n === n), true)));
  }

  function renderFilters() {
    $('#filters').replaceChildren(...FILTERS.map((f) => {
      const b = document.createElement('button');
      b.type = 'button'; b.textContent = t('sc.' + f);
      b.setAttribute('aria-pressed', String(f === filter));
      b.addEventListener('click', () => { filter = f; renderFilters(); renderShortcuts(); });
      return b;
    }));
  }

  // ---------- Tabs ----------
  const tabs = [$('#tab-proxy'), $('#tab-unblocker')];
  function selectTab(tab, focus) {
    tabs.forEach((el) => {
      const on = el === tab;
      el.setAttribute('aria-selected', String(on));
      el.tabIndex = on ? 0 : -1;
      $('#' + el.getAttribute('aria-controls')).hidden = !on;
    });
    if (focus) tab.focus();
    safe.set('gp_tab', tab.id);
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        e.preventDefault();
        selectTab(tabs[(i + 1) % tabs.length], true);
      }
    });
  });
  document.querySelectorAll('[data-goto]').forEach((a) => {
    a.addEventListener('click', () => {
      const g = a.dataset.goto;
      if (g === 'proxy') selectTab(tabs[0]);
      if (g === 'unblocker') selectTab(tabs[1]);
    });
  });

  // ---------- API ----------
  async function api(path, body) {
    const opts = body === undefined
      ? { credentials: 'same-origin' }
      : { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'gorransproxy' }, body: JSON.stringify(body) };
    let res;
    try { res = await fetch(path, opts); } catch { throw new Error(t('err.network')); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { const e = new Error(data.error || t('err.network')); e.code = data.code; e.status = res.status; throw e; }
    return data;
  }

  // ---------- Proxy mode ----------
  const state = { proxyEnabled: false, authenticated: false, hosts: [] };
  const urlInput = $('#proxy-url');
  const errBox = $('#proxy-error');

  function showError(msg) { errBox.textContent = msg; errBox.hidden = !msg; }

  function renderAuth() {
    const badge = $('#auth-badge');
    const btn = $('#auth-btn');
    badge.className = 'badge';
    if (!state.proxyEnabled) {
      badge.classList.add('off'); badge.textContent = t('auth.disabled'); btn.hidden = true;
    } else if (state.authenticated) {
      badge.classList.add('ok'); badge.textContent = t('auth.signedin');
      btn.hidden = false; btn.textContent = t('auth.signout'); btn.dataset.action = 'logout';
    } else {
      badge.textContent = t('auth.signedout');
      btn.hidden = false; btn.textContent = t('auth.signin'); btn.dataset.action = 'login';
    }
    const chips = $('#allowed-chips');
    chips.replaceChildren(...state.hosts.map((h) => {
      const li = document.createElement('li');
      const b = document.createElement('button');
      b.type = 'button'; b.textContent = h;
      b.addEventListener('click', () => { urlInput.value = 'https://' + h; urlInput.focus(); });
      li.append(b);
      return li;
    }));
  }

  function validateUrl(raw) {
    const text = raw.trim();
    if (!text) return { error: t('err.empty') };
    const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(text) ? text : 'https://' + text;
    let u;
    try { u = new URL(withScheme); } catch { return { error: t('err.invalid') }; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return { error: t('err.scheme') };
    if (!u.hostname.includes('.') || /\s/.test(text)) return { error: t('err.invalid') };
    return { url: u.href };
  }

  let currentTarget = null;
  async function openProxy(target) {
    const data = await api('/api/proxy/open', { url: target });
    currentTarget = data.target;
    $('#viewer').hidden = false;
    $('#viewer-url').textContent = data.target;
    $('#viewer-open').href = data.target;
    $('#viewer-frame').src = data.viewUrl;
    $('#viewer').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  $('#proxy-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('');
    const v = validateUrl(urlInput.value);
    if (v.error) return showError(v.error);
    if (!state.proxyEnabled) return showError(t('auth.disabled'));
    if (!state.authenticated) { openLogin(); return; }
    const go = e.submitter || $('.go', e.target);
    go.disabled = true;
    try {
      await openProxy(v.url);
    } catch (err) {
      if (err.code === 'auth_required') { state.authenticated = false; renderAuth(); openLogin(); }
      else showError(err.message);
    } finally { go.disabled = false; }
  });

  $('#viewer-reload').addEventListener('click', async () => {
    if (!currentTarget) return;
    try { await openProxy(currentTarget); } catch (err) { showError(err.message); }
  });
  $('#viewer-close').addEventListener('click', () => {
    $('#viewer-frame').src = 'about:blank';
    $('#viewer').hidden = true;
    currentTarget = null;
  });

  // ---------- Login dialog ----------
  const dialog = $('#login-dialog');
  const loginErr = $('#login-error');
  function openLogin() {
    loginErr.hidden = true; $('#login-code').value = '';
    if (dialog.showModal) dialog.showModal(); else dialog.setAttribute('open', '');
    $('#login-code').focus();
  }
  $('#login-cancel').addEventListener('click', () => dialog.close());
  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = $('#login-code').value;
    if (!code) { loginErr.textContent = t('err.code'); loginErr.hidden = false; return; }
    try {
      await api('/api/login', { code });
      state.authenticated = true; renderAuth(); dialog.close();
      if (urlInput.value.trim()) $('#proxy-form').requestSubmit();
    } catch (err) { loginErr.textContent = err.message; loginErr.hidden = false; }
  });
  $('#auth-btn').addEventListener('click', async (e) => {
    if (e.currentTarget.dataset.action === 'login') return openLogin();
    try { await api('/api/logout', {}); } catch { /* ignore */ }
    state.authenticated = false; renderAuth();
    $('#viewer-close').click();
  });

  // ---------- Unblocker mode: Google search ----------
  $('#search-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const q = $('#search-q').value.trim();
    const url = q ? G + 'search?q=' + encodeURIComponent(q) : G;
    window.open(url, '_blank', 'noopener,noreferrer');
  });

  // ---------- Boot ----------
  $('#lang').addEventListener('change', (e) => applyLang(e.target.value));
  const saved = safe.get('gp_lang');
  const guess = (navigator.language || 'en').slice(0, 2).toLowerCase();
  applyLang(dict[saved] ? saved : dict[guess] ? guess : 'en');
  if (safe.get('gp_tab') === 'tab-unblocker') selectTab(tabs[1]);

  api('/api/config').then((c) => {
    state.proxyEnabled = c.proxyEnabled; state.authenticated = c.authenticated; state.hosts = c.allowedHosts || [];
    renderAuth();
  }).catch(() => { renderAuth(); });
})();
