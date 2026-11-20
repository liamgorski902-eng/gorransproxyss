# Gorransproxy 🇵🇱🦫

A small, dependency-free web proxy with a Polish beaver mascot. HTML + CSS + vanilla JS on the front, plain Node.js (no npm packages) on the back.

* **Proxy mode** is a real server-side proxy: it fetches pages for you, strips scripts, rewrites links and shows a safe read-only copy in a sandboxed viewer.
* **Unblocker mode** is a Google search box and a grid of shortcuts that open in a new tab. It is only a launcher. It does not bypass school, workplace or network filters, and it isn't meant to.

## What Proxy mode will and won't do

It is deliberately conservative, because an open proxy gets abused within hours of going online.

| Protection | How it works |
|---|---|
| Authentication | Proxy mode is off until you set `ACCESS_CODES`. Visitors sign in with a code. Sessions are HMAC-signed, `HttpOnly`, `SameSite=Strict` cookies. |
| Destination allowlist | Only domains in `ALLOWED_HOSTS` (and their subdomains) can be fetched. `*` is rejected. |
| SSRF | Blocks IP literals (including decimal, hex and IPv6 forms), `localhost`, dotless names, non-80/443 ports and embedded credentials. Every DNS answer is checked against private, loopback, link-local, CGNAT, metadata and IPv4-mapped ranges at connect time (stops DNS rebinding). Every redirect hop is re-validated. |
| Rate limits | Per-IP request budget, login attempt limit, per-IP and global concurrency caps. |
| Resource limits | 10 s connect timeout, 20 s body deadline, 5 MB response cap, 5 redirect cap, no compressed responses. |
| Content safety | Scripts, frames, plugins, forms, event handlers and `javascript:` URLs are removed. The page is served with `Content-Security-Policy: sandbox` and shown in a sandboxed iframe. |
| Privacy | Your cookies, referrer and IP are never forwarded to the destination. |
| CSRF | State-changing calls need a custom header and a same-origin `Origin`. |
| Signed links | Page and asset URLs are HMAC-signed and expire after 30 minutes, so the server can't be used to fetch arbitrary URLs. |

Because scripts are removed, this is a reader for documents and articles. It is not for YouTube, TikTok, Snapchat, logins or games. Those use the shortcuts.

## Folder structure

```
gorransproxy/
├── server.js              # HTTP server, routing, API, proxy endpoints
├── package.json           # no dependencies
├── .env.example           # configuration template
├── render.yaml            # one-click deploy blueprint (Render)
├── Dockerfile             # for Fly.io, Railway, Koyeb, etc.
├── lib/
│   ├── config.js          # env parsing + safe defaults
│   ├── netguard.js        # URL validation, allowlist, SSRF protection
│   ├── fetcher.js         # safe upstream fetch with manual redirects
│   ├── rewrite.js         # HTML/CSS sanitiser and link rewriter
│   ├── auth.js            # access codes, sessions, signed URLs
│   └── ratelimit.js       # rate limiter + concurrency gate
├── public/
│   ├── index.html         # the homepage
│   ├── css/style.css
│   ├── js/app.js          # UI logic (tabs, validation, viewer, shortcuts)
│   ├── js/i18n.js         # English / Polski / Svenska
│   └── assets/            # beaver.svg, sprite.svg (logo), favicon.svg
└── test/security.test.js  # 16 tests (SSRF, sanitiser, auth, limits, HTTP)
```

## Run locally

You need **Node.js 20 or newer**. There's nothing to install.

```bash
cd gorransproxy
cp .env.example .env
```

Edit `.env` and set two values:

```bash
# generate a secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

```
SESSION_SECRET=<paste the generated value>
ACCESS_CODES=pick-a-long-passphrase
```

Then:

```bash
npm start            # http://localhost:3000
npm test             # run the security test suite
```

Without `ACCESS_CODES` the site still works. The homepage, shortcuts and Google search are all available, and Proxy mode shows as "not configured".

On Windows, use `copy .env.example .env` instead of `cp`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `3000` | Listen port (hosts usually set this). |
| `SESSION_SECRET` | random per start | At least 32 characters. Set it, or sign-ins reset on every restart. |
| `ACCESS_CODES` | empty (Proxy mode off) | Comma-separated codes, each at least 8 characters. |
| `ALLOWED_HOSTS` | Wikipedia, Wikimedia, Wikisource, Wolne Lektury, Gutenberg, gov.pl, example.com/.org | Domains the proxy may fetch. |
| `TRUST_PROXY_HOPS` | `0` | Set to `1` behind one reverse proxy (all hosts below) so rate limits see real client IPs. |
| `PROXY_UNITS_PER_MIN` | `240` | A page view costs 6 units, an asset costs 1. |
| `LOGIN_ATTEMPTS_PER_10_MIN` | `8` | Per IP. |
| `NODE_ENV` | | Set to `production` online (enables `Secure` cookies). |

Only add sites you're happy to be responsible for. Adding a broad list turns your server into a general-purpose proxy, which hosts commonly treat as abuse.

## Publish online for free

Use **HTTPS** (every host below provides it), set `NODE_ENV=production` and `TRUST_PROXY_HOPS=1`, and never commit `.env`.

### Option A: Render (easiest)

1. Push the folder to a GitHub repository.
2. On [render.com](https://render.com): **New → Blueprint**, pick the repo. `render.yaml` configures everything.
3. When prompted, enter `ACCESS_CODES`. `SESSION_SECRET` is generated for you.
4. Deploy. Your site is at `https://gorransproxy.onrender.com` (or your chosen name).

The free plan sleeps after about 15 minutes of inactivity, so the first visit afterwards takes a few seconds. Free-tier terms change, so check the current plan page.

### Option B: Fly.io, Railway, Koyeb or any Docker host

The included `Dockerfile` works anywhere. For example, with Fly.io:

```bash
fly launch --no-deploy        # accept defaults, internal port 3000
fly secrets set SESSION_SECRET=<value> ACCESS_CODES=<codes> NODE_ENV=production TRUST_PROXY_HOPS=1
fly deploy
```

### Option C: Any Node host

Anything that runs `npm start` works (Glitch, Replit, a VPS). Set the environment variables from the table above.

### Static-only hosting (GitHub Pages, Netlify drop, Cloudflare Pages)

You can host `public/` alone and everything except Proxy mode works, because Proxy mode needs the Node server. Without it the sign-in and open buttons will show a network error.

## Customising

* **Languages:** add a block to `public/js/i18n.js` and an `<option>` in `index.html`.
* **Shortcuts:** edit the `SHORTCUTS` array at the top of `public/js/app.js`.
* **Mascot and logo:** `public/assets/*.svg`. They're plain SVG, so edit the colours freely.
* **Colours:** CSS variables at the top of `public/css/style.css`.

## Notes

* Brand tiles use coloured letters or symbols instead of official logos, so no trademarks are reproduced.
* The in-memory rate limiter fits a single instance. If you scale to several, move it to a shared store.
* Logs record host, status and timing only, never full URLs or visitor IPs.
