# PrivacyLens — website permission scanner

A small, genuinely working scanner: paste a live website, and the backend
fetches it for real, then reports two kinds of real evidence:

1. **The `Permissions-Policy` (or legacy `Feature-Policy`) response header** —
   sites use this to explicitly allow or block browser features like camera,
   microphone, and geolocation. This is read directly, not guessed.
2. **A static scan of the site's HTML plus up to 6 linked scripts**, checked
   for real calls to permission-gated browser APIs (`getUserMedia`,
   `navigator.geolocation`, `Notification.requestPermission`, etc.).

Detected permissions are then compared against a small "what's normal for
this kind of site" table (e.g. video-calling tools legitimately need
camera/mic; a banking site asking for Bluetooth would not) to flag which
findings are worth a second look.

## Run it

Requires Node 18+ (for built-in `fetch`).

```bash
cd privacylens-scanner
npm install
npm start
```

Then open **http://localhost:3000**.

## Why this needs a backend, and can't be "just a webpage"

Browsers block a webpage from reading another site's HTML/JS directly
(CORS) — that's a deliberate security boundary, not a bug to route around.
Fetching the target server-side, as this backend does, is the correct and
standard way to do this.

## Honest limitations

- **Single-page apps** (React/Vue/etc.) often render almost nothing in the
  initial HTML and build the UI at runtime from large, often minified,
  JavaScript bundles. This scanner only reads static code reachable from the
  first response, so it can under-report for those sites.
- Only the **first 6 linked scripts** on the page are fetched, to keep scans
  fast. A site with more scripts may have permission calls we don't reach.
- A permission API appearing in the code means the site *can* ask for it —
  not that every visitor is prompted. The browser's own permission dialog is
  still the real gatekeeper.
- Sites that block non-browser `User-Agent`s or require JavaScript to render
  anything meaningful will return thin results.

## Production hardening (not done here, since this is a demo)

- Add rate limiting per IP and a request queue — this proxies arbitrary
  outbound fetches on your server, which is expensive to abuse.
- Expand the SSRF guard beyond the basic private-IP checks in `server.js`
  (e.g. resolve DNS and re-check the IP, block redirects to internal hosts).
- Consider a headless browser (Playwright/Puppeteer) if you need to catch
  permissions requested only after JS runs — this scanner deliberately
  doesn't execute code, to keep the server simple and safe to run.
