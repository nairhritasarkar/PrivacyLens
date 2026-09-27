// PrivacyLens scanner — a small backend that does REAL inspection of a
// target website's permission footprint. It does not guess: it reads the
// site's actual HTTP headers and scans its actual HTML/JS for permission
// API usage.
//
// Two real signal sources:
//  1. Permissions-Policy / Feature-Policy response header — sites use this
//     to explicitly allow or block browser features (camera, mic, geo...).
//  2. Static scan of the page's HTML plus its first few linked scripts,
//     looking for calls to permission-gated browser APIs.
//
// Known, honest limitations (surfaced to the user in the response, not hidden):
//  - Single-page apps often render almost nothing server-side, and ship
//    logic inside large bundled/minified JS we only partially fetch, so
//    detection can under-report for those sites.
//  - We only look at code that is reachable from the initial HTML response
//    (inline scripts + up to 6 linked scripts). We do not execute JS.
//  - A feature being "requested in code" does not mean every visitor is
//    prompted; the browser still gates the actual permission dialog.

import express from "express";
import * as cheerio from "cheerio";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const FETCH_TIMEOUT_MS = 8000;
const MAX_SCRIPTS_TO_FETCH = 6;
const MAX_TEXT_PER_RESOURCE = 300_000; // chars, per HTML/script fetched
const USER_AGENT = "PrivacyLensScanner/1.0 (+https://example.invalid/bot)";

// ---------- Basic SSRF guard ----------
// Blocks obvious internal/loopback targets. This is a minimal safety net,
// not a substitute for a proper allowlist/egress-proxy in production.
function isBlockedHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "0.0.0.0") return true;
  if (h === "127.0.0.1" || h.startsWith("127.")) return true;
  if (h.startsWith("10.")) return true;
  if (h.startsWith("192.168.")) return true;
  if (h.startsWith("169.254.")) return true;
  const m = h.match(/^172\.(\d{1,3})\./);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
  if (h === "::1") return true;
  return false;
}

function normalizeUrl(raw) {
  let candidate = raw.trim();
  if (!/^https?:\/\//i.test(candidate)) candidate = "https://" + candidate;
  const u = new URL(candidate);
  if (!["http:", "https:"].includes(u.protocol)) {
    throw new Error("Only http/https URLs are supported.");
  }
  if (isBlockedHost(u.hostname)) {
    throw new Error("That host isn't allowed to be scanned.");
  }
  return u;
}

async function fetchText(url, { timeout = FETCH_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": USER_AGENT, Accept: "text/html,*/*" },
    });
    const text = await res.text();
    return {
      ok: res.ok,
      status: res.status,
      finalUrl: res.url || url,
      headers: res.headers,
      text: text.slice(0, MAX_TEXT_PER_RESOURCE),
    };
  } finally {
    clearTimeout(t);
  }
}

// ---------- Permissions-Policy header parsing ----------
// Format example: "geolocation=(self \"https://x.com\"), camera=(), microphone=(self)"
function parsePermissionsPolicy(headerValue) {
  if (!headerValue) return [];
  return headerValue
    .split(",")
    .map((chunk) => chunk.trim())
    .filter(Boolean)
    .map((chunk) => {
      const m = chunk.match(/^([a-zA-Z0-9-]+)=\(([^)]*)\)/);
      if (!m) return null;
      const directive = m[1];
      const allowlist = m[2].trim();
      let interpretation;
      if (allowlist === "") interpretation = "Explicitly blocked, even for the site itself";
      else if (allowlist.includes("*")) interpretation = "Allowed for this site and any site it embeds";
      else if (allowlist.includes("self")) interpretation = "Allowed for this site itself";
      else interpretation = `Allowed for: ${allowlist}`;
      return { directive, allowlist, interpretation };
    })
    .filter(Boolean);
}

// ---------- Static code scan for permission-gated APIs ----------
// Each entry: human label, regex over raw source, and the category key it
// belongs to (used to decide "needed vs excessive" below).
const API_SIGNATURES = [
  { label: "Camera / microphone (getUserMedia)", re: /getUserMedia\s*\(|mediaDevices\s*\.\s*getUserMedia/, key: "camera_mic" },
  { label: "Screen recording (getDisplayMedia)", re: /getDisplayMedia\s*\(/, key: "screen" },
  { label: "Precise location (Geolocation API)", re: /navigator\s*\.\s*geolocation/, key: "location" },
  { label: "Push notifications", re: /Notification\s*\.\s*requestPermission|PushManager/, key: "notifications" },
  { label: "Clipboard access", re: /navigator\s*\.\s*clipboard/, key: "clipboard" },
  { label: "Device motion / orientation sensors", re: /DeviceMotionEvent|DeviceOrientationEvent/, key: "motion" },
  { label: "Bluetooth devices", re: /navigator\s*\.\s*bluetooth/, key: "bluetooth" },
  { label: "USB devices", re: /navigator\s*\.\s*usb\b/, key: "usb" },
  { label: "MIDI devices", re: /requestMIDIAccess/, key: "midi" },
  { label: "Payment Request API", re: /new\s+PaymentRequest/, key: "payment" },
  { label: "Stored credentials / autofill (Credential Management)", re: /navigator\s*\.\s*credentials/, key: "credentials" },
  { label: "Persistent storage quota", re: /navigator\s*\.\s*storage\s*\.\s*persist/, key: "storage" },
  { label: "Contacts Picker", re: /navigator\s*\.\s*contacts/, key: "contacts" },
];

// ---------- Site-category baseline (what's typically *legitimate* to need) ----------
const CATEGORY_RULES = [
  { key: "social", match: /(facebook|instagram|twitter|x\.com|tiktok|linkedin|reddit|snapchat)/, label: "Social network", legitimate: ["notifications", "camera_mic"] },
  { key: "shopping", match: /(amazon|shop|store|etsy|ebay|target|walmart)/, label: "E-commerce", legitimate: ["payment"] },
  { key: "streaming", match: /(spotify|netflix|youtube|hulu|disney|music)/, label: "Streaming / media", legitimate: [] },
  { key: "productivity", match: /(notion|slack|asana|trello|drive|docs|dropbox|zoom|meet)/, label: "Productivity / work tool", legitimate: ["camera_mic", "screen", "notifications", "storage"] },
  { key: "travel", match: /(airbnb|booking|expedia|hotel|uber|lyft|maps)/, label: "Travel / rides / maps", legitimate: ["location", "payment"] },
  { key: "finance", match: /(bank|chase|paypal|venmo|wise|revolut)/, label: "Banking / finance", legitimate: ["credentials"] },
  { key: "video-chat", match: /(zoom|meet\.google|teams\.microsoft|webex|whereby)/, label: "Video calling", legitimate: ["camera_mic", "screen", "notifications"] },
];

function detectCategory(hostname) {
  return CATEGORY_RULES.find((c) => c.match.test(hostname)) || null;
}

function resolveScriptUrls(html, baseUrl) {
  const $ = cheerio.load(html);
  const urls = [];
  $("script[src]").each((_, el) => {
    const src = $(el).attr("src");
    if (!src) return;
    try {
      urls.push(new URL(src, baseUrl).toString());
    } catch {
      /* ignore malformed src */
    }
  });
  return urls.slice(0, MAX_SCRIPTS_TO_FETCH);
}

app.post("/api/scan", async (req, res) => {
  const { url } = req.body || {};
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Provide a website URL." });
  }

  let target;
  try {
    target = normalizeUrl(url);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  let page;
  try {
    page = await fetchText(target.toString());
  } catch (e) {
    const reason = e.name === "AbortError" ? "The site took too long to respond." : "Could not reach that site.";
    return res.status(502).json({ error: reason });
  }

  const finalUrl = new URL(page.finalUrl);
  const permissionsPolicyHeader = page.headers.get("permissions-policy") || page.headers.get("feature-policy") || "";
  const policyDirectives = parsePermissionsPolicy(permissionsPolicyHeader);

  // Gather text to scan: main HTML + inline scripts + a handful of linked scripts.
  let corpus = page.text;
  const scriptUrls = resolveScriptUrls(page.text, finalUrl.toString());
  const fetched = await Promise.allSettled(scriptUrls.map((u) => fetchText(u, { timeout: 5000 })));
  const fetchedScripts = [];
  for (const r of fetched) {
    if (r.status === "fulfilled" && r.value.ok) {
      corpus += "\n" + r.value.text;
      fetchedScripts.push(r.value.finalUrl);
    }
  }

  const detected = API_SIGNATURES.filter((sig) => sig.re.test(corpus)).map((sig) => ({
    label: sig.label,
    key: sig.key,
  }));

  const category = detectCategory(finalUrl.hostname);
  const legitimateKeys = new Set(category ? category.legitimate : []);

  const needed = detected.filter((d) => legitimateKeys.has(d.key));
  const questionable = detected.filter((d) => !legitimateKeys.has(d.key));

  const explicitlyBlocked = policyDirectives.filter((p) => p.allowlist === "");
  const explicitlyAllowed = policyDirectives.filter((p) => p.allowlist !== "");

  res.json({
    scannedUrl: finalUrl.toString(),
    httpStatus: page.status,
    category: category ? category.label : null,
    scriptsInspected: fetchedScripts.length,
    scriptsFoundTotal: scriptUrls.length,
    permissionsPolicyHeaderPresent: policyDirectives.length > 0,
    explicitlyBlocked,
    explicitlyAllowed,
    detected,
    needed,
    questionable,
    notes:
      fetchedScripts.length === 0 && scriptUrls.length > 0
        ? "Linked scripts could not be fetched (blocked or errored), so this scan is based on the HTML and inline scripts only — coverage is partial."
        : "Detection is based on static analysis of fetched HTML/JS. Sites that build their UI at runtime via large bundles may use more permissions than shown here.",
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`PrivacyLens scanner running at http://localhost:${PORT}`);
});
