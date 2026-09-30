import { createRequire as __ccCreateRequire } from "node:module"; import { fileURLToPath as __ccFileURLToPath } from "node:url"; import { dirname as __ccDirname } from "node:path"; const require = __ccCreateRequire(import.meta.url); const __filename = __ccFileURLToPath(import.meta.url); const __dirname = __ccDirname(__filename);
var __require = /* @__PURE__ */ ((x2) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x2, {
  get: (a2, b2) => (typeof require !== "undefined" ? require : a2)[b2]
}) : x2)(function(x2) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x2 + '" is not supported');
});

// src/index.ts
import { createServer as createServer2 } from "http";
import { randomUUID as randomUUID3 } from "crypto";
import { readFileSync as readFileSync19 } from "fs";

// src/auth.ts
import { importSPKI, jwtVerify } from "jose";
var saasPublicKey = null;
var ownVmId = null;
var mitmPinnedKey = null;
var mitmPinnedKeyLoader = null;
function setSaasPublicKey(key) {
  saasPublicKey = key;
}
function setMitmPinnedKeyLoader(loader) {
  mitmPinnedKeyLoader = loader;
  mitmPinnedKey = null;
}
function setOwnVmId(id) {
  ownVmId = id;
}
async function verifySaasToken(token) {
  if (!saasPublicKey) return null;
  try {
    const key = await importSPKI(saasPublicKey, "EdDSA");
    const { payload } = await jwtVerify(token, key, { algorithms: ["EdDSA"] });
    const p2 = payload;
    if (ownVmId && p2.vmId !== ownVmId) return null;
    return p2;
  } catch {
    return null;
  }
}
async function verifyRequest(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  const payload = await verifySaasToken(authHeader.slice(7));
  if (!payload || payload.purpose !== void 0) return null;
  return payload;
}
async function verifyLoginToken(token, vmId, purpose) {
  const payload = await verifySaasToken(token);
  if (!payload || payload.purpose !== purpose || payload.vmId !== vmId) return null;
  if (typeof payload.jti !== "string" || typeof payload.exp !== "number") return null;
  return { ...payload, canWrite: payload.canWrite === true, next: payload.next === "files" ? "files" : void 0 };
}
async function verifyMitmRequest(req, purpose = "channels") {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  if (!mitmPinnedKey && mitmPinnedKeyLoader) mitmPinnedKey = mitmPinnedKeyLoader();
  if (!mitmPinnedKey) return null;
  try {
    const key = await importSPKI(mitmPinnedKey, "EdDSA");
    const { payload } = await jwtVerify(authHeader.slice(7), key, { algorithms: ["EdDSA"] });
    const p2 = payload;
    if (p2.purpose !== purpose || typeof p2.vmId !== "string") return null;
    if (ownVmId && p2.vmId !== ownVmId) return null;
    return { vmId: p2.vmId, iss: typeof p2.iss === "string" ? p2.iss : "" };
  } catch {
    return null;
  }
}
var FIREWALL_TICKET_MAX_S = 120;
async function verifyFirewallTicket(token, vmId, purpose) {
  if (!mitmPinnedKey && mitmPinnedKeyLoader) mitmPinnedKey = mitmPinnedKeyLoader();
  if (!mitmPinnedKey) return null;
  try {
    const key = await importSPKI(mitmPinnedKey, "EdDSA");
    const { payload } = await jwtVerify(token, key, { algorithms: ["EdDSA"] });
    const p2 = payload;
    if (p2.purpose !== purpose || p2.vmId !== vmId) return null;
    if (typeof p2.iss !== "string" || !p2.iss.startsWith("fw:")) return null;
    if (typeof p2.jti !== "string" || typeof p2.exp !== "number" || typeof p2.iat !== "number") return null;
    if (p2.exp - p2.iat > FIREWALL_TICKET_MAX_S) return null;
    if (typeof p2.c !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(p2.c)) return null;
    if (typeof p2.deviceId !== "string" || !p2.deviceId) return null;
    return {
      vmId: p2.vmId,
      purpose,
      jti: p2.jti,
      exp: p2.exp,
      c: p2.c,
      deviceId: p2.deviceId,
      canWrite: p2.canWrite === true,
      ...p2.next === "files" ? { next: "files" } : {}
    };
  } catch {
    return null;
  }
}
async function requireAuth(req, res) {
  const payload = await verifyRequest(req);
  if (!payload) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized" }));
    return false;
  }
  return true;
}

// src/session.ts
import crypto from "crypto";
import { existsSync, readFileSync as readFileSync2, writeFileSync as writeFileSync2 } from "fs";
import { join as join2 } from "path";
import { SignJWT, jwtVerify as jwtVerify2 } from "jose";

// ../origin-guard/src/index.ts
var SAFE_METHODS = /* @__PURE__ */ new Set(["GET", "HEAD", "OPTIONS"]);
function normalizeOrigin(origin) {
  if (!origin) return null;
  const raw = origin.trim();
  if (!raw || raw === "null") return null;
  try {
    const url2 = new URL(raw);
    if (url2.protocol !== "http:" && url2.protocol !== "https:") return raw;
    const defaultPort = url2.protocol === "https:" ? "443" : "80";
    const port = url2.port && url2.port !== defaultPort ? `:${url2.port}` : "";
    return `${url2.protocol}//${url2.hostname.toLowerCase()}${port}`;
  } catch {
    return raw;
  }
}
function isStateChanging(facts) {
  return facts.isUpgrade || !SAFE_METHODS.has(facts.method.toUpperCase());
}
var EMBEDDED_DESTS = /* @__PURE__ */ new Set(["iframe", "frame", "fencedframe", "embed", "object"]);
function navigationKind(facts) {
  if (isStateChanging(facts) || facts.secFetchMode !== "navigate") return null;
  return EMBEDDED_DESTS.has(facts.secFetchDest ?? "") ? "framed" : "top-level";
}
function checkOrigin(facts, policy) {
  if (!facts.credentialed && (policy.uncredentialed ?? "allow") === "allow") return { ok: true };
  const origin = normalizeOrigin(facts.origin);
  const navigation = navigationKind(facts);
  if (policy.allowTopLevelNavigation && navigation === "top-level") return { ok: true };
  if (facts.secFetchSite === "cross-site") return { ok: false, reason: "cross_site", origin };
  if (origin !== null) {
    const allowed = policy.allowed.map((o2) => normalizeOrigin(o2)).filter((o2) => o2 !== null);
    return allowed.includes(origin) ? { ok: true } : { ok: false, reason: "bad_origin", origin };
  }
  if (isStateChanging(facts)) return { ok: false, reason: "missing_origin", origin: null };
  return { ok: true };
}
function denialMessage(verdict) {
  if (verdict.reason === "cross_site") return "refused a cross-site request";
  if (verdict.reason === "missing_origin") return "refused a state-changing request with no Origin";
  return `refused an unexpected Origin: ${verdict.origin ?? "(none)"}`;
}
function one(value) {
  if (value === void 0) return null;
  return Array.isArray(value) ? value[0] ?? null : value;
}
function nodeRequestFacts(req, methodOverride) {
  const headers = req.headers;
  const forwarded = one(headers["x-forwarded-method"]);
  return {
    method: (methodOverride ?? forwarded ?? req.method ?? "GET").toUpperCase(),
    origin: one(headers.origin),
    secFetchSite: one(headers["sec-fetch-site"]),
    secFetchMode: one(headers["sec-fetch-mode"]),
    secFetchDest: one(headers["sec-fetch-dest"]),
    isUpgrade: (one(headers.upgrade) ?? "").toLowerCase() === "websocket",
    credentialed: one(headers.cookie) !== null
  };
}
function cookieValues(header2, name) {
  if (!header2) return [];
  const out = [];
  for (const part of header2.split(";")) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    if (trimmed.slice(0, eq) !== name) continue;
    out.push(trimmed.slice(eq + 1));
  }
  return out;
}
function readUniqueCookie(header2, name) {
  const values = cookieValues(header2, name);
  if (values.length === 1) return { value: values[0] ?? null, duplicated: false };
  return { value: null, duplicated: values.length > 1 };
}

// src/access-state.ts
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "fs";
import { dirname, join } from "path";
var REVOKED_KEEP_MS = 12 * 60 * 6e4;
function statePath() {
  return join(process.env.STATE_DIR ?? "/opt/controlclaw/state", "access.json");
}
var cache = null;
function load() {
  const path = statePath();
  if (cache?.path === path) return cache.state;
  let state = { firewallOrigin: null, revoked: {} };
  try {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    state = {
      firewallOrigin: typeof raw.firewallOrigin === "string" && validFirewallOrigin(raw.firewallOrigin) ? raw.firewallOrigin : null,
      revoked: raw.revoked && typeof raw.revoked === "object" ? raw.revoked : {}
    };
  } catch {
  }
  cache = { path, state };
  return state;
}
function save(state) {
  const path = statePath();
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(state), { mode: 384 });
  renameSync(tmp, path);
  cache = { path, state };
}
function validFirewallOrigin(origin) {
  return /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(origin) && origin.length <= 261;
}
function firewallOrigin() {
  return load().firewallOrigin;
}
function setFirewallOrigin(origin) {
  const state = load();
  if (state.firewallOrigin === origin) return;
  save({ ...state, firewallOrigin: origin });
}
function revokeDevices(ids, now = Date.now()) {
  const state = load();
  const revoked = prune(state.revoked, now);
  for (const id of ids) revoked[id] = now;
  save({ ...state, revoked });
}
function clearRevoked() {
  const state = load();
  save({ ...state, revoked: {} });
}
function isRevoked(deviceId, now = Date.now()) {
  const at2 = load().revoked[deviceId];
  return typeof at2 === "number" && now - at2 < REVOKED_KEEP_MS;
}
function prune(revoked, now) {
  const out = {};
  for (const [id, at2] of Object.entries(revoked)) if (typeof at2 === "number" && now - at2 < REVOKED_KEEP_MS) out[id] = at2;
  return out;
}

// src/session.ts
var SESSION_COOKIE = "__Host-cc_session";
var SESSION_TTL_SECONDS = 12 * 60 * 60;
var VIEW_COOKIE = "__Secure-cc_view";
var VIEW_COOKIE_PATH = "/__cc/novnc";
var VIEW_AUDIENCE = "view";
var secret = null;
var secretDir = null;
function ensureSessionSecret(keysDir2) {
  secretDir = keysDir2;
  const path = join2(keysDir2, "session_secret");
  if (!existsSync(path)) {
    writeFileSync2(path, crypto.randomBytes(32).toString("hex"), { mode: 384 });
    console.log("[session] generated session secret");
  }
  secret = Buffer.from(readFileSync2(path, "utf8").trim(), "hex");
}
function rotateSessionSecret() {
  if (!secretDir) throw new Error("session secret not initialised");
  const path = join2(secretDir, "session_secret");
  writeFileSync2(path, crypto.randomBytes(32).toString("hex"), { mode: 384 });
  secret = Buffer.from(readFileSync2(path, "utf8").trim(), "hex");
  clearRevoked();
  console.log("[session] rotated the session secret: every browser is signed out");
}
async function issueSession(vmId, claims = { canWrite: false }) {
  if (!secret) throw new Error("session secret not initialised");
  return new SignJWT({ sub: vmId, ...claims.canWrite ? { canWrite: true } : {}, ...claims.deviceId ? { dev: claims.deviceId } : {} }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime(`${SESSION_TTL_SECONDS}s`).sign(secret);
}
function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
}
function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}
async function readSession(cookieHeader, vmId) {
  if (!secret || !cookieHeader) return null;
  const token = uniqueCookie(cookieHeader, SESSION_COOKIE);
  if (!token) return null;
  try {
    const { payload } = await jwtVerify2(token, secret, { algorithms: ["HS256"] });
    if (payload.sub !== vmId || payload.aud !== void 0) return null;
    const deviceId = typeof payload.dev === "string" ? payload.dev : void 0;
    if (deviceId && isRevoked(deviceId)) return null;
    return { canWrite: payload.canWrite === true, ...deviceId ? { deviceId } : {} };
  } catch {
    return null;
  }
}
async function verifySession(cookieHeader, vmId) {
  return await readSession(cookieHeader, vmId) !== null;
}
async function issueViewSession(vmId, deviceId) {
  if (!secret) throw new Error("session secret not initialised");
  return new SignJWT({ sub: vmId, ...deviceId ? { dev: deviceId } : {} }).setProtectedHeader({ alg: "HS256" }).setAudience(VIEW_AUDIENCE).setIssuedAt().setExpirationTime(`${SESSION_TTL_SECONDS}s`).sign(secret);
}
function viewSessionCookie(token) {
  return `${VIEW_COOKIE}=${token}; Path=${VIEW_COOKIE_PATH}; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=None`;
}
function clearViewSessionCookie() {
  return `${VIEW_COOKIE}=; Path=${VIEW_COOKIE_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=None`;
}
async function verifyViewSession(cookieHeader, vmId) {
  if (!secret || !cookieHeader) return false;
  const token = uniqueCookie(cookieHeader, VIEW_COOKIE);
  if (!token) return false;
  try {
    const { payload } = await jwtVerify2(token, secret, { algorithms: ["HS256"], audience: VIEW_AUDIENCE });
    if (typeof payload.dev === "string" && isRevoked(payload.dev)) return false;
    return payload.sub === vmId;
  } catch {
    return false;
  }
}
function uniqueCookie(header2, name) {
  const reading = readUniqueCookie(header2, name);
  if (reading.duplicated) console.warn(`[session] ${name} arrived more than once \u2014 ignoring it (cookie tossing)`);
  return reading.value;
}
var seenJti = /* @__PURE__ */ new Map();
function consumeJti(jti, expSeconds) {
  const now = Math.floor(Date.now() / 1e3);
  for (const [key, exp] of seenJti) if (exp <= now) seenJti.delete(key);
  if (seenJti.has(jti)) return false;
  seenJti.set(jti, expSeconds);
  return true;
}

// src/routes/access.ts
import { createHash, randomBytes } from "crypto";
import { execFile } from "child_process";
import { readFileSync as readFileSync3 } from "fs";
import { join as join4 } from "path";

// src/http.ts
async function readJsonBody(req, limit = 16384) {
  return new Promise((resolve2) => {
    let data = "";
    let done = false;
    const finish = (v2) => {
      if (done) return;
      done = true;
      resolve2(v2);
    };
    req.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (data.length > limit) {
        finish(null);
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        const parsed = JSON.parse(data);
        finish(parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null);
      } catch {
        finish(null);
      }
    });
    req.on("error", () => finish(null));
  });
}
function sendJson(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", ...extraHeaders });
  res.end(JSON.stringify(body));
}

// src/routes/files-page.ts
import { readFile } from "fs/promises";
import { basename, join as join3 } from "path";
import { fileURLToPath } from "url";
function uiDir() {
  return process.env.FILES_UI_DIR ?? fileURLToPath(new URL("./files-ui/", import.meta.url));
}
var TYPES = {
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".woff2": "font/woff2"
};
var ASSET_RE = /^[A-Za-z0-9_-]+\.(js|css|woff2)$/;
async function serveFilesAsset(res, name) {
  const file = basename(name);
  if (file !== name || !ASSET_RE.test(file)) {
    res.writeHead(404, { "Content-Type": "text/plain" }).end("Not found");
    return;
  }
  let body;
  try {
    body = await readFile(join3(uiDir(), file));
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain" }).end("Not found");
    return;
  }
  res.writeHead(200, {
    "Content-Type": TYPES[file.slice(file.lastIndexOf("."))] ?? "application/octet-stream",
    // Chunks and fonts are named by their content hash, so they never change; the three entry
    // files keep their names from build to build and are revalidated.
    "Cache-Control": /^(chunk|asset)-/.test(file) ? "public, max-age=31536000, immutable" : "no-cache",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(body);
}
function inlineJson(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}
async function serveFilesPage(req, res, ctx) {
  const headers = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    // The bundle and the box's own routes, nothing else. `img-src blob:` is the image preview, which
    // the explorer reads as bytes and shows through an object URL; `data:` is the editors' icons.
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
  };
  const session = await readSession(req.headers.cookie, ctx.vmId);
  if (!session) {
    res.writeHead(401, headers);
    res.end(ctx.deniedPage);
    return;
  }
  const agentName = ctx.hostname ? ctx.hostname.split(".")[0] : "your agent";
  const data = { canWrite: session.canWrite, agentName, consoleUrl: ctx.consoleUrl };
  res.writeHead(200, headers);
  res.end(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${agentName.replace(/[&<>"']/g, "")} \xB7 files</title><link rel="stylesheet" href="/__cc/files-ui/tw.css"><link rel="stylesheet" href="/__cc/files-ui/app.css"></head><body class="bg-bg text-ink antialiased"><div id="root"></div><script id="cc-files" type="application/json">${inlineJson(data)}</script><script type="module" src="/__cc/files-ui/app.js"></script></body></html>`
  );
}

// src/routes/access.ts
var DASHBOARD_BUDGET_MS = 4e4;
var DASHBOARD_RETRY_WAIT_MS = 3e3;
var DASHBOARD_MIN_ATTEMPT_MS = 5e3;
function openclawBin() {
  return process.env.OPENCLAW_BIN ?? "/usr/bin/openclaw";
}
var NOVNC_URL = "/__cc/novnc/vnc_lite.html?path=__cc/novnc/websockify&scale=1";
function keysDir() {
  return process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
}
function installId(gatewayToken, vmId) {
  return createHash("sha256").update(gatewayToken ?? vmId).digest("hex").slice(0, 16);
}
var FORGET_PREVIOUS_GATEWAY_JS = `
  try {
    const KEY = 'controlclaw.install';
    if (d.install && localStorage.getItem(KEY) !== d.install) {
      localStorage.clear(); sessionStorage.clear();
      if (indexedDB.databases) {
        const dbs = await indexedDB.databases();
        await Promise.all(dbs.filter((x) => x.name).map((x) => new Promise((done) => {
          const req = indexedDB.deleteDatabase(x.name); req.onsuccess = req.onerror = req.onblocked = () => done();
        })));
      }
      localStorage.setItem(KEY, d.install);
    }
  } catch (e) { /* storage blocked: the bootstrap link still works in a clean browser */ }`;
function readKey(name) {
  try {
    return readFileSync3(join4(keysDir(), name), "utf-8").trim() || null;
  } catch {
    return null;
  }
}
function html(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    ...extraHeaders
  });
  res.end(body);
}
function consoleOrigin() {
  const configUrl = readKey("config_api_url");
  if (!configUrl) return null;
  try {
    return new URL(configUrl).origin;
  } catch {
    return null;
  }
}
function boxOrigin() {
  const hostname = readKey("vm_hostname");
  return hostname ? `https://${hostname}` : null;
}
var origins = null;
function allowedOrigins() {
  if (!origins) {
    origins = { box: boxOrigin(), console: consoleOrigin() };
    if (!origins.box) console.error("[access] no vm_hostname in KEYS_DIR: this box cannot recognise its own Origin");
  }
  return origins;
}
function sameSite(a2, b2) {
  const site = (origin) => {
    if (!origin) return null;
    try {
      return new URL(origin).hostname.split(".").slice(-2).join(".");
    } catch {
      return null;
    }
  };
  const x2 = site(a2);
  return x2 !== null && x2 === site(b2);
}
var AGENT_POLICY = () => ({ allowed: [allowedOrigins().box], allowTopLevelNavigation: true });
var VIEW_POLICY = () => ({ allowed: [allowedOrigins().box], allowTopLevelNavigation: true });
var EXCHANGE_POLICY = () => ({ allowed: [allowedOrigins().box], uncredentialed: "check" });
var LOGOUT_POLICY = () => {
  const { box, console: consoleOrigin2 } = allowedOrigins();
  return { allowed: [box, consoleOrigin2], uncredentialed: "check" };
};
function originAllowed(req, policy, label) {
  const verdict = checkOrigin(nodeRequestFacts(req), policy);
  if (verdict.ok) return true;
  console.warn(`[access] ${label}: ${denialMessage(verdict)}`);
  return false;
}
function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", ...extraHeaders });
  res.end(JSON.stringify(body));
}
var PAGE_CSS = `
:root{--bg:#f7f6fb;--card:#fff;--ink:#17162b;--ink2:#6b6a80;--line:#e6e4f0;--brand:#6d4aff;--brand-soft:#efeaff;--ok:#1a9c5b;--bad:#d64545}
@media(prefers-color-scheme:dark){:root{--bg:#0f0e17;--card:#17162b;--ink:#f3f2fa;--ink2:#a09fb5;--line:#2a2940;--brand:#9b82ff;--brand-soft:#2a2350;--ok:#3ccf82;--bad:#ff7070}}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font:15px/1.5 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:grid;place-items:center;padding:1.5rem}
.card{width:100%;max-width:26rem;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:2rem;box-shadow:0 20px 50px -30px rgba(23,22,43,.35)}
.mark{width:44px;height:44px;border-radius:12px;background:var(--brand-soft);color:var(--brand);display:grid;place-items:center;margin-bottom:1.25rem}
h1{font-size:1.2rem;margin:0 0 .25rem;letter-spacing:-.01em}
.host{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--ink2);margin:0 0 1.5rem;word-break:break-all}
.steps{list-style:none;margin:0;padding:0;display:grid;gap:.6rem}
.steps li{display:flex;align-items:center;gap:.7rem;color:var(--ink2);transition:color .2s}
.steps li.active{color:var(--ink)}.steps li.done{color:var(--ink)}
.dot{width:20px;height:20px;border-radius:50%;border:2px solid var(--line);display:grid;place-items:center;flex:none;transition:all .2s}
.active .dot{border-color:var(--brand);border-top-color:transparent;animation:spin .8s linear infinite}
.done .dot{border-color:var(--ok);background:var(--ok)}
.done .dot::after{content:"";width:5px;height:9px;border:solid #fff;border-width:0 2px 2px 0;transform:translateY(-1px) rotate(45deg)}
@keyframes spin{to{transform:rotate(360deg)}}
.err{display:none;margin-top:1.25rem;padding:.9rem 1rem;border-radius:12px;background:color-mix(in srgb,var(--bad) 10%,transparent);color:var(--bad);font-size:14px}
.err.show{display:block}
a.btn{display:inline-block;margin-top:1.25rem;padding:.55rem .9rem;border-radius:10px;background:var(--brand);color:#fff;text-decoration:none;font-weight:600;font-size:14px}
a.btn.alt{margin-left:.5rem;background:transparent;color:var(--brand);border:1px solid var(--line)}
p.note{margin:1.25rem 0 0;font-size:13px;color:var(--ink2)}
.foot{margin-top:1.5rem;font-size:12px;color:var(--ink2);display:flex;align-items:center;gap:.4rem}
p.lead{margin:0 0 1rem;color:var(--ink2)}
input.code{width:100%;font:600 1.6rem/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.3em;text-align:center;padding:.7rem;border:1px solid var(--line);border-radius:12px;background:var(--bg);color:var(--ink)}
input.code:focus{outline:2px solid var(--brand);outline-offset:1px}
button.btn{margin-top:1rem;width:100%;padding:.7rem;border:0;border-radius:10px;background:var(--brand);color:#fff;font-weight:600;font-size:15px;cursor:pointer}
`;
var MARK_SVG = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>`;
var CONSOLE_URL = "https://controlclaw.com/dashboard/agents";
function shell(title, body, script = "") {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${title}</title><style>${PAGE_CSS}</style></head><body><main class="card"><div class="mark">${MARK_SVG}</div>${body}<div class="foot"><span style="width:6px;height:6px;border-radius:50%;background:var(--brand)"></span>Secured by ControlClaw</div></main>${script ? `<script>${script}</script>` : ""}</body></html>`;
}
function escapeHtml(s2) {
  return s2.replace(/[&<>"']/g, (c2) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c2]);
}
function loginPage(hostname) {
  const agent = hostname ? escapeHtml(hostname.split(".")[0]) : "your agent";
  const host = hostname ? escapeHtml(hostname) : "";
  return shell(
    `Opening ${agent}\u2026`,
    `<h1 id="h">Opening ${agent}</h1><p class="host">${host}</p>
<ol class="steps">
  <li id="s1" class="active"><span class="dot"></span>Checking your ControlClaw pass</li>
  <li id="s2"><span class="dot"></span>Pairing this browser with the agent</li>
  <li id="s3"><span class="dot"></span>Loading OpenClaw</li>
</ol>
<div class="err" id="err"></div>
<p class="note" id="note" style="display:none"></p>
<a class="btn" id="back" href="${CONSOLE_URL}" style="display:none">Back to the console</a>
<a class="btn alt" id="anyway" href="/" style="display:none">Continue anyway</a>`,
    `
(async () => {
  const $ = (id) => document.getElementById(id);
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const step = (n) => { for (let i = 1; i <= 3; i++) { const el = $('s' + i); el.className = i < n ? 'done' : i === n ? 'active' : ''; } };
  const fail = (msg) => { $('h').textContent = 'Could not open the agent'; for (let i = 1; i <= 3; i++) $('s' + i).className = ''; $('err').textContent = msg; $('err').className = 'err show'; $('back').style.display = 'inline-block'; };
  const notPaired = (next, why) => { $('h').textContent = "Couldn't pair this browser"; $('s1').className = 'done'; $('s2').className = ''; $('s3').className = ''; $('note').textContent = (why ? 'The agent is running, but ' + why + '. ' : '') + 'Continue anyway opens OpenClaw, which will ask you to approve this browser. Or click Open again in your ControlClaw console.'; $('note').style.display = 'block'; $('back').style.display = 'inline-block'; $('anyway').href = next || '/'; $('anyway').style.display = 'inline-block'; };
  const t = new URLSearchParams(location.hash.slice(1)).get('t');
  history.replaceState(null, '', location.pathname);
  if (!t) { fail('This page only works from the Open button in your ControlClaw console.'); return; }
  const started = Date.now();
  let d, ok;
  try {
    const r = await fetch('/__cc/session', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: t }) });
    d = await r.json().catch(() => ({})); ok = r.ok;
  } catch (e) { fail('Could not reach the agent. Try again from your ControlClaw console.'); return; }
  if (!ok) { fail(d.error || 'This link has expired. Open the agent from your ControlClaw console again.'); return; }
  await wait(Math.max(0, 500 - (Date.now() - started)));
  step(2);
  ${FORGET_PREVIOUS_GATEWAY_JS}
  if (d.view === 'files') { $('h').textContent = 'Opening files'; step(3); location.replace(d.next); return; }
  if (d.paired === false) { notPaired(d.next, d.pairError); return; }
  await wait(450);
  step(3); await wait(350);
  location.replace(d.next || '/');
})();`
  );
}
var DENIED_PAGE = shell(
  "This agent is private",
  `<h1>This agent is private</h1>
<p class="note">Open it from your ControlClaw console. If you were signed in, your session has expired: click Open again.</p>
<a class="btn" href="${CONSOLE_URL}">Go to the console</a>`
);
var DENIED_VIEW_PAGE = shell(
  "This browser is private",
  `<h1>This browser is private</h1>
<p class="note">Open it from your ControlClaw console. If you were watching a moment ago, the view has expired: press Screen again.</p>
<a class="btn" href="${CONSOLE_URL}">Go to the console</a>`
);
var DENIED_FILES_PAGE = shell(
  "These files are private",
  `<h1>These files are private</h1>
<p class="note">Open them from your ControlClaw console. If you were signed in, your session has expired: click Files again.</p>
<a class="btn" href="${CONSOLE_URL}">Go to the console</a>`
);
function browserPage(hostname) {
  const agent = hostname ? escapeHtml(hostname.split(".")[0]) : "your agent";
  const host = hostname ? escapeHtml(hostname) : "";
  return shell(
    `Connecting to ${agent}\u2026`,
    `<h1 id="h">Opening the browser</h1><p class="host">${host}</p>
<ol class="steps">
  <li id="s1" class="active"><span class="dot"></span>Checking your ControlClaw pass</li>
  <li id="s2"><span class="dot"></span>Connecting to the live view</li>
</ol>
<div class="err" id="err"></div>`,
    `
(async () => {
  const $ = (id) => document.getElementById(id);
  const fail = (msg) => { $('h').textContent = 'Could not open the browser'; for (let i = 1; i <= 2; i++) $('s' + i).className = ''; $('err').textContent = msg; $('err').className = 'err show'; };
  const t = new URLSearchParams(location.hash.slice(1)).get('t');
  history.replaceState(null, '', location.pathname);
  if (!t) { fail('This page only works from the Screen button in your ControlClaw console.'); return; }
  let d, ok;
  try {
    const r = await fetch('/__cc/view-session', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: t }) });
    d = await r.json().catch(() => ({})); ok = r.ok;
  } catch (e) { fail('Could not reach the agent. Press Screen again in your ControlClaw console.'); return; }
  if (!ok) { fail(d.error || 'This view has expired. Press Screen again in your ControlClaw console.'); return; }
  $('s1').className = 'done'; $('s2').className = 'active';
  location.replace(${JSON.stringify(NOVNC_URL)});
})();`
  );
}
var OPEN_ERRORS = {
  invalid: "This link is not valid any more. Open the agent from your ControlClaw console again.",
  used: "This link was already used. Open the agent from your ControlClaw console again.",
  stopped: "This agent is stopped by your organization's emergency stop.",
  busy: "Too many sign-ins in a short time. Wait a minute, then open the agent again.",
  unreachable: "This browser needs a code, and your firewall could not send one. Make sure the agent with your chat channel is running, then open the agent again.",
  code_expired: "That code expired or ran out of tries. Open the agent from your ControlClaw console again to get a new one.",
  no_firewall: "This agent cannot check your browser with its firewall yet. Open it again from your ControlClaw console."
};
function openPage(hostname) {
  const agent = hostname ? escapeHtml(hostname.split(".")[0]) : "your agent";
  const host = hostname ? escapeHtml(hostname) : "";
  return shell(
    `Opening ${agent}\u2026`,
    `<h1 id="h">Opening ${agent}</h1><p class="host">${host}</p>
<ol class="steps">
  <li id="s1" class="active"><span class="dot"></span>Checking this browser with your firewall</li>
</ol>
<div class="err" id="err"></div>
<a class="btn" id="back" href="${CONSOLE_URL}" style="display:none">Back to the console</a>`,
    `
(async () => {
  const $ = (id) => document.getElementById(id);
  const ERRORS = ${JSON.stringify(OPEN_ERRORS)};
  const fail = (msg) => { $('h').textContent = 'Could not open the agent'; $('s1').className = ''; $('err').textContent = msg; $('err').className = 'err show'; $('back').style.display = 'inline-block'; };
  const h = new URLSearchParams(location.hash.slice(1));
  const i = h.get('i'), e = h.get('e');
  history.replaceState(null, '', location.pathname);
  if (e) { fail(ERRORS[e] || ERRORS.invalid); return; }
  if (!i) { fail('This page only works from the Open button in your ControlClaw console.'); return; }
  let d, ok;
  try {
    const r = await fetch('/__cc/open/begin', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    d = await r.json().catch(() => ({})); ok = r.ok;
  } catch (err) { fail('Could not reach the agent. Try again from your ControlClaw console.'); return; }
  if (!ok || !d.firewall || !d.c) { fail(d.error || ERRORS.no_firewall); return; }
  const f = document.createElement('form');
  f.method = 'POST'; f.action = d.firewall + '/__cc/open';
  for (const [k, v] of [['intent', i], ['c', d.c]]) { const x = document.createElement('input'); x.type = 'hidden'; x.name = k; x.value = v; f.appendChild(x); }
  document.body.appendChild(f);
  f.submit();
})();`
  );
}
var CHANNEL_NAMES = { telegram: "Telegram", slack: "Slack", whatsapp: "WhatsApp" };
function enrollPage(hostname, firewall) {
  const agent = hostname ? escapeHtml(hostname.split(".")[0]) : "your agent";
  const host = hostname ? escapeHtml(hostname) : "";
  if (!firewall) {
    return shell("Could not open the agent", `<h1>Could not open the agent</h1><p class="host">${host}</p><p class="note">${escapeHtml(OPEN_ERRORS.no_firewall)}</p><a class="btn" href="${CONSOLE_URL}">Back to the console</a>`);
  }
  return shell(
    `Confirm this browser`,
    `<h1>Confirm this browser</h1><p class="host">${host}</p>
<p class="lead" id="lead">This browser has not opened your organization's agents before. We sent a 6-digit code to your organization's chat channel. Type it here to open ${agent}.</p>
<form id="f" method="post" action="${escapeHtml(firewall)}/__cc/enroll/confirm">
  <input type="hidden" name="p" id="p">
  <input class="code" name="code" id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required autofocus aria-label="6-digit code">
  <div class="err" id="err"></div>
  <button class="btn" type="submit">Continue</button>
</form>
<p class="note">Only type the code on this page, at ${host}. If you did not just press Open, close this tab.</p>`,
    `
(() => {
  const $ = (id) => document.getElementById(id);
  const NAMES = ${JSON.stringify(CHANNEL_NAMES)};
  const h = new URLSearchParams(location.hash.slice(1));
  const p = h.get('p'), via = h.get('via'), e = h.get('e'), left = h.get('left');
  if (!p) { location.replace('/__cc/open#e=code_expired'); return; }
  $('p').value = p;
  // Keep the pending id in the fragment for a reload, drop the rest.
  history.replaceState(null, '', location.pathname + '#p=' + encodeURIComponent(p) + (via ? '&via=' + encodeURIComponent(via) : ''));
  if (via && NAMES[via]) $('lead').textContent = ${JSON.stringify("This browser has not opened your organization's agents before. We sent a 6-digit code to your ")} + NAMES[via] + ${JSON.stringify(`. Type it here to open ${agent}.`)};
  if (e === 'invalid_code') { $('err').textContent = 'Wrong code. ' + (left === '1' ? '1 try left.' : (left || 'A few') + ' tries left.'); $('err').className = 'err show'; }
})();`
  );
}
var BIND_COOKIE_PREFIX = "__Host-cc_bind_";
var BIND_TTL_S = 15 * 60;
var BIND_READ_MAX = 8;
function bindings(cookieHeader) {
  if (!cookieHeader) return [];
  const out = [];
  for (const part of cookieHeader.split(";")) {
    const i2 = part.indexOf("=");
    if (i2 < 0) continue;
    const name = part.slice(0, i2).trim();
    const value = part.slice(i2 + 1).trim();
    if (name.startsWith(BIND_COOKIE_PREFIX) && /^[A-Za-z0-9_-]{43}$/.test(value)) out.push({ name, value });
  }
  return out.slice(-BIND_READ_MAX);
}
function bindCookie(name, value) {
  return value ? `${name}=${value}; Path=/; Max-Age=${BIND_TTL_S}; HttpOnly; Secure; SameSite=Lax` : `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}
function bindingHash(value) {
  return createHash("sha256").update(value).digest("base64url");
}
async function acceptTicket(req, token, vmId, purpose) {
  const invalid = { error: "This link is not valid for this agent. Open it from your ControlClaw console again." };
  if (!token) return invalid;
  const cp = await verifyLoginToken(token, vmId, purpose);
  if (cp) return { jti: cp.jti, exp: cp.exp, canWrite: cp.canWrite === true, ...cp.next ? { next: cp.next } : {}, issuer: "control-plane", cookies: [] };
  const fw = await verifyFirewallTicket(token, vmId, purpose);
  if (!fw) return invalid;
  const match = bindings(req.headers.cookie).find((b2) => bindingHash(b2.value) === fw.c);
  if (!match) return { error: "This link was opened in a different browser. Open the agent again from this one." };
  return {
    jti: fw.jti,
    exp: fw.exp,
    canWrite: fw.canWrite,
    ...fw.next ? { next: fw.next } : {},
    deviceId: fw.deviceId,
    issuer: "firewall",
    cookies: [bindCookie(match.name, null)]
  };
}
function parseDashboardOutput(stdout, hostname, err) {
  let out = null;
  try {
    out = stdout.trim() ? JSON.parse(stdout) : null;
  } catch {
    out = null;
  }
  if (out?.browserUrl) {
    try {
      const params = new URLSearchParams(new URL(out.browserUrl).hash.slice(1));
      if (params.get("bootstrapToken")) {
        params.set("gatewayUrl", `wss://${hostname}`);
        return { url: `/#${params.toString()}` };
      }
    } catch {
    }
    return { reason: "the pairing link had no bootstrap token", retryable: false };
  }
  if (err?.code === "ENOENT") return { reason: "the OpenClaw CLI is not installed", retryable: false };
  if (err?.killed) return { reason: "the OpenClaw CLI did not answer in time", retryable: true };
  if (out?.ok === false) return { reason: out.reason || "OpenClaw could not issue a pairing link", retryable: true };
  return { reason: err ? `the OpenClaw CLI failed: ${err.message.split("\n")[0]}` : "the OpenClaw CLI printed nothing usable", retryable: false };
}
function runDashboard(hostname, timeoutMs) {
  return new Promise((resolve2) => {
    execFile(
      openclawBin(),
      ["dashboard", "--json", "--no-open"],
      { timeout: timeoutMs, env: { ...process.env, HOME: process.env.HOME ?? "/home/controlclaw" } },
      (err, stdout) => resolve2(parseDashboardOutput(String(stdout ?? ""), hostname, err))
    );
  });
}
async function dashboardBootstrapUrl(hostname, opts = {}) {
  const inFlight = dashboardInFlight.get(hostname);
  if (inFlight) return inFlight;
  const attempt = dashboardAttempt(hostname, opts).finally(() => dashboardInFlight.delete(hostname));
  dashboardInFlight.set(hostname, attempt);
  return attempt;
}
var dashboardInFlight = /* @__PURE__ */ new Map();
async function dashboardAttempt(hostname, opts) {
  const run3 = opts.run ?? runDashboard;
  const deadline = Date.now() + (opts.budgetMs ?? DASHBOARD_BUDGET_MS);
  let last = { reason: "no time left to ask OpenClaw", retryable: false };
  for (let attempt = 1; attempt <= 2; attempt++) {
    const left = deadline - Date.now();
    if (left < DASHBOARD_MIN_ATTEMPT_MS) break;
    last = await run3(hostname, left);
    if ("url" in last) return last;
    console.error(`[access] openclaw dashboard failed (attempt ${attempt}): ${last.reason}`);
    if (!last.retryable || attempt === 2) break;
    await new Promise((r2) => setTimeout(r2, opts.retryWaitMs ?? DASHBOARD_RETRY_WAIT_MS));
  }
  return last;
}
async function handleAccess(req, res, pathname) {
  const vmId = readKey("vm_id");
  if (!vmId) {
    json(res, 500, { error: "Box has no vm_id" });
    return;
  }
  if (pathname === "/__cc/login" && req.method === "GET") {
    html(res, 200, loginPage(readKey("vm_hostname")));
    return;
  }
  if (pathname === "/__cc/open" && req.method === "GET") {
    html(res, 200, openPage(readKey("vm_hostname")));
    return;
  }
  if (pathname === "/__cc/open/begin" && req.method === "POST") {
    if (!originAllowed(req, EXCHANGE_POLICY(), "/__cc/open/begin")) {
      json(res, 403, { error: "This request did not come from your agent's own page." });
      return;
    }
    const firewall = firewallOrigin();
    if (!firewall) {
      json(res, 409, { error: OPEN_ERRORS.no_firewall });
      return;
    }
    const value = randomBytes(32).toString("base64url");
    const name = `${BIND_COOKIE_PREFIX}${randomBytes(6).toString("base64url")}`;
    json(res, 200, { c: bindingHash(value), firewall }, { "Set-Cookie": bindCookie(name, value) });
    return;
  }
  if (pathname === "/__cc/enroll" && req.method === "GET") {
    html(res, 200, enrollPage(readKey("vm_hostname"), firewallOrigin()));
    return;
  }
  if (pathname === "/__cc/verify" && req.method === "GET") {
    if (originAllowed(req, AGENT_POLICY(), "/__cc/verify") && await verifySession(req.headers.cookie, vmId)) {
      res.writeHead(200, { "Cache-Control": "no-store" });
      res.end();
    } else {
      html(res, 401, DENIED_PAGE);
    }
    return;
  }
  if (pathname === "/__cc/session" && req.method === "POST") {
    if (!originAllowed(req, EXCHANGE_POLICY(), "/__cc/session")) {
      json(res, 403, { error: "This request did not come from your agent's own page." });
      return;
    }
    const body = await readJsonBody(req, 8192);
    const token = typeof body?.token === "string" ? body.token : "";
    const payload = await acceptTicket(req, token, vmId, "browser-login");
    if ("error" in payload) {
      json(res, 401, { error: payload.error });
      return;
    }
    if (!consumeJti(payload.jti, payload.exp)) {
      json(res, 401, { error: "This link was already used. Open the agent from your ControlClaw console again." });
      return;
    }
    const claims = { canWrite: payload.canWrite, ...payload.deviceId ? { deviceId: payload.deviceId } : {} };
    console.log(`[access] sign-in with a ${payload.issuer} ticket${payload.deviceId ? ` (browser ${payload.deviceId})` : ""}`);
    if (payload.next === "files") {
      const session2 = await issueSession(vmId, claims);
      json(res, 200, { next: "/__cc/files", view: "files", paired: true }, { "Set-Cookie": [sessionCookie(session2), ...payload.cookies] });
      return;
    }
    const hostname = readKey("vm_hostname");
    let next = "/";
    let paired = false;
    let pairError = null;
    if (hostname) {
      const bootstrap2 = await dashboardBootstrapUrl(hostname);
      if ("url" in bootstrap2) {
        next = bootstrap2.url;
        paired = true;
      } else {
        pairError = bootstrap2.reason;
      }
    } else {
      pairError = "this box does not know its own hostname";
    }
    if (!paired) {
      const gatewayToken = readKey("openclaw_gateway_token");
      if (gatewayToken) next = `/#token=${encodeURIComponent(gatewayToken)}`;
    }
    const session = await issueSession(vmId, claims);
    const install = installId(readKey("openclaw_gateway_token"), vmId);
    json(res, 200, { next, install, paired, pairError }, { "Set-Cookie": [sessionCookie(session), ...payload.cookies] });
    return;
  }
  if (pathname === "/__cc/browser" && req.method === "GET") {
    html(res, 200, browserPage(readKey("vm_hostname")));
    return;
  }
  if (pathname === "/__cc/view-session" && req.method === "POST") {
    if (!originAllowed(req, EXCHANGE_POLICY(), "/__cc/view-session")) {
      json(res, 403, { error: "This request did not come from your agent's own page." });
      return;
    }
    const body = await readJsonBody(req, 8192);
    const token = typeof body?.token === "string" ? body.token : "";
    const payload = await acceptTicket(req, token, vmId, "browser-view");
    if ("error" in payload) {
      json(res, 401, { error: payload.error.replace("Open it from your ControlClaw console again.", "Open the browser from your ControlClaw console again.") });
      return;
    }
    if (!consumeJti(payload.jti, payload.exp)) {
      json(res, 401, { error: "This link was already used. Press Screen again in your ControlClaw console." });
      return;
    }
    json(res, 200, { ok: true }, { "Set-Cookie": [viewSessionCookie(await issueViewSession(vmId, payload.deviceId)), ...payload.cookies] });
    return;
  }
  if (pathname === "/__cc/verify-view" && req.method === "GET") {
    if (originAllowed(req, VIEW_POLICY(), "/__cc/verify-view") && (await verifyViewSession(req.headers.cookie, vmId) || await verifySession(req.headers.cookie, vmId))) {
      res.writeHead(200, { "Cache-Control": "no-store" });
      res.end();
    } else {
      html(res, 401, DENIED_VIEW_PAGE);
    }
    return;
  }
  if (pathname === "/__cc/files" && req.method === "GET") {
    await serveFilesPage(req, res, { vmId, hostname: readKey("vm_hostname"), consoleUrl: CONSOLE_URL, deniedPage: DENIED_FILES_PAGE });
    return;
  }
  if (pathname.startsWith("/__cc/files-ui/") && req.method === "GET") {
    await serveFilesAsset(res, pathname.slice("/__cc/files-ui/".length));
    return;
  }
  if (pathname === "/__cc/logout" && req.method === "POST") {
    if (!originAllowed(req, LOGOUT_POLICY(), "/__cc/logout")) {
      json(res, 403, { error: "This request did not come from your agent's own page." });
      return;
    }
    json(res, 200, { ok: true }, { "Set-Cookie": [clearSessionCookie(), clearViewSessionCookie()] });
    return;
  }
  json(res, 404, { error: "Not found" });
}

// src/box-token.ts
import { readFileSync as readFileSync4 } from "fs";
import { importPKCS8, SignJWT as SignJWT2 } from "jose";
function readKeyFile(keysDir2, name) {
  try {
    return readFileSync4(`${keysDir2}/${name}`, "utf-8").trim();
  } catch {
    return null;
  }
}
async function signBoxToken(vmId, privateKeyPem) {
  const key = await importPKCS8(privateKeyPem, "EdDSA");
  return new SignJWT2({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
}
function makeBoxTokenSigner(keysDir2) {
  return async () => {
    const vmId = readKeyFile(keysDir2, "vm_id");
    const pem = readKeyFile(keysDir2, "vm_private_key.pem");
    if (!vmId || !pem) throw new Error("missing vm_id / vm_private_key.pem in KEYS_DIR");
    return signBoxToken(vmId, pem);
  };
}
function saasBaseUrl(keysDir2) {
  if (process.env.CONTROLCLAW_URL) return process.env.CONTROLCLAW_URL.replace(/\/$/, "");
  const configUrl = readKeyFile(keysDir2, "config_api_url");
  return configUrl ? configUrl.replace(/\/api\/.*$/, "") : null;
}

// src/software.ts
import { readFileSync as readFileSync5, realpathSync } from "fs";
import { dirname as dirname2 } from "path";
var BUILD = {
  version: true ? "0.1.0" : "dev",
  commit: true ? "0a71b73" : "unknown",
  builtAt: true ? "2026-09-30T15:58:35+01:00" : "unknown"
};
var RELEASE_PATH = process.env.RELEASE_FILE ?? "/etc/controlclaw/release.json";
var OPENCLAW_CANDIDATES = [
  "/usr/lib/node_modules/openclaw/package.json",
  "/usr/local/lib/node_modules/openclaw/package.json"
];
var OPENCLAW_BIN = "/usr/bin/openclaw";
var MAX_FIELD = 64;
function clip(value) {
  return typeof value === "string" && value.length > 0 ? value.slice(0, MAX_FIELD) : null;
}
function readJson(path) {
  try {
    const parsed = JSON.parse(readFileSync5(path, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
function readRelease(path = RELEASE_PATH) {
  const raw = readJson(path);
  if (!raw) return null;
  const commit2 = clip(raw.commit);
  const commitDate = clip(raw.commitDate);
  const installedAt = clip(raw.installedAt);
  if (!commit2 || !commitDate || !installedAt) return null;
  return { commit: commit2, commitDate, installedAt };
}
function readOpenClawVersion(candidates = OPENCLAW_CANDIDATES, bin = OPENCLAW_BIN) {
  for (const path of candidates) {
    const version = clip(readJson(path)?.version);
    if (version) return version;
  }
  let dir;
  try {
    dir = dirname2(realpathSync(bin));
  } catch {
    return null;
  }
  for (let i2 = 0; i2 < 4; i2++) {
    const pkg = readJson(`${dir}/package.json`);
    if (pkg?.name === "openclaw") return clip(pkg.version);
    const parent = dirname2(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
function boxSoftware(opts = {}) {
  return {
    agent: { ...BUILD },
    release: readRelease(opts.releasePath ?? RELEASE_PATH),
    openclaw: readOpenClawVersion(opts.openclawCandidates),
    features: firewallOrigin() ? ["open_v1"] : []
  };
}

// src/ready.ts
var KEYS_DIR = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
var readKeyFile2 = (name) => readKeyFile(KEYS_DIR, name);
var sleep = (ms) => new Promise((r2) => setTimeout(r2, ms));
function sshReading(readSsh) {
  const status = readSsh?.();
  return status ? { ...status, at: (/* @__PURE__ */ new Date()).toISOString() } : void 0;
}
async function reportReady(readSsh, extra = {}) {
  const vmId = readKeyFile2("vm_id");
  const readyUrl = readKeyFile2("ready_api_url");
  const privateKey = readKeyFile2("vm_private_key.pem");
  if (!vmId || !readyUrl || !privateKey) {
    console.warn(
      "[ready] missing vm_id / ready_api_url / vm_private_key.pem in KEYS_DIR \u2014 skipping ready report"
    );
    return;
  }
  const maxAttempts = 20;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const token = await signBoxToken(vmId, privateKey);
      const res = await fetch(readyUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
        // `ssh` is absent, not null, when there is nothing to report: the control plane reads an
        // absent key as "this box is too old to say" and leaves the grant alone.
        body: JSON.stringify({ software: boxSoftware(), ssh: sshReading(readSsh), ...extra })
      });
      if (res.ok) {
        console.log(`[ready] reported ready to SaaS (attempt ${attempt})`);
        return;
      }
      console.warn(`[ready] attempt ${attempt}/${maxAttempts}: HTTP ${res.status}`);
    } catch (err) {
      console.warn(`[ready] attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
    }
    await sleep(Math.min(2e3 * attempt, 15e3));
  }
  console.error(`[ready] gave up reporting ready after ${maxAttempts} attempts`);
}

// src/keys.ts
import crypto2 from "crypto";
import { readFileSync as readFileSync6, writeFileSync as writeFileSync3, existsSync as existsSync2, mkdirSync as mkdirSync2 } from "fs";
function readFile2(path) {
  try {
    return readFileSync6(path, "utf8").trim();
  } catch {
    return null;
  }
}
function ensureVmKeypair(keysDir2) {
  const privPath = `${keysDir2}/vm_private_key.pem`;
  const pubPath = `${keysDir2}/vm_public_key.pem`;
  if (existsSync2(privPath)) {
    return readFile2(pubPath) ?? derivePublicKey(readFileSync6(privPath, "utf8"));
  }
  const { publicKey, privateKey } = crypto2.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  mkdirSync2(keysDir2, { recursive: true });
  writeFileSync3(privPath, privateKey, { mode: 384 });
  writeFileSync3(pubPath, publicKey, { mode: 420 });
  console.log("[keys] generated on-box vm keypair");
  return publicKey;
}
function derivePublicKey(privatePem) {
  const pub = crypto2.createPublicKey(privatePem);
  return pub.export({ type: "spki", format: "pem" }).toString();
}
var sleep2 = (ms) => new Promise((r2) => setTimeout(r2, ms));
async function registerPublicKey(keysDir2) {
  const vmId = readFile2(`${keysDir2}/vm_id`);
  const token = readFile2(`${keysDir2}/bootstrap_token`);
  const registerUrl = readFile2(`${keysDir2}/register_api_url`);
  const publicKey = readFile2(`${keysDir2}/vm_public_key.pem`);
  if (!token || !registerUrl) {
    return;
  }
  if (!vmId || !publicKey) {
    console.warn("[keys] missing vm_id / vm_public_key.pem \u2014 cannot register");
    return;
  }
  const maxAttempts = 10;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(registerUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ vm_id: vmId, public_key: publicKey })
      });
      if (res.ok) {
        console.log(`[keys] registered public key (attempt ${attempt})`);
        return;
      }
      if (res.status === 409) {
        console.error("[keys] registration refused (409): identity already registered to another key");
        return;
      }
      console.warn(`[keys] register attempt ${attempt}/${maxAttempts}: HTTP ${res.status}`);
    } catch (err) {
      console.warn(`[keys] register attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
    }
    await sleep2(Math.min(2e3 * attempt, 15e3));
  }
  console.error(`[keys] gave up registering after ${maxAttempts} attempts`);
}
function spkiFromPem(pem) {
  const body = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
  return crypto2.createPublicKey({ key: Buffer.from(body, "base64"), format: "der", type: "spki" });
}
function verifyDetached(message, signatureB64, publicKeyPem) {
  try {
    const key = spkiFromPem(publicKeyPem);
    return crypto2.verify(null, Buffer.from(message, "utf8"), key, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}
function sha256Hex(s2) {
  return crypto2.createHash("sha256").update(s2, "utf8").digest("hex");
}

// src/mitm-ca.ts
import { readFileSync as readFileSync7, writeFileSync as writeFileSync4, existsSync as existsSync3 } from "fs";
import { execFileSync } from "child_process";
import { getCACertificates, setDefaultCACertificates } from "tls";
function readFile3(path) {
  try {
    return readFileSync7(path, "utf8").trim();
  } catch {
    return null;
  }
}
var SYSTEM_MITM_CA_PATH = "/usr/local/share/ca-certificates/controlclaw-mitm.crt";
function trustMitmCaInProcess(path = SYSTEM_MITM_CA_PATH) {
  const pem = readFile3(path);
  if (!pem) return false;
  setDefaultCACertificates([...getCACertificates("bundled"), pem]);
  return true;
}
var sleep3 = (ms) => new Promise((r2) => setTimeout(r2, ms));
async function ensureMitmCaInstalled(keysDir2, maxAttempts = 90) {
  const mitmIp = readFile3(`${keysDir2}/mitm_box_private_ip`);
  if (!mitmIp) {
    return { trusted: true, installed: false, message: "This box is not behind a firewall proxy." };
  }
  trustMitmCaInProcess();
  const configUrl = readFile3(`${keysDir2}/config_api_url`);
  const vmId = readFile3(`${keysDir2}/vm_id`);
  const privateKey = readFile3(`${keysDir2}/vm_private_key.pem`);
  if (!configUrl || !vmId || !privateKey) {
    console.warn("[mitm-ca] missing config_api_url / vm_id / vm_private_key.pem \u2014 cannot install CA");
    return { trusted: false, installed: false, message: "This box cannot ask for the firewall's certificate." };
  }
  const pinPath = `${keysDir2}/mitm_pinned_pubkey.pem`;
  const fprPath = `${keysDir2}/mitm_ca_fingerprint`;
  const caSrcPath = `${keysDir2}/mitm-ca.crt`;
  let last = "The firewall has not published a certificate yet.";
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const token = await signBoxToken(vmId, privateKey);
      const res = await fetch(configUrl, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const cfg = await res.json();
        const mitm = cfg.mitm;
        if (mitm?.caCert && mitm.caSig) {
          let pin = existsSync3(pinPath) ? readFile3(pinPath) : null;
          if (!pin && mitm.pubKey) {
            pin = mitm.pubKey;
            writeFileSync4(pinPath, pin, { mode: 420 });
            console.log("[mitm-ca] TOFU-pinned mitm public key (first box for this org)");
          }
          if (!pin) {
            console.warn(`[mitm-ca] attempt ${attempt}: CA present but no pin available yet`);
            last = "This box has no pinned firewall key yet.";
          } else if (!verifyDetached(mitm.caCert, mitm.caSig, pin)) {
            console.error(`[mitm-ca] attempt ${attempt}: CA signature does NOT match pinned key \u2014 refusing`);
            last = "The certificate on offer is not signed by this box's pinned firewall key, so it was refused.";
          } else {
            const fpr = sha256Hex(mitm.caCert);
            if (readFile3(fprPath) === fpr) return { trusted: true, installed: false, message: "Already up to date." };
            installCa(caSrcPath, mitm.caCert);
            trustMitmCaInProcess();
            writeFileSync4(fprPath, fpr, { mode: 420 });
            console.log(`[mitm-ca] installed mitm CA (sha256=${fpr.slice(0, 16)}\u2026)`);
            return { trusted: true, installed: true, message: `Installed the firewall's certificate (sha256=${fpr.slice(0, 16)}\u2026).` };
          }
        } else {
          console.log(`[mitm-ca] attempt ${attempt}/${maxAttempts}: mitm CA not published yet`);
        }
      } else {
        console.warn(`[mitm-ca] attempt ${attempt}/${maxAttempts}: config HTTP ${res.status}`);
        last = `The control plane answered HTTP ${res.status}.`;
      }
    } catch (err) {
      console.warn(`[mitm-ca] attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
      last = err.message;
    }
    if (attempt < maxAttempts) await sleep3(Math.min(1e3 * attempt, 1e4));
  }
  console.error("[mitm-ca] gave up waiting for a trusted mitm CA");
  return { trusted: false, installed: false, message: last };
}
function installCa(caSrcPath, caCert) {
  writeFileSync4(caSrcPath, caCert, { mode: 420 });
  execFileSync("sudo", ["/usr/local/bin/cc-install-ca"], { stdio: "inherit" });
}

// src/egress.ts
import { readFileSync as readFileSync8 } from "fs";
import { execFileSync as execFileSync2 } from "child_process";
import net from "net";
var MITM_PROXY_PORT = parseInt(process.env.MITM_PROXY_PORT ?? "8080", 10);
function readFile4(path) {
  try {
    return readFileSync8(path, "utf8").trim();
  } catch {
    return null;
  }
}
var sleep4 = (ms) => new Promise((r2) => setTimeout(r2, ms));
function probe(host, port, timeoutMs = 3e3) {
  return new Promise((resolve2) => {
    const sock = net.connect({ host, port });
    const done = (ok) => {
      sock.destroy();
      resolve2(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}
async function enableTransparentEgress(keysDir2) {
  const mitmIp = readFile4(`${keysDir2}/mitm_box_private_ip`);
  if (!mitmIp) return true;
  if (await waitForMitmProxy(mitmIp)) {
    try {
      execFileSync2("sudo", ["/usr/local/bin/cc-enable-egress"], { stdio: "inherit" });
      console.log("[egress] transparent egress activated (redirect + DNS \u2192 mitm box)");
      return true;
    } catch (err) {
      console.error(`[egress] cc-enable-egress failed: ${err.message}`);
      return false;
    }
  }
  console.error("[egress] gave up waiting for the mitm proxy \u2014 NOT activating egress");
  return false;
}
function waitForMitmProxy(mitmIp) {
  return (async () => {
    const maxAttempts = 90;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      if (await probe(mitmIp, MITM_PROXY_PORT)) return true;
      if (attempt % 10 === 0 || attempt <= 3) {
        console.log(`[egress] attempt ${attempt}/${maxAttempts}: mitm proxy ${mitmIp}:${MITM_PROXY_PORT} not reachable yet`);
      }
      await sleep4(Math.min(1e3 * attempt, 1e4));
    }
    return false;
  })();
}

// src/routes/health.ts
import { execSync } from "child_process";
function getServiceStatus(service) {
  try {
    const result = execSync(`systemctl is-active ${service}`, { encoding: "utf-8", timeout: 5e3 }).trim();
    return result === "active" ? "running" : "stopped";
  } catch {
    try {
      execSync(`systemctl cat ${service}`, { encoding: "utf-8", timeout: 5e3 });
      return "stopped";
    } catch {
      return "not-installed";
    }
  }
}
function handleHealth(res) {
  const services = {
    docker: getServiceStatus("docker"),
    tailscaled: getServiceStatus("tailscaled"),
    "browser-stream": getServiceStatus("browser-stream"),
    openclaw: getServiceStatus("openclaw")
  };
  let ps = "";
  try {
    ps = execSync("ps faux", { encoding: "utf-8", timeout: 5e3 });
  } catch {
    ps = "Failed to get process list";
  }
  const response = {
    status: "ok",
    uptime: process.uptime(),
    services,
    ps
  };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(response));
}

// src/routes/openclaw.ts
import { execSync as execSync2 } from "child_process";

// src/budgets.ts
var GATEWAY_READ_MS = 1e4;
var CONFIG_PATCH_MS = 2e4;
var CONFIG_PATCH_RESTART_MS = 45e3;
var APPLY_INLINE_WAIT_MS = 25e3;
var APPLY_RECORD_TTL_MS = 10 * 6e4;
var CHANNELS_STATUS_MS = 8e3;
var SERVICE_ACTION_MS = 3e4;
var TAILSCALE_STATUS_MS = 2e4;
var GOOGLE_VERSION_MS = 1e4;
function patchRestartsGateway(patch) {
  return Object.hasOwn(patch, "channels") || Object.hasOwn(patch, "plugins") || Object.hasOwn(patch, "models") || Object.hasOwn(patch, "memory");
}
var DEVICES_LIST_MS = GATEWAY_READ_MS;
var DEVICES_LIST_CLI_MS = 8e3;
var DEVICES_LIST_TOTAL_MS = 18e3;
var DEVICES_ACTION_MS = CONFIG_PATCH_MS;
var DEVICES_ACTION_CLI_MS = 45e3;

// src/routes/openclaw.ts
var SERVICE = process.env.CC_SERVICE ?? "openclaw";
var EXEC_TIMEOUT_MS = 5e3;
var ACTION_TIMEOUT_MS = SERVICE_ACTION_MS;
function runIsActive() {
  try {
    return execSync2(`systemctl is-active ${SERVICE}`, { encoding: "utf-8", timeout: EXEC_TIMEOUT_MS }).trim();
  } catch (err) {
    const stdout = err.stdout;
    if (stdout) return stdout.toString().trim();
    return "unknown";
  }
}
function runStatusSummary() {
  try {
    return execSync2(`systemctl status ${SERVICE} --no-pager -n 5`, {
      encoding: "utf-8",
      timeout: EXEC_TIMEOUT_MS
    }).trim();
  } catch (err) {
    const stdout = err.stdout;
    return stdout ? stdout.toString().trim() : "status unavailable";
  }
}
function send(res, statusCode, body) {
  res.writeHead(statusCode, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}
function runAction(action) {
  try {
    execSync2(`sudo systemctl ${action} ${SERVICE}`, { encoding: "utf-8", timeout: ACTION_TIMEOUT_MS });
    return { ok: true };
  } catch (err) {
    const message = err.stderr?.toString().trim() || (err instanceof Error ? err.message : "systemctl failed");
    return { ok: false, error: message };
  }
}
function isOpenClawActive() {
  return runIsActive() === "active";
}
function handleAction(res, action) {
  const result = runAction(action);
  const status = runIsActive();
  const summary = runStatusSummary();
  send(res, result.ok ? 200 : 500, {
    ok: result.ok,
    action,
    active: status === "active",
    status,
    message: result.ok ? summary : result.error ?? "failed"
  });
}
function handleStart(res) {
  handleAction(res, "start");
}
function handleStop(res) {
  handleAction(res, "stop");
}
function handleRestart(res) {
  handleAction(res, "restart");
}
function handleStatus(res, drive2) {
  const status = runIsActive();
  const summary = runStatusSummary();
  send(res, 200, {
    ok: true,
    action: "status",
    active: status === "active",
    status,
    message: summary,
    software: boxSoftware(),
    // A count, not the detail: this is polled for every agent, so it reads a file and makes no
    // rclone call. `GET /drive/status` is where the cache sizes and queues live.
    ...drive2 ? { drive: drive2 } : {}
  });
}

// src/routes/logs.ts
import { execFile as execFile2, spawn } from "child_process";
import { closeSync, fstatSync, openSync, readSync, readdirSync, statSync } from "fs";
import { join as join6 } from "path";

// src/redact.ts
import { readFileSync as readFileSync9 } from "fs";
import { join as join5 } from "path";
var SECRET_FILES = ["openclaw_gateway_token", "session_secret", "bootstrap_token"];
var MIN_SECRET_LENGTH = 8;
var PARAM_RE = /\b(token|api[_-]?key|key|secret|password|passwd|code_challenge|code_verifier|access_token|refresh_token|client_secret|authorization)=([^&\s"'`,;]+)/gi;
var BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g;
var secrets = [];
function escapeRegExp(s2) {
  return s2.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
var secretRe = null;
function loadRedactionSecrets(keysDir2) {
  const found = [];
  for (const name of SECRET_FILES) {
    try {
      const value = readFileSync9(join5(keysDir2, name), "utf-8").trim();
      if (value.length >= MIN_SECRET_LENGTH) found.push(value);
    } catch {
    }
  }
  setRedactionSecrets(found);
  return found.length;
}
function setRedactionSecrets(values) {
  secrets = values.filter((v2) => v2.length >= MIN_SECRET_LENGTH);
  secretRe = secrets.length ? new RegExp(secrets.map(escapeRegExp).join("|"), "g") : null;
}
function redact(text2) {
  let out = text2;
  if (secretRe) out = out.replace(secretRe, "[redacted]");
  out = out.replace(PARAM_RE, (_m, k2) => `${k2}=[redacted]`);
  out = out.replace(BEARER_RE, "Bearer [redacted]");
  return out;
}

// src/routes/logs.ts
var OPENCLAW_BIN2 = "/usr/bin/openclaw";
var SERVICE2 = process.env.CC_SERVICE ?? "openclaw";
var SNAPSHOT_TIMEOUT_MS = 15e3;
var CLI_TIMEOUT_MS = 1e4;
var MAX_BYTES = "250000";
var DEFAULT_LINES = 200;
var MAX_LINES = 1e3;
var PING_MS = 2e4;
var SERVICE_POLL_MS = 5e3;
var LOGS_STREAM_MAX_MS = 28e4;
var JOURNAL_LINES = 200;
var LOG_DIR = process.env.OPENCLAW_LOG_DIR ?? "/tmp/openclaw";
var TAIL_BYTES = 512 * 1024;
var FOLLOW_POLL_MS = 700;
var FOLLOW_BACKLOG_LINES = 50;
var CRASH_RE = /^(\s+at |\w*Error\b|node:|FATAL|Unhandled|ELIFECYCLE|Segmentation fault)/;
function env() {
  return { ...process.env, HOME: process.env.HOME ?? "/home/controlclaw" };
}
function run(cmd, args, timeout, maxBuffer = 4 * 1024 * 1024) {
  return new Promise((resolve2) => {
    execFile2(cmd, args, { timeout, maxBuffer, env: env(), encoding: "utf-8" }, (err, stdout, stderr) => {
      resolve2({
        stdout: typeof stdout === "string" ? stdout : String(stdout ?? ""),
        error: err ? String(stderr ?? "").trim().split("\n")[0] || err.message : null
      });
    });
  });
}
function mapCliRecord(raw) {
  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return null;
  }
  if (rec.type === "log") {
    return {
      time: String(rec.time ?? ""),
      level: String(rec.level ?? "info").toLowerCase(),
      subsystem: String(rec.subsystem ?? "openclaw"),
      message: redact(String(rec.message ?? ""))
    };
  }
  if (rec.type === "notice") {
    return { time: (/* @__PURE__ */ new Date()).toISOString(), level: "notice", subsystem: "openclaw", message: redact(String(rec.message ?? "")) };
  }
  return null;
}
function mapFileRecord(raw) {
  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return null;
  }
  const meta = rec._meta ?? {};
  if (typeof rec.message !== "string" || typeof rec.time !== "string") return null;
  let subsystem = "openclaw";
  const name = typeof meta.name === "string" ? meta.name : "";
  if (name.startsWith("{")) {
    try {
      const ctx = JSON.parse(name);
      const s2 = ctx.subsystem ?? ctx.module;
      if (typeof s2 === "string" && s2) subsystem = s2;
    } catch {
    }
  } else if (name) {
    subsystem = name;
  }
  return {
    time: rec.time,
    level: String(meta.logLevelName ?? "info").toLowerCase(),
    subsystem,
    message: redact(rec.message)
  };
}
function newestLogFile() {
  try {
    const candidates = readdirSync(LOG_DIR).filter((f2) => f2.startsWith("openclaw") && f2.endsWith(".log"));
    let best = null;
    for (const f2 of candidates) {
      const path = join6(LOG_DIR, f2);
      const mtime = statSync(path).mtimeMs;
      if (!best || mtime > best.mtime) best = { path, mtime };
    }
    return best?.path ?? null;
  } catch {
    return null;
  }
}
function readFileTail(lines) {
  const path = newestLogFile();
  if (!path) return null;
  let fd = null;
  try {
    fd = openSync(path, "r");
    const size = fstatSync(fd).size;
    const start = Math.max(0, size - TAIL_BYTES);
    const buf = Buffer.alloc(size - start);
    readSync(fd, buf, 0, buf.length, start);
    let text2 = buf.toString("utf-8");
    if (start > 0) text2 = text2.slice(text2.indexOf("\n") + 1);
    const out = [];
    for (const line of text2.split("\n")) {
      if (!line.trim()) continue;
      const mapped = mapFileRecord(line);
      if (mapped) out.push(mapped);
    }
    return { path, size, lines: out.slice(-lines) };
  } catch {
    return null;
  } finally {
    if (fd !== null) closeSync(fd);
  }
}
function followFile(start, onLine) {
  let path = start.path;
  let offset = start.size;
  let partial = "";
  const tick = () => {
    try {
      const newest = newestLogFile();
      if (newest && newest !== path) {
        path = newest;
        offset = 0;
        partial = "";
      }
      const size = statSync(path).size;
      if (size < offset) {
        offset = 0;
        partial = "";
      }
      if (size === offset) return;
      const fd = openSync(path, "r");
      try {
        const buf = Buffer.alloc(Math.min(size - offset, TAIL_BYTES));
        const n2 = readSync(fd, buf, 0, buf.length, offset);
        offset += n2;
        partial += buf.toString("utf-8", 0, n2);
      } finally {
        closeSync(fd);
      }
      let idx;
      while ((idx = partial.indexOf("\n")) >= 0) {
        const line = partial.slice(0, idx);
        partial = partial.slice(idx + 1);
        if (!line.trim()) continue;
        const mapped = mapFileRecord(line);
        if (mapped) onLine(mapped);
      }
    } catch {
    }
  };
  const timer = setInterval(tick, FOLLOW_POLL_MS);
  return () => clearInterval(timer);
}
async function readCliSnapshot(lines) {
  const { stdout, error } = await run(
    OPENCLAW_BIN2,
    ["logs", "--json", "--limit", String(lines), "--max-bytes", MAX_BYTES, "--timeout", String(CLI_TIMEOUT_MS)],
    SNAPSHOT_TIMEOUT_MS
  );
  const out = [];
  for (const line of stdout.split("\n")) {
    if (!line.trim()) continue;
    const mapped = mapCliRecord(line);
    if (mapped) out.push(mapped);
  }
  return { lines: out, warning: error && out.length === 0 ? redact(`openclaw logs: ${error}`) : null };
}
function mapJournalRecord(raw) {
  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return null;
  }
  const message = typeof rec.MESSAGE === "string" ? rec.MESSAGE : null;
  if (!message) return null;
  const ts = Number(rec.__REALTIME_TIMESTAMP);
  const time = Number.isFinite(ts) ? new Date(ts / 1e3).toISOString() : (/* @__PURE__ */ new Date()).toISOString();
  if (rec.SYSLOG_IDENTIFIER === "systemd") {
    return { time, level: "unit", subsystem: "systemd", message: redact(message) };
  }
  if (CRASH_RE.test(message)) {
    return { time, level: "error", subsystem: "stderr", message: redact(message) };
  }
  return null;
}
async function readJournal() {
  const { stdout } = await run(
    "sudo",
    ["journalctl", "-u", SERVICE2, "-n", String(JOURNAL_LINES), "-o", "json", "--no-pager"],
    SNAPSHOT_TIMEOUT_MS
  );
  const out = [];
  for (const line of stdout.split("\n")) {
    if (!line.trim()) continue;
    const mapped = mapJournalRecord(line);
    if (mapped) out.push(mapped);
  }
  return out;
}
function parseServiceShow(stdout) {
  const kv = {};
  for (const line of stdout.split("\n")) {
    const i2 = line.indexOf("=");
    if (i2 > 0) kv[line.slice(0, i2)] = line.slice(i2 + 1).trim();
  }
  const sinceRaw = kv.ExecMainStartTimestamp;
  const since = sinceRaw && !Number.isNaN(Date.parse(sinceRaw)) ? new Date(sinceRaw).toISOString() : null;
  const exit = Number(kv.ExecMainStatus);
  return {
    active: kv.ActiveState ?? "unknown",
    subState: kv.SubState ?? "unknown",
    result: kv.Result ?? "unknown",
    exitStatus: Number.isFinite(exit) ? exit : null,
    since,
    restarts: Number(kv.NRestarts) || 0
  };
}
async function readServiceState() {
  const { stdout } = await run(
    "systemctl",
    ["show", SERVICE2, "-p", "ActiveState,SubState,Result,ExecMainStatus,ExecMainStartTimestamp,NRestarts"],
    5e3
  );
  return parseServiceShow(stdout);
}
function parseLines(url2) {
  const n2 = parseInt(url2.searchParams.get("lines") ?? "", 10);
  if (!Number.isFinite(n2) || n2 < 1) return DEFAULT_LINES;
  return Math.min(n2, MAX_LINES);
}
async function handleLogs(url2, res) {
  const lines = parseLines(url2);
  const fromFile = readFileTail(lines);
  const [gateway2, journal2, service] = await Promise.all([
    fromFile ? Promise.resolve({ lines: fromFile.lines, warning: null }) : readCliSnapshot(lines),
    readJournal(),
    readServiceState()
  ]);
  const ts = (l2) => Date.parse(l2.time) || 0;
  const merged = [...gateway2.lines, ...journal2].sort((a2, b2) => ts(a2) - ts(b2)).slice(-lines);
  res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify({ service, lines: merged, ...gateway2.warning ? { warning: gateway2.warning } : {} }));
}
async function handleLogStream(req, res) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no"
  });
  res.flushHeaders?.();
  let closed = false;
  const write = (chunk) => {
    if (closed) return;
    try {
      res.write(chunk);
    } catch {
      cleanup();
    }
  };
  const event = (name, data) => write(`${name ? `event: ${name}
` : ""}data: ${JSON.stringify(data)}

`);
  const ping = setInterval(() => write(": ping\n\n"), PING_MS);
  const stop = setTimeout(() => {
    event("end", { reason: "max-duration" });
    cleanup();
  }, LOGS_STREAM_MAX_MS);
  let stopFollow = null;
  function cleanup() {
    if (closed) return;
    closed = true;
    clearInterval(ping);
    clearInterval(servicePoll);
    clearTimeout(stop);
    stopFollow?.();
    try {
      res.end();
    } catch {
    }
  }
  req.on("close", cleanup);
  res.on("close", cleanup);
  let lastService = "";
  const pushService = async () => {
    const service = await readServiceState();
    const key = JSON.stringify(service);
    if (key !== lastService) {
      lastService = key;
      event("service", service);
    }
  };
  void pushService();
  const servicePoll = setInterval(() => void pushService(), SERVICE_POLL_MS);
  const tail = readFileTail(FOLLOW_BACKLOG_LINES);
  if (tail) {
    for (const line of tail.lines) event(null, line);
    stopFollow = followFile(tail, (line) => event(null, line));
  } else {
    stopFollow = followCli((line) => event(null, line), () => {
      event("end", { reason: "cli-exit" });
      cleanup();
    });
  }
}
function followCli(onLine, onExit) {
  const child = spawn(OPENCLAW_BIN2, ["logs", "--json", "--follow", "--limit", String(FOLLOW_BACKLOG_LINES), "--max-bytes", MAX_BYTES], {
    env: env(),
    stdio: ["ignore", "pipe", "ignore"],
    detached: true
  });
  let buffer = "";
  child.stdout.on("data", (chunk) => {
    buffer += chunk.toString("utf-8");
    let idx;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      if (!line.trim()) continue;
      const mapped = mapCliRecord(line);
      if (mapped) onLine(mapped);
    }
  });
  child.on("exit", onExit);
  return () => {
    if (child.exitCode !== null || child.pid === void 0) return;
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch {
      child.kill("SIGTERM");
    }
  };
}

// src/gateway.ts
var GATEWAY_SCOPES = ["operator.read", "operator.approvals", "operator.admin"];
var PROTOCOL = 4;
var CONNECT_TIMEOUT_MS = 1e4;
var DEFAULT_CALL_TIMEOUT_MS = 1e4;
var DEFAULT_MIN_BACKOFF_MS = 1e3;
var RESTART_BEGIN_WAIT_MS = 15e3;
var RESTART_BACK_WAIT_MS = 9e4;
function isPersistedPendingRestart(message) {
  return /persisted and (updated the active Gateway, but a recovery restart is required|was accepted for restart)/i.test(message);
}
function isRestartWindow(message) {
  return /unavailable during gateway restart|gateway not connected|gateway disconnected|ECONNREFUSED/i.test(message);
}
var DEFAULT_MAX_BACKOFF_MS = 2e3;
async function patchConfig(gw, patch, opts) {
  const raw = JSON.stringify(patch);
  const log = opts.log ?? ((l2) => console.log(`[gateway] ${l2}`));
  for (let attempt = 0; ; attempt++) {
    const baseHash = attempt === 0 && opts.baseHash ? opts.baseHash : await freshHash(gw, opts.readTimeoutMs);
    try {
      await gw.call("config.patch", { raw, baseHash }, opts.timeoutMs);
      return;
    } catch (err) {
      const message = err.message ?? "";
      if (isPersistedPendingRestart(message)) {
        log("config write saved; waiting for the gateway restart it is queued behind");
        if (!await awaitRestart(gw)) throw new Error("The config was saved but the agent did not come back after restarting.", { cause: err });
        return;
      }
      if (attempt === 0 && isRestartWindow(message)) {
        log("config write landed while the gateway was restarting; sending it again once it is back");
        if (!await whenBack(gw, RESTART_BACK_WAIT_MS)) throw err;
        continue;
      }
      throw err;
    }
  }
}
async function freshHash(gw, timeoutMs = DEFAULT_CALL_TIMEOUT_MS) {
  const snapshot = await gw.call("config.get", {}, timeoutMs);
  if (typeof snapshot.hash !== "string" || !snapshot.hash) throw new Error("OpenClaw returned no config hash");
  return snapshot.hash;
}
async function whenBack(gw, timeoutMs) {
  if (gw.whenConnected) return gw.whenConnected(timeoutMs);
  const deadline = Date.now() + timeoutMs;
  while (!gw.connected && Date.now() < deadline) await new Promise((r2) => setTimeout(r2, 250));
  return gw.connected;
}
async function awaitRestart(gw) {
  if (gw.connected && gw.onDisconnected) {
    await new Promise((resolve2) => {
      const timer = setTimeout(done, RESTART_BEGIN_WAIT_MS);
      const off = gw.onDisconnected(done);
      function done() {
        clearTimeout(timer);
        off();
        resolve2();
      }
    });
  }
  return whenBack(gw, RESTART_BACK_WAIT_MS);
}
var GatewayClient = class {
  constructor(opts) {
    this.opts = opts;
    this.backoff = opts.minBackoffMs ?? DEFAULT_MIN_BACKOFF_MS;
  }
  ws = null;
  seq = 0;
  pending = /* @__PURE__ */ new Map();
  handlers = /* @__PURE__ */ new Map();
  connectHandlers = /* @__PURE__ */ new Set();
  disconnectHandlers = /* @__PURE__ */ new Set();
  backoff;
  reconnectTimer = null;
  stopped = false;
  outageLogged = false;
  _connected = false;
  get connected() {
    return this._connected;
  }
  start() {
    this.stopped = false;
    this.connect();
  }
  stop() {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.ws?.close();
  }
  /** Subscribe to a gateway event by name. Returns the unsubscribe function. */
  on(event, handler) {
    let set = this.handlers.get(event);
    if (!set) {
      set = /* @__PURE__ */ new Set();
      this.handlers.set(event, set);
    }
    set.add(handler);
    return () => set?.delete(handler);
  }
  /** Runs after every successful handshake (initial and each reconnect). */
  onConnected(handler) {
    this.connectHandlers.add(handler);
    return () => this.connectHandlers.delete(handler);
  }
  /** Resolves true once the handshake is done (at once if it already is), false after `timeoutMs`. */
  whenConnected(timeoutMs) {
    if (this._connected) return Promise.resolve(true);
    return new Promise((resolve2) => {
      const done = (ok) => {
        clearTimeout(timer);
        off();
        resolve2(ok);
      };
      const timer = setTimeout(() => done(false), timeoutMs);
      const off = this.onConnected(() => done(true));
    });
  }
  /** Runs every time an established connection closes. Returns the unsubscribe function. */
  onDisconnected(handler) {
    this.disconnectHandlers.add(handler);
    return () => this.disconnectHandlers.delete(handler);
  }
  async call(method, params = {}, timeoutMs = DEFAULT_CALL_TIMEOUT_MS) {
    const ws = this.ws;
    if (!ws || ws.readyState !== ws.OPEN) throw new Error("gateway not connected");
    return this.send(ws, method, params, timeoutMs);
  }
  send(ws, method, params, timeoutMs) {
    const id = String(++this.seq);
    return new Promise((resolve2, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`gateway call ${method} timed out`));
      }, timeoutMs);
      this.pending.set(id, { resolve: resolve2, reject, timer });
      try {
        ws.send(JSON.stringify({ type: "req", id, method, params }));
      } catch (err) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(err);
      }
    });
  }
  log(msg) {
    (this.opts.log ?? console.log)(`[gateway] ${msg}`);
  }
  connect() {
    if (this.stopped) return;
    const Impl = this.opts.WebSocketImpl ?? WebSocket;
    let ws;
    try {
      ws = new Impl(this.opts.url);
    } catch (err) {
      this.scheduleReconnect(err.message);
      return;
    }
    this.ws = ws;
    const connectTimer = setTimeout(() => {
      if (!this._connected) ws.close();
    }, CONNECT_TIMEOUT_MS);
    ws.onopen = () => {
      this.send(
        ws,
        "connect",
        {
          minProtocol: PROTOCOL,
          maxProtocol: PROTOCOL,
          client: { id: "gateway-client", version: "controlclaw-vm-agent", platform: "linux", mode: "backend" },
          role: "operator",
          scopes: this.opts.scopes ?? GATEWAY_SCOPES,
          caps: ["approvals", "exec-approvals"],
          auth: { token: this.opts.token }
        },
        CONNECT_TIMEOUT_MS
      ).then(() => {
        clearTimeout(connectTimer);
        this._connected = true;
        this.backoff = this.opts.minBackoffMs ?? DEFAULT_MIN_BACKOFF_MS;
        this.outageLogged = false;
        this.log("connected");
        for (const h2 of this.connectHandlers) {
          try {
            h2();
          } catch (err) {
            this.log(`connect handler failed: ${err.message}`);
          }
        }
      }).catch((err) => {
        this.log(`handshake failed: ${err.message}`);
        ws.close();
      });
    };
    ws.onmessage = (m2) => {
      let frame2;
      try {
        frame2 = JSON.parse(String(m2.data));
      } catch {
        return;
      }
      if (frame2.type === "res") {
        const p2 = this.pending.get(frame2.id);
        if (!p2) return;
        this.pending.delete(frame2.id);
        clearTimeout(p2.timer);
        if (frame2.ok) p2.resolve(frame2.payload);
        else p2.reject(new Error(frame2.error?.message ?? frame2.error?.code ?? "gateway error"));
        return;
      }
      if (frame2.type === "event") {
        const set = this.handlers.get(frame2.event);
        if (!set) return;
        for (const h2 of set) {
          try {
            h2(frame2.payload);
          } catch (err) {
            this.log(`handler for ${frame2.event} failed: ${err.message}`);
          }
        }
      }
    };
    ws.onerror = () => {
    };
    ws.onclose = () => {
      clearTimeout(connectTimer);
      const wasConnected = this._connected;
      this._connected = false;
      if (this.ws === ws) this.ws = null;
      if (wasConnected) for (const h2 of [...this.disconnectHandlers]) h2();
      for (const [id, p2] of this.pending) {
        clearTimeout(p2.timer);
        p2.reject(new Error("gateway disconnected"));
        this.pending.delete(id);
      }
      this.scheduleReconnect(wasConnected ? "connection closed" : "gateway unreachable");
    };
  }
  scheduleReconnect(reason) {
    if (this.stopped) return;
    if (!this.outageLogged) {
      this.log(`down (${reason}); retrying in the background`);
      this.outageLogged = true;
    }
    const delay = this.backoff;
    this.backoff = Math.min(this.backoff * 2, this.opts.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }
};

// src/audit.ts
import { existsSync as existsSync4, mkdirSync as mkdirSync3, readFileSync as readFileSync10, renameSync as renameSync2, writeFileSync as writeFileSync5 } from "fs";
import { dirname as dirname3 } from "path";
var PAGE_LIMIT = 500;
var MAX_PAGES = 40;
var AFTER_SLACK_MS = 6e4;
var MIN_BACKOFF_MS = 5e3;
var MAX_BACKOFF_MS = 6e4;
function mapAuditEvent(ev) {
  if (ev.kind !== "tool_action" && ev.kind !== "agent_run") return null;
  if (typeof ev.sequence !== "number" || typeof ev.eventId !== "string" || typeof ev.occurredAt !== "number") return null;
  if (ev.kind === "tool_action" && !ev.toolCallId) return null;
  if (ev.kind === "agent_run" && !ev.runId) return null;
  const cut = (v2, max) => v2 ? v2.slice(0, max) : void 0;
  const rec = {
    source: ev.kind,
    event_id: ev.eventId.slice(0, 64),
    sequence: ev.sequence,
    occurred_at: ev.occurredAt,
    status: ev.status ?? "unknown",
    action: (ev.action ?? "").slice(0, 64)
  };
  const toolName = cut(ev.toolName, 120);
  const toolCallId = cut(ev.toolCallId, 200);
  const runId = cut(ev.runId, 128);
  const sessionKey = cut(ev.sessionKey, 200);
  const agentId = cut(ev.agentId, 64);
  if (toolName) rec.tool_name = toolName;
  if (toolCallId) rec.tool_call_id = toolCallId;
  if (runId) rec.run_id = runId;
  if (sessionKey) rec.session_key = sessionKey;
  if (agentId) rec.agent_id = agentId;
  return rec;
}
var AuditShipper = class {
  constructor(opts) {
    this.opts = opts;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.batchSize = opts.batchSize ?? PAGE_LIMIT;
    this.cursor = this.loadCursor() ?? { sequence: 0, occurredAt: this.now() };
  }
  cursor;
  inFlight = false;
  nextAttemptAt = 0;
  backoff = MIN_BACKOFF_MS;
  fetchImpl;
  batchSize;
  get position() {
    return { ...this.cursor };
  }
  now() {
    return (this.opts.now ?? Date.now)();
  }
  log(msg) {
    (this.opts.log ?? console.log)(`[audit] ${msg}`);
  }
  loadCursor() {
    try {
      if (!existsSync4(this.opts.cursorPath)) return null;
      const c2 = JSON.parse(readFileSync10(this.opts.cursorPath, "utf-8"));
      if (typeof c2.sequence === "number" && typeof c2.occurredAt === "number") return { sequence: c2.sequence, occurredAt: c2.occurredAt };
    } catch {
    }
    return null;
  }
  saveCursor() {
    const tmp = `${this.opts.cursorPath}.tmp`;
    mkdirSync3(dirname3(this.opts.cursorPath), { recursive: true });
    writeFileSync5(tmp, JSON.stringify(this.cursor), { mode: 384 });
    renameSync2(tmp, this.opts.cursorPath);
  }
  async tick() {
    const total = { read: 0, accepted: 0, duplicates: 0 };
    if (this.inFlight || !this.opts.client.connected) return total;
    if (this.now() < this.nextAttemptAt) return total;
    this.inFlight = true;
    try {
      return await this.tickInner(total);
    } finally {
      this.inFlight = false;
    }
  }
  async tickInner(total) {
    let fresh;
    try {
      fresh = await this.fetchNew();
    } catch (err) {
      this.log(`ledger read failed: ${err.message}`);
      this.nextAttemptAt = this.now() + MIN_BACKOFF_MS;
      return total;
    }
    total.read = fresh.length;
    if (fresh.length === 0) return total;
    fresh.sort((a2, b2) => a2.sequence - b2.sequence);
    for (let i2 = 0; i2 < fresh.length; i2 += this.batchSize) {
      const batch = fresh.slice(i2, i2 + this.batchSize);
      const records = batch.map(mapAuditEvent).filter((r2) => r2 !== null);
      const last = batch[batch.length - 1];
      if (records.length > 0) {
        const res = await this.post(records);
        if (!res) {
          this.nextAttemptAt = this.now() + this.backoff;
          this.backoff = Math.min(this.backoff * 2, MAX_BACKOFF_MS);
          return total;
        }
        total.accepted += res.accepted;
        total.duplicates += res.duplicates;
      }
      this.cursor = { sequence: last.sequence, occurredAt: Math.max(this.cursor.occurredAt, last.occurredAt) };
      this.saveCursor();
      this.backoff = MIN_BACKOFF_MS;
      this.nextAttemptAt = 0;
    }
    return total;
  }
  /** Events with sequence above the cursor, unordered. */
  async fetchNew() {
    const out = [];
    const after = Math.max(0, this.cursor.occurredAt - AFTER_SLACK_MS);
    let cursor;
    let reachedOld = false;
    for (let page = 0; page < MAX_PAGES; page++) {
      const res = await this.opts.client.call("audit.activity.list", {
        after,
        limit: PAGE_LIMIT,
        ...cursor ? { cursor } : {}
      });
      const events = res.events ?? [];
      for (const ev of events) {
        if (typeof ev.sequence !== "number") continue;
        if (ev.sequence <= this.cursor.sequence) {
          reachedOld = true;
          continue;
        }
        out.push(ev);
      }
      if (reachedOld || !res.nextCursor || events.length < PAGE_LIMIT) break;
      cursor = res.nextCursor;
    }
    if (!reachedOld && out.length >= MAX_PAGES * PAGE_LIMIT) {
      const oldest = Math.min(...out.map((e) => e.sequence));
      this.log(`backlog larger than ${out.length} events; ledger entries below sequence ${oldest} are not shipped`);
    }
    return out;
  }
  async post(records) {
    try {
      const token = await this.opts.getToken();
      const res = await this.fetchImpl(this.opts.activityUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ records })
      });
      if (res.status === 400 || res.status === 413) {
        this.log(`batch of ${records.length} rejected with HTTP ${res.status}; dropped`);
        return { accepted: 0, duplicates: 0 };
      }
      if (!res.ok) {
        this.log(`ship failed: HTTP ${res.status}`);
        return null;
      }
      const body = await res.json().catch(() => ({}));
      return { accepted: body.accepted ?? records.length, duplicates: body.duplicates ?? 0 };
    } catch (err) {
      this.log(`ship failed: ${err.message}`);
      return null;
    }
  }
};

// src/approvals.ts
var APPROVAL_FAMILIES = {
  exec: "exec",
  plugin: "plugin",
  openclaw: "system"
};
var TITLE_MAX = 200;
var LIST_METHODS = Object.keys(APPROVAL_FAMILIES).map((family) => [
  family,
  `${family}.approval.list`
]);
var CONTROL_RE = /\x1b\[[0-9;?]*[ -/]*[@-~]|[\x00-\x1f\x7f]/g;
function sanitizeTitle(text2) {
  const flat = redact(text2).replace(CONTROL_RE, " ").replace(/\s+/g, " ").trim();
  return flat.length > TITLE_MAX ? `${flat.slice(0, TITLE_MAX - 1)}\u2026` : flat;
}
function str(v2) {
  return typeof v2 === "string" && v2.trim() ? v2.trim() : null;
}
function summaryOf(kind, p2) {
  const r2 = p2.request ?? {};
  const pres = p2.presentation ?? {};
  const candidate = str(r2.command) ?? str(pres.commandText) ?? str(r2.rawCommand) ?? str(r2.summary) ?? str(pres.summary) ?? str(r2.title) ?? str(pres.title) ?? str(r2.toolName) ?? str(r2.pluginId) ?? str(r2.action);
  return sanitizeTitle(candidate ?? `${kind} approval`);
}
function detailOf(p2) {
  const r2 = p2.request ?? {};
  const rows = [];
  const add = (k2, v2) => {
    const s2 = str(v2);
    if (s2) rows.push([k2, sanitizeTitle(s2)]);
  };
  add("agent", r2.agentId);
  add("session", r2.sessionKey);
  add("cwd", r2.cwd);
  add("host", r2.host);
  add("plugin", r2.pluginId ?? r2.plugin);
  add("tool", r2.toolName);
  const analysis = r2.commandAnalysis;
  if (Array.isArray(analysis?.riskKinds) && analysis.riskKinds.length > 0) {
    rows.push(["risk", sanitizeTitle(analysis.riskKinds.map(String).join(", "))]);
  }
  add("warning", r2.warningText);
  return rows;
}
function resolutionOf(p2) {
  const d2 = (p2.decision ?? p2.status ?? "").toLowerCase();
  if (d2.startsWith("allow")) return "approved";
  if (d2 === "deny" || d2 === "denied") return p2.resolvedBy ? "denied" : "expired";
  return "expired";
}
var ApprovalsBridge = class {
  constructor(opts) {
    this.opts = opts;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }
  tracked = /* @__PURE__ */ new Map();
  inFlight = false;
  fetchImpl;
  unsubscribe = [];
  now() {
    return (this.opts.now ?? Date.now)();
  }
  log(msg) {
    (this.opts.log ?? console.log)(`[approvals] ${msg}`);
  }
  get pendingCount() {
    let n2 = 0;
    for (const t2 of this.tracked.values()) if (!t2.done) n2++;
    return n2;
  }
  start() {
    for (const [family, kind] of Object.entries(APPROVAL_FAMILIES)) {
      this.unsubscribe.push(
        this.opts.client.on(`${family}.approval.requested`, (payload) => {
          void this.onRequested(kind, payload).catch(
            (err) => this.log(`request handling failed: ${err.message}`)
          );
        }),
        this.opts.client.on(`${family}.approval.resolved`, (payload) => {
          void this.onResolved(payload).catch(
            (err) => this.log(`resolution handling failed: ${err.message}`)
          );
        })
      );
    }
    this.unsubscribe.push(
      this.opts.client.onConnected(() => {
        void this.reconcile().catch((err) => this.log(`reconcile failed: ${err.message}`));
      })
    );
    if (this.opts.client.connected) void this.reconcile().catch(() => void 0);
  }
  stop() {
    for (const u2 of this.unsubscribe) u2();
    this.unsubscribe = [];
  }
  /** After (re)connect: raise what is pending on the gateway, settle what vanished meanwhile. */
  async reconcile() {
    const known = [...this.tracked.keys()];
    const seen = /* @__PURE__ */ new Set();
    for (const [family, method] of LIST_METHODS) {
      let list = [];
      try {
        list = await this.opts.client.call(method, {}) ?? [];
      } catch (err) {
        this.log(`${method} failed: ${err.message}`);
        continue;
      }
      for (const p2 of list) {
        if (!p2.id) continue;
        seen.add(p2.id);
        if (!this.tracked.has(p2.id)) await this.onRequested(APPROVAL_FAMILIES[family], p2);
      }
    }
    for (const id of known) {
      const t2 = this.tracked.get(id);
      if (!t2 || t2.done || seen.has(id)) continue;
      let resolution = "expired";
      try {
        const got = await this.opts.client.call("approval.get", {
          id,
          kind: t2.approvalKind
        });
        const p2 = got.approval ?? got;
        if (p2?.decision || p2?.status) resolution = resolutionOf(p2);
      } catch {
      }
      t2.done = true;
      this.log(`${id} gone from the gateway: ${resolution}`);
      await this.postResolution(id, resolution);
    }
  }
  async onRequested(kind, p2) {
    const id = p2.id;
    if (!id || this.tracked.has(id)) return;
    this.tracked.set(id, {
      kind,
      approvalKind: p2.approvalKind ?? (kind === "system" ? "openclaw" : kind),
      payload: p2,
      expiresAt: typeof p2.expiresAtMs === "number" ? p2.expiresAtMs : null,
      raised: false,
      done: false,
      resolvedByUs: false
    });
    await this.raise(id);
  }
  /** POST the approval to the control plane; on failure tick() tries again. */
  async raise(id) {
    const t2 = this.tracked.get(id);
    if (!t2 || t2.raised || t2.done) return;
    const body = {
      permission_id: `oc:${id}`,
      kind: t2.kind,
      title: summaryOf(t2.kind, t2.payload),
      detail: detailOf(t2.payload),
      expires_at: t2.expiresAt ? new Date(t2.expiresAt).toISOString() : null
    };
    const res = await this.post(body);
    if (!res) return;
    t2.raised = true;
    this.log(`raised ${t2.kind} approval ${id} \u2192 ${res.status}`);
    await this.applyStatus(id, res.status);
  }
  async onResolved(p2) {
    const id = p2.id;
    if (!id) return;
    const t2 = this.tracked.get(id);
    if (!t2) return;
    if (t2.done && t2.resolvedByUs) return;
    if (t2.done) return;
    t2.done = true;
    const resolution = resolutionOf(p2);
    this.log(`${id} settled on the gateway: ${resolution}`);
    await this.postResolution(id, resolution);
  }
  /** Poll the console for decisions on pending approvals. Called on an interval. */
  async tick() {
    if (this.inFlight) return;
    this.inFlight = true;
    try {
      for (const [id, t2] of this.tracked) {
        if (t2.done) {
          if (!t2.expiresAt || this.now() > t2.expiresAt + 36e5) this.tracked.delete(id);
          continue;
        }
        if (t2.expiresAt && this.now() > t2.expiresAt + 6e4) {
          t2.done = true;
          if (t2.raised) await this.postResolution(id, "expired");
          continue;
        }
        if (!t2.raised) {
          await this.raise(id);
          continue;
        }
        const status = await this.getStatus(id);
        if (status) await this.applyStatus(id, status);
      }
    } finally {
      this.inFlight = false;
    }
  }
  async applyStatus(id, status) {
    const t2 = this.tracked.get(id);
    if (!t2 || t2.done) return;
    let decision;
    if (status === "approved") decision = "allow-once";
    else if (status === "denied") decision = "deny";
    else if (status === "expired") {
      t2.done = true;
      return;
    } else return;
    try {
      await this.opts.client.call("approval.resolve", { id, kind: t2.approvalKind, decision });
      t2.done = true;
      t2.resolvedByUs = true;
      this.log(`${id}: ${decision}`);
    } catch (err) {
      this.log(`approval.resolve ${id} failed: ${err.message}`);
    }
  }
  async getStatus(id) {
    try {
      const token = await this.opts.getToken();
      const url2 = `${this.opts.permissionUrl}?permission_id=${encodeURIComponent(`oc:${id}`)}`;
      const res = await this.fetchImpl(url2, { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) return null;
      const body = await res.json();
      return body.status ?? null;
    } catch {
      return null;
    }
  }
  async post(body) {
    try {
      const token = await this.opts.getToken();
      const res = await this.fetchImpl(this.opts.permissionUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      if (!res.ok) {
        this.log(`POST failed: HTTP ${res.status}`);
        return null;
      }
      const out = await res.json();
      return { status: out.status ?? "pending" };
    } catch (err) {
      this.log(`POST failed: ${err.message}`);
      return null;
    }
  }
  async postResolution(id, resolution) {
    if (!this.tracked.get(id)?.raised) return;
    await this.post({ permission_id: `oc:${id}`, resolution, resolved_by: "openclaw" });
  }
};

// src/channels.ts
import { existsSync as existsSync6, mkdirSync as mkdirSync4, readFileSync as readFileSync11, renameSync as renameSync3, writeFileSync as writeFileSync6 } from "fs";
import { dirname as dirname4 } from "path";
import { randomUUID } from "crypto";

// src/exec.ts
import { execFile as execFile3 } from "child_process";
var defaultExec = (file, args, timeoutMs, stdin, opts) => new Promise((resolve2, reject) => {
  const env2 = { ...process.env, HOME: process.env.HOME ?? "/home/controlclaw", ...opts?.env };
  const child = execFile3(file, args, { timeout: timeoutMs, env: env2, maxBuffer: opts?.maxBuffer }, (err, stdout, stderr) => {
    if (err) {
      const e = err;
      e.stdout = String(stdout ?? "");
      e.stderr = String(stderr ?? "");
      reject(e);
    } else resolve2({ stdout: String(stdout ?? ""), stderr: String(stderr ?? "") });
  });
  if (child.stdin) {
    child.stdin.on("error", () => void 0);
    if (stdin !== void 0) child.stdin.end(stdin);
    else child.stdin.end();
  }
});
function execFailureLine(err) {
  const e = err;
  const text2 = (e.stderr || e.stdout || e.message || "").replace(/\x1b\[[0-9;]*m/g, "").trim();
  return text2.split("\n").filter((l2) => l2.trim()).pop() ?? "command failed";
}

// src/openclaw-allow.ts
import { existsSync as existsSync5 } from "fs";
import { createRequire } from "module";
var ENTRY_CAP = 200;
var requireBuiltin = createRequire(import.meta.url);
function nodeSqlite() {
  try {
    return requireBuiltin("node:sqlite");
  } catch {
    return null;
  }
}
var defaultOpener = (path) => {
  const sqlite = nodeSqlite();
  if (!sqlite) throw new Error("this Node build has no node:sqlite");
  const db = new sqlite.DatabaseSync(path, { readOnly: true });
  try {
    db.exec("PRAGMA busy_timeout = 2000;");
  } catch {
  }
  return db;
};
function looksBusy(message) {
  return /\b(EBUSY|EAGAIN|SQLITE_BUSY|SQLITE_PROTOCOL)\b|database is locked|database table is locked|locking protocol/i.test(message);
}
function looksUnopenable(message) {
  return /\b(SQLITE_CANTOPEN|SQLITE_READONLY_CANTINIT|SQLITE_READONLY_RECOVERY)\b|unable to open database file/i.test(message);
}
function failure(message) {
  if (looksBusy(message)) return { busy: true, message: "The agent is busy right now, so who it has allowed could not be read." };
  if (looksUnopenable(message)) {
    return { busy: false, message: "Your agent's own list could not be opened. Restarting the agent clears this." };
  }
  return { busy: false, message: "Your agent's own list could not be read." };
}
function isSender(entry) {
  return entry !== "*" && !entry.startsWith("accessGroup:");
}
function text(v2) {
  return typeof v2 === "string" && v2.length > 0 ? v2 : null;
}
function stamp(v2) {
  const n2 = typeof v2 === "number" ? v2 : typeof v2 === "bigint" ? Number(v2) : Number.NaN;
  if (!Number.isFinite(n2) || n2 <= 0) return null;
  const ms = n2 < 1e11 ? n2 * 1e3 : n2;
  const d2 = new Date(ms);
  return Number.isNaN(d2.getTime()) ? null : d2.toISOString();
}
function labelFromMeta(metaJson) {
  const raw = text(metaJson);
  if (!raw) return null;
  let meta;
  try {
    meta = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!meta || typeof meta !== "object") return null;
  return text(meta.name) ?? text(meta.displayName) ?? text(meta.username) ?? text(meta.title) ?? null;
}
function readAllowList(opts) {
  if (opts.channels.length === 0) return { senders: [], error: null, canonical: false };
  if (!existsSync5(opts.dbPath)) return { senders: [], error: null, canonical: false };
  let db;
  try {
    db = (opts.open ?? defaultOpener)(opts.dbPath);
  } catch (err) {
    const message = err.message;
    opts.log?.(`[channels] could not open OpenClaw's state database: ${message}`);
    return { senders: [], canonical: false, error: failure(message) };
  }
  try {
    const senders = [];
    for (const channel of opts.channels) {
      let rows;
      let requests = [];
      try {
        rows = db.prepare("SELECT account_id, entry, updated_at FROM channel_pairing_allow_entries WHERE channel_key = ? ORDER BY account_id, sort_order, entry").all(channel);
      } catch (err) {
        const message = err.message;
        if (/no such table/i.test(message)) return { senders: [], error: null, canonical: false };
        throw err;
      }
      if (rows.length > 0) {
        try {
          requests = db.prepare("SELECT request_id, meta_json FROM channel_pairing_requests WHERE channel_key = ?").all(channel);
        } catch {
        }
      }
      for (const row of rows) {
        const entry = text(row.entry);
        if (!entry || !isSender(entry)) continue;
        const request = requests.find((r2) => text(r2.request_id) === entry);
        senders.push({
          channel,
          accountId: text(row.account_id) ?? "default",
          senderId: entry,
          label: request ? labelFromMeta(request.meta_json) : null,
          at: stamp(row.updated_at)
        });
        if (senders.length >= ENTRY_CAP) return { senders, error: null, canonical: true };
      }
    }
    return { senders, error: null, canonical: true };
  } catch (err) {
    const message = err.message;
    opts.log?.(`[channels] could not read OpenClaw's allow list: ${message}`);
    return { senders: [], canonical: false, error: failure(message) };
  } finally {
    try {
      db.close();
    } catch {
    }
  }
}
function readPendingPairings(opts) {
  if (opts.channels.length === 0) return { pairings: [], error: null, canonical: false };
  if (!existsSync5(opts.dbPath)) return { pairings: [], error: null, canonical: false };
  let db;
  try {
    db = (opts.open ?? defaultOpener)(opts.dbPath);
  } catch (err) {
    const message = err.message;
    opts.log?.(`[channels] could not open OpenClaw's state database: ${message}`);
    return { pairings: [], canonical: false, error: pairingFailure(message) };
  }
  try {
    const pairings = [];
    for (const channel of opts.channels) {
      let rows;
      try {
        rows = db.prepare("SELECT request_id, code, created_at, meta_json FROM channel_pairing_requests WHERE channel_key = ? ORDER BY created_at").all(channel);
      } catch (err) {
        const message = err.message;
        if (/no such table/i.test(message)) return { pairings: [], error: null, canonical: false };
        throw err;
      }
      for (const row of rows) {
        const senderId = text(row.request_id);
        const code = text(row.code);
        if (!senderId || !code) continue;
        pairings.push({ channel, senderId, code, label: labelFromMeta(row.meta_json), createdAt: textStamp(row.created_at) });
        if (pairings.length >= ENTRY_CAP) return { pairings, error: null, canonical: true };
      }
    }
    return { pairings, error: null, canonical: true };
  } catch (err) {
    const message = err.message;
    opts.log?.(`[channels] could not read OpenClaw's pending pairings: ${message}`);
    return { pairings: [], canonical: false, error: pairingFailure(message) };
  } finally {
    try {
      db.close();
    } catch {
    }
  }
}
function textStamp(v2) {
  if (typeof v2 === "number" || typeof v2 === "bigint") return stamp(v2);
  const raw = text(v2);
  if (!raw) return null;
  if (/^\d+$/.test(raw)) return stamp(Number(raw));
  const d2 = new Date(raw);
  return Number.isNaN(d2.getTime()) ? null : d2.toISOString();
}
function pairingFailure(message) {
  if (looksBusy(message)) return { busy: true, message: "The agent is busy right now, so who is waiting could not be read." };
  if (looksUnopenable(message)) return { busy: false, message: "Your agent's pairing list could not be opened. Restarting the agent clears this." };
  return { busy: false, message: "Your agent's pairing list could not be read." };
}

// src/once.ts
var Once = class {
  ttlMs;
  errorTtlMs;
  now;
  entries = /* @__PURE__ */ new Map();
  /** Runs still going, so a second caller joins instead of starting another process. */
  inFlight = /* @__PURE__ */ new Map();
  /** Bumped by `invalidate`, so a run that started before it cannot cache what it found. */
  epoch = /* @__PURE__ */ new Map();
  constructor(opts) {
    this.ttlMs = opts.ttlMs;
    this.errorTtlMs = opts.errorTtlMs ?? Math.max(1, Math.round(opts.ttlMs / 4));
    this.now = opts.now ?? Date.now;
  }
  /**
   * The cached answer for `key`, the run already in flight for it, or a new run.
   *
   * `run` is never called twice concurrently for one key. Note that the SAME promise is handed to
   * every caller, so a rejection reaches all of them — which is what they asked for.
   */
  get(key, run3) {
    const cached = this.entries.get(key);
    if (cached && this.now() - cached.at < (cached.ok ? this.ttlMs : this.errorTtlMs)) return cached.value;
    const running = this.inFlight.get(key);
    if (running) return running;
    const started = this.now();
    const epoch = this.epoch.get(key) ?? 0;
    const value = (async () => run3())();
    const tracked = value.then(
      (v2) => {
        this.settle(key, started, true, value, epoch);
        return v2;
      },
      (err) => {
        this.settle(key, started, false, value, epoch);
        throw err;
      }
    );
    this.inFlight.set(key, tracked);
    tracked.catch(() => void 0);
    return tracked;
  }
  settle(key, started, ok, value, epoch) {
    this.inFlight.delete(key);
    if ((this.epoch.get(key) ?? 0) !== epoch) return;
    this.entries.set(key, { at: started, ok, value });
  }
  /** Drop what is cached, so the next caller runs again. Does not touch a run in flight. */
  forget(key) {
    if (key === void 0) this.entries.clear();
    else this.entries.delete(key);
  }
  /**
   * Like `forget`, but a run already in flight may not cache its answer either.
   *
   * `forget` alone is not enough after a WRITE. A read that started just before the write settles
   * just after it, and `settle` puts that pre-write snapshot back for the whole TTL — so a device
   * the owner has just approved goes on reading as pending for the next few seconds, which is
   * exactly what dropping the cache was meant to prevent. The epoch is bumped here and checked in
   * `settle`, so an answer fetched before the write is handed to whoever asked for it and then
   * thrown away instead of being kept.
   */
  invalidate(key) {
    this.entries.delete(key);
    this.epoch.set(key, (this.epoch.get(key) ?? 0) + 1);
  }
};

// src/channels.ts
var CHANNEL_TYPES = ["telegram", "slack", "whatsapp"];
var PLUGIN_BY_CHANNEL = {
  slack: "@openclaw/slack",
  whatsapp: "@openclaw/whatsapp"
};
var APPROVE_TIMEOUT_MS = 45e3;
var LIST_TIMEOUT_MS = 2e4;
var LIST_ATTEMPTS = 3;
var LIST_RETRY_MS = [400, 1200];
var APPROVED_CAP = 200;
var APPROVE_LOOKUP_TIMEOUT_MS = 8e3;
var PLUGIN_INSTALL_TIMEOUT_MS = 10 * 6e4;
var PLUGIN_INSTALL_MAX_BUFFER = 8 * 1024 * 1024;
var GATEWAY_READY_TIMEOUT_MS = 9e4;
var GATEWAY_POLL_MS = 500;
var PAIRINGS_CACHE_MS = 4e3;
var PAIRINGS_ERROR_CACHE_MS = 1500;
var ALLOWED_CACHE_MS = 5e3;
var WA_QR_TIMEOUT_MS = 12e4;
var WA_QR_STALE_MS = 15e4;
var WA_INSTALL_STALE_MS = 15 * 6e4;
var WA_RESULT_TTL_MS = 10 * 6e4;
function bool(v2) {
  return v2 === true;
}
function str2(v2) {
  return typeof v2 === "string" && v2.length > 0 ? v2 : null;
}
function selfNumber(v2) {
  if (typeof v2 === "string") return str2(v2);
  if (!v2 || typeof v2 !== "object") return null;
  const s2 = v2;
  return str2(s2.e164) ?? str2(s2.jid);
}
function channelAccount(type, payload) {
  const list = payload.channelAccounts?.[type];
  if (!Array.isArray(list)) return null;
  const accounts = list.filter((a2) => !!a2 && typeof a2 === "object");
  const defaultId = str2(payload.channelDefaultAccountId?.[type]);
  const byDefault = defaultId ? accounts.find((a2) => a2.accountId === defaultId) : void 0;
  if (byDefault) return byDefault;
  const enabled = accounts.filter((a2) => a2.enabled !== false);
  return enabled.find((a2) => a2.connected === true) ?? enabled[0] ?? null;
}
function channelStatusFrom(type, payload) {
  const s2 = payload.channels?.[type];
  if (!s2) return null;
  const account = channelAccount(type, payload);
  const entry = {
    configured: bool(s2.configured),
    running: bool(s2.running),
    connected: typeof s2.connected === "boolean" ? s2.connected : bool(account?.connected),
    lastError: str2(s2.lastError) ?? str2(account?.lastError)
  };
  if (type === "whatsapp") entry.self = selfNumber(s2.self) ?? selfNumber(account?.self);
  return entry;
}
function toPairing(type, r2) {
  const senderId = str2(r2.id) ?? str2(r2.senderId);
  const code = str2(r2.code);
  if (!senderId || !code) return null;
  const meta = r2.meta ?? {};
  const label = str2(meta.name) ?? str2(meta.displayName) ?? str2(meta.username) ?? str2(meta.title) ?? str2(r2.label) ?? null;
  return { type, code, senderId, label, createdAt: str2(r2.createdAt) };
}
function looksBusy2(message) {
  return /\b(EBUSY|EAGAIN|ECONNREFUSED|SQLITE_BUSY)\b|database is locked|gateway (is )?(not running|unavailable|starting|restarting)|connection refused|socket hang up/i.test(
    message
  );
}
function readChannelState(path) {
  if (!path || !existsSync6(path)) return { version: 1, seededAt: null, approved: [] };
  try {
    const parsed = JSON.parse(readFileSync11(path, "utf8"));
    const approved = Array.isArray(parsed.approved) ? parsed.approved : [];
    return {
      version: 1,
      seededAt: typeof parsed.seededAt === "string" ? parsed.seededAt : null,
      approved: approved.filter(
        (a2) => !!a2 && typeof a2.senderId === "string" && (typeof a2.code === "string" || a2.code === null) && CHANNEL_TYPES.includes(a2.type)
      )
    };
  } catch {
    return { version: 1, seededAt: null, approved: [] };
  }
}
function writeChannelState(path, state) {
  mkdirSync4(dirname4(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync6(tmp, JSON.stringify(state), { mode: 384 });
  renameSync3(tmp, path);
}
function channelBlock(input) {
  if ("remove" in input) return null;
  switch (input.type) {
    case "telegram":
      return { enabled: true, botToken: input.secrets.botToken, dmPolicy: "pairing" };
    case "slack":
      return { enabled: true, mode: "socket", botToken: input.secrets.botToken, appToken: input.secrets.appToken, dmPolicy: "pairing" };
    case "whatsapp": {
      const self2 = input.settings?.self ?? null;
      if (input.settings?.personal && self2) {
        return { enabled: true, dmPolicy: "allowlist", allowFrom: [self2], selfChatMode: true };
      }
      return { enabled: true, dmPolicy: "pairing" };
    }
  }
}
var ChannelsService = class {
  constructor(opts) {
    this.opts = opts;
    this.exec = opts.execImpl ?? defaultExec;
    this.log = opts.log ?? ((line) => console.log(line));
    this.now = opts.now ?? Date.now;
    this.state = readChannelState(opts.statePath);
    const fresh = opts.pairingsCacheMs ?? PAIRINGS_CACHE_MS;
    this.pairingsOnce = new Once({ ttlMs: fresh, errorTtlMs: Math.min(PAIRINGS_ERROR_CACHE_MS, fresh), now: this.now });
  }
  exec;
  log;
  now;
  pairingsOnce;
  /** Who this box has approved, as it saw it. Loaded once; written on every approval. */
  state;
  /** OpenClaw's own allow list, briefly reused; see `ALLOWED_CACHE_MS`. */
  allowedCache = null;
  /** Per-channel plugin-install progress, surfaced through `status()`. In memory only. */
  setup = /* @__PURE__ */ new Map();
  /** Single-flight per channel, so a repeated apply or a `channels.push` fan-out installs once. */
  installing = /* @__PURE__ */ new Map();
  /** Serialises our own config writes; the installer writes the same file from underneath us. */
  patchChain = Promise.resolve();
  /** How the last write per channel ended, for a firewall that stopped listening. See `ChannelApplyRecord`. */
  applies = /* @__PURE__ */ new Map();
  waLogin = {
    state: "idle",
    qrDataUrl: null,
    message: null,
    at: 0,
    personal: false
  };
  /**
   * Everyone this box has approved. The firewall reads this back to repair its own list, so it
   * must not depend on the gateway or on the pairing listing — both of which fail exactly when a
   * box is busy, which is when this matters. The one gateway call here is the seed, and it is
   * best-effort and at most once.
   */
  async approved() {
    await this.seed();
    return this.state.approved;
  }
  /**
   * Who OpenClaw itself will talk to, which is NOT who this box approved.
   *
   * The two lists exist separately on purpose. `approved()` is what this box did — the approvals the
   * firewall asked for — and the firewall trusts it, because the box only records a sender once
   * OpenClaw accepted the pairing code the firewall passed down. This one is OpenClaw's own DM allow
   * list, and the agent can write to it by itself: the owner pastes a pairing code into the chat and
   * the assistant runs `openclaw pairing approve`. Nobody but OpenClaw ever hears about that, which
   * leaves a box where people can talk to the agent and nobody can receive a confirmation code.
   *
   * So this is reported, never merged: the firewall shows it as a suggestion and an owner adds each
   * sender under the normal consent rule (`docs/security-design.md`). A compromised agent can put an
   * attacker in this table; it must not thereby be able to confirm anything.
   *
   * Two sources, because two OpenClaw generations: the SQLite pairing store (2026.9 and later) and
   * the config `channels.<type>.allowFrom` array an older gateway used. Both are advisory, so a
   * failure on either side is reported rather than thrown.
   *
   * One thing it deliberately does NOT do is mirror `forgetApproved`. When a channel leaves this box
   * we drop the approvals we made, because whatever is put there next is a different bot; OpenClaw's
   * table is keyed by channel and not by token, so it keeps those senders — and they really can
   * still message the new bot. Reporting them is therefore honest, and confirming any of them is
   * still a decision the owner has to make.
   */
  async allowedByAgent() {
    const cached = this.allowedCache;
    if (cached && this.now() - cached.at < ALLOWED_CACHE_MS) return cached.value;
    const fromDb = this.opts.stateDbPath ? readAllowList({ dbPath: this.opts.stateDbPath, channels: CHANNEL_TYPES, open: this.opts.sqliteOpen, log: this.log }) : { senders: [], error: null, canonical: false };
    const senders = [];
    for (const s2 of fromDb.senders) {
      if (!CHANNEL_TYPES.includes(s2.channel)) continue;
      senders.push({ type: s2.channel, senderId: s2.senderId, label: s2.label, accountId: s2.accountId, at: s2.at });
    }
    if (!fromDb.canonical && !fromDb.error) {
      for (const old of await this.allowedFromConfig()) {
        if (!senders.some((x2) => x2.type === old.type && x2.senderId === old.senderId)) senders.push(old);
      }
    }
    const value = { senders, error: fromDb.error };
    this.allowedCache = { at: this.now(), value };
    return value;
  }
  /**
   * `channels.<type>.allowFrom` — where an OpenClaw older than the SQLite pairing store kept the
   * same list. Best effort: a gateway that will not answer costs us this half and nothing else,
   * because on any OpenClaw that has the SQLite store the canonical read above already has it.
   */
  async allowedFromConfig() {
    let config;
    try {
      config = await this.config();
    } catch {
      return [];
    }
    const channels2 = config.channels ?? {};
    const out = [];
    for (const type of CHANNEL_TYPES) {
      const raw = channels2[type]?.allowFrom;
      for (const entry of Array.isArray(raw) ? raw : []) {
        const senderId = str2(entry);
        if (!senderId || senderId === "*" || senderId.startsWith("accessGroup:")) continue;
        if (out.some((o2) => o2.type === type && o2.senderId === senderId)) continue;
        out.push({ type, senderId, label: null, accountId: "default", at: null });
      }
    }
    return out;
  }
  recordApproved(type, senderId, code) {
    const at2 = new Date(this.now()).toISOString();
    const kept = this.state.approved.filter((a2) => !(a2.type === type && a2.senderId === senderId));
    kept.push({ type, senderId, code, at: at2 });
    this.state = { ...this.state, approved: kept.slice(-APPROVED_CAP) };
    this.persist();
  }
  /**
   * Forget this box's approvals for a channel. Called when the channel is taken off the box, so a
   * different connection put here later does not inherit the people the old one had approved —
   * they were approved on a different bot.
   */
  forgetApproved(type) {
    if (!this.state.approved.some((a2) => a2.type === type)) {
      if (!this.state.seededAt) {
        this.state = { ...this.state, seededAt: new Date(this.now()).toISOString() };
        this.persist();
      }
      return;
    }
    this.state = {
      ...this.state,
      seededAt: this.state.seededAt ?? new Date(this.now()).toISOString(),
      approved: this.state.approved.filter((a2) => a2.type !== type)
    };
    this.persist();
    this.log(`[channels] forgot the approved ${type} senders: the channel was removed from this box`);
  }
  persist() {
    if (!this.opts.statePath) return;
    try {
      writeChannelState(this.opts.statePath, this.state);
    } catch (err) {
      this.log(`[channels] could not write the channel state: ${err.message}`);
    }
  }
  /**
   * Boxes that approved somebody before this agent kept a record of it. OpenClaw writes the FIRST
   * sender approved on a box into `commands.ownerAllowFrom` as `<channel>:<id>`
   * (`bootstrapCommandOwnerFromPairing`, and only while that key is empty), so on such a box that
   * one entry is the box's own evidence of an approval it made. Reading it back is what repairs a
   * firewall whose approval was lost before any of this existed.
   *
   * Once, ever: `seededAt` is stamped whether or not anything was found, so a channel removed
   * later cannot come back through a key OpenClaw never clears.
   */
  async seed() {
    if (this.state.seededAt) return;
    let config;
    try {
      config = await this.config();
    } catch (err) {
      this.log(`[channels] could not read the config to seed approved senders: ${err.message}`);
      return;
    }
    const owners = config.commands?.ownerAllowFrom;
    const channels2 = config.channels ?? {};
    const found = [];
    for (const raw of Array.isArray(owners) ? owners : []) {
      const [type, ...rest] = String(raw).split(":");
      const senderId = rest.join(":");
      if (!senderId || !CHANNEL_TYPES.includes(type ?? "") || !bool(channels2[type]?.enabled)) continue;
      found.push({ type, senderId, code: null, at: new Date(this.now()).toISOString() });
    }
    this.state = {
      version: 1,
      seededAt: new Date(this.now()).toISOString(),
      approved: [...this.state.approved, ...found.filter((f2) => !this.state.approved.some((a2) => a2.type === f2.type && a2.senderId === f2.senderId))].slice(-APPROVED_CAP)
    };
    this.persist();
    if (found.length) this.log(`[channels] ${found.length} approved sender(s) read out of this agent's own config`);
  }
  gateway() {
    const c2 = this.opts.client;
    if (!c2 || !c2.connected) throw new Error("OpenClaw is not running on this box");
    return c2;
  }
  bin() {
    return this.opts.openclawBin ?? "/usr/bin/openclaw";
  }
  /**
   * Pending DM pairing requests of the configured channels: `openclaw pairing list <channel> --json`
   * (the SQLite store), plus whatever an older gateway left in the pairing files.
   */
  async pairings(types) {
    return (await this.pairingsRead(types)).pairings;
  }
  /**
   * The listing plus why it is short, when it is. The error matters: an empty list and a listing
   * that could not be taken look the same to the console, and the console says "No pending
   * requests" for both — which is how a person ends up waiting for a request that is right there.
   */
  async pairingsRead(types) {
    const key = [...types].sort().join(",");
    if (key === "") return { pairings: [], error: null };
    return this.pairingsOnce.get(key, () => this.readPairings(types));
  }
  async readPairings(types) {
    const fromDb = this.opts.stateDbPath ? readPendingPairings({ dbPath: this.opts.stateDbPath, channels: types, open: this.opts.sqliteOpen, log: this.log }) : null;
    if (fromDb?.canonical) {
      const out2 = fromDb.pairings.map((p2) => ({ type: p2.channel, code: p2.code, senderId: p2.senderId, label: p2.label, createdAt: p2.createdAt }));
      this.mergeLegacyFiles(out2);
      return { pairings: out2, error: null };
    }
    if (fromDb?.error) {
      const out2 = [];
      this.mergeLegacyFiles(out2);
      return { pairings: out2, error: fromDb.error };
    }
    const failures = [];
    const fromCli = await Promise.all(
      types.map(async (type) => {
        const r2 = await this.listPairings(type);
        if (r2.error) failures.push(r2.error);
        return r2.pairings;
      })
    );
    const out = fromCli.flat();
    this.mergeLegacyFiles(out);
    return { pairings: out, error: failures.find((f2) => !f2.busy) ?? failures[0] ?? null };
  }
  /** Whatever an OpenClaw older than 2026.9 left in `<channel>-pairing.json`, without duplicates. */
  mergeLegacyFiles(out) {
    for (const legacy of this.pairingsFromFiles()) {
      if (!out.some((p2) => p2.type === legacy.type && p2.senderId === legacy.senderId)) out.push(legacy);
    }
  }
  /**
   * One channel's pending requests, retried: right after a `config.patch` the gateway is
   * restarting and the CLI simply exits non-zero for a second or two. Reported on production as
   * repeated "Command failed" from `pairing list telegram --json` minutes after a token apply,
   * with the same command working again afterwards.
   */
  async listPairings(type) {
    const bin = this.opts.openclawBin ?? "/usr/bin/openclaw";
    let last = "";
    for (let attempt = 0; attempt < LIST_ATTEMPTS; attempt++) {
      if (attempt > 0) await new Promise((r2) => setTimeout(r2, LIST_RETRY_MS[attempt - 1] ?? 1e3));
      try {
        const { stdout } = await this.exec(bin, ["pairing", "list", type, "--json"], LIST_TIMEOUT_MS);
        const start = stdout.indexOf("{");
        const parsed = JSON.parse(stdout.slice(start));
        const requests = Array.isArray(parsed) ? parsed : parsed.requests ?? [];
        return { pairings: requests.map((r2) => toPairing(type, r2)).filter((p2) => p2 !== null), error: null };
      } catch (err) {
        last = execFailureLine(err);
      }
    }
    const busy = !this.opts.client?.connected || looksBusy2(last);
    this.log(`[channels] pairing list ${type} failed after ${LIST_ATTEMPTS} tries: ${last}`);
    return {
      pairings: [],
      error: busy ? { busy: true, message: `The agent is busy right now, so who is waiting on ${type} could not be read.` } : { busy: false, message: `The agent could not list who is waiting on ${type}: ${last}` }
    };
  }
  /** Older gateways (before 2026.9) kept pending requests in `<channel>-pairing.json`. */
  pairingsFromFiles() {
    const out = [];
    for (const type of CHANNEL_TYPES) {
      let raw;
      try {
        raw = readFileSync11(`${this.opts.credentialsDir}/${type}-pairing.json`, "utf8");
      } catch {
        continue;
      }
      try {
        const parsed = JSON.parse(raw);
        for (const r2 of parsed.requests ?? []) {
          const p2 = toPairing(type, r2);
          if (p2) out.push(p2);
        }
      } catch (err) {
        this.log(`[channels] unreadable ${type}-pairing.json: ${err.message}`);
      }
    }
    return out;
  }
  /** Per-channel state from `channels.status`, reduced to what the console needs. */
  async status() {
    const channels2 = {};
    if (this.opts.client?.connected) {
      const payload = await this.gateway().call("channels.status", { probe: false }, CHANNELS_STATUS_MS);
      for (const type of CHANNEL_TYPES) {
        const entry = channelStatusFrom(type, payload);
        if (entry) channels2[type] = entry;
      }
    }
    for (const [type, setup] of this.setup) {
      channels2[type] = { configured: false, running: false, connected: false, lastError: null, ...channels2[type], setup };
    }
    for (const type of CHANNEL_TYPES) {
      const record = this.applyRecord(type);
      if (!record) continue;
      channels2[type] = { configured: false, running: false, connected: false, lastError: null, ...channels2[type], lastApply: record };
    }
    const wa2 = this.whatsappLogin();
    const configured = Object.keys(channels2).filter((t2) => channels2[t2]?.configured);
    const read = await this.pairingsRead(configured);
    return { channels: channels2, pairings: read.pairings, pairingsError: read.error, whatsappLogin: wa2.state === "idle" ? null : { state: wa2.state } };
  }
  /**
   * `config.get` for the hash, then `config.patch` with one channel block (or its removal).
   *
   * The patch goes first and the plugin install follows in the background: OpenClaw accepts a
   * `channels.<type>` block whether or not the plugin is there, and the firewall gives us only 25 s
   * for this whole call while an install runs for minutes. Writing first also means no channel
   * secret has to be held in memory — once patched, "enabled but no plugin" is a complete
   * description of the work left, which is what `reconcile()` reads after a restart.
   */
  async apply(input) {
    this.gateway();
    const block = channelBlock(input);
    const patch = { channels: { [input.type]: block } };
    const what = block ? `applied ${input.type}` : `removed ${input.type}`;
    const id = input.applyId ?? randomUUID();
    const type = input.type;
    this.noteApply(type, { id, state: "pending", what: block ? "apply" : "remove", error: null, at: new Date(this.now()).toISOString() });
    const write = this.patchConfig(patch).then(
      () => {
        this.noteApply(type, { id, state: "applied", what: block ? "apply" : "remove", error: null, at: new Date(this.now()).toISOString() });
        this.log(`[channels] ${what}`);
        if (!block) this.forgetApproved(type);
        if (block) void this.ensurePlugin(type);
        return true;
      },
      (err) => {
        this.noteApply(type, { id, state: "failed", what: block ? "apply" : "remove", error: err.message, at: new Date(this.now()).toISOString() });
        this.log(`[channels] could not ${block ? "apply" : "remove"} ${type}: ${err.message}`);
        return false;
      }
    );
    void write;
    const finished = await this.waitFor(write, this.opts.applyInlineWaitMs ?? APPLY_INLINE_WAIT_MS);
    if (finished === null) {
      this.log(`[channels] ${type} is still being written (${id}); the firewall will read the outcome back`);
      return { ok: true, status: "pending", applyId: id, message: `${block ? "Applying" : "Removing"} ${type} on this agent\u2026` };
    }
    if (!finished) throw new Error(this.applies.get(type)?.error ?? `could not ${block ? "apply" : "remove"} ${type}`);
    return { ok: true, status: "applied", applyId: id, message: what };
  }
  /** `p`'s value if it settles inside `ms`, otherwise null. Never rejects: `p` reports its own end. */
  waitFor(p2, ms) {
    return new Promise((resolve2) => {
      const timer = setTimeout(() => resolve2(null), ms);
      timer.unref?.();
      void p2.then(
        (v2) => {
          clearTimeout(timer);
          resolve2(v2);
        },
        () => {
          clearTimeout(timer);
          resolve2(null);
        }
      );
    });
  }
  /**
   * The last write on a channel, as the firewall should read it, or null once it is too old to be
   * anybody's answer.
   *
   * A `pending` record is reported as pending however long it has been there. It is tempting to
   * call an old one failed, and wrong: `patchConfig` serialises writes, so a patch queued behind a
   * restarting one has not started yet and its stamp says nothing about its progress. Guessing
   * there is the same mistake one level down — and there is no need, because the firewall's
   * confirm has a deadline of its own and settles as `unconfirmed`, which is honest.
   *
   * Pruned here rather than only on write: once writes stop, `noteApply` never runs again, and a
   * record kept forever makes `status()` invent an entry for a channel OpenClaw does not report.
   */
  applyRecord(type) {
    const record = this.applies.get(type);
    if (!record) return null;
    if (record.state !== "pending" && this.now() - Date.parse(record.at) >= APPLY_RECORD_TTL_MS) {
      this.applies.delete(type);
      return null;
    }
    return record;
  }
  /** Record one apply's state, dropping records too old to be anybody's answer. */
  noteApply(type, record) {
    const cutoff = this.now() - APPLY_RECORD_TTL_MS;
    for (const [t2, r2] of this.applies) {
      if (r2.state !== "pending" && Date.parse(r2.at) < cutoff) this.applies.delete(t2);
    }
    this.applies.set(type, record);
  }
  /**
   * One config write at a time, with a single retry when OpenClaw says the file moved under us —
   * `openclaw plugins install` edits the same file, and so does the WhatsApp login when it lands.
   */
  patchConfig(patch) {
    const run3 = this.patchChain.then(
      () => this.patchOnce(patch),
      () => this.patchOnce(patch)
    );
    this.patchChain = run3.catch(() => void 0);
    return run3;
  }
  async patchOnce(patch) {
    try {
      await this.writeConfig(patch);
    } catch (err) {
      if (!/config changed since last load/i.test(err.message ?? "")) throw err;
      await this.writeConfig(patch);
    }
  }
  async writeConfig(patch) {
    const budget = patchRestartsGateway(patch) ? CONFIG_PATCH_RESTART_MS : CONFIG_PATCH_MS;
    await patchConfig(this.gateway(), patch, { timeoutMs: budget, readTimeoutMs: GATEWAY_READ_MS });
  }
  /** The live config, for deciding whether a channel's plugin is already there. */
  async config() {
    const snapshot = await this.gateway().call("config.get", {}, GATEWAY_READ_MS);
    const cfg = snapshot.parsed ?? snapshot.config;
    return cfg ?? {};
  }
  /**
   * Presence of the `plugins.entries.<type>` key, not `enabled === true`: someone who turned a
   * plugin off meant it, and reinstalling would only put them back where they started.
   *
   * The key is ours: `openclaw plugins install` drops the package under `~/.openclaw/npm` and
   * writes nothing to the config, so this is the record that the install finished AND was
   * trusted — see `trustPlugin`.
   */
  pluginInstalled(config, type) {
    if (!PLUGIN_BY_CHANNEL[type]) return true;
    const entries = config.plugins?.entries;
    return Boolean(entries && Object.hasOwn(entries, type));
  }
  /**
   * Install the channel's OpenClaw plugin if it is missing, then restart so it loads. Resolves
   * true once the channel can actually run. Safe to call repeatedly: single-flight per channel,
   * and a no-op for Telegram and for anything already installed.
   */
  ensurePlugin(type) {
    const pkg = PLUGIN_BY_CHANNEL[type];
    if (!pkg) return Promise.resolve(true);
    const inFlight = this.installing.get(type);
    if (inFlight) return inFlight;
    const run3 = this.installPlugin(type, pkg).catch((err) => {
      const message = execFailureLine(err);
      this.setup.set(type, { state: "failed", message });
      this.log(`[channels] installing ${pkg} failed: ${message}`);
      return false;
    }).finally(() => this.installing.delete(type));
    this.installing.set(type, run3);
    return run3;
  }
  async installPlugin(type, pkg) {
    try {
      if (this.pluginInstalled(await this.config(), type)) return true;
    } catch (err) {
      this.log(`[channels] could not read the config to check the ${type} plugin: ${err.message}`);
      return false;
    }
    this.setup.set(type, { state: "installing", message: `Setting up ${type} on this agent\u2026` });
    this.log(`[channels] installing ${pkg}`);
    try {
      const ca2 = this.opts.mitmCaPath;
      const env2 = ca2 && existsSync6(ca2) ? { NODE_EXTRA_CA_CERTS: ca2 } : void 0;
      await this.exec(this.bin(), ["plugins", "install", `npm:${pkg}`], PLUGIN_INSTALL_TIMEOUT_MS, void 0, {
        maxBuffer: PLUGIN_INSTALL_MAX_BUFFER,
        env: env2
      });
    } catch (err) {
      const detail = execFailureLine(err);
      if (!await this.pluginPresent(type)) {
        this.setup.set(type, { state: "failed", message: detail });
        this.log(`[channels] installing ${pkg} failed: ${detail}`);
        return false;
      }
      this.log(`[channels] ${pkg} was already on this box`);
    }
    if (!await this.trustPlugin(type, pkg)) return false;
    const restart = this.opts.restartService?.();
    if (restart && !restart.ok) {
      const message = restart.error ?? "the agent could not be restarted";
      this.setup.set(type, { state: "failed", message });
      this.log(`[channels] restart after installing ${pkg} failed: ${message}`);
      return false;
    }
    if (!await this.waitForGateway()) {
      this.setup.set(type, { state: "failed", message: "the agent did not come back after the restart" });
      this.log(`[channels] gateway did not return after installing ${pkg}`);
      return false;
    }
    this.setup.delete(type);
    this.log(`[channels] installed ${pkg}`);
    return true;
  }
  /**
   * Is the channel's plugin package on the box? `plugins list --json` is the only authority:
   * an npm plugin lives under `~/.openclaw/npm` and leaves no trace in the config.
   */
  async pluginPresent(type) {
    try {
      const { stdout } = await this.exec(this.bin(), ["plugins", "list", "--json"], LIST_TIMEOUT_MS);
      const start = stdout.indexOf("{");
      if (start < 0) return false;
      const parsed = JSON.parse(stdout.slice(start));
      return (parsed.plugins ?? []).some((p2) => p2.id === type);
    } catch (err) {
      this.log(`[channels] could not list the plugins: ${(err.message ?? "").split("\n")[0]}`);
      return false;
    }
  }
  /**
   * Mark the freshly installed plugin as trusted. An external plugin is inert until the config
   * says so: the gateway loads it, sees no `plugins.entries.<type>.enabled`, and refuses to start
   * the channel with "external plugin is installed without explicit trust" — which looks exactly
   * like the plugin never having been installed at all.
   */
  async trustPlugin(type, pkg) {
    try {
      await this.patchConfig({ plugins: { entries: { [type]: { enabled: true } } } });
      return true;
    } catch (err) {
      const message = err.message;
      this.setup.set(type, { state: "failed", message });
      this.log(`[channels] trusting ${pkg} failed: ${message}`);
      return false;
    }
  }
  async waitForGateway() {
    const deadline = this.now() + (this.opts.gatewayReadyTimeoutMs ?? GATEWAY_READY_TIMEOUT_MS);
    const every = this.opts.pollIntervalMs ?? GATEWAY_POLL_MS;
    while (this.now() < deadline) {
      if (this.opts.client?.connected) return true;
      await new Promise((r2) => setTimeout(r2, every));
    }
    return Boolean(this.opts.client?.connected);
  }
  /**
   * Finish any install that a restart interrupted, and repair boxes configured before this agent
   * knew to install plugins at all. The config is the whole state: a channel that is enabled with
   * no plugin behind it has never been able to run.
   *
   * Runs on every gateway connect, not just the first. It costs one `config.get`, and the work it
   * finds is single-flighted by `ensurePlugin`, so a flapping socket cannot pile up installs — and
   * the connect that follows our own post-install restart doubles as the check that it worked.
   */
  async reconcile() {
    let config;
    try {
      config = await this.config();
    } catch (err) {
      this.log(`[channels] could not read the config to reconcile plugins: ${err.message}`);
      return;
    }
    const channels2 = config.channels ?? {};
    for (const type of CHANNEL_TYPES) {
      if (!PLUGIN_BY_CHANNEL[type]) continue;
      if (!bool(channels2[type]?.enabled)) continue;
      if (this.pluginInstalled(config, type)) continue;
      this.log(`[channels] ${type} is configured but its plugin is missing; installing it`);
      void this.ensurePlugin(type);
    }
  }
  /** Deliver a text to a sender over one of the agent's channels. The text is not ours to change. */
  async send(input) {
    await this.gateway().call(
      "send",
      { channel: input.type, to: input.to, message: input.text, idempotencyKey: randomUUID() },
      3e4
    );
    this.log(`[channels] sent a message on ${input.type}`);
    return { ok: true };
  }
  /**
   * `openclaw pairing approve <channel> <code>`.
   *
   * Since 2026.9 OpenClaw also has `channels.pairing.approve` over the gateway, which would skip
   * a whole Node process (most of the 28 s this route is budgeted for). It is not a drop-in: it is
   * keyed by `requestId`, and its `channels.pairing.list` does not return the pairing code the
   * console shows people, so both listings would be needed. Worth doing, on a real box.
   *
   * Idempotent on the code. The firewall may ask twice — its first call timed out, or it restarted
   * mid-change — and by then OpenClaw has dropped the request, so the CLI answers "No pending
   * pairing", which is also what a made-up code gets. The state file tells the two apart: a code
   * this box already approved is answered from the record, with `alreadyApproved` so the caller
   * knows nothing ran.
   *
   * The sender is recorded BEFORE this returns, so a caller that never sees the answer can still
   * read it back from `/channels/status`.
   */
  async approvePairing(input) {
    const known = this.state.approved.find((a2) => a2.type === input.type && a2.code === input.code);
    if (known) {
      this.log(`[channels] ${input.type} sender ${known.senderId} was already approved with this code`);
      return { ok: true, senderId: known.senderId, alreadyApproved: true };
    }
    const before = this.pairingFromStore(input.type, input.code) ?? await this.lookupPairing(input.type, input.code);
    const bin = this.opts.openclawBin ?? "/usr/bin/openclaw";
    let approvedId = null;
    try {
      const { stdout } = await this.exec(bin, ["pairing", "approve", input.type, input.code], APPROVE_TIMEOUT_MS);
      approvedId = /sender\s+(\S+?)\.?\s*$/m.exec(stdout.replace(/\x1b\[[0-9;]*m/g, ""))?.[1] ?? null;
    } catch (err) {
      const e = err;
      const detail = (e.stderr || e.stdout || e.message || "").trim().split("\n").pop() ?? "";
      throw new Error(detail.includes("No pending pairing") ? "That pairing request is gone. Ask the person to message the bot again." : `pairing approve failed: ${detail}`);
    }
    this.pairingsOnce.forget();
    const senderId = before?.senderId ?? approvedId;
    if (senderId) this.recordApproved(input.type, senderId, input.code);
    this.log(`[channels] approved ${input.type} sender ${senderId ?? "?"}`);
    return { ok: true, senderId };
  }
  /** One code in OpenClaw's own pairing store. Never the CLI: `lookupPairing` is that fallback. */
  pairingFromStore(type, code) {
    if (!this.opts.stateDbPath) return void 0;
    const read = readPendingPairings({ dbPath: this.opts.stateDbPath, channels: [type], open: this.opts.sqliteOpen, log: this.log });
    const row = read.pairings.find((p2) => p2.code === code);
    return row ? { type, code: row.code, senderId: row.senderId, label: row.label, createdAt: row.createdAt } : void 0;
  }
  /** One listing, short and optional: it only tells us whose code this is. */
  async lookupPairing(type, code) {
    try {
      const { stdout } = await this.exec(this.bin(), ["pairing", "list", type, "--json"], APPROVE_LOOKUP_TIMEOUT_MS);
      const parsed = JSON.parse(stdout.slice(stdout.indexOf("{")));
      return (parsed.requests ?? []).map((r2) => toPairing(type, r2)).find((p2) => p2 !== null && p2.code === code);
    } catch {
      return void 0;
    }
  }
  whatsappLogin() {
    const l2 = this.waLogin;
    if (l2.state === "qr" && this.now() - l2.at > WA_QR_STALE_MS) {
      return { state: "expired", qrDataUrl: null, message: "The QR code expired. Start again." };
    }
    if (l2.state === "installing" && this.now() - l2.at > WA_INSTALL_STALE_MS) {
      return { state: "failed", qrDataUrl: null, message: "Setting up WhatsApp took too long. Try again." };
    }
    if (l2.state !== "idle" && l2.state !== "qr" && this.now() - l2.at > WA_RESULT_TTL_MS) {
      return { state: "idle", qrDataUrl: null, message: null };
    }
    return { state: l2.state, qrDataUrl: l2.qrDataUrl, message: l2.message };
  }
  /**
   * Start the QR login and wait for the scan in the background. On connect, the channel block is
   * written (personal mode allowlists the linked number and turns on self-chat mode).
   *
   * `web.login.start` *is* the WhatsApp plugin, so with the plugin missing there is no RPC to call
   * and no config write to piggyback on — unlike the other channels, this path has to install
   * first and only then ask for a QR code.
   */
  async whatsappLoginStart(personal) {
    if (!this.pluginInstalled(await this.config(), "whatsapp")) {
      this.waLogin = { state: "installing", qrDataUrl: null, message: "Setting up WhatsApp on this agent\u2026", at: this.now(), personal };
      void this.installThenLogin(personal);
      return { ok: true, state: "installing", qrDataUrl: null };
    }
    return this.startQr(personal);
  }
  async startQr(personal) {
    const gw = this.gateway();
    const started = await gw.call(
      "web.login.start",
      { force: true, timeoutMs: WA_QR_TIMEOUT_MS },
      3e4
    );
    this.waLogin = { state: "qr", qrDataUrl: started.qrDataUrl ?? null, message: started.message ?? null, at: this.now(), personal };
    void this.waitForWhatsapp(gw);
    return { ok: true, state: "qr", qrDataUrl: this.waLogin.qrDataUrl };
  }
  async installThenLogin(personal) {
    try {
      if (!await this.ensurePlugin("whatsapp")) {
        const why = this.setup.get("whatsapp")?.message ?? "WhatsApp could not be set up on this agent";
        this.waLogin = { ...this.waLogin, state: "failed", qrDataUrl: null, message: why, at: this.now() };
        return;
      }
      await this.startQr(personal);
    } catch (err) {
      this.waLogin = { ...this.waLogin, state: "failed", qrDataUrl: null, message: err.message, at: this.now() };
      this.log(`[channels] whatsapp setup failed: ${err.message}`);
    }
  }
  async waitForWhatsapp(gw) {
    try {
      const r2 = await gw.call("web.login.wait", { timeoutMs: WA_QR_TIMEOUT_MS }, WA_QR_TIMEOUT_MS + 1e4);
      if (!r2.connected) {
        this.waLogin = { ...this.waLogin, state: "expired", qrDataUrl: null, message: r2.message ?? "Not scanned in time", at: this.now() };
        return;
      }
      let self2 = null;
      try {
        self2 = (await this.status()).channels.whatsapp?.self ?? null;
      } catch {
      }
      await this.apply({ type: "whatsapp", settings: { personal: this.waLogin.personal, self: self2 } });
      this.waLogin = { ...this.waLogin, state: "connected", qrDataUrl: null, message: self2 ? `Linked ${self2}` : "Linked", at: this.now() };
    } catch (err) {
      this.waLogin = { ...this.waLogin, state: "failed", qrDataUrl: null, message: err.message, at: this.now() };
      this.log(`[channels] whatsapp login failed: ${err.message}`);
    }
  }
};

// src/routes/channels.ts
function isType(v2) {
  return typeof v2 === "string" && CHANNEL_TYPES.includes(v2);
}
function fail(res, err) {
  const message = err instanceof Error ? err.message : String(err);
  const status = /not running|not connected/i.test(message) ? 503 : 500;
  sendJson(res, status, { ok: false, error: message });
}
async function handleChannels(req, res, pathname, service) {
  const write = req.method === "POST";
  const mitm = await verifyMitmRequest(req);
  const auth = write ? mitm : mitm ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "channel changes must come from the org firewall" : "Unauthorized" });
    return;
  }
  if (!service) {
    sendJson(res, 503, { ok: false, error: "OpenClaw is not running on this box" });
    return;
  }
  try {
    if (pathname === "/channels/status" && req.method === "GET") {
      sendJson(res, 200, await service.status());
      return;
    }
    if (pathname === "/channels/approved" && req.method === "GET") {
      if (!mitm) return sendJson(res, 403, { error: "who this agent has approved is the org firewall's to read" });
      const allowedByAgent = await service.allowedByAgent().catch((err) => ({
        senders: [],
        error: { busy: false, message: `The agent's own allow list could not be read: ${err.message}` }
      }));
      sendJson(res, 200, { approved: await service.approved(), allowedByAgent });
      return;
    }
    if (pathname === "/channels/whatsapp/login" && req.method === "GET") {
      sendJson(res, 200, service.whatsappLogin());
      return;
    }
    if (!write) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    const body = await readJsonBody(req);
    if (!body) {
      sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
      return;
    }
    if (pathname === "/channels/apply") {
      if (!isType(body.type)) return sendJson(res, 400, { ok: false, error: "type must be telegram, slack or whatsapp" });
      const secrets2 = body.secrets ?? {};
      const applyId = typeof body.applyId === "string" && /^[\w.:-]{1,64}$/.test(body.applyId) ? body.applyId : void 0;
      let input;
      if (body.remove === true) input = { applyId, type: body.type, remove: true };
      else if (body.type === "telegram") {
        if (typeof secrets2.botToken !== "string") return sendJson(res, 400, { ok: false, error: "botToken required" });
        input = { applyId, type: "telegram", secrets: { botToken: secrets2.botToken } };
      } else if (body.type === "slack") {
        if (typeof secrets2.botToken !== "string" || typeof secrets2.appToken !== "string")
          return sendJson(res, 400, { ok: false, error: "botToken and appToken required" });
        input = { applyId, type: "slack", secrets: { botToken: secrets2.botToken, appToken: secrets2.appToken } };
      } else {
        const settings = body.settings ?? {};
        input = { applyId, type: "whatsapp", settings: { personal: settings.personal === true, self: typeof settings.self === "string" ? settings.self : null } };
      }
      sendJson(res, 200, await service.apply(input));
      return;
    }
    if (pathname === "/channels/send") {
      if (!isType(body.type) || typeof body.to !== "string" || typeof body.text !== "string" || !body.to || !body.text) {
        return sendJson(res, 400, { ok: false, error: "type, to and text required" });
      }
      sendJson(res, 200, await service.send({ type: body.type, to: body.to, text: body.text.slice(0, 1e3) }));
      return;
    }
    if (pathname === "/channels/pairings/approve") {
      if (!isType(body.type) || typeof body.code !== "string" || !/^[A-Z0-9-]{4,16}$/i.test(body.code)) {
        return sendJson(res, 400, { ok: false, error: "type and code required" });
      }
      sendJson(res, 200, await service.approvePairing({ type: body.type, code: body.code.toUpperCase() }));
      return;
    }
    if (pathname === "/channels/whatsapp/login") {
      sendJson(res, 200, await service.whatsappLoginStart(body.personal === true));
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    fail(res, err);
  }
}

// src/llm.ts
import { existsSync as existsSync7, mkdirSync as mkdirSync5, readFileSync as readFileSync12, renameSync as renameSync4, writeFileSync as writeFileSync7 } from "fs";
import { dirname as dirname5 } from "path";
var CLI_TIMEOUT_MS2 = 45e3;
var MODELS_CACHE_MS = 3e4;
var REINDEX_TIMEOUT_MS = 15 * 6e4;
var MEMORY_CORE_PLUGIN = "memory-core";
var RETIRED_CODEX_PROVIDER_ID = "openai-codex";
function str3(v2) {
  return typeof v2 === "string" && v2.length > 0 ? v2 : null;
}
function memoryPatch(want, have) {
  if (want === void 0) return null;
  if (!want) {
    if (!have.provider && !have.model && !have.baseUrl && !have.apiKey && have.dreaming) return null;
    return {
      patch: { memory: { search: { provider: null, model: null, remote: null } }, plugins: { entries: { [MEMORY_CORE_PLUGIN]: { config: { dreaming: { enabled: null } } } } } },
      reindex: !!have.provider || !!have.model
    };
  }
  if (have.provider === want.provider && have.model === want.model && have.baseUrl === want.baseUrl && have.apiKey === want.apiKey && have.dreaming === want.dreaming) return null;
  return {
    patch: {
      memory: { search: { provider: want.provider, model: want.model, remote: { baseUrl: want.baseUrl, apiKey: want.apiKey } } },
      plugins: { entries: { [MEMORY_CORE_PLUGIN]: { config: { dreaming: { enabled: want.dreaming } } } } }
    },
    // Only the embedding identity: OpenClaw ties an index to the adapter and the model, not to the
    // key or the endpoint, so a rotated placeholder is written without touching the vectors.
    reindex: have.provider !== want.provider || have.model !== want.model
  };
}
function readMemory(config) {
  const search2 = config.memory?.search;
  const remote = search2?.remote;
  const entries = config.plugins?.entries;
  const dreaming = entries?.[MEMORY_CORE_PLUGIN]?.config?.dreaming?.enabled;
  return { provider: str3(search2?.provider), model: str3(search2?.model), baseUrl: str3(remote?.baseUrl), apiKey: str3(remote?.apiKey), dreaming: dreaming !== false };
}
function readReindexFailure(path) {
  if (!path || !existsSync7(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync12(path, "utf8"));
    return typeof parsed.error === "string" && parsed.error ? parsed.error : null;
  } catch {
    return null;
  }
}
var LlmService = class {
  constructor(opts) {
    this.opts = opts;
    this.exec = opts.execImpl ?? defaultExec;
    this.log = opts.log ?? ((line) => console.log(line));
    this.now = opts.now ?? Date.now;
    this.reindexFailed = readReindexFailure(opts.statePath);
    if (this.reindexFailed) this.log(`[llm] the memory index was left unbuilt: ${this.reindexFailed}`);
  }
  exec;
  log;
  now;
  modelsCache = /* @__PURE__ */ new Map();
  /** The last index rebuild's failure, reported on `/llm/status` until one succeeds. */
  reindexFailed = null;
  /** A rebuild in flight; a second `--force` over the same index would fight the first. */
  reindexing = false;
  gateway() {
    const c2 = this.opts.client;
    if (!c2 || !c2.connected) throw new Error("OpenClaw is not running on this box");
    return c2;
  }
  bin() {
    return this.opts.openclawBin ?? "/usr/bin/openclaw";
  }
  async config() {
    const snapshot = await this.gateway().call("config.get", {}, GATEWAY_READ_MS);
    const hash = str3(snapshot.hash);
    if (!hash) throw new Error("OpenClaw returned no config hash");
    const config = snapshot.parsed ?? snapshot.config ?? {};
    return { hash, config: config && typeof config === "object" ? config : {} };
  }
  async patchConfig(patch, baseHash) {
    const hash = baseHash ?? (await this.config()).hash;
    await patchConfig(this.gateway(), patch, { baseHash: hash, timeoutMs: patchRestartsGateway(patch) ? CONFIG_PATCH_RESTART_MS : CONFIG_PATCH_MS, readTimeoutMs: GATEWAY_READ_MS });
  }
  /** Make OpenClaw match the desired state. Applies what it can and reports each failure by name. */
  async apply(input) {
    this.gateway();
    const applied = [];
    const failed = [];
    const providerPatch = {};
    for (const r2 of input.remove) {
      try {
        if (r2.providerBlock || !r2.profileId.includes(":")) providerPatch[r2.provider] = null;
        if (r2.profileId.includes(":")) await this.exec(this.bin(), ["models", "auth", "logout", r2.profileId, "--yes"], CLI_TIMEOUT_MS2);
        applied.push(`remove:${r2.provider}`);
      } catch (err) {
        const line = execFailureLine(err);
        if (/not found|no such|unknown profile/i.test(line)) applied.push(`remove:${r2.provider}`);
        else failed.push({ what: `remove ${r2.provider}`, error: line });
      }
    }
    for (const c2 of input.credentials) {
      if (c2.providerBlock) {
        try {
          await this.patchConfig({ models: { providers: { [c2.provider]: { baseUrl: c2.providerBlock.baseUrl, api: c2.providerBlock.api, models: c2.providerBlock.models } } } });
        } catch (err) {
          failed.push({ what: c2.provider, error: err.message });
          continue;
        }
      }
      try {
        const sub = c2.kind === "api_key" ? "paste-api-key" : "paste-token";
        const args = ["models", "auth", sub, "--provider", c2.provider, "--profile-id", c2.profileId, ...c2.kind !== "api_key" ? ["--expires-in", "365d"] : []];
        await this.exec(this.bin(), args, CLI_TIMEOUT_MS2, `${c2.value}
`);
        applied.push(c2.provider);
      } catch (err) {
        failed.push({ what: c2.provider, error: execFailureLine(err) });
      }
    }
    const { hash, config } = await this.config();
    const providers = config.models?.providers;
    if (providers && RETIRED_CODEX_PROVIDER_ID in providers) providerPatch[RETIRED_CODEX_PROVIDER_ID] = null;
    const patch = {};
    if (Object.keys(providerPatch).length) patch.models = { providers: providerPatch };
    patch.agents = { defaults: { model: input.model.primary ? { primary: input.model.primary, fallbacks: input.model.fallbacks } : null } };
    const memory = memoryPatch(input.memory, readMemory(config));
    if (memory) Object.assign(patch, memory.patch);
    let reindex = false;
    try {
      await this.patchConfig(patch, hash);
      applied.push("model");
      if (memory) {
        applied.push("memory");
        reindex = memory.reindex;
      }
    } catch (err) {
      failed.push({ what: "model", error: err.message });
    }
    this.modelsCache.clear();
    const credentialsChanged = input.credentials.some((c2) => applied.includes(c2.provider)) || input.remove.some((r2) => applied.includes(`remove:${r2.provider}`));
    if (credentialsChanged) {
      const restarted = await this.restartIfAuthStale(input.credentials.map((c2) => c2.profileId));
      if (restarted) applied.push("restart");
    }
    if (reindex || this.reindexFailed && input.memory) this.reindexMemory();
    this.log(`[llm] applied ${applied.join(", ") || "nothing"}${failed.length ? `; failed ${failed.map((f2) => f2.what).join(", ")}` : ""}`);
    if (failed.length) {
      const err = new Error(failed.map((f2) => `${f2.what}: ${f2.error}`).join("; "));
      err.applied = applied;
      throw err;
    }
    return { ok: true, applied, failed };
  }
  /**
   * Rebuild the memory index in the background. It walks the whole corpus and embeds it, which
   * takes minutes on a long history, so `/llm/apply` does not wait for it: what a person sees is
   * the model change, and recall catches up on its own.
   *
   * One at a time. A rebuild runs for up to fifteen minutes and the control plane pushes again
   * whenever it sees a box that is not settled yet, so without this two `--force` runs would be
   * walking the same SQLite index at once.
   *
   * The CA has to be passed in. On a secured box every embedding call goes through the org proxy,
   * which presents the firewall's own certificate; `openclaw.service` and `profile.d` carry
   * `NODE_EXTRA_CA_CERTS`, and the vm-agent's unit only on a box whose role is from T-88 or later,
   * so without this a rebuild started from here would fail the handshake — or hang on it — and
   * leave vector search paused for good.
   *
   * A failure leaves `memory.search` written and the index paused, which `/llm/status` cannot
   * otherwise tell from a healthy one — so the failure is remembered and reported there, and the
   * next `/llm/apply` for this box retries it. The flag is cleared only once a run succeeds:
   * clearing it on the way in would report a healthy index while the vectors were still being
   * built, and the control plane would stop asking.
   */
  reindexMemory() {
    if (this.reindexing) {
      this.log("[llm] memory index rebuild already running; not starting another");
      return;
    }
    this.reindexing = true;
    this.writeReindexFailure("the memory index rebuild did not finish");
    const ca2 = this.opts.mitmCaPath;
    const env2 = ca2 && existsSync7(ca2) ? { NODE_EXTRA_CA_CERTS: ca2 } : void 0;
    void this.exec(this.bin(), ["memory", "index", "--force"], REINDEX_TIMEOUT_MS, void 0, { env: env2 }).then(() => {
      this.writeReindexFailure(null);
      this.log("[llm] memory index rebuilt for the new embedding provider");
    }).catch((err) => {
      this.writeReindexFailure(execFailureLine(err));
      this.log(`[llm] memory index rebuild failed: ${this.reindexFailed}`);
    }).finally(() => {
      this.reindexing = false;
    });
  }
  writeReindexFailure(error) {
    this.reindexFailed = error;
    const path = this.opts.statePath;
    if (!path) return;
    try {
      mkdirSync5(dirname5(path), { recursive: true });
      const tmp = `${path}.tmp`;
      writeFileSync7(tmp, JSON.stringify({ version: 1, error }), { mode: 384 });
      renameSync4(tmp, path);
    } catch (err) {
      this.log(`[llm] could not record the memory index state: ${err.message}`);
    }
  }
  /**
   * True when the gateway already reports every auth profile we just wrote. Otherwise restart it
   * so it loads the new credential store. Returns whether a restart was run.
   *
   * Profiles, not providers: an OpenAI key and a ChatGPT login are two profiles of `openai`, so
   * the gateway reporting `openai` says nothing about whether it has picked up the other one.
   */
  async restartIfAuthStale(profileIds) {
    let ready = false;
    try {
      const r3 = await this.gateway().call("models.authStatus", { refresh: true }, 15e3);
      const seen = new Set(
        (r3.providers ?? []).flatMap((p2) => Array.isArray(p2.profiles) ? p2.profiles : []).map((prof) => (str3(prof?.profileId) ?? str3(prof?.id) ?? "").toLowerCase())
      );
      ready = !r3.unavailable && profileIds.every((id) => seen.has(id.toLowerCase()));
    } catch (err) {
      this.log(`[llm] models.authStatus failed after apply: ${err.message}`);
    }
    if (ready) return false;
    if (!this.opts.restartService) {
      this.log("[llm] gateway does not report the new credential and no restart hook is set");
      return false;
    }
    const r2 = this.opts.restartService();
    this.log(r2.ok ? "[llm] restarted OpenClaw so it loads the new credential" : `[llm] restart failed: ${r2.error ?? "unknown"}`);
    return r2.ok;
  }
  /** What the box has right now, from the config and `models.authStatus`. No secrets. */
  async status() {
    const { config } = await this.config();
    const configured = readMemory(config);
    const agents = config.agents;
    const model = agents?.defaults?.model;
    const providers = /* @__PURE__ */ new Set();
    const profiles = [];
    const auth = config.auth;
    for (const [profileId, p2] of Object.entries(auth?.profiles ?? {})) {
      const provider = str3(p2?.provider) ?? profileId.split(":")[0];
      providers.add(provider);
      profiles.push({ profileId, provider, mode: str3(p2?.mode) });
    }
    const models = config.models;
    for (const id of Object.keys(models?.providers ?? {})) providers.add(id);
    let authStatus = [];
    try {
      const r2 = await this.gateway().call("models.authStatus", {}, 1e4);
      authStatus = (r2.providers ?? []).map((p2) => ({
        provider: str3(p2.provider) ?? str3(p2.id) ?? "?",
        status: str3(p2.status) ?? str3(p2.state) ?? null,
        profiles: Array.isArray(p2.profiles) ? p2.profiles.length : 0
      }));
    } catch (err) {
      this.log(`[llm] models.authStatus failed: ${err.message}`);
    }
    return {
      model: {
        primary: str3(model?.primary),
        fallbacks: Array.isArray(model?.fallbacks) ? model.fallbacks.filter((f2) => typeof f2 === "string") : []
      },
      providers: [...providers].sort(),
      profiles,
      auth: authStatus,
      // Only what the control plane compares. The endpoint and the placeholder are read for the
      // apply's own comparison and stay on the box; nothing downstream needs them.
      // A rebuild in flight is not a healthy index yet, and reporting it as one would tell the
      // control plane to stop watching. It reads as an error until the run lands.
      memory: {
        provider: configured.provider,
        model: configured.model,
        dreaming: configured.dreaming,
        indexError: this.reindexing ? "the memory index is being rebuilt" : this.reindexFailed
      }
    };
  }
  /** The models OpenClaw knows for a provider (`models.list`, full catalog), as `provider/model` refs. */
  async models(provider) {
    const cached = this.modelsCache.get(provider);
    if (cached && this.now() - cached.at < MODELS_CACHE_MS) return cached.value;
    const r2 = await this.gateway().call("models.list", { view: "all", provider }, 2e4);
    const out = [];
    for (const m2 of r2.models ?? []) {
      const rawId = str3(m2.id) ?? str3(m2.model);
      if (!rawId) continue;
      const p2 = str3(m2.provider);
      const id = rawId.includes("/") ? rawId : p2 ? `${p2}/${rawId}` : `${provider}/${rawId}`;
      if (!id.startsWith(`${provider}/`)) continue;
      out.push({ id, name: str3(m2.name) ?? id.slice(provider.length + 1) });
    }
    this.modelsCache.set(provider, { at: this.now(), value: out });
    return out;
  }
};

// src/routes/llm.ts
function fail2(res, err) {
  const message = err instanceof Error ? err.message : String(err);
  const status = /not running|not connected/i.test(message) ? 503 : 500;
  const applied = err.applied;
  sendJson(res, status, { ok: false, error: message, ...applied ? { applied } : {} });
}
var KINDS = /* @__PURE__ */ new Set(["api_key", "token", "oauth"]);
var PROVIDER_RE = /^[a-z0-9][a-z0-9_-]{0,40}$/i;
var BLOCK_APIS = /* @__PURE__ */ new Set(["openai-completions", "anthropic-messages", "openai-responses"]);
function parseProviderBlock(raw) {
  if (raw === void 0 || raw === null) return void 0;
  const b2 = raw;
  if (typeof b2.baseUrl !== "string" || !/^https:\/\/[a-z0-9.-]+(\/[\w./-]*)?$/i.test(b2.baseUrl)) return "credentials[].providerBlock.baseUrl must be an https URL";
  if (typeof b2.api !== "string" || !BLOCK_APIS.has(b2.api)) return "credentials[].providerBlock.api is not supported";
  if (!Array.isArray(b2.models) || b2.models.length === 0 || b2.models.length > 50) return "credentials[].providerBlock.models must list 1-50 models";
  const models = [];
  for (const m2 of b2.models) {
    if (typeof m2?.id !== "string" || !/^[A-Za-z0-9._:/-]{1,120}$/.test(m2.id)) return "credentials[].providerBlock.models[].id is invalid";
    models.push({ id: m2.id, name: typeof m2.name === "string" && m2.name ? m2.name.slice(0, 120) : m2.id });
  }
  return { baseUrl: b2.baseUrl, api: b2.api, models };
}
function parseMemory(raw) {
  if (raw === void 0) return void 0;
  if (raw === null) return null;
  const m2 = raw;
  if (typeof m2.provider !== "string" || !PROVIDER_RE.test(m2.provider)) return "memory.provider is invalid";
  if (typeof m2.model !== "string" || !/^[A-Za-z0-9._:/-]{1,120}$/.test(m2.model)) return "memory.model is invalid";
  if (typeof m2.baseUrl !== "string" || !/^https:\/\/[a-z0-9.-]+(\/[\w./-]*)?$/i.test(m2.baseUrl)) return "memory.baseUrl must be an https URL";
  if (typeof m2.apiKey !== "string" || !m2.apiKey) return "memory.apiKey required";
  return { provider: m2.provider, model: m2.model, baseUrl: m2.baseUrl, apiKey: m2.apiKey, dreaming: m2.dreaming === true };
}
function parseApply(body) {
  const model = body.model ?? {};
  const primary = typeof model.primary === "string" && model.primary ? model.primary : null;
  const fallbacks = Array.isArray(model.fallbacks) ? model.fallbacks.filter((f2) => typeof f2 === "string") : [];
  const credentials = [];
  for (const raw of Array.isArray(body.credentials) ? body.credentials : []) {
    if (typeof raw.provider !== "string" || !PROVIDER_RE.test(raw.provider)) return "credentials[].provider is invalid";
    if (typeof raw.kind !== "string" || !KINDS.has(raw.kind)) return "credentials[].kind must be api_key, token or oauth";
    if (typeof raw.profileId !== "string" || !raw.profileId) return "credentials[].profileId required";
    if (typeof raw.value !== "string" || !raw.value) return "credentials[].value required";
    if (typeof raw.model !== "string" || !raw.model) return "credentials[].model required";
    const codex = raw.codex;
    const providerBlock = parseProviderBlock(raw.providerBlock);
    if (typeof providerBlock === "string") return providerBlock;
    credentials.push({
      provider: raw.provider,
      kind: raw.kind,
      profileId: raw.profileId,
      value: raw.value,
      model: raw.model,
      ...codex && typeof codex.accountId === "string" ? { codex: { accountId: codex.accountId } } : {},
      ...providerBlock ? { providerBlock } : {}
    });
  }
  const remove = [];
  for (const raw of Array.isArray(body.remove) ? body.remove : []) {
    if (typeof raw.provider !== "string" || !PROVIDER_RE.test(raw.provider)) return "remove[].provider is invalid";
    if (typeof raw.profileId !== "string" || !raw.profileId) return "remove[].profileId required";
    remove.push({
      provider: raw.provider,
      profileId: raw.profileId,
      ...typeof raw.kind === "string" && KINDS.has(raw.kind) ? { kind: raw.kind } : {},
      ...raw.providerBlock === true ? { providerBlock: true } : {}
    });
  }
  const memory = parseMemory(body.memory);
  if (typeof memory === "string") return memory;
  return { model: { primary, fallbacks }, credentials, remove, ...memory !== void 0 ? { memory } : {} };
}
async function handleLlm(req, res, url2, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "llm") : await verifyMitmRequest(req, "llm") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "model changes must come from the org firewall" : "Unauthorized" });
    return;
  }
  if (!service) {
    sendJson(res, 503, { ok: false, error: "OpenClaw is not running on this box" });
    return;
  }
  try {
    if (url2.pathname === "/llm/status" && req.method === "GET") {
      sendJson(res, 200, await service.status());
      return;
    }
    if (url2.pathname === "/llm/models" && req.method === "GET") {
      const provider = url2.searchParams.get("provider") ?? "";
      if (!PROVIDER_RE.test(provider)) return sendJson(res, 400, { ok: false, error: "provider required" });
      sendJson(res, 200, { models: await service.models(provider) });
      return;
    }
    if (!write) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    const body = await readJsonBody(req);
    if (!body) {
      sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
      return;
    }
    if (url2.pathname === "/llm/apply") {
      const input = parseApply(body);
      if (typeof input === "string") return sendJson(res, 400, { ok: false, error: input });
      sendJson(res, 200, await service.apply(input));
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    fail2(res, err);
  }
}

// src/search.ts
var CLI_TIMEOUT_MS3 = 3e4;
function str4(v2) {
  return typeof v2 === "string" && v2.length > 0 ? v2 : null;
}
var SearchService = class _SearchService {
  constructor(opts) {
    this.opts = opts;
    this.exec = opts.execImpl ?? defaultExec;
    this.log = opts.log ?? ((line) => console.log(line));
  }
  exec;
  log;
  gateway() {
    const c2 = this.opts.client;
    if (!c2 || !c2.connected) throw new Error("OpenClaw is not running on this box");
    return c2;
  }
  bin() {
    return this.opts.openclawBin ?? "/usr/bin/openclaw";
  }
  async config() {
    const snapshot = await this.gateway().call("config.get", {}, GATEWAY_READ_MS);
    const hash = str4(snapshot.hash);
    if (!hash) throw new Error("OpenClaw returned no config hash");
    const config = snapshot.parsed ?? snapshot.config ?? {};
    return { hash, config: config && typeof config === "object" ? config : {} };
  }
  async patchConfig(patch, baseHash) {
    await patchConfig(this.gateway(), patch, { baseHash, timeoutMs: CONFIG_PATCH_RESTART_MS, readTimeoutMs: GATEWAY_READ_MS });
  }
  /**
   * Plugin ids this box HAS, from `openclaw plugins list --json`. Empty when it cannot say.
   *
   * A plugin that is installed but currently disabled counts: enabling it is exactly what `apply`
   * does a few lines below, so treating it as missing would tell the customer to re-provision a box
   * that already has everything it needs (and re-provisioning does not clear a disabled flag).
   * A plugin whose load failed does not count — that one really cannot serve a search.
   */
  async installedPlugins() {
    try {
      const { stdout } = await this.exec(this.bin(), ["plugins", "list", "--json"], CLI_TIMEOUT_MS3);
      const start = stdout.indexOf("{");
      if (start < 0) return /* @__PURE__ */ new Set();
      const parsed = JSON.parse(stdout.slice(start));
      const ids = (parsed.plugins ?? []).filter((p2) => p2.status !== "error").map((p2) => str4(p2.id));
      return new Set(ids.filter((id) => !!id));
    } catch (err) {
      this.log(`[search] could not list plugins: ${execFailureLine(err)}`);
      return /* @__PURE__ */ new Set();
    }
  }
  /** The entries of `plugins.entries`, defensively (OpenClaw writes to this file itself). */
  static entriesOf(config) {
    const plugins = config.plugins;
    const entries = plugins?.entries;
    return entries && typeof entries === "object" ? entries : {};
  }
  static providerOf(config) {
    const tools = config.tools;
    return str4(tools?.web?.search?.provider);
  }
  /** Make OpenClaw match the desired state. One config write, and a restart only when one is needed. */
  async apply(input) {
    this.gateway();
    const { hash, config } = await this.config();
    const entries = _SearchService.entriesOf(config);
    const current = _SearchService.providerOf(config);
    const applied = [];
    const entryPatch = {};
    const ours = new Set(input.remove.map((r2) => r2.id));
    let cleared = 0;
    for (const id of ours) {
      if (id === input.search?.plugin.id) continue;
      if (!(id in entries)) continue;
      entryPatch[id] = null;
      cleared++;
      applied.push(`remove:${id}`);
    }
    let provider = current;
    let needsRestart = cleared > 0;
    if (input.search) {
      const s2 = input.search;
      const installed = await this.installedPlugins();
      if (!installed.has(s2.plugin.id)) {
        throw new Error(
          `This box does not have the ${s2.plugin.id} search plugin. It is installed at provisioning (${s2.plugin.package}); re-provision the box, or update it from its Settings page, and try again.`
        );
      }
      const before = entries[s2.plugin.id];
      if (!before || before.enabled !== true) needsRestart = true;
      entryPatch[s2.plugin.id] = { enabled: true, config: { webSearch: { apiKey: s2.apiKey, baseUrl: s2.baseUrl, ...s2.config ?? {} } } };
      provider = s2.provider;
      applied.push(s2.plugin.id);
    } else {
      provider = current && ours.has(current) ? input.defaultProvider : current;
    }
    const patch = {};
    if (Object.keys(entryPatch).length) patch.plugins = { entries: entryPatch };
    if (provider !== current) patch.tools = { web: { search: { provider } } };
    if (!Object.keys(patch).length) {
      this.log("[search] nothing to change");
      return { ok: true, applied: [], provider: current };
    }
    try {
      await this.patchConfig(patch, hash);
    } catch (err) {
      const retryable = !input.search && provider !== null && /provider is not available/i.test(err.message);
      if (!retryable) throw err;
      this.log(`[search] ${provider} is not available on this box; unsetting the provider instead`);
      await this.patchConfig({ ...patch, tools: { web: { search: { provider: null } } } }, (await this.config()).hash);
      provider = null;
    }
    if (patch.tools) applied.push("provider");
    if (needsRestart && this.opts.restartService) {
      const r2 = this.opts.restartService();
      this.log(r2.ok ? "[search] restarted OpenClaw so it loads the search plugin" : `[search] restart failed: ${r2.error ?? "unknown"}`);
      if (r2.ok) applied.push("restart");
    }
    this.log(`[search] applied ${applied.join(", ")} (provider ${provider ?? "none"})`);
    return { ok: true, applied, provider };
  }
  /** What the box has right now. No secrets: the key it holds is a placeholder anyway. */
  async status() {
    const { config } = await this.config();
    const provider = _SearchService.providerOf(config);
    return { provider, plugins: [...await this.installedPlugins()].sort() };
  }
};

// src/routes/search.ts
var ID_RE = /^[a-z0-9][a-z0-9_-]{0,40}$/i;
var PROVIDER_RE2 = /^[a-z0-9][a-z0-9_-]{0,60}$/i;
var CONFIG_KEYS_MAX = 10;
function fail3(res, err) {
  const message = err instanceof Error ? err.message : String(err);
  const status = /not running|not connected/i.test(message) ? 503 : 500;
  sendJson(res, status, { ok: false, error: message });
}
function parseDesired(raw) {
  if (raw === null || raw === void 0) return null;
  const s2 = raw;
  if (typeof s2.provider !== "string" || !PROVIDER_RE2.test(s2.provider)) return "search.provider is invalid";
  const plugin = s2.plugin;
  if (!plugin || typeof plugin.id !== "string" || !ID_RE.test(plugin.id)) return "search.plugin.id is invalid";
  if (typeof plugin.package !== "string" || plugin.package.length > 120) return "search.plugin.package is invalid";
  if (typeof s2.baseUrl !== "string" || !/^https:\/\/[a-z0-9.-]+(\/[\w./-]*)?$/i.test(s2.baseUrl)) return "search.baseUrl must be an https URL";
  if (typeof s2.apiKey !== "string" || !s2.apiKey) return "search.apiKey required";
  let config;
  if (s2.config !== void 0 && s2.config !== null) {
    if (typeof s2.config !== "object") return "search.config must be an object";
    const entries = Object.entries(s2.config);
    if (entries.length > CONFIG_KEYS_MAX) return "search.config has too many keys";
    config = {};
    for (const [k2, v2] of entries) {
      if (!ID_RE.test(k2) || typeof v2 !== "string" || v2.length > 200) return "search.config values must be short strings";
      config[k2] = v2;
    }
  }
  return { provider: s2.provider, plugin: { id: plugin.id, package: plugin.package }, baseUrl: s2.baseUrl, apiKey: s2.apiKey, ...config ? { config } : {} };
}
function parseApply2(body) {
  const search2 = parseDesired(body.search);
  if (typeof search2 === "string") return search2;
  const defaultProvider = body.defaultProvider;
  if (defaultProvider !== null && defaultProvider !== void 0 && (typeof defaultProvider !== "string" || !PROVIDER_RE2.test(defaultProvider))) {
    return "defaultProvider is invalid";
  }
  const remove = [];
  for (const raw of Array.isArray(body.remove) ? body.remove : []) {
    if (typeof raw?.id !== "string" || !ID_RE.test(raw.id)) return "remove[].id is invalid";
    remove.push({ id: raw.id });
  }
  if (search2 && !remove.some((r2) => r2.id === search2.plugin.id)) remove.push({ id: search2.plugin.id });
  return { search: search2, defaultProvider: typeof defaultProvider === "string" ? defaultProvider : null, remove };
}
async function handleSearch(req, res, url2, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "search") : await verifyMitmRequest(req, "search") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "web search changes must come from the org firewall" : "Unauthorized" });
    return;
  }
  if (!service) {
    sendJson(res, 503, { ok: false, error: "OpenClaw is not running on this box" });
    return;
  }
  try {
    if (url2.pathname === "/search/status" && req.method === "GET") {
      sendJson(res, 200, await service.status());
      return;
    }
    if (!write) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    const body = await readJsonBody(req);
    if (!body) {
      sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
      return;
    }
    if (url2.pathname === "/search/apply") {
      const input = parseApply2(body);
      if (typeof input === "string") return sendJson(res, 400, { ok: false, error: input });
      sendJson(res, 200, await service.apply(input));
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    fail3(res, err);
  }
}

// src/connectors.ts
import { existsSync as existsSync8, mkdirSync as mkdirSync6, readFileSync as readFileSync13, renameSync as renameSync5, unlinkSync, writeFileSync as writeFileSync8 } from "fs";
import { dirname as dirname6 } from "path";
import { createServer, request as httpRequest } from "http";
var MCP_SERVER_NAME = "controlclaw";
var RELAYED = [/^\/mcp$/, /^\/mcp\/tools$/, /^\/v1\/health$/, /^\/v1\/apps(\/|$)/, /^\/v1\/actions(\/|$)/, /^\/v1\/proxy\//];
var ConnectorsService = class {
  constructor(opts) {
    this.opts = opts;
    this.log = opts.log ?? ((l2) => console.log(l2));
    this.now = opts.now ?? Date.now;
    this.state = readState(opts.statePath);
  }
  state;
  log;
  now;
  relay = null;
  gatewayReachable = null;
  patchChain = Promise.resolve();
  get relayUrl() {
    return `http://127.0.0.1:${this.opts.relayPort}`;
  }
  gateway() {
    const c2 = this.opts.client;
    if (!c2 || !c2.connected) throw new Error("OpenClaw is not running on this box");
    return c2;
  }
  /** Bring OpenClaw and the CLI in line with what the firewall sent. */
  async apply(input) {
    this.gateway();
    const applied = [];
    if (input.remove) {
      this.state = { gateway: null, connections: [], updatedAt: new Date(this.now()).toISOString() };
      writeState(this.opts.statePath, this.state);
      removeFile(this.opts.cliEnvPath);
      await this.patchMcp(null);
      applied.push("removed");
      this.log("[connectors] removed the MCP server entry and the CLI environment");
      return { ok: true, applied };
    }
    this.state = { gateway: input.gateway, connections: input.connections, updatedAt: new Date(this.now()).toISOString() };
    writeState(this.opts.statePath, this.state);
    applied.push("state");
    writeCliEnv(this.opts.cliEnvPath, this.relayUrl, input.gateway.token);
    applied.push("cli");
    await this.patchMcp({ url: `${this.relayUrl}/mcp`, transport: "streamable-http" });
    applied.push("mcp");
    this.log(`[connectors] ${input.connections.length} connection(s) available through ${this.relayUrl}/mcp`);
    return { ok: true, applied };
  }
  /**
   * One config write at a time, with a single retry when OpenClaw says the file moved under us.
   * `ChannelsService.patchConfig` does the same and for the same reason: `openclaw plugins
   * install` (a Slack or WhatsApp add-on, minutes long) and the WhatsApp login edit the same
   * file, and losing the race used to fail the whole apply and have the firewall record a push
   * failure. The two services still hold no lock between them, so the retry is what covers it.
   */
  patchMcp(entry) {
    const run3 = this.patchChain.then(
      () => this.patchMcpOnce(entry),
      () => this.patchMcpOnce(entry)
    );
    this.patchChain = run3.catch(() => void 0);
    return run3;
  }
  async patchMcpOnce(entry) {
    try {
      await this.writeMcp(entry);
    } catch (err) {
      if (!/config changed since last load/i.test(err.message ?? "")) throw err;
      await this.writeMcp(entry);
    }
  }
  async writeMcp(entry) {
    const snapshot = await this.gateway().call("config.get", {}, GATEWAY_READ_MS);
    const hash = typeof snapshot.hash === "string" ? snapshot.hash : null;
    if (!hash) throw new Error("OpenClaw returned no config hash");
    await patchConfig(this.gateway(), { mcpServers: { [MCP_SERVER_NAME]: entry } }, { baseHash: hash, timeoutMs: CONFIG_PATCH_RESTART_MS, readTimeoutMs: GATEWAY_READ_MS });
  }
  async status() {
    let configured = false;
    try {
      const snapshot = await this.gateway().call("config.get", {}, GATEWAY_READ_MS);
      const config = snapshot.parsed ?? snapshot.config ?? {};
      configured = !!config.mcpServers?.[MCP_SERVER_NAME];
    } catch (err) {
      this.log(`[connectors] could not read the OpenClaw config: ${err.message}`);
    }
    return {
      configured,
      relayUrl: this.relayUrl,
      gatewayReachable: this.gatewayReachable,
      connections: this.state.connections,
      updatedAt: this.state.updatedAt ?? null
    };
  }
  /**
   * Start the loopback relay. Unauthenticated on purpose — it is bound to 127.0.0.1 on its own
   * port (never the agent's control port, so `AGENT_BIND=0.0.0.0` on a legacy box cannot expose
   * it), and it exists to add the one header OpenClaw's config cannot carry. It forwards only
   * `/mcp` and `/v1`, so even a process on this box that finds it cannot reach the runtime's
   * admin API through it.
   */
  startRelay() {
    if (this.relay) return this.relay;
    const server2 = createServer((req, res) => {
      const path = (req.url ?? "/").split("?")[0];
      if (!RELAYED.some((re2) => re2.test(path))) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
        req.resume();
        return;
      }
      const gw = this.state.gateway;
      if (!gw) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "This agent has no app connections yet." }));
        req.resume();
        return;
      }
      const target = new URL(gw.url);
      const upstream = httpRequest(
        {
          host: target.hostname,
          port: target.port || 80,
          // http only; `parseApply` refuses anything else
          method: req.method,
          path: req.url,
          headers: { ...req.headers, host: target.host, authorization: `Bearer ${gw.token}` }
        },
        (up) => {
          this.gatewayReachable = true;
          res.writeHead(up.statusCode ?? 502, up.headers);
          up.pipe(res);
        }
      );
      upstream.setTimeout(12e4, () => upstream.destroy(new Error("timeout")));
      upstream.on("error", (err) => {
        this.gatewayReachable = false;
        this.log(`[connectors] relay upstream failed: ${err.message}`);
        if (!res.headersSent) {
          res.writeHead(502, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "Your firewall's connector runtime is not answering." }));
        } else res.end();
      });
      req.pipe(upstream);
    });
    server2.on("error", (err) => this.log(`[connectors] relay: ${err.message}`));
    server2.listen(this.opts.relayPort, "127.0.0.1", () => this.log(`[connectors] relay listening on ${this.relayUrl} (/mcp and /v1 only)`));
    this.relay = server2;
    return server2;
  }
};
function readState(path) {
  if (!existsSync8(path)) return { gateway: null, connections: [], updatedAt: "" };
  try {
    const parsed = JSON.parse(readFileSync13(path, "utf8"));
    return {
      gateway: parsed.gateway && typeof parsed.gateway.url === "string" && typeof parsed.gateway.token === "string" ? parsed.gateway : null,
      connections: Array.isArray(parsed.connections) ? parsed.connections : [],
      updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : ""
    };
  } catch {
    return { gateway: null, connections: [], updatedAt: "" };
  }
}
function writeState(path, state) {
  mkdirSync6(dirname6(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync8(tmp, JSON.stringify(state), { mode: 384 });
  renameSync5(tmp, path);
}
function cliEnvContents(relayUrl, token) {
  return [
    "# Written by ControlClaw's vm-agent. The base URL is the loopback relay on this box;",
    "# the token is this agent's own OpenConnector runtime token.",
    `OOMOL_CONNECT_BASE_URL=${relayUrl}`,
    `OOMOL_CONNECT_RUNTIME_TOKEN=${token}`,
    ""
  ].join("\n");
}
function writeCliEnv(path, relayUrl, token) {
  mkdirSync6(dirname6(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync8(tmp, cliEnvContents(relayUrl, token), { mode: 384 });
  renameSync5(tmp, path);
}
function removeFile(path) {
  try {
    if (existsSync8(path)) unlinkSync(path);
  } catch {
  }
}

// src/routes/connectors.ts
var SERVICE_RE = /^[a-z0-9][a-z0-9_]{0,60}$/;
var ID_RE2 = /^[A-Za-z0-9:._-]{1,128}$/;
var MAX_CONNECTIONS = 100;
function parseApply3(body) {
  if (body.remove === true) return { remove: true };
  const gateway2 = body.gateway;
  if (!gateway2 || typeof gateway2.url !== "string" || typeof gateway2.token !== "string" || !gateway2.token) return "gateway.url and gateway.token are required";
  let url2;
  try {
    url2 = new URL(gateway2.url);
  } catch {
    return "gateway.url is not a URL";
  }
  if (url2.protocol !== "http:") return "gateway.url must be http (the relay dials it without TLS)";
  const raw = Array.isArray(body.connections) ? body.connections : [];
  if (raw.length > MAX_CONNECTIONS) return `at most ${MAX_CONNECTIONS} connections`;
  const connections = [];
  for (const c2 of raw) {
    if (typeof c2.id !== "string" || !ID_RE2.test(c2.id)) return "connections[].id is invalid";
    if (typeof c2.service !== "string" || !SERVICE_RE.test(c2.service)) return "connections[].service is invalid";
    if (typeof c2.alias !== "string" || !ID_RE2.test(c2.alias)) return "connections[].alias is invalid";
    connections.push({
      id: c2.id,
      service: c2.service,
      alias: c2.alias,
      label: typeof c2.label === "string" ? c2.label.slice(0, 120) : null,
      accountLabel: typeof c2.accountLabel === "string" ? c2.accountLabel.slice(0, 200) : null
    });
  }
  return { gateway: { url: gateway2.url, token: gateway2.token }, connections };
}
async function handleConnectors(req, res, url2, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "connectors") : await verifyMitmRequest(req, "connectors") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "integration changes must come from the org firewall" : "Unauthorized" });
    return;
  }
  if (!service) {
    sendJson(res, 503, { ok: false, error: "This box does not support app integrations yet." });
    return;
  }
  try {
    if (url2.pathname === "/connectors/status" && req.method === "GET") {
      sendJson(res, 200, await service.status());
      return;
    }
    if (url2.pathname === "/connectors/apply" && write) {
      const body = await readJsonBody(req, 65536);
      if (!body) {
        sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
        return;
      }
      const input = parseApply3(body);
      if (typeof input === "string") {
        sendJson(res, 400, { ok: false, error: input });
        return;
      }
      sendJson(res, 200, await service.apply(input));
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    sendJson(res, /not running|not connected/i.test(message) ? 503 : 500, { ok: false, error: message });
  }
}

// src/drive.ts
import { existsSync as existsSync9, mkdirSync as mkdirSync7, readFileSync as readFileSync14, renameSync as renameSync6, writeFileSync as writeFileSync9 } from "fs";
import { dirname as dirname7 } from "path";
var LAUNCH_TIMEOUT_MS = 2e4;
var RC_TIMEOUT_MS = 3e3;
var MAX_MOUNTS = 8;
var APPLY_UNIT = "cc-drive-apply";
var NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 _-]{0,39}$/;
var isValidName = (name) => NAME_RE.test(name) && !name.endsWith(" ");
var FOLDER_ID_RE = /^[A-Za-z0-9_-]{10,200}$/;
var PLACEHOLDER_RE = /^CC-DRIVE-[0-9a-f]{8,64}$/;
var SETTING_RE = /^[A-Za-z0-9,.]{1,64}$/;
var DRIVE_SCOPES = /* @__PURE__ */ new Set([
  "https://www.googleapis.com/auth/drive",
  "https://www.googleapis.com/auth/drive.readonly",
  "https://www.googleapis.com/auth/drive.metadata.readonly"
]);
function parseApply4(body) {
  const placeholder = typeof body.placeholder === "string" ? body.placeholder : "";
  if (!PLACEHOLDER_RE.test(placeholder)) return "placeholder is not the shape the firewall generates";
  const scope = typeof body.scope === "string" ? body.scope : "";
  if (!DRIVE_SCOPES.has(scope)) return "scope is not a Google Drive scope";
  const d2 = body.defaults ?? {};
  const defaults = {
    exportFormats: typeof d2.exportFormats === "string" ? d2.exportFormats : "docx,xlsx,pdf",
    // Default true: a Google-native file reads as 0 bytes through the mount (measured 2026-09-24),
    // and an older firewall that does not send the flag should still hide them rather than serve
    // empty files an agent would treat as the document.
    skipGdocs: d2.skipGdocs !== false,
    vfsCacheMaxSize: typeof d2.vfsCacheMaxSize === "string" ? d2.vfsCacheMaxSize : "2G",
    vfsCacheMinFreeSpace: typeof d2.vfsCacheMinFreeSpace === "string" ? d2.vfsCacheMinFreeSpace : "4G"
  };
  for (const [key, value] of Object.entries(defaults)) {
    if (typeof value === "string" && !SETTING_RE.test(value)) return `defaults.${key} has characters that cannot go on a command line`;
  }
  if (!Array.isArray(body.mounts)) return "mounts must be an array";
  const raw = body.mounts;
  if (raw.length > MAX_MOUNTS) return `at most ${MAX_MOUNTS} Drive folders`;
  const mounts = [];
  const seen = /* @__PURE__ */ new Set();
  for (const m2 of raw) {
    const name = typeof m2.name === "string" ? m2.name : "";
    const folderId = typeof m2.folderId === "string" ? m2.folderId : "";
    if (!isValidName(name)) return `mounts[].name ${JSON.stringify(name)} cannot be a directory name`;
    if (!FOLDER_ID_RE.test(folderId)) return `mounts[].folderId ${JSON.stringify(folderId)} is invalid`;
    if (m2.mode !== "ro" && m2.mode !== "rw") return "mounts[].mode must be ro or rw";
    if (seen.has(name.toLowerCase())) return `two folders are both named ${JSON.stringify(name)}`;
    seen.add(name.toLowerCase());
    mounts.push({ name, folderId, mode: m2.mode });
  }
  return { placeholder, scope, connected: body.connected === true, defaults, mounts };
}
function writeAtomic(path, body, mode) {
  mkdirSync7(dirname7(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync9(tmp, body, { mode });
  renameSync6(tmp, path);
}
var DriveService = class {
  constructor(opts) {
    this.opts = opts;
    this.exec = opts.exec ?? defaultExec;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.log = opts.log ?? ((l2) => console.log(l2));
    this.applyScript = opts.applyScript ?? "/usr/local/bin/cc-drive-apply";
  }
  exec;
  fetchImpl;
  log;
  applyScript;
  /**
   * The modes of the set that was last asked for. Read fresh from the desired file rather than
   * cached: a cached map drifts from the file the moment an apply does not finish, and then the
   * console is told a folder is writable on the strength of a reconcile that failed.
   */
  modes() {
    const out = /* @__PURE__ */ new Map();
    try {
      const desired = JSON.parse(readFileSync14(this.opts.desiredPath, "utf8"));
      for (const m2 of desired.mounts ?? []) if (m2?.name) out.set(m2.name, m2.mode);
    } catch {
    }
    return out;
  }
  /**
   * The reconcile's own report. Written by a root script that lives in another repo, so its shape
   * is checked rather than trusted: an `/opt/controlclaw/state` half-written by a killed reconcile
   * used to throw straight out of the `/status` handler, which has no catch above it, and took the
   * whole agent down on the control plane's next poll.
   */
  readState() {
    try {
      const raw = JSON.parse(readFileSync14(this.opts.statePath, "utf8"));
      if (!raw || typeof raw !== "object" || !Array.isArray(raw.mounts)) return null;
      const mounts = raw.mounts.filter((m2) => !!m2 && typeof m2.name === "string" && typeof m2.rcPort === "number");
      return {
        status: typeof raw.status === "string" ? raw.status : "unknown",
        detail: typeof raw.detail === "string" ? raw.detail : "",
        connected: raw.connected === true,
        unsaved: Array.isArray(raw.unsaved) ? raw.unsaved.filter((u2) => !!u2 && typeof u2.name === "string") : [],
        mounts,
        at: typeof raw.at === "string" ? raw.at : ""
      };
    } catch {
      return null;
    }
  }
  /**
   * Hand a mount set to the box. Writes the desired set, launches the reconcile detached, and
   * returns — see the note at the top of this file for why it does not wait. `reconciling: false`
   * means one was already running and this set will be picked up by it or by the next push.
   */
  async apply(input) {
    const previous = this.readDesiredRaw();
    writeAtomic(this.opts.desiredPath, JSON.stringify(input, null, 2), 416);
    try {
      await this.exec("sudo", ["/usr/bin/systemd-run", `--unit=${APPLY_UNIT}`, "--collect", this.applyScript], LAUNCH_TIMEOUT_MS);
    } catch (err) {
      const line = execFailureLine(err);
      if (/already loaded|already exists|already running/i.test(line)) {
        this.log(`[drive] a reconcile is already running; the new set is on disk and will be applied`);
        return { ok: true, reconciling: false, folders: input.mounts.map((m2) => m2.name) };
      }
      if (previous !== null) writeAtomic(this.opts.desiredPath, previous, 416);
      this.log(`[drive] could not launch the reconcile: ${line}`);
      return { ok: false, error: line };
    }
    this.log(`[drive] reconciling ${input.mounts.length} folder(s)${input.connected ? "" : " (no Google connection, they stay unmounted)"}`);
    return { ok: true, reconciling: true, folders: input.mounts.map((m2) => m2.name) };
  }
  /** The desired file as written, so a failed launch can put it back byte for byte. */
  readDesiredRaw() {
    try {
      return readFileSync14(this.opts.desiredPath, "utf8");
    } catch {
      return null;
    }
  }
  /** `vfs/stats` from one mount's rclone, on loopback. Null when it is not answering. */
  async stats(port) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RC_TIMEOUT_MS);
    try {
      const res = await this.fetchImpl(`http://127.0.0.1:${port}/vfs/stats`, { method: "POST", signal: controller.signal });
      if (!res.ok) return null;
      const body = await res.json();
      const c2 = body.diskCache;
      if (!c2) return null;
      const num2 = (v2) => typeof v2 === "number" ? v2 : 0;
      return {
        bytesUsed: num2(c2.bytesUsed),
        uploadsQueued: num2(c2.uploadsQueued),
        uploadsInProgress: num2(c2.uploadsInProgress),
        erroredFiles: num2(c2.erroredFiles),
        outOfSpace: c2.outOfSpace === true
      };
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
  /**
   * How many queued writes have already been refused and are waiting to be tried again.
   *
   * Keyed off "has been attempted and is not attempting now", not off `tries > 1`: rclone counts an
   * attempt as it starts, so an item whose first upload was refused sits in its backoff at
   * `tries === 1` — and the backoff starts in seconds and doubles, so for the whole first window a
   * folder nothing can be written to would still have read as merely busy.
   */
  async failing(port) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RC_TIMEOUT_MS);
    try {
      const res = await this.fetchImpl(`http://127.0.0.1:${port}/vfs/queue`, { method: "POST", signal: controller.signal });
      if (!res.ok) return null;
      const body = await res.json();
      if (!Array.isArray(body.queue)) return null;
      return body.queue.filter((q2) => typeof q2.tries === "number" && q2.tries >= 1 && q2.uploading !== true).length;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
  /**
   * What the heartbeat carries. Every mount is reported even when its rclone is not answering:
   * "mounted, but I cannot ask it anything" is the state a customer most needs to see, and
   * dropping the row would read as "this folder is gone".
   */
  async status() {
    const state = this.readState();
    if (!state) return { connected: false, applyStatus: "none", applyDetail: "", unsaved: [], mounts: [], at: null };
    const modes = this.modes();
    const mounts = await Promise.all(
      state.mounts.map(async (m2) => {
        const stats = m2.mounted ? await this.stats(m2.rcPort) : null;
        const failing = m2.mounted && stats && stats.uploadsQueued > 0 ? await this.failing(m2.rcPort) : stats ? 0 : null;
        return {
          name: m2.name,
          mode: modes.get(m2.name) ?? null,
          mounted: m2.mounted,
          active: m2.active,
          cacheBytes: stats?.bytesUsed ?? null,
          queuedUploads: stats?.uploadsQueued ?? null,
          failingUploads: failing,
          erroredFiles: stats?.erroredFiles ?? null,
          outOfSpace: stats?.outOfSpace ?? null,
          // Only silent when the organisation has no Google connection: then every folder is
          // deliberately down and saying so per row is noise. Otherwise a mount that is not up gets
          // a reason, including `inactive` — systemd leaves a unit that was stopped or gave up
          // inactive rather than failed, and "not mounted, no reason given" is the worst row to
          // show somebody. The journal has the detail; the console links to the Logs page.
          lastError: m2.mounted || !state.connected ? null : `the mount is ${m2.active}`
        };
      })
    );
    return { connected: state.connected, applyStatus: state.status, applyDetail: state.detail, unsaved: state.unsaved, mounts, at: state.at };
  }
  /**
   * A count for the agent's `/status`, which the console polls for every agent. Reads the state
   * file and nothing else — no rclone call per mount — so putting it on a hot path costs a file
   * read. The full picture, with cache sizes and queues, is `GET /drive/status`.
   */
  summary() {
    const state = this.readState();
    if (!state) return null;
    return { folders: state.mounts.length, mounted: state.mounts.filter((m2) => m2.mounted).length, connected: state.connected };
  }
  /** Whether this box has Drive support installed at all (an older box does not). */
  supported() {
    return existsSync9(this.applyScript);
  }
};

// src/routes/drive.ts
async function handleDrive(req, res, url2, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "drive") : await verifyMitmRequest(req, "drive") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "Drive folder changes must come from the org firewall" : "Unauthorized" });
    return;
  }
  if (!service) {
    sendJson(res, 501, { error: "This agent's software does not support Drive folders yet. Update it." });
    return;
  }
  try {
    if (url2.pathname === "/drive/apply" && write) {
      const body = await readJsonBody(req);
      if (!body) {
        sendJson(res, 400, { error: "invalid JSON body" });
        return;
      }
      const input = parseApply4(body);
      if (typeof input === "string") {
        sendJson(res, 400, { error: input });
        return;
      }
      const result = await service.apply(input);
      if (!result.ok) {
        sendJson(res, 500, { error: result.error });
        return;
      }
      sendJson(res, 202, { ok: true, reconciling: result.reconciling, folders: result.folders });
      return;
    }
    if (url2.pathname === "/drive/status" && req.method === "GET") {
      sendJson(res, 200, await service.status());
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    sendJson(res, 500, { error: err.message });
  }
}

// src/google.ts
import { existsSync as existsSync10, mkdirSync as mkdirSync8, readFileSync as readFileSync15, renameSync as renameSync7, rmSync, writeFileSync as writeFileSync10 } from "fs";
import { dirname as dirname8 } from "path";
var PLACEHOLDER_RE2 = /^CC-GOOG-[0-9a-f]{8,64}$/;
var PROJECT_ID_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
var SERVICES = ["gmail", "calendar", "drive", "contacts", "sheets", "docs"];
var LABEL_RE = /^[^\s<>"'\\]{3,254}$/;
var VERSION_TIMEOUT_MS = GOOGLE_VERSION_MS;
function parseApply5(body) {
  const rawPlaceholder = body.placeholder;
  if (rawPlaceholder !== null && typeof rawPlaceholder !== "string") return "placeholder must be a string or null";
  const placeholder = rawPlaceholder === null || rawPlaceholder === "" ? null : rawPlaceholder;
  if (placeholder !== null && !PLACEHOLDER_RE2.test(placeholder)) return "placeholder is not the shape the firewall generates";
  const rawProject = body.projectId;
  if (rawProject !== null && rawProject !== void 0 && typeof rawProject !== "string") return "projectId must be a string or null";
  const projectId = rawProject ? String(rawProject) : null;
  if (projectId !== null && !PROJECT_ID_RE.test(projectId)) return "projectId is not a Google Cloud project id";
  if (!Array.isArray(body.services)) return "services must be an array";
  const services = [];
  for (const s2 of body.services) {
    if (typeof s2 !== "string" || !SERVICES.includes(s2)) return `services[] ${JSON.stringify(s2)} is not a Google service`;
    if (!services.includes(s2)) services.push(s2);
  }
  const rawLabel = body.accountLabel;
  if (rawLabel !== null && rawLabel !== void 0 && typeof rawLabel !== "string") return "accountLabel must be a string or null";
  const accountLabel = rawLabel ? String(rawLabel) : null;
  if (accountLabel !== null && !LABEL_RE.test(accountLabel)) return "accountLabel is not an address";
  return { placeholder, connected: body.connected === true, projectId, services, accountLabel };
}
function writeAtomic2(path, body, mode) {
  mkdirSync8(dirname8(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync10(tmp, body, { mode });
  renameSync7(tmp, path);
}
function envValue(value) {
  return `'${value.replace(/'/g, "'\\''")}'`;
}
var GoogleService = class {
  constructor(opts) {
    this.opts = opts;
    this.exec = opts.exec ?? defaultExec;
    this.log = opts.log ?? ((l2) => console.log(l2));
    this.gogBin = opts.gogBin ?? "/usr/local/bin/gog";
  }
  exec;
  log;
  gogBin;
  /** Whether this box has `gog` at all. A file check, so a box updated in place picks it up. */
  supported() {
    return existsSync10(this.gogBin);
  }
  /**
   * Make the box match the desired state. One atomic write, or one removal.
   *
   * A box with no grant has **no file**, rather than a file with an empty value: an empty
   * `GOG_ACCESS_TOKEN` would leave `gog` looking for a stored account and reporting that none is
   * configured, which is the same outcome by a more confusing route.
   */
  async apply(input) {
    const granted = input.connected && !!input.placeholder;
    try {
      if (!granted) {
        rmSync(this.opts.envPath, { force: true });
      } else {
        const lines = [
          "# Written by the ControlClaw agent from what the org firewall pushed. Do not edit:",
          "# the next push overwrites it. Nothing here is a secret.",
          "#",
          "# GOG_ACCESS_TOKEN is a PLACEHOLDER, not a token. The org firewall's proxy swaps it for a",
          "# real Google access token on *.googleapis.com, for this box only. It does not expire, so",
          "# ignore gog's note about a direct token expiring in about an hour (it prints that for any",
          "# --access-token and cannot tell ours from a real one).",
          `GOG_ACCESS_TOKEN=${envValue(input.placeholder)}`,
          // Out of the home directory on purpose: gog's cache and config must not turn up in the
          // agent's workspace, in the console's Files page, or in a workspace backup.
          "GOG_HOME=/opt/controlclaw/gog",
          // What the organization granted, for the bundled skill to tell the agent about. Not a
          // permission boundary — Google enforces the scopes — just what is worth trying.
          `CC_GOOGLE_SERVICES=${envValue(input.services.join(","))}`,
          ...input.accountLabel ? [`CC_GOOGLE_ACCOUNT=${envValue(input.accountLabel)}`] : [],
          // Sent as X-Goog-User-Project. Absent rather than empty when the organization named no
          // project: a project this identity may not use turns working calls into USER_PROJECT_DENIED.
          ...input.projectId ? [`GOG_QUOTA_PROJECT=${envValue(input.projectId)}`] : [],
          ""
        ];
        writeAtomic2(this.opts.envPath, lines.join("\n"), 384);
      }
      writeAtomic2(
        this.opts.statePath,
        JSON.stringify({ ...input, placeholder: granted ? "set" : null, at: (/* @__PURE__ */ new Date()).toISOString() }, null, 2),
        384
      );
    } catch (err) {
      return { ok: false, error: `Could not write this box's Google settings: ${err.message}` };
    }
    this.log(granted ? `[google] ${input.accountLabel ?? "an account"} is available to gog (${input.services.join(", ") || "no services"})` : "[google] no grant on this box; gog has nothing to send");
    return { ok: true, granted };
  }
  /** What the box has right now. No secrets: what it holds is a placeholder, and not even that. */
  async status() {
    const applied = this.readState();
    return {
      gogVersion: await this.version(),
      // The file, not the remembered state: this is the question the console is really asking, and
      // a state file that outlived its env file would answer it wrongly.
      hasPlaceholder: existsSync10(this.opts.envPath),
      connected: applied?.connected ?? false,
      services: applied?.services ?? [],
      projectId: applied?.projectId ?? null,
      accountLabel: applied?.accountLabel ?? null,
      at: applied?.at ?? null
    };
  }
  readState() {
    try {
      const raw = JSON.parse(readFileSync15(this.opts.statePath, "utf8"));
      if (!raw || typeof raw !== "object") return null;
      return {
        placeholder: null,
        connected: raw.connected === true,
        projectId: typeof raw.projectId === "string" ? raw.projectId : null,
        services: Array.isArray(raw.services) ? raw.services.filter((s2) => SERVICES.includes(s2)) : [],
        accountLabel: typeof raw.accountLabel === "string" ? raw.accountLabel : null,
        at: typeof raw.at === "string" ? raw.at : ""
      };
    } catch {
      return null;
    }
  }
  /** `gog --version`, best effort. Null when it cannot be read, which the console shows as unknown. */
  async version() {
    try {
      const { stdout } = await this.exec(this.gogBin, ["--version"], VERSION_TIMEOUT_MS);
      const matched = /([0-9]+\.[0-9]+\.[0-9]+)/.exec(stdout)?.[1];
      return matched ?? (stdout.trim().split("\n")[0] || null);
    } catch (err) {
      this.log(`[google] could not read the gog version: ${execFailureLine(err)}`);
      return null;
    }
  }
};

// src/routes/google.ts
async function handleGoogle(req, res, url2, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "google") : await verifyMitmRequest(req, "google") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "Google account changes must come from the org firewall" : "Unauthorized" });
    return;
  }
  if (!service) {
    sendJson(res, 501, { error: "This agent does not have gog yet, so it cannot use your Google account. Update it." });
    return;
  }
  try {
    if (url2.pathname === "/google/apply" && write) {
      const body = await readJsonBody(req);
      if (!body) {
        sendJson(res, 400, { error: "invalid JSON body" });
        return;
      }
      const input = parseApply5(body);
      if (typeof input === "string") {
        sendJson(res, 400, { error: input });
        return;
      }
      const result = await service.apply(input);
      if (!result.ok) {
        sendJson(res, 500, { error: result.error });
        return;
      }
      sendJson(res, 200, { ok: true, granted: result.granted });
      return;
    }
    if (url2.pathname === "/google/status" && req.method === "GET") {
      sendJson(res, 200, await service.status());
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    sendJson(res, 500, { error: err.message });
  }
}

// src/update.ts
import { readFileSync as readFileSync16 } from "fs";
import { spawn as spawn2 } from "child_process";
var IDLE = { phase: "idle", detail: null, ref: null, at: null };
var STALE_MS = 45 * 6e4;
function detach(file, args) {
  try {
    const child = spawn2(file, args, { detached: true, stdio: "ignore" });
    child.on("error", (error) => console.error(`[update] could not start cc-reprovision: ${error.message}`));
    child.unref();
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}
var UpdateService = class {
  constructor(opts) {
    this.opts = opts;
    this.spawnImpl = opts.spawnImpl ?? detach;
    this.log = opts.log ?? ((line) => console.log(line));
    this.now = opts.now ?? Date.now;
  }
  spawnImpl;
  log;
  now;
  /** Whether this box was provisioned with an update pin at all. */
  pinned() {
    return this.conf() !== null;
  }
  conf() {
    const path = this.opts.confPath ?? "/etc/controlclaw/update.conf";
    let raw;
    try {
      raw = readFileSync16(path, "utf8");
    } catch {
      return null;
    }
    const out = {};
    for (const line of raw.split("\n")) {
      const m2 = /^([A-Z_]+)=(.*)$/.exec(line.trim());
      if (m2) out[m2[1]] = m2[2];
    }
    return out.ANSIBLE_REPO ? out : null;
  }
  status() {
    let raw;
    try {
      raw = readFileSync16(this.opts.statePath, "utf8");
    } catch {
      return IDLE;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return IDLE;
    }
    const phase = typeof parsed.phase === "string" ? parsed.phase : "idle";
    const at2 = typeof parsed.at === "string" ? parsed.at : null;
    const status = {
      phase,
      detail: typeof parsed.detail === "string" && parsed.detail.length > 0 ? parsed.detail : null,
      ref: typeof parsed.ref === "string" && parsed.ref.length > 0 ? parsed.ref : null,
      at: at2
    };
    const running = phase === "resolving" || phase === "installing" || phase === "running";
    if (running && at2 && this.now() - Date.parse(at2) > STALE_MS) {
      return { ...status, phase: "failed", detail: "The update stopped reporting. Check the agent's logs." };
    }
    return status;
  }
  /**
   * Start a run, unless one is already going. Returns as soon as it is launched — the run itself
   * takes minutes and will restart this process before it finishes.
   */
  start() {
    if (!this.pinned()) throw new Error("This agent was created before in-place updates; it has to be rebuilt instead.");
    const current = this.status();
    if (current.phase === "resolving" || current.phase === "installing" || current.phase === "running") {
      return { ok: true, status: current };
    }
    const r2 = this.spawnImpl("sudo", ["/usr/bin/systemd-run", "--unit=cc-reprovision", "--collect", "/usr/local/bin/cc-reprovision"]);
    if (!r2.ok) throw new Error(`The update could not be started: ${r2.error ?? "unknown error"}`);
    this.log("[update] started cc-reprovision");
    return { ok: true, status: { phase: "resolving", detail: "Starting\u2026", ref: null, at: new Date(this.now()).toISOString() } };
  }
};

// src/routes/update.ts
async function handleUpdate(req, res, pathname, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "update") : await verifyMitmRequest(req, "update") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "an update must come from the org firewall" : "Unauthorized" });
    return;
  }
  if (!service) {
    sendJson(res, 503, { ok: false, error: "This agent cannot update itself" });
    return;
  }
  try {
    if (pathname === "/update" && req.method === "GET") {
      sendJson(res, 200, { ok: true, pinned: service.pinned(), ...service.status() });
      return;
    }
    if (pathname === "/update" && req.method === "POST") {
      sendJson(res, 200, service.start());
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) });
  }
}

// src/backup.ts
import { createReadStream, createWriteStream } from "fs";
import { mkdir, mkdtemp, lstat, opendir, readlink, rename, rm, stat, symlink, utimes, writeFile, chmod } from "fs/promises";
import { tmpdir } from "os";
import { dirname as dirname9, join as join7 } from "path";
import { Readable } from "stream";
import { pipeline } from "stream/promises";
import { createGunzip, createGzip } from "zlib";

// ../../node_modules/.pnpm/libsodium@0.8.4/node_modules/libsodium/dist/modules-esm/libsodium.mjs
async function A(A3 = {}) {
  var I2, g2 = A3, C2 = !!globalThis.window, B2 = !!globalThis.WorkerGlobalScope, Q2 = (globalThis.process?.versions?.node && globalThis.process, import.meta.url);
  if (C2 || B2) {
    try {
      new URL(".", Q2).href;
    } catch {
    }
    B2 && (I2 = (A4) => {
      var I3 = new XMLHttpRequest();
      return I3.open("GET", A4, false), I3.responseType = "arraybuffer", I3.send(null), new Uint8Array(I3.response);
    });
  }
  (function() {
  }).bind();
  var E2, i2, D2, F2, o2, w2, h2, S2, y2, k2, c2, M2 = function() {
  }.bind(), U2 = false, G2 = false;
  function J2() {
    var A4 = d2.buffer;
    h2 = new Int8Array(A4), o2 = new Int16Array(A4), g2.HEAPU8 = c2 = new Uint8Array(A4), new Uint16Array(A4), w2 = new Int32Array(A4), k2 = new Uint32Array(A4), S2 = new Float32Array(A4), y2 = new Float64Array(A4);
  }
  function Y2(A4) {
    g2.onAbort?.(A4), M2(A4 = `Aborted(${A4})`), U2 = true, A4 += ". Build with -sASSERTIONS for more info.";
    var I3 = new WebAssembly.RuntimeError(A4);
    throw D2?.(I3), I3;
  }
  for (var N2 = (A4) => {
    for (; A4.length > 0; ) A4.shift()(g2);
  }, K2 = [], H2 = (A4) => K2.push(A4), a2 = [], f2 = (A4) => a2.push(A4), s2 = globalThis.TextDecoder && new TextDecoder(), L2 = (A4, I3, g3) => A4 ? ((A5, I4 = 0, g4, C3) => {
    var B3 = ((A6, I5, g5, C4) => {
      var B4 = I5 + g5;
      if (C4) return B4;
      for (; A6[I5] && !(I5 >= B4); ) ++I5;
      return I5;
    })(A5, I4, g4, C3);
    if (B3 - I4 > 16 && A5.buffer && s2) return s2.decode(A5.subarray(I4, B3));
    for (var Q3 = ""; I4 < B3; ) {
      var E3 = A5[I4++];
      if (128 & E3) {
        var i3 = 63 & A5[I4++];
        if (192 != (224 & E3)) {
          var D3 = 63 & A5[I4++];
          if ((E3 = 224 == (240 & E3) ? (15 & E3) << 12 | i3 << 6 | D3 : (7 & E3) << 18 | i3 << 12 | D3 << 6 | 63 & A5[I4++]) < 65536) Q3 += String.fromCharCode(E3);
          else {
            var F3 = E3 - 65536;
            Q3 += String.fromCharCode(55296 | F3 >> 10, 56320 | 1023 & F3);
          }
        } else Q3 += String.fromCharCode((31 & E3) << 6 | i3);
      } else Q3 += String.fromCharCode(E3);
    }
    return Q3;
  })(c2, A4, I3, g3) : "", R2 = [], p2 = (A4, I3) => Math.ceil(A4 / I3) * I3, t2 = (A4) => {
    var I3 = (A4 - d2.buffer.byteLength + 65535) / 65536 | 0;
    try {
      return d2.grow(I3), J2(), 1;
    } catch (A5) {
    }
  }, n2 = new Uint8Array(123), q2 = 25; q2 >= 0; --q2) n2[48 + q2] = 52 + q2, n2[65 + q2] = q2, n2[97 + q2] = 26 + q2;
  if (n2[43] = 62, n2[47] = 63, g2.noExitRuntime && g2.noExitRuntime, g2.print && g2.print, g2.printErr && (M2 = g2.printErr), g2.wasmBinary && (E2 = g2.wasmBinary), g2.arguments && g2.arguments, g2.thisProgram && g2.thisProgram, g2.preInit) for ("function" == typeof g2.preInit && (g2.preInit = [g2.preInit]); g2.preInit.length > 0; ) g2.preInit.shift()();
  g2.setValue = function(A4, I3, g3 = "i8") {
    switch (g3.endsWith("*") && (g3 = "*"), g3) {
      case "i1":
      case "i8":
        h2[A4] = I3;
        break;
      case "i16":
        o2[A4 >> 1] = I3;
        break;
      case "i32":
        w2[A4 >> 2] = I3;
        break;
      case "i64":
        Y2("to do setValue(i64) use WASM_BIGINT");
      case "float":
        S2[A4 >> 2] = I3;
        break;
      case "double":
        y2[A4 >> 3] = I3;
        break;
      case "*":
        k2[A4 >> 2] = I3;
        break;
      default:
        Y2(`invalid type for setValue: ${g3}`);
    }
  }, g2.getValue = function(A4, I3 = "i8") {
    switch (I3.endsWith("*") && (I3 = "*"), I3) {
      case "i1":
      case "i8":
        return h2[A4];
      case "i16":
        return o2[A4 >> 1];
      case "i32":
        return w2[A4 >> 2];
      case "i64":
        Y2("to do getValue(i64) use WASM_BIGINT");
      case "float":
        return S2[A4 >> 2];
      case "double":
        return y2[A4 >> 3];
      case "*":
        return k2[A4 >> 2];
      default:
        Y2(`invalid type for getValue: ${I3}`);
    }
  }, g2.UTF8ToString = L2;
  var d2, O2, r2 = { 40216: () => g2.getRandomValue(), 40252: () => {
    if (void 0 === g2.getRandomValue) try {
      var A4 = "object" == typeof window ? window : self, I3 = void 0 !== A4.crypto ? A4.crypto : A4.msCrypto;
      I3 = void 0 === I3 ? B3 : I3;
      var C3 = function() {
        var A5 = new Uint32Array(1);
        return I3.getRandomValues(A5), A5[0] >>> 0;
      };
      C3(), g2.getRandomValue = C3;
    } catch (A5) {
      try {
        var B3 = __require("crypto"), Q3 = function() {
          var A6 = B3.randomBytes(4);
          return (A6[0] << 24 | A6[1] << 16 | A6[2] << 8 | A6[3]) >>> 0;
        };
        Q3(), g2.getRandomValue = Q3;
      } catch (A6) {
        throw "No secure random number generator found";
      }
    }
  } }, e = { a: (A4, I3, g3, C3) => Y2(`Assertion failed: ${L2(A4)}, at: ` + [I3 ? L2(I3) : "unknown filename", g3, C3 ? L2(C3) : "unknown function"]), c: () => Y2(""), b: (A4, I3, g3) => ((A5, I4, g4) => {
    var C3 = ((A6, I5) => {
      var g5;
      for (R2.length = 0; g5 = c2[A6++]; ) {
        var C4 = 105 != g5;
        I5 += (C4 &= 112 != g5) && I5 % 8 ? 4 : 0, R2.push(112 == g5 ? k2[I5 >> 2] : 105 == g5 ? w2[I5 >> 2] : y2[I5 >> 3]), I5 += C4 ? 8 : 4;
      }
      return R2;
    })(I4, g4);
    return r2[A5](...C3);
  })(A4, I3, g3), d: (A4) => {
    var I3 = c2.length, g3 = 2147483648;
    if ((A4 >>>= 0) > g3) return false;
    for (var C3 = 1; C3 <= 4; C3 *= 2) {
      var B3 = I3 * (1 + 0.2 / C3);
      B3 = Math.min(B3, A4 + 100663296);
      var Q3 = Math.min(g3, p2(Math.max(A4, B3), 65536));
      if (t2(Q3)) return true;
    }
    return false;
  } };
  return O2 = await (async function() {
    function A4(A5, I3) {
      return (function(A6) {
        g2._crypto_aead_aegis128l_keybytes = A6.f, g2._crypto_aead_aegis128l_nsecbytes = A6.g, g2._crypto_aead_aegis128l_npubbytes = A6.h, g2._crypto_aead_aegis128l_abytes = A6.i, g2._crypto_aead_aegis128l_messagebytes_max = A6.j, g2._crypto_aead_aegis128l_keygen = A6.k, g2._crypto_aead_aegis128l_encrypt = A6.l, g2._crypto_aead_aegis128l_encrypt_detached = A6.m, g2._crypto_aead_aegis128l_decrypt = A6.n, g2._crypto_aead_aegis128l_decrypt_detached = A6.o, g2._crypto_aead_aegis256_keybytes = A6.p, g2._crypto_aead_aegis256_nsecbytes = A6.q, g2._crypto_aead_aegis256_npubbytes = A6.r, g2._crypto_aead_aegis256_abytes = A6.s, g2._crypto_aead_aegis256_messagebytes_max = A6.t, g2._crypto_aead_aegis256_keygen = A6.u, g2._crypto_aead_aegis256_encrypt = A6.v, g2._crypto_aead_aegis256_encrypt_detached = A6.w, g2._crypto_aead_aegis256_decrypt = A6.x, g2._crypto_aead_aegis256_decrypt_detached = A6.y, g2._crypto_aead_aes256gcm_is_available = A6.z, g2._crypto_aead_chacha20poly1305_encrypt_detached = A6.A, g2._crypto_aead_chacha20poly1305_encrypt = A6.B, g2._crypto_aead_chacha20poly1305_ietf_encrypt_detached = A6.C, g2._crypto_aead_chacha20poly1305_ietf_encrypt = A6.D, g2._crypto_aead_chacha20poly1305_decrypt_detached = A6.E, g2._crypto_aead_chacha20poly1305_decrypt = A6.F, g2._crypto_aead_chacha20poly1305_ietf_decrypt_detached = A6.G, g2._crypto_aead_chacha20poly1305_ietf_decrypt = A6.H, g2._crypto_aead_chacha20poly1305_ietf_keybytes = A6.I, g2._crypto_aead_chacha20poly1305_ietf_npubbytes = A6.J, g2._crypto_aead_chacha20poly1305_ietf_nsecbytes = A6.K, g2._crypto_aead_chacha20poly1305_ietf_abytes = A6.L, g2._crypto_aead_chacha20poly1305_ietf_messagebytes_max = A6.M, g2._crypto_aead_chacha20poly1305_ietf_keygen = A6.N, g2._crypto_aead_chacha20poly1305_keybytes = A6.O, g2._crypto_aead_chacha20poly1305_npubbytes = A6.P, g2._crypto_aead_chacha20poly1305_nsecbytes = A6.Q, g2._crypto_aead_chacha20poly1305_abytes = A6.R, g2._crypto_aead_chacha20poly1305_messagebytes_max = A6.S, g2._crypto_aead_chacha20poly1305_keygen = A6.T, g2._crypto_aead_xchacha20poly1305_ietf_encrypt_detached = A6.U, g2._crypto_aead_xchacha20poly1305_ietf_encrypt = A6.V, g2._crypto_aead_xchacha20poly1305_ietf_decrypt_detached = A6.W, g2._crypto_aead_xchacha20poly1305_ietf_decrypt = A6.X, g2._crypto_aead_xchacha20poly1305_ietf_keybytes = A6.Y, g2._crypto_aead_xchacha20poly1305_ietf_npubbytes = A6.Z, g2._crypto_aead_xchacha20poly1305_ietf_nsecbytes = A6._, g2._crypto_aead_xchacha20poly1305_ietf_abytes = A6.$, g2._crypto_aead_xchacha20poly1305_ietf_messagebytes_max = A6.aa, g2._crypto_aead_xchacha20poly1305_ietf_keygen = A6.ba, g2._crypto_auth_bytes = A6.ca, g2._crypto_auth_keybytes = A6.da, g2._crypto_auth = A6.ea, g2._crypto_auth_verify = A6.fa, g2._crypto_auth_keygen = A6.ga, g2._crypto_box_seedbytes = A6.ha, g2._crypto_box_publickeybytes = A6.ia, g2._crypto_box_secretkeybytes = A6.ja, g2._crypto_box_beforenmbytes = A6.ka, g2._crypto_box_noncebytes = A6.la, g2._crypto_box_macbytes = A6.ma, g2._crypto_box_messagebytes_max = A6.na, g2._crypto_box_seed_keypair = A6.oa, g2._crypto_box_keypair = A6.pa, g2._crypto_box_beforenm = A6.qa, g2._crypto_box_detached_afternm = A6.ra, g2._crypto_box_detached = A6.sa, g2._crypto_box_easy_afternm = A6.ta, g2._crypto_box_easy = A6.ua, g2._crypto_box_open_detached_afternm = A6.va, g2._crypto_box_open_detached = A6.wa, g2._crypto_box_open_easy_afternm = A6.xa, g2._crypto_box_open_easy = A6.ya, g2._crypto_box_seal = A6.za, g2._crypto_box_seal_open = A6.Aa, g2._crypto_box_sealbytes = A6.Ba, g2._crypto_generichash_bytes_min = A6.Ca, g2._crypto_generichash_bytes_max = A6.Da, g2._crypto_generichash_bytes = A6.Ea, g2._crypto_generichash_keybytes_min = A6.Fa, g2._crypto_generichash_keybytes_max = A6.Ga, g2._crypto_generichash_keybytes = A6.Ha, g2._crypto_generichash_statebytes = A6.Ia, g2._crypto_generichash = A6.Ja, g2._crypto_generichash_init = A6.Ka, g2._crypto_generichash_update = A6.La, g2._crypto_generichash_final = A6.Ma, g2._crypto_generichash_keygen = A6.Na, g2._crypto_hash_bytes = A6.Oa, g2._crypto_hash = A6.Pa, g2._crypto_hash_sha3256_bytes = A6.Qa, g2._crypto_hash_sha3256_statebytes = A6.Ra, g2._crypto_hash_sha3256_init = A6.Sa, g2._crypto_hash_sha3256_update = A6.Ta, g2._crypto_hash_sha3256_final = A6.Ua, g2._crypto_hash_sha3256 = A6.Va, g2._crypto_hash_sha3512_bytes = A6.Wa, g2._crypto_hash_sha3512_statebytes = A6.Xa, g2._crypto_hash_sha3512_init = A6.Ya, g2._crypto_hash_sha3512_update = A6.Za, g2._crypto_hash_sha3512_final = A6._a, g2._crypto_hash_sha3512 = A6.$a, g2._crypto_ipcrypt_bytes = A6.ab, g2._crypto_ipcrypt_keybytes = A6.bb, g2._crypto_ipcrypt_nd_keybytes = A6.cb, g2._crypto_ipcrypt_nd_tweakbytes = A6.db, g2._crypto_ipcrypt_nd_inputbytes = A6.eb, g2._crypto_ipcrypt_nd_outputbytes = A6.fb, g2._crypto_ipcrypt_ndx_keybytes = A6.gb, g2._crypto_ipcrypt_ndx_tweakbytes = A6.hb, g2._crypto_ipcrypt_ndx_inputbytes = A6.ib, g2._crypto_ipcrypt_ndx_outputbytes = A6.jb, g2._crypto_ipcrypt_pfx_keybytes = A6.kb, g2._crypto_ipcrypt_pfx_bytes = A6.lb, g2._crypto_ipcrypt_keygen = A6.mb, g2._crypto_ipcrypt_nd_keygen = A6.nb, g2._crypto_ipcrypt_ndx_keygen = A6.ob, g2._crypto_ipcrypt_pfx_keygen = A6.pb, g2._crypto_ipcrypt_encrypt = A6.qb, g2._crypto_ipcrypt_decrypt = A6.rb, g2._crypto_ipcrypt_nd_encrypt = A6.sb, g2._crypto_ipcrypt_nd_decrypt = A6.tb, g2._crypto_ipcrypt_ndx_encrypt = A6.ub, g2._crypto_ipcrypt_ndx_decrypt = A6.vb, g2._crypto_ipcrypt_pfx_encrypt = A6.wb, g2._crypto_ipcrypt_pfx_decrypt = A6.xb, g2._crypto_kdf_bytes_min = A6.yb, g2._crypto_kdf_bytes_max = A6.zb, g2._crypto_kdf_contextbytes = A6.Ab, g2._crypto_kdf_keybytes = A6.Bb, g2._crypto_kdf_derive_from_key = A6.Cb, g2._crypto_kdf_keygen = A6.Db, g2._crypto_kdf_hkdf_sha256_extract_init = A6.Eb, g2._crypto_kdf_hkdf_sha256_extract_update = A6.Fb, g2._crypto_kdf_hkdf_sha256_extract_final = A6.Gb, g2._crypto_kdf_hkdf_sha256_extract = A6.Hb, g2._crypto_kdf_hkdf_sha256_keygen = A6.Ib, g2._crypto_kdf_hkdf_sha256_expand = A6.Jb, g2._crypto_kdf_hkdf_sha256_keybytes = A6.Kb, g2._crypto_kdf_hkdf_sha256_bytes_min = A6.Lb, g2._crypto_kdf_hkdf_sha256_bytes_max = A6.Mb, g2._crypto_kdf_hkdf_sha256_statebytes = A6.Nb, g2._crypto_kdf_hkdf_sha512_extract_init = A6.Ob, g2._crypto_kdf_hkdf_sha512_extract_update = A6.Pb, g2._crypto_kdf_hkdf_sha512_extract_final = A6.Qb, g2._crypto_kdf_hkdf_sha512_extract = A6.Rb, g2._crypto_kdf_hkdf_sha512_keygen = A6.Sb, g2._crypto_kdf_hkdf_sha512_expand = A6.Tb, g2._crypto_kdf_hkdf_sha512_keybytes = A6.Ub, g2._crypto_kdf_hkdf_sha512_bytes_min = A6.Vb, g2._crypto_kdf_hkdf_sha512_bytes_max = A6.Wb, g2._crypto_kdf_hkdf_sha512_statebytes = A6.Xb, g2._crypto_kem_publickeybytes = A6.Yb, g2._crypto_kem_secretkeybytes = A6.Zb, g2._crypto_kem_ciphertextbytes = A6._b, g2._crypto_kem_sharedsecretbytes = A6.$b, g2._crypto_kem_seedbytes = A6.ac, g2._crypto_kem_primitive = A6.bc, g2._crypto_kem_seed_keypair = A6.cc, g2._crypto_kem_keypair = A6.dc, g2._crypto_kem_enc = A6.ec, g2._crypto_kem_dec = A6.fc, g2._crypto_kem_mlkem768_publickeybytes = A6.gc, g2._crypto_kem_mlkem768_secretkeybytes = A6.hc, g2._crypto_kem_mlkem768_ciphertextbytes = A6.ic, g2._crypto_kem_mlkem768_sharedsecretbytes = A6.jc, g2._crypto_kem_mlkem768_seedbytes = A6.kc, g2._crypto_kem_mlkem768_seed_keypair = A6.lc, g2._crypto_kem_mlkem768_keypair = A6.mc, g2._crypto_kem_mlkem768_enc = A6.nc, g2._crypto_kem_mlkem768_enc_deterministic = A6.oc, g2._crypto_kem_mlkem768_dec = A6.pc, g2._crypto_kem_xwing_publickeybytes = A6.qc, g2._crypto_kem_xwing_secretkeybytes = A6.rc, g2._crypto_kem_xwing_ciphertextbytes = A6.sc, g2._crypto_kem_xwing_sharedsecretbytes = A6.tc, g2._crypto_kem_xwing_seedbytes = A6.uc, g2._crypto_kem_xwing_seed_keypair = A6.vc, g2._crypto_kem_xwing_keypair = A6.wc, g2._crypto_kem_xwing_enc_deterministic = A6.xc, g2._crypto_kem_xwing_enc = A6.yc, g2._crypto_kem_xwing_dec = A6.zc, g2._crypto_kx_seed_keypair = A6.Ac, g2._crypto_kx_keypair = A6.Bc, g2._crypto_kx_client_session_keys = A6.Cc, g2._crypto_kx_server_session_keys = A6.Dc, g2._crypto_kx_publickeybytes = A6.Ec, g2._crypto_kx_secretkeybytes = A6.Fc, g2._crypto_kx_seedbytes = A6.Gc, g2._crypto_kx_sessionkeybytes = A6.Hc, g2._crypto_scalarmult_base = A6.Ic, g2._crypto_scalarmult = A6.Jc, g2._crypto_scalarmult_bytes = A6.Kc, g2._crypto_scalarmult_scalarbytes = A6.Lc, g2._crypto_secretbox_keybytes = A6.Mc, g2._crypto_secretbox_noncebytes = A6.Nc, g2._crypto_secretbox_macbytes = A6.Oc, g2._crypto_secretbox_messagebytes_max = A6.Pc, g2._crypto_secretbox_keygen = A6.Qc, g2._crypto_secretbox_detached = A6.Rc, g2._crypto_secretbox_easy = A6.Sc, g2._crypto_secretbox_open_detached = A6.Tc, g2._crypto_secretbox_open_easy = A6.Uc, g2._crypto_secretstream_xchacha20poly1305_keygen = A6.Vc, g2._crypto_secretstream_xchacha20poly1305_init_push = A6.Wc, g2._crypto_secretstream_xchacha20poly1305_init_pull = A6.Xc, g2._crypto_secretstream_xchacha20poly1305_rekey = A6.Yc, g2._crypto_secretstream_xchacha20poly1305_push = A6.Zc, g2._crypto_secretstream_xchacha20poly1305_pull = A6._c, g2._crypto_secretstream_xchacha20poly1305_statebytes = A6.$c, g2._crypto_secretstream_xchacha20poly1305_abytes = A6.ad, g2._crypto_secretstream_xchacha20poly1305_headerbytes = A6.bd, g2._crypto_secretstream_xchacha20poly1305_keybytes = A6.cd, g2._crypto_secretstream_xchacha20poly1305_messagebytes_max = A6.dd, g2._crypto_secretstream_xchacha20poly1305_tag_message = A6.ed, g2._crypto_secretstream_xchacha20poly1305_tag_push = A6.fd, g2._crypto_secretstream_xchacha20poly1305_tag_rekey = A6.gd, g2._crypto_secretstream_xchacha20poly1305_tag_final = A6.hd, g2._crypto_shorthash_bytes = A6.id, g2._crypto_shorthash_keybytes = A6.jd, g2._crypto_shorthash = A6.kd, g2._crypto_shorthash_keygen = A6.ld, g2._crypto_sign_statebytes = A6.md, g2._crypto_sign_bytes = A6.nd, g2._crypto_sign_seedbytes = A6.od, g2._crypto_sign_publickeybytes = A6.pd, g2._crypto_sign_secretkeybytes = A6.qd, g2._crypto_sign_messagebytes_max = A6.rd, g2._crypto_sign_seed_keypair = A6.sd, g2._crypto_sign_keypair = A6.td, g2._crypto_sign = A6.ud, g2._crypto_sign_open = A6.vd, g2._crypto_sign_detached = A6.wd, g2._crypto_sign_verify_detached = A6.xd, g2._crypto_sign_init = A6.yd, g2._crypto_sign_update = A6.zd, g2._crypto_sign_final_create = A6.Ad, g2._crypto_sign_final_verify = A6.Bd, g2._crypto_sign_ed25519_pk_to_curve25519 = A6.Cd, g2._crypto_sign_ed25519_sk_to_curve25519 = A6.Dd, g2._crypto_xof_shake128_blockbytes = A6.Ed, g2._crypto_xof_shake128_statebytes = A6.Fd, g2._crypto_xof_shake128_domain_standard = A6.Gd, g2._crypto_xof_shake128 = A6.Hd, g2._crypto_xof_shake128_init = A6.Id, g2._crypto_xof_shake128_init_with_domain = A6.Jd, g2._crypto_xof_shake128_update = A6.Kd, g2._crypto_xof_shake128_squeeze = A6.Ld, g2._crypto_xof_shake256_blockbytes = A6.Md, g2._crypto_xof_shake256_statebytes = A6.Nd, g2._crypto_xof_shake256_domain_standard = A6.Od, g2._crypto_xof_shake256 = A6.Pd, g2._crypto_xof_shake256_init = A6.Qd, g2._crypto_xof_shake256_init_with_domain = A6.Rd, g2._crypto_xof_shake256_update = A6.Sd, g2._crypto_xof_shake256_squeeze = A6.Td, g2._crypto_xof_turboshake128_blockbytes = A6.Ud, g2._crypto_xof_turboshake128_statebytes = A6.Vd, g2._crypto_xof_turboshake128_domain_standard = A6.Wd, g2._crypto_xof_turboshake128 = A6.Xd, g2._crypto_xof_turboshake128_init = A6.Yd, g2._crypto_xof_turboshake128_init_with_domain = A6.Zd, g2._crypto_xof_turboshake128_update = A6._d, g2._crypto_xof_turboshake128_squeeze = A6.$d, g2._crypto_xof_turboshake256_blockbytes = A6.ae, g2._crypto_xof_turboshake256_statebytes = A6.be, g2._crypto_xof_turboshake256_domain_standard = A6.ce, g2._crypto_xof_turboshake256 = A6.de, g2._crypto_xof_turboshake256_init = A6.ee, g2._crypto_xof_turboshake256_init_with_domain = A6.fe, g2._crypto_xof_turboshake256_update = A6.ge, g2._crypto_xof_turboshake256_squeeze = A6.he, g2._randombytes_random = A6.ie, g2._randombytes_stir = A6.je, g2._randombytes_uniform = A6.ke, g2._randombytes_buf = A6.le, g2._randombytes_buf_deterministic = A6.me, g2._randombytes_seedbytes = A6.ne, g2._randombytes_close = A6.oe, g2._randombytes = A6.pe, g2._sodium_bin2hex = A6.qe, g2._sodium_hex2bin = A6.re, g2._sodium_base64_encoded_len = A6.se, g2._sodium_bin2base64 = A6.te, g2._sodium_base642bin = A6.ue, g2._sodium_ip2bin = A6.ve, g2._sodium_bin2ip = A6.we, g2._sodium_init = A6.xe, g2._sodium_pad = A6.ye, g2._sodium_unpad = A6.ze, g2._sodium_version_string = A6.Ae, g2._sodium_library_version_major = A6.Be, g2._sodium_library_version_minor = A6.Ce, g2._sodium_library_minimal = A6.De, g2._malloc = A6.Ee, g2._free = A6.Fe, A6.dynCall_iiiji, A6.dynCall_iiij, A6.dynCall_iijii, A6.dynCall_iiijiji, A6.dynCall_iiijiii, d2 = A6.e, A6.__indirect_function_table;
      })(O2 = A5.exports), J2(), O2;
    }
    var C3 = { a: e };
    return g2.instantiateWasm ? new Promise((I3, B3) => {
      g2.instantiateWasm(C3, (g3, C4) => {
        I3(A4(g3));
      });
    }) : (F2 ??= ((A5) => {
      for (var I3, g3, C4 = 0, B3 = 0, Q3 = 295748, E3 = new Uint8Array(221811 - ("=" == A5[295746]) - ("=" == A5[295747])); C4 < Q3; C4 += 4, B3 += 3) I3 = n2[A5.charCodeAt(C4 + 1)], g3 = n2[A5.charCodeAt(C4 + 2)], E3[B3] = n2[A5.charCodeAt(C4)] << 2 | I3 >> 4, E3[B3 + 1] = I3 << 4 | g3 >> 2, E3[B3 + 2] = g3 << 6 | n2[A5.charCodeAt(C4 + 3)];
      return E3;
    })("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IgMgATQCGCIGfnwgAigCCCIsrCINIAE0AhAiB358IAIoAgwiLawiECABKAIMIi5BAXSsIhV+fCACKAIQIi+sIhEgATQCCCIIfnwgAigCFCIwrCIWIAEoAgQiMUEBdKwiF358IAIoAhgiMqwiICABNAIAIgl+fCACKAIcIjNBE2ysIgwgASgCJCI0QQF0rCIYfnwgAigCICI1QRNsrCIEIAE0AiAiCn58IAIoAiQiAkETbKwiBSABKAIcIgFBAXSsIhl+fCAHIAt+IAMgK6wiGn58IA0gLqwiG358IAggEH58IBEgMawiHH58IAkgFn58IDJBE2ysIg4gNKwiHX58IAogDH58IAQgAawiHn58IAUgBn58IAsgFX4gAyAHfnwgCCANfnwgECAXfnwgCSARfnwgMEETbKwiHyAYfnwgCiAOfnwgDCAZfnwgBCAGfnwgBSAUfnwiIkKAgIAQfCIjQhqHfCIkQoCAgAh8IiVCGYd8IhIgEkKAgIAQfCITQoCAgOAPg30+AhggACALIBd+IAMgCH58IAkgDX58IC1BE2ysIg8gGH58IAogL0ETbKwiEn58IBkgH358IAYgDn58IAwgFH58IAQgB358IAUgFX58IAkgC34gAyAcfnwgLEETbKwiISAdfnwgCiAPfnwgEiAefnwgBiAffnwgDiAafnwgByAMfnwgBCAbfnwgBSAIfnwgKkETbKwgGH4gAyAJfnwgCiAhfnwgDyAZfnwgBiASfnwgFCAffnwgByAOfnwgDCAVfnwgBCAIfnwgBSAXfnwiIUKAgIAQfCImQhqHfCInQoCAgAh8IihCGYd8Ig8gD0KAgIAQfCIpQoCAgOAPg30+AgggACAGIAt+IAMgHn58IA0gGn58IAcgEH58IBEgG358IAggFn58IBwgIH58IAkgM6wiD358IAQgHX58IAUgCn58IBNCGod8IhMgE0KAgIAIfCITQoCAgPAPg30+AhwgACAIIAt+IAMgG358IA0gHH58IAkgEH58IBIgHX58IAogH358IA4gHn58IAYgDH58IAQgGn58IAUgB358IClCGod8IgQgBEKAgIAIfCIEQoCAgPAPg30+AgwgACALIBl+IAMgCn58IAYgDX58IBAgFH58IAcgEX58IBUgFn58IAggIH58IA8gF358IAkgNawiDH58IAUgGH58IBNCGYd8IgUg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IAZSDQALCyAAIAsgDCAMQYAFaiINEDsgASAFp2ohASACIAV9IgJC/wBWBEADQCAAIAEgDCANEDsgAUGAAWohASACQoABfSICQv8AVg0ACwsCQCACUA0AIAJCA4MhBEIAIQdCACEDIAJCBFoEQCACQvwAgyEFQgAhAgNAIAsgA6ciAGogACABai0AADoAACALIABBAXIiDWogASANai0AADoAACALIABBAnIiDWogASANai0AADoAACALIABBA3IiAGogACABai0AADoAACADQgR8IQMgAkIEfCICIAVSDQALIARQDQELA0AgCyADpyIAaiAAIAFqLQAAOgAAIANCAXwhAyAHQgF8IgcgBFINAAsLIAxBwAUQBwwBCyACQgODIQVCACEDIAJCBFoEQCACQnyDIQIDQCALIAMgBHynaiABIAOnai0AADoAACALIANCAYQiBiAEfKdqIAEgBqdqLQAAOgAAIAsgA0IChCIGIAR8p2ogASAGp2otAAA6AAAgCyADQgOEIgYgBHynaiABIAanai0AADoAACADQgR8IQMgCUIEfCIJIAJSDQALIAVQDQELA0AgCyADIAR8p2ogASADp2otAAA6AAAgA0IBfCEDIAdCAXwiByAFUg0ACwsgDEHABWokAEEAC6UFAQN/IwBBsAFrIgIkACACIAEoAAA2AgBBBCEDIAIgASgABDYCBCACIAEoAAg2AgggAiABKAAMIgE2AgwDQCACIANBAnRqIgQgA0EDcQR/IAEFIANBAnZB8IgCai0AACABQRh3IgFBCHZB/wFxQYCrAmotAABBCHQgAUH/AXFBgKsCai0AAHIgAUEQdkH/AXFBgKsCai0AAEEQdHIgAUEYdkGAqwJqLQAAQRh0cnMLIARBEGsoAgBzIgE2AgAgA0EBaiIDQSxHDQALIAAgAigCADYCACAAIAIoAgQ2AgQgACACKAIINgIIIAAgAigCDDYCDCAAIAIoAhA2AhAgACACKAIUNgIUIAAgAigCGDYCGCAAIAIoAhw2AhwgACACKAIgNgIgIAAgAigCJDYCJCAAIAIoAig2AiggACACKAIsNgIsIAAgAigCMDYCMCAAIAIoAjQ2AjQgACACKAI4NgI4IAAgAigCPDYCPCAAQUBrIAIoAkA2AgAgACACKAJENgJEIAAgAigCSDYCSCAAIAIoAkw2AkwgACACKAJQNgJQIAAgAigCVDYCVCAAIAIoAlg2AlggACACKAJcNgJcIAAgAigCYDYCYCAAIAIoAmQ2AmQgACACKAJoNgJoIAAgAigCbDYCbCAAIAIoAnA2AnAgACACKAJ0NgJ0IAAgAigCeDYCeCAAIAIoAnw2AnwgACACKAKAATYCgAEgACACKAKEATYChAEgACACKAKIATYCiAEgACACKAKMATYCjAEgACACKAKQATYCkAEgACACKAKUATYClAEgACACKAKYATYCmAEgACACKAKcATYCnAEgACACKAKgATYCoAEgACACKAKkATYCpAEgACACKAKoATYCqAEgACACKAKsATYCrAEgAkGwAWokAAufBAETfyABKAIoIQIgASgCBCEDIAEoAiwhBCABKAIIIQUgASgCMCEGIAEoAgwhByABKAI0IQggASgCECEJIAEoAjghCiABKAIUIQsgASgCPCEMIAEoAhghDSABQUBrIg4oAgAhDyABKAIcIRAgASgCRCERIAEoAiAhEiABKAJIIRMgASgCACEUIAAgASgCJCABKAJMajYCJCAAIBIgE2o2AiAgACAQIBFqNgIcIAAgDSAPajYCGCAAIAsgDGo2AhQgACAJIApqNgIQIAAgByAIajYCDCAAIAUgBmo2AgggACADIARqNgIEIAAgAiAUajYCACABKAIoIQIgASgCBCEDIAEoAiwhBCABKAIIIQUgASgCMCEGIAEoAgwhByABKAI0IQggASgCECEJIAEoAjghCiABKAIUIQsgASgCPCEMIAEoAhghDSAOKAIAIQ4gASgCHCEPIAEoAkQhECABKAIgIREgASgCSCESIAEoAgAhEyAAIAEoAkwgASgCJGs2AkwgACASIBFrNgJIIAAgECAPazYCRCAAQUBrIA4gDWs2AgAgACAMIAtrNgI8IAAgCiAJazYCOCAAIAggB2s2AjQgACAGIAVrNgIwIAAgBCADazYCLCAAIAIgE2s2AiggACABKQJQNwJQIAAgASkCWDcCWCAAIAEpAmA3AmAgACABKQJoNwJoIAAgASkCcDcCcCAAQfgAaiABQfgAakGgCxAGC/AJAR5/IAEoAighAyABKAIEIQQgASgCLCEFIAEoAgghBiABKAIwIQcgASgCDCEIIAEoAjQhCSABKAIQIQogASgCOCELIAEoAhQhDCABKAI8IQ0gASgCGCEOIAFBQGsiDygCACEQIAEoAhwhESABKAJEIRIgASgCICETIAEoAkghFCABKAIAIRUgACABKAIkIAEoAkxqNgIkIAAgEyAUajYCICAAIBEgEmo2AhwgACAOIBBqNgIYIAAgDCANajYCFCAAIAogC2o2AhAgACAIIAlqNgIMIAAgBiAHajYCCCAAIAQgBWo2AgQgACADIBVqNgIAIAEoAighBSABKAIEIQMgASgCLCEGIAEoAgghByABKAIwIQggASgCDCEJIAEoAjQhCiABKAIQIQsgASgCOCEMIAEoAhQhDSABKAI8IQ4gASgCGCEQIA8oAgAhDyABKAIcIQQgASgCRCERIAEoAiAhEiABKAJIIRMgASgCACEUIAAgASgCTCABKAIkazYCTCAAIBMgEms2AkggACARIARrNgJEIABBQGsiBCAPIBBrNgIAIAAgDiANazYCPCAAIAwgC2s2AjggACAKIAlrNgI0IAAgCCAHazYCMCAAIAYgA2s2AiwgAEEoaiIDIAUgFGs2AgAgAEHQAGogACACEAYgAyADIAJBKGoQBiAAQfgAaiACQfgAaiABQfgAahAGIAAgAUHQAGogAkHQAGoQBiAAKAIEIRUgACgCCCEWIAAoAgwhFyAAKAIQIRggACgCFCEZIAAoAhghGiAAKAIcIRsgACgCICEcIAAoAiQhHSADKAIAIQEgACgCUCECIAAoAiwhBSAAKAJUIQYgACgCMCEHIAAoAlghCCAAKAI0IQkgACgCXCEKIAAoAjghCyAAKAJgIQwgACgCPCENIAAoAmQhDiAEKAIAIQ8gACgCaCEQIAAoAkQhESAAKAJsIRIgACgCSCETIAAoAnAhFCAAKAIAIR4gACAAKAJMIh8gACgCdCIgajYCTCAAIBMgFGo2AkggACARIBJqNgJEIAQgDyAQajYCACAAIA0gDmo2AjwgACALIAxqNgI4IAAgCSAKajYCNCAAIAcgCGo2AjAgACAFIAZqNgIsIAMgASACajYCACAAICAgH2s2AiQgACAUIBNrNgIgIAAgEiARazYCHCAAIBAgD2s2AhggACAOIA1rNgIUIAAgDCALazYCECAAIAogCWs2AgwgACAIIAdrNgIIIAAgBiAFazYCBCAAIAIgAWs2AgAgACAdQQF0IgEgACgCnAEiAms2ApwBIAAgHEEBdCIDIAAoApgB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QQA2AuABIABBADoA7AFBfwVBAAsgBQRAIAAoAuABIQMDQCAAKALkASIEIANGBEAgABAOIABBADYC4AEgACgC5AEhBEEAIQMLIAAgASAGaiADIAQgA2siAyAFIAZrIgQgAyAESRsiBBANIAAgACgC4AEgBGoiAzYC4AEgBCAGaiIGIAVJDQALCwvoAQIGfwJ+An8gAkIAUgRAIABB4AFqIQggAEHgAGohBCAAKADgAiEFIABBQGshBgNAIAQgBWohB0GAAiAFayIDrSIJIAJaBEAgAqciAwRAIAcgASAD/AoAAAsgACAAKADgAiADajYA4AJBAAwDCyADBEAgByABIAP8CgAACyAAIAAoAOACIANqNgDgAiAGIAYpAAAiCkKAAXw3AAAgACAAKQBIIApC/35WrXw3AEggACAEEDwgBCAIQYAB/AoAACAAIAAoAOACQYABayIFNgDgAiABIANqIQEgAiAJfSICQgBSDQALC0EACwvoBAEJfyAAIAEoAiAiBSABKAIcIgYgASgCGCIHIAEoAhQiCCABKAIQIgkgASgCDCIKIAEoAggiBCABKAIEIgMgASgCACICIAEoAiQiAUETbEGAgIAIakEZdmpBGnVqQRl1akEadWpBGXVqQRp1akEZdWpBGnVqQRl1akEadSABakEZdUETbCACaiICOgAAIAAgAkEQdjoAAiAAIAJBCHY6AAEgACADIAJBGnVqIgNBDnY6AAUgACADQQZ2OgAEIAAgAkEYdkEDcSADQQJ0cjoAAyAAIAQgA0EZdWoiAkENdjoACCAAIAJBBXY6AAcgACACQQN0IANBgICADnFBFnZyOgAGIAAgCiACQRp1aiIEQQt2OgALIAAgBEEDdjoACiAAIARBBXQgAkGAgIAfcUEVdnI6AAkgACAJIARBGXVqIgJBEnY6AA8gACACQQp2OgAOIAAgAkECdjoADSAAIAggAkEadWoiAzoAECAAIAJBBnQgBEGAgOAPcUETdnI6AAwgACADQRB2OgASIAAgA0EIdjoAESAAIAcgA0EZdWoiAkEPdjoAFSAAIAJBB3Y6ABQgACADQRh2QQFxIAJBAXRyOgATIAAgBiACQRp1aiIDQQ12OgAYIAAgA0EFdjoAFyAAIANBA3QgAkGAgIAccUEXdnI6ABYgACAFIANBGXVqIgJBDHY6ABsgACACQQR2OgAa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LQAAczoAACADQQRqIQMgCEEEaiIIIAJHDQALIAdFDQELA0AgBEFAayADaiIAIAAtAAAgASADai0AAHM6AAAgA0EBaiEDIApBAWoiCiAHRw0ACwsgCSAEQUBrIgBCgAEQEBogAEGAARAHIARBwAAQByAEQcABaiQAQQAPCxAKAAuVAQEBfyMAQdABayIDJAAgA0IANwNIIANCADcDQCADQZCtAikDADcDACADQZitAikDADcDCCADQaCtAikDADcDECADQaitAikDADcDGCADQbCtAikDADcDICADQbitAikDADcDKCADQcCtAikDADcDMCADQcitAikDADcDOCADIAEgAhAQGiADIAAQHCADQdABaiQAQQALVwIBfwF+AkBBsLkCKAIAIgGtIACtQgd8Qvj///8fg3wiAkL/////D1gEQCACpyIAPwBBEHRNDQEgABADDQELQdDAAkEwNgIAQX8PC0GwuQIgADYCACABCzoBAn8jAEEgayIDJABBfyEEIAMgAiABEClFBEAgAEGguQIgAxBfIANBIBAHQQAhBAsgA0EgaiQAIAQLBABBbwuiAwIDfwF+IwBB4AJrIgYkACAGIAQgBRBfAn8CQAJAIAAgAksgAyAAIAJrrVZxRQRAIAAgAk8NASADIAIgAGutWA0BCyADpyIFBEAgACACIAX8CgAACyAGQgA3AzggBkIANwMwIAZCADcDKCAGQgA3AyBCICADIANCIFobIQkgA0IgViEFIAAhAgwBCyAGQgA3AzggBkIANwMwIAZCADcDKCAGQgA3AyBCICADIANCIFobIQkgA0IgViEFIANCAFINAEEBDAELIAmnIgcEQCAGQUBrIAIgB/wKAAALQQALIQggBkEgaiIHIAcgCUIgfCAEQRBqIgRCACAGQdS5AigCABEPABogBkHgAGogB0G8uQIoAgARAQAaAkAgCA0AIAmnIgdFDQAgACAGQUBrIAf8CgAACyAGQSBqQcAAEAcgBQRAIAAgCaciBWogAiAFaiADIAl9IARCASAGQdS5AigCABEPABoLIAZBIBAHIAZB4ABqIgIgACADQcC5AigCABEAABogAiABQcS5AigCABEBABogAkGAAhAHIAZB4AJqJABBAAuHGAEOf0H/ACECA0AgACABQQF0aiIDIAMuAQQiBCADLgEAIgZqIgXBQb+dAWxBGnVB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IAEgA6dqLQAAOgAAIANCAXwhAyAHQgF8IgcgBlINAAsLIAAgCyAMIAxBgAJqIg0QTyABIAWnaiEBIAIgBX0iAkI/VgRAA0AgACABIAwgDRBPIAFBQGshASACQkB8IgJCP1YNAAsLAkAgAlANACACQgODIQRCACEHQgAhAyACQgRaBEAgAkI8gyEFQgAhAgNAIAsgA6ciAGogACABai0AADoAACALIABBAXIiDWogASANai0AADoAACALIABBAnIiDWogASANai0AADoAACALIABBA3IiAGogACABai0AADoAACADQgR8IQMgAkIEfCICIAVSDQALIARQDQELA0AgCyADpyIAaiAAIAFqLQAAOgAAIANCAXwhAyAHQgF8IgcgBFINAAsLIAxBoAIQBwwBCyACQgODIQVCACEDIAJCBFoEQCACQnyDIQIDQCALIAMgBHynaiABIAOnai0AADoAACALIANCAYQiBiAEfKdqIAEgBqdqLQAAOgAAIAsgA0IChCIGIAR8p2ogASAGp2otAAA6AAAgCyADQgOEIgYgBHynaiABIAanai0AADoAACADQgR8IQMgCUIEfCIJIAJSDQALIAVQDQELA0AgCyADIAR8p2ogASADp2otAAA6AAAgA0IBfCEDIAdCAXwiByAFUg0ACwsgDEGgAmokAAsEAEEYC+kDAQJ/QX8hBQJAIAJBwABLDQAgA0HBAGsiBEFASQ0AAkAgAUEAIAIbRQRAIARB/wFxQb8BTQRAEAoACyAAQUBrQQBBpQL8CwAgAEL5wvibkaOz8NsANwA4IABC6/qG2r+19sEfNwAwIABCn9j52cKR2oKbfzcAKCAAQtGFmu/6z5SH0QA3ACAgAELx7fT4paf9p6V/NwAYIABCq/DT9K/uvLc8NwAQIABCu86qptjQ67O7fzcACCAAIAOtQoiS95X/zPmE6gCFNwAADAELAn8jAEGAAWsiBCQAAkAgA0HBAGtB/wFxQb8BTQ0AIAFFDQAgAkHBAGtB/wFxQb8BTQ0AIABBQGtBAEGlAvwLACAAQvnC+JuRo7Pw2wA3ADggAELr+obav7X2wR83ADAgAEKf2PnZwpHagpt/NwAoIABC0YWa7/rPlIfRADcAICAAQvHt9Pilp/2npX83ABggAEKr8NP0r+68tzw3ABAgAEK7zqqm2NDrs7t/NwAIIAAgA60g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GiABKAAUIRsgASgAGCEcIAEoABwhLCABKAAgIS0gASgAJCEuIAEoACghLyABKAAsITAgASgAMCExIAEoADQhMiABKAA4ITMgASgAPCE0IAUgASgAACAIICpqczYAACAFIDQgECAdanM2ADwgBSAzIBcgHmpzNgA4IAUgMiASIBhqczYANCAFIDEgDSATanM2ADAgBSAwIBEgH2pzNgAsIAUgLyAMICBqczYAKCAFIC4gDyAhanM2ACQgBSAtIAsgImpzNgAgIAUgLCAHICNqczYAHCAFIBwgBiAkanM2ABggBSAbIAIgJWpzNgAUIAUgGiAEICZqczYAECAFIBkgFCAnanM2AAwgBSAVIA4gKGpzNgAIIAUgFiAKIClqczYABCASIBNBAWoiE0VqIRIgA0LAAFgEQCADQj9YBEAgA6chAUEAIQQDQCAEICtqIAQgBWotAAA6AAAgBEEBaiIEIAFJDQALCyAAIBI2AjQgACATNgIwBSABQUBrIQEgBUFAayECIANCQHwhAwwBCwsLCAAgAEEQEBUL0QYBCn8jAEGgAmsiAiQAIAAoABwhBCAAKAAYIQUgACgAFCEGIAAoABAhByAAKAAEIQggACgACCEJIAAoAAwhCiAAKAAAIQsgAiABKQJ4NwOYAiACIAEpAnA3A5ACIAIgASkCYDcD8AEgAiABKQJoNwP4ASACIAEpAnA3A+ABIAIgASkCeDcD6AEgAkGAAmoiAyACQfABaiACQeABahAFIAEgAikCiAI3AnggASACKQKAAjcCcCACIAEpAlA3A9ABIAIgASkCWDcD2AEgAiABKQJgNwPAASACIAEpAmg3A8gBIAMgAkHQAWogAkHAAWoQBSABIAIpAogCNwJoIAEgAikCgAI3AmAgAiABQUBrIgApAgA3A7ABIAIgASkCSDcDuAEgAiABKQJQNwOgASACIAEpAlg3A6gBIAMgAkGwAWogAkGgAWoQBSABIAIpAogCNwJYIAEgAikCgAI3AlAgAiABKQIwNwOQASACIAEpAjg3A5gBIAIgACkCADcDgAEgAiABKQJINwOIASADIAJBkAFqIAJBgAFqEAUgASACKQKIAjcCSCAAIAIpAoACNwIAIAIgASkCIDcDcCACIAEpAig3A3ggAiABKQIwNwNgIAIgASkCODcDaCADIAJB8ABqIAJB4ABqEAUgASAC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IiAKIAUgBBAGIAJBkANqIgEgByADEAYgAkG4A2oiBiADIAQQBiAFIAoQIiAKIAUgBBAGIAEgByADEAYgBiADIAQQBiAFIAoQIiAKIAUgBBAGIAEgByADEAYgBiADIAQQBiAFIAoQIiAAIAUgBBAGIAggByADEAYgCSADIAQQBiALIAUgBxAGQQAhAQNAIAJBCGoiBiABQQF2IAJBoAJqIAFqLAAAEHYgAkGAAWoiBSAAIAYQWSAAIAUgBBAGIAggByADEAYgCSADIAQQBiALIAUgBxAGIAFBPkkgAUECaiEBDQALIAJB4ANqJAALYgEDfyMAQbABayICJAAgAkHgAGoiAyABQdAAahBEIAJBMGoiBCABIAMQBiACIAFBKGogAxAGIAAgAhAaIAJBkAFqIAQQGiAAIAAtAB8gAi0AkAFBB3RzOgAfIAJBsAFqJAALyggBA38jAEHAAWsiAiQAIAJBkAFqIgQgARAEIAJB4ABqIgMgBBAEIAMgAxAEIAMgASADEAYgBCAEIAMQBiACQTBqIgEgBBAEIAMgAyABEAYgASADEAQgASABEAQgASABEAQgASABEAQgASABEAQgAyABIAMQBiABIAMQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEgAxAGIAIgARAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAEgAiABEAYgASABEAQgASABEAQgASABEAQgASABEAQgASABEAQgASABEAQgASABEAQgASABEAQgASABEAQgASABEAQgAyABIAMQBiABIAMQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEQBCABIAEgAxAGIAIgARAEQQEhAQNAIAIgAhAEIAFBAWoiAUHkAEcNAAsgAkEwaiIBIAIgARAGIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAEgARAEIAJB4ABqIgMgASADEAYgAyADEAQgAyADEAQgAyADEAQgAyADEAQgAyADEAQgACADIAJBkAFqEAYgAkHAAWokAAv8AgIDfwF+IwBB4ABrIgYkACAGIAQgBRBfIAZBIGoiBUIgIARBEGoiBCAGQdC5AigCABERABoCfyACIAEgAyAFQbi5AigCABEWAARAIAZBIBAHQX8MAQsCQCAARQRAIAZBIBAHIAZBIGpBwAAQBwwBCwJAAkACQAJAIAAgAUkgAyABIABrrVZxRQRAIAAgAU0NASADIAAgAWutWA0BCyADpyICBEAgACABIAL8CgAACyAAIQEMAQsgA1ANAQsgBkFAayEFQiAgAyADQiBaGyIJpyICRSIHRQRAIAUgASAC/AoAAAsgBkEgaiIIIAggCUIgfCAEQgAgBkHUuQIoAgARDwAaIAdFBEAgACAFIAL8CgAACyAGQSBqQcAAEAcgA0IhVA0BIAAgAmogASACaiADIAl9IARCASAGQdS5AigCABEPABoMAQsgBkEgaiIAIABCICAEQgAgBkHUuQIoAgARDwAaIABBwAAQBwsg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BEAgAxAOIANBADYC4AEgAygC5AEhBEEAIQULIAMgASAGaiAFIAQgBWsiBSAHIAZrIgQgBCAFSxsiBBANIAMgAygC4AEgBGoiBTYC4AEgBCAGaiIGIAdJDQALCyADIAAQNhogA0GAAhAHIANBgAJqJABBAAuxAQEBfyMAQRBrIgIgADYCDCACIAE2AghBACEAIAJBADsBBgNAIAIgAi8BBiACKAIMIABqLQAAIAIoAgggAGotAABzcjsBBiACIAIvAQYgAEEBciIBIAIoAgxqLQAAIAIoAgggAWotAABzcjsBBiAAQQJqIgBBIEcNAAsgAiACLwEGOwEGIAIgAi8BBkEBazsBBiACQeDEAi8BAEECdiACLwEGQQ92czsBBiACLwEGQQFrCzQBAX8jAEEgayICJAAgACACEGUgAEHoAGoiACACQiAQNyAAIAEQZSACQSAQByACQSBqJAAL4gcBCX8jAEHgAGsiAyQAAkACQCACQcEATwRAIABCADcDICAAQeCzAikDADcDACAAQeizAikDADcDCCAAQfCzAikDADcDECAAQfizAikDADcDGCAAIAEgAq0QNyAAIAMQZUEgIQIgAyEBDAELIAENACACDQELIABCADcDICAAQeCzAikDADcDACAAQeizAikDADcDCCAAQfCzAikDADcDECAAQfizAikDADcDGCADQrbs2LHjxo2bNjcDWCADQrbs2LHjxo2bNjcDUCADQrbs2LHjxo2bNjcDSCADQrbs2LHjxo2bNjcDQCADQrbs2LHjxo2bNjcDOCADQrbs2LHjxo2bNjcDMCADQrbs2LHjxo2bNjcDKCADQrbs2LHjxo2bNjcDIAJAIAJFDQAgAkEDcSEJIAJBBE8EQCACQfwAcSEGA0AgA0EgaiIHIARqIgUgBS0AACABIARqLQAAczoAACAHIARBAXIiBWoiCyALLQAAIAEgBWotAABzOgAAIAcgBEECciIFaiILIAstAAAgASAFai0AAHM6AAAgByAEQQNyIgVqIgcgBy0AACABIAVqLQAAczoAACAEQQRqIQQgCEEEaiIIIAZHDQALIAlFDQELA0AgA0EgaiAEaiIIIAgtAAAgASAEai0AAHM6AAAgBEEBaiEEIApBAWoiCiAJRw0ACwsgACADQSBqQsAAEDcgAEHoAGoiCSIAQgA3AyAgAEHgswIpAwA3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EAghAyAAIAAoAmwQCDYCbCAAIAM2AmggACACNgJkIAAgATYCYCAAKAJwEAghASAAKAJ0EAghAiAAKAJ4EAghAyAAIAAoAnwQCDYCfCAAIAM2AnggACACNgJ0IAAgATYCcCAAKAKAARAIIQEgACgChAEQCCECIAAoAogBEAghAyAAIAAoAowBEAg2AowBIAAgAzYCiAEgACACNgKEASAAIAE2AoABIAAoApABEAghASAAKAKUARAIIQIgACgCmAEQCCEDIAAgACgCnAEQCDYCnAEgACADNgKYASAAIAI2ApQBIAAgATYCkAEL9xICFX4DfyAAIAAoACwiFkEFdkH///8Aca0gACgAPEEDdq0iAkKDoVZ+IAAzACogADEALEIQhkKAgPwAg4R8IgtCgIBAfSIIQhWHfCIBQoOhVn4gADUAMUIHiEL///8AgyIDQtOMQ34gACgAFyIXQRh2rSAAMQAbQgiGhCAAMQAcQhCGhEICiEL///8Ag3wgACgANCIYQQR2Qf///wBxrSIEQuf2J358IBZBGHatIAAxADBCCIaEIAAxADFCEIaEQgKIQv///wCDIgVC0asIfnwgADUAOUIGiEL///8AgyIGQpPYKH58IBhBGHatIAAxADhCCIaEIAAxADlCEIaEQgGIQv///wCDIglCmNocfnwiB3wgB0KAgEB9IhFCgICAf4N9IBdBBXZB////AHGtIANC5/YnfnwgBEKY2hx+fCAFQtOMQ358IAlCk9gofnwgA0KY2hx+IAAzABUgADEAF0IQhkKAgPwAg4R8IARCk9gofnwgBULn9id+fCIHQoCAQH0iCkIViHwiDEKAgEB9Ig1CFYd8Ig8gD0KAgEB9Ig9CgICAf4N9IAwgAULRqwh+fCANQoCAgH+DfSALIAhCgICAf4N9IAJC0asIfiAAKAAkIhZBGHatIAAxAChCCIaEIAAxAClCEIaEQgOIfCAGQoOhVn58IBZBBnZB////AHGtIAJC04xDfnwgBkLRqwh+fCAJQoOhVn58IgxCgIBAfSINQhWHfCIIQoCAQH0iDkIVh3wiC0KDoVZ+fCAHIApCgICA////A4N9IANCk9gofiAAKAAPIhZBGHatIAAxABNCCIaEIAAxABRCEIaEQgOIfCAFQpjaHH58IBZBBnZB////AHGtIAVCk9gofnwiCkKAgEB9IhJCFYh8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IAAoAgQiGq0hCSAaQQVsrSEQIBlBBWytIQ4gGEEFbK0hDCAXQQVsrSEKIAA1AgAhCANAIAEoAANBAnZB////H3EgFWqtIgMgDX4gASgAAEH///8fcSARaq0iBCAPfnwgASgABkEEdkH///8fcSAUaq0iBSALfnwgASgACUEGdiATaq0iBiAJfnwgEiAWaiABKAAMQQh2aq0iByAIfnwgAyALfiAEIA1+fCAFIAl+fCAGIAh+fCAHIAp+fCADIAl+IAQgC358IAUgCH58IAYgCn58IAcgDH58IAMgCH4gBCAJfnwgBSAKfnwgBiAMfnwgByAOfnwgAyAKfiAEIAh+fCAFIAx+fCAGIA5+fCAHIBB+fCIDQhqIQv////8Pg3wiBEIaiEL/////D4N8IgVCGohC/////w+DfCIGQhqIQv////8Pg3wiB0IaiKdBBWwgA6dB////H3FqIhFBGnYgBKdB////H3FqIRUgBadB////H3EhFCAGp0H///8fcSETIAenQf///x9xIRIgEUH///8fcSERIAFBEGohASACQhB9IgJCD1YNAAsgACASNgIkIAAgEzYCICAAIBQ2AhwgACAVNgIYIAAgETYCFAvvJgEnfyMAQdAEayIdJABBfyENIABBIGohCEEgIQpBASEFA0AgCkEBayIJQfAUai0AACIHIAggCWotAAAiCXNBAWtBCHUgBXEiBiAIIApBAmsiCmotAAAiDCAKQfAUai0AACIOa0EIdXEgCSAHa0EIdSAFcSALcnIhCyAMIA5zQQFrQQh1IAZxIQUgCg0ACwJAIAtFDQAgABBYDQAgAy0AH0F/c0H/AHEgAy0AASADLQACIAMtAAMgAy0ABCADLQAFIAMtAAYgAy0AByADLQAIIAMtAAkgAy0ACiADLQALIAMtAAwgAy0ADSADLQAOIAMtAA8gAy0AECADLQARIAMtABIgAy0AEyADLQAUIAMtABUgAy0AFiADLQAXIAMtABggAy0AGSADLQAaIAMtABsgAy0AHCADLQAeIAMtAB1xcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcUH/AXNyQQFrQewBIAMtAABrcUF/c0EIdkEBcUUNACADEFgNACAdQYABaiIKIAMQeQ0AIB1BgANqIgsQJSAEBEAgC0HguAJCIhAQGgsgCyAAQiAQEBogCyADQiAQ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HCAAIAcgCSAKc3M2ABggACAOIAsgDHNzNgAUIAAgASAGIAhzczYAEAwBCyABRQ0AIABBACAB/AsACyAFQeABaiQAC6UGARR/IwBB4AFrIgMkACACKAIQIQUgAkFAayIEKAIAIQkgAigCUCEKIAIoAiAhCyACKAIwIQwgASgABCEGIAIoAhQhDSACKAJEIQ4gAigCVCEPIAIoAiQhECACKAI0IREgASgACCEHIAIoAhghEiACKAJIIRMgAigCWCEUIAIoAighFSACKAI4IRYgASgAACEIIAAgASgADCIBIAIoAiwgAigCPHEgAigCHCACKAJcIAIoAkxzc3NzNgAMIAAgByAVIBZxIBIgEyAUc3NzczYACCAAIAYgECARcSANIA4gD3Nzc3M2AAQgACAIIAsgDHEgBSAJIApzc3NzNgAAIAMgAikCWDcD2AEgAyACKQJQNwPQASADIAQpAgA3A7ABIAMgAikCSDcDuAEgAyACKQJQNwOgASADIAIpAlg3A6gBIANBwAFqIgAgA0GwAWogA0GgAWoQBSACIAMpAsgBNwJYIAIgAykCwAE3AlAgAyACKQIwNwOQASADIAIpAjg3A5gBIAMgBCkCADcDgAEgAyACKQJINwOIASAAIANBkAFqIANBgAFqEAUgAiADKQLIATcCSCAEIAMpAsABNwIAIAMgAikCIDcDcCADIAIpAig3A3ggAyACKQIwNwNgIAMgAikCODcDaCAAIANB8ABqIANB4ABqEAUgAiADKQLIATcCOCACIAMpAsABNwIwIAMgAikCEDcDUCADIAIpAhg3A1ggAyACKQIgNwNAIAMgAikCKDcDSCAAIANB0ABqIANBQGsQBSACIAMpAsgBNwIoIAIgAykCwAE3AiAgAyACKQIANwMwIAMgAikCCDcDOCADIAIpAhA3AyAgAyACKQIYNwMoIAAgA0EwaiADQSBqEAUgAiADKQLIATcCGCACIAMpAsABNwIQIAMgAykD0AE3AxAgAyADKQPYATcDGCADIAIpAgA3AwAgAyACKQIINwMIIAAgA0EQaiADEAUgAygCwAEhACADKALEASEEIAMoAsgBIQUgAiABIAMoAswBczYCDCACIAUgB3M2AgggAiAEIAZzNgIEIAIgACAIczYCACADQeABaiQAC6UJAQ1/IwBBoANrIgIkACAAKAAQIQYgACgAFCEHIAAoABghCCAAKAAcIQkgACgABCEEIAAoAAghBSAAKAAMIQogACgAACELIAIgASkCWDcDmAMgAiABKQJQNwOQAyACIAFBQGsiACkCADcD8AIgAiABKQJINwP4AiACIAEpAlA3A+ACIAIgASkCWDcD6AIgAkGAA2oiAyACQfACaiACQeACahAFIAEgAikCiAM3AlggASACKQKAAzcCUCACIAEpAjA3A9ACIAIgASkCODcD2AIgAiAAKQIANwPAAiACIAEpAkg3A8gCIAMgAkHQAmogAkHAAmoQBSABIAIpAogDNwJIIAAgAikCgAM3AgAgAiABKQIgNwOwAiACIAEpAig3A7gCIAIgASkCMDcDoAIgAiABKQI4NwOoAiADIAJBsAJqIAJBoAJqEAUgASACKQKIAzcCOCABIAIpAoADNwIwIAIgASkCEDcDkAIgAiABKQIYNwOYAiACIAEpAiA3A4ACIAIgASkCKDcDiAIgAyACQZACaiACQYACahAFIAEgAikCiAM3AiggASACKQKAAzcCICACIAEpAgA3A/ABIAIgASkCCDcD+AEgAiABKQIQNwPgASACIAEpAhg3A+gBIAMgAkHwAWogAkHgAWoQBSABIAIpAogDNwIYIAEgAikCgAM3AhAgAiACKQOQAzcD0AEgAiACKQOYAzcD2AEgAiABKQIANwPAASACIAEpAgg3A8gBIAMgAkHQAWogAkHAAWoQBSACKAKAAyEMIAIoAoQDIQ0gAigCiAMhDiABIAogAigCjANzNgIMIAEgBSAOczYCCCABIAQgDXM2AgQgASALIAxzNgIAIAIgASkCWDcDmAMgAiABKQJQNwOQAyACIAApAgA3A7ABIAIgASkCSDcDuAEgAiABKQJQNwOgASACIAEpAlg3A6gBIAMgAkGwAWogAkGgAWoQBSABIAIpAogDNwJYIAEgAikCgAM3AlAgAiABKQIwNwOQASACIAEpAjg3A5gBIAIgACkCADcDgAEgAiABKQJINwOIASADIAJBkAFqIAJBgAFqEAUgASACKQKIAzcCSCAAIAIpAoADNwIAIAIgASkCIDcDcCACIAEpAig3A3ggAiABKQIwNwNgIAIgASkCODcDaCADIAJB8ABqIAJB4ABqEAUgASACKQKIAzcCOCABIAIpAoADNwIwIAIgASkCEDcDUCACIAEpAhg3A1ggAiABKQIgNwNAIAIgASkCKDcDSCADIAJB0ABqIAJBQGsQBSABIAIpAogDNwIoIAEgAikCgAM3AiAgAiABKQIANwMwIAIgASkCCDcDOCACIAEpAhA3AyAgAiABKQIYNwMoIAMgAkEwaiACQSBqEAUgASACKQKIAzcCGCABIAIpAoADNwIQIAIgAikDkAM3AxAgAiACKQOYAzcDGCACIAEpAgA3AwAgAiABKQIINwMIIAMgAkEQaiACEAUgAigCgAMhACACKAKEAyEEIAIoAogDIQUgASAJIAIoAowDczYCDCABIAUgCHM2AgggASAEIAdzNgIEIAEgACAGczYCACACQaADaiQAC94UARV/IwBBoAZrIgMkACABKAAEIQggASgACCEJIAEoAAwhCiABKAAQIQsgASgAFCEMIAEoABghDSABKAAcIQ4gACgABCEPIAAoAAghECAAKAAMIREgACgAECESIAAoABQhEyAAKAAYIRQgACgAHCEVIAEoAAAhFiACQUBrIgEgACgAACIAQYCChBBzNgIAIAJClcTcyYWy+rziADcCOCACQoCChJCwoIGEDTcCMCACQqCixJG0rq2UXTcCKCACQtv74KjVzfCXcTcCICACIAAgFnMiFjYCACACIBVB8+qi6X1zNgJcIAIgFEGgosSRBHM2AlggAiATQe2Ev4l/czYCVCACIBJB2/vgqAVzNgJQIAIgEUGQ0+eTBnM2AkwgAiAQQZXE3MkFczYCSCACIA9Bg4qg6ABzNgJEIAIgDiAVcyIONgIcIAIgDSAUcyINNgIYIAIgDCATcyIMNgIUIAIgCyAScyILNgIQIAIgCiARcyIKNgIMIAIgCSAQcyIJNgIIIAIgCCAPcyIXNgIEQQAhCANAIAMgAikCWDcDmAYgAyACKQJQNwOQBiADIAEpAgA3A/AFIAMgASkCCDcD+AUgAyACKQJQNwPgBSADIAIpAlg3A+gFIANBgAZqIgQgA0HwBWogA0HgBWoQBSACIAMpAogGNwJYIAIgAykCgAY3AlAgAyACKQIwNwPQBSADIAIpAjg3A9gFIAMgASkCADcDwAUgAyABKQIINwPIBSAEIANB0AVqIANBwAVqEAUgASADKQKIBjcCCCABIAMpAoAGNwIAIAMgAikCIDcDsAUgAyACKQIoNwO4BSADIAIpAjA3A6AFIAMgAikCODcDqAUgBCADQbAFaiADQaAFahAFIAIgAykCiAY3AjggAiADKQKABjcCMCADIAIpAhA3A5AFIAMgAikCGDcDmAUgAyACKQIgNwOABSADIAIpAig3A4gFIAQgA0GQBWogA0GABWoQBSACIAMpAogGNwIoIAIgAykCgAY3AiAgAyACKQIANwPwBCADIAIpAgg3A/gEIAMgAikCEDcD4AQgAyACKQIYNwPoBCAEIANB8ARqIANB4ARqEAUgAiADKQKIBjcCGCACIAMpAoAGNwIQIAMgAykDkAY3A9AEIAMgAykDmAY3A9gEIAMgAikCADcDwAQgAyACKQIINwPIBCAEIANB0ARqIANBwARqEAUgAygCgAYhBSADKAKEBiEGIAMoAogGIQcgAiADKAKMBiARczYCDCACIAcgEHM2AgggAiAGIA9zNgIEIAIgACAFczYCACADIAIpAlg3A5gGIAMgAikCUDcDkAYgAyABKQIANwOwBCADIAEpAgg3A7gEIAMgAikCWDcDqAQgAyACKQJQNwOgBCAEIANBsARqIANBoARqEAUgAiADKQKIBjcCWCACIAMpAoAGNwJQIAMgAikCMDcDkAQgAyACKQI4NwOYBCADIAEpAgA3A4AEIAMgASkCCDcDiAQgBCADQZAEaiADQYAEahAFIAEgAykCiAY3AgggASADKQKABjcCACADIAIpAiA3A/ADIAMgAikCKDcD+AMgAyACKQIwNwPgAyADIAIpAjg3A+gDIAQgA0HwA2ogA0HgA2oQBSACIAMpAogGNwI4IAIgAykCgAY3AjAgAyACKQIQNwPQAyADIAIpAhg3A9gDIAMgAikCIDcDwAMgAyACKQIoNwPIAyAEIANB0ANqIANBwANqEAUgAiADKQKIBjcCKCACIAMpAoAGNwIgIAMgAikCADcDsAMgAyACKQIINwO4AyADIAIpAhA3A6ADIAMgAikCGDcDqAMgBCADQbADaiADQaADahAFIAIgAykCiAY3AhggAiADKQKABjcCECADIAMpA5AGNwOQAyADIAMpA5gGNwOYAyADIAIpAgA3A4ADIAMgAikCCDcDiAMgBCADQZADaiADQYADahAFIAMoAoAGIQUgAygChAYhBiADKAKIBiEHIAIgAygCjAYgFXM2AgwgAiAHIBRzNgIIIAIgBiATczYCBCACIAUgEnM2AgAgAyACKQJYNwOYBiADIAIpAlA3A5AGIAMgASkCADcD8AIgAyABKQIINwP4AiADIAIpAlg3A+gCIAMgAikCUDcD4AIgBCADQfACaiADQeACahAFIAIgAykCiAY3AlggAiADKQKABjcCUCADIAIpAjA3A9ACIAMgAikCODcD2AIgAyABKQIANwPAAiADIAEpAgg3A8gCIAQgA0HQAmogA0HAAmoQBSABIAMpAogGNwIIIAEgAykCgAY3AgAgAyACKQIgNwOwAiADIAIpAig3A7gCIAMgAikCMDcDoAIgAyACKQI4NwOoAiAEIANBsAJqIANBoAJqEAUgAiADKQKIBjcCOCACIAMpAoAGNwIwIAMgAikCEDcDkAIgAyACKQIYNwOYAiADIAIpAiA3A4ACIAMgAikCKDcDiAIgBCADQZACaiADQYACahAFIAIgAykCiAY3AiggAiADKQKABjcCICADIAIpAgA3A/ABIAMgAikCCDcD+AEgAyACKQIQNwPgASADIAIpAhg3A+gBIAQgA0HwAWogA0HgAWoQBSACIAMpAogGNwIYIAIgAykCgAY3AhAgAyADKQOQBjcD0AEgAyADKQOYBjcD2AEgAyACKQIANwPAASADIAIpAgg3A8gBIAQgA0HQAWogA0HAAWoQBSADKAKABiEFIAMoAoQGIQYgAygCiAYhByACIAMoAowGIApzNgIMIAIgByAJczYCCCACIAYgF3M2AgQgAiAFIBZzNgIAIAMgAikCWDcDmAYgAyACKQJQNwOQBiADIAEpAgA3A7ABIAMgASkCCDcDuAEgAyACKQJYNwOoASADIAIpAlA3A6ABIAQgA0GwAWogA0GgAWoQBSACIAMpAogGNwJYIAIgAykCgAY3AlAgAyACKQIwNwOQASADIAIpAjg3A5gBIAMgASkCADcDgAEgAyABKQIINwOIASAEIANBkAFqIANBgAFqEAUgASADKQKIBjcCCCABIAMpAoAGNwIAIAMgAikCIDcDcCADIAIpAig3A3ggAyACKQIwNwNgIAMgAikCODcDaCAEIANB8ABqIANB4ABqEAUgAiADKQKIBjcCOCACIAMpAoAGNwIwIAMgAikCEDcDUCADIAIpAhg3A1ggAyACKQIgNwNAIAMgAikCKDcDSCAEIANB0ABqIANBQGsQBSACIAMpAogGNwIoIAIgAykCgAY3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BSACIAMpAogCNwJYIAIgAykCgAI3AlAgAyACKQIwNwOQASADIAIpAjg3A5gBIAMgACkCADcDgAEgAyACKQJINwOIASAEIANBkAFqIANBgAFqEAUgAiADKQKIAjcCSCAAIAMpAoACNwIAIAMgAikCIDcDcCADIAIpAig3A3ggAyACKQIwNwNgIAMgAikCODcDaCAEIANB8ABqIANB4ABqEAUgAiADKQKIAjcCOCACIAMpAoACNwIwIAMgAikCEDcDUCADIAIpAhg3A1ggAyACKQIgNwNAIAMgAikCKDcDSCAEIANB0ABqIANBQGsQBSACIAMpAogCNwIoIAIgAykCgAI3AiAgAyACKQIANwMwIAMgAikCCDcDOCADIAIpAhA3AyAgAyACKQIYNwMoIAQgA0EwaiADQSBqEAUgAiADKQKIAjcCGCACIAMpAoACNwIQIAMgAykDkAI3AxAgAyADKQOYAjcDGCADIAIpAgA3AwAgAyACKQIINwMIIAQgA0EQaiADEAUgAiADKQKIAjcCCCACIAMpAoACNwIAIAIgByACKAIMczYCDCACIAYgAigCCHM2AgggAiAFIAIoAgRzNgIEIAIgECACKAIAczYCACAAIAggACgCAHM2AgAgAiALIAIoAkRzNgJEIAIgDiACKAJIczYCSCACIAEgAigCTHM2AkwgA0GgAmokAAuZDQESfyMAQaAEayICJAAgACgAPCEEIAAoADghBSAAKAA0IQYgACgAMCEHIAAoACAhCCAAKAAkIQkgACgAKCEKIAAoACwhCyAAKAAcIQwgACgAGCENIAAoABQhDiAAKAAQIQ8gACgABCEQIAAoAAghESAAKAAMIRIgACgAACETIAIgASkCeDcDmAQgAiABKQJwNwOQBCACIAEpAmA3A/ADIAIgASkCaDcD+AMgAiABKQJwNwPgAyACIAEpAng3A+gDIAJBgARqIgMgAkHwA2ogAkHgA2oQBSABIAIpAogENwJ4IAEgAikCgAQ3AnAgAiABKQJQNwPQAyACIAEpAlg3A9gDIAIgASkCYDcDwAMgAiABKQJoNwPIAyADIAJB0ANqIAJBwANqEAUgASACKQKIBDcCaCABIAIpAoAENwJgIAIgAUFAayIAKQIANwOwAyACIAEpAkg3A7gDIAIgASkCUDcDoAMgAiABKQJYNwOoAyADIAJBsANqIAJBoANqEAUgASACKQKIBDcCWCABIAIpAoAENwJQIAIgASkCMDcDkAMgAiABKQI4NwOYAyACIAApAgA3A4ADIAIgASkCSDcDiAMgAyACQZADaiACQYADahAFIAEgAikCiAQ3AkggACACKQKABDcCACACIAEpAiA3A/ACIAIgASkCKDcD+AIgAiABKQIwNwPgAiACIAEpAjg3A+gCIAMgAkHwAmogAkHgAmoQBSABIAIpAogENwI4IAEgAikCgAQ3AjAgAiABKQIQNwPQAiACIAEpAhg3A9gCIAIgASkCIDcDwAIgAiABKQIoNwPIAiADIAJB0AJqIAJBwAJqEAUgASACKQKIBDcCKCABIAIpAoAENwIgIAIgASkCADcDsAIgAiABKQIINwO4AiACIAEpAhA3A6ACIAIgASkCGDcDqAIgAyACQbACaiACQaACahAFIAEgAikCiAQ3AhggASACKQKABDcCECACIAIpA5AENwOQAiACIAIpA5gENwOYAiACIAEpAgA3A4ACIAIgASkCCDcDiAIgAyACQZACaiACQYACahAFIAEgAikCiAQ3AgggASACKQKABDcCACABIBIgASgCDHM2AgwgASARIAEoAghzNgIIIAEgECABKAIEczYCBCABIBMgASgCAHM2AgAgACAPIAAoAgBzNgIAIAEgDiABKAJEczYCRCABIA0gASgCSHM2AkggASAMIAEoAkxzNgJMIAIgASkCeDcDmAQgAiABKQJwNwOQBCACIAEpAmA3A/ABIAIgASkCaDcD+AEgAiABKQJwNwPgASACIAEpAng3A+gBIAMgAkHwAWogAkHgAWoQBSABIAIpAogENwJ4IAEgAikCgAQ3AnAgAiABKQJQNwPQASACIAEpAlg3A9gBIAIgASkCYDcDwAEgAiABKQJoNwPIASADIAJB0AFqIAJBwAFqEAUgASACKQKIBDcCaCABIAIpAoAENwJgIAIgACkCADcDsAEgAiABKQJINwO4ASACIAEpAlA3A6ABIAIgASkCWDcDqAEgAyACQbABaiACQaABahAFIAEgAikCiAQ3AlggASACKQKABDcCUCACIAEpAjA3A5ABIAIgASkCODcDmAEgAiAAKQIANwOAASACIAEpAkg3A4gBIAMgAkGQAWogAkGAAWoQBSABIAIpAogENwJIIAAgAikCgAQ3AgAgAiABKQIgNwNwIAIgASkCKDcDeCACIAEpAjA3A2AgAiABKQI4NwNoIAMgAkHwAGogAkHgAGoQBSABIAIpAogENwI4IAEgAikCgAQ3AjAgAiABKQIQNwNQIAIgASkCGDcDWCACIAEpAiA3A0AgAiABKQIoNwNIIAMgAkHQAGogAkFAaxAFIAEgAikCiAQ3AiggASACKQKABDcCICACIAEpAgA3AzAgAiABKQIINwM4IAIgASkCEDcDICACIAEpAhg3AyggAyACQTBqIAJBIGoQBSABIAIpAogENwIYIAEgAikCgAQ3AhAgAiACKQOQBDcDECACIAIpA5gENwMYIAIgASkCADcDACACIAEpAgg3AwggAyACQRBqIAIQBSABIAIpAogENwIIIAEgAikCgAQ3AgAgASALIAEoAgxzNgIMIAEgCiABKAIIczYCCCABIAkgASgCBHM2AgQgASAIIAEoAgBzNgIAIAAgByAAKAIAczYCACABIAYgASgCRHM2AkQgASAFIAEoAkhzNgJIIAEgBCABKAJMczYCTCACQaAEaiQAC5wJAQt/IwBBoAJrIgMkACABKAAEIQogASgACCELIAEoAAwhDCAAKAAEIQYgACgACCEHIAAoAAwhCCABKAAAIQ0gAiAAKAAAIgFBgIKEEHMiADYCcCACIAFB2/vgqAVzNgJgIAIgADYCUCACQUBrIgAgASANcyIFNgIAIAJCoKLEkbSurZRdNwI4IAJC2/vgqNXN8JdxNwIwIAJClcTcyYWy+rziADcCKCACQoCChJCwoIGEDTcCICACQqCixJG0rq2UXTcCGCACQtv74KjVzfCXcTcCECACIAU2AgAgAiAIQZDT55MGcyIFNgJ8IAIgB0GVxNzJBXMiBDYCeCACIAZBg4qg6ABzIgk2AnQgAiAIQfPqoul9czYCbCACIAdBoKLEkQRzNgJoIAIgBkHthL+Jf3M2AmQgAiAFNgJcIAIgBDYCWCACIAk2AlQgAiAIIAxzIgU2AkwgAiAHIAtzIgQ2AkggAiAGIApzIgk2AkQgAiAFNgIMIAIgBDYCCCACIAk2AgRBACEFA0AgAyACKQJ4NwOYAiADIAIpAnA3A5ACIAMgAikCYDcD8AEgAyACKQJoNwP4ASADIAIpAnA3A+ABIAMgAikCeDcD6AEgA0GAAmoiBCADQfABaiADQeABahAFIAIgAykCiAI3AnggAiADKQKAAjcCcCADIAIpAlA3A9ABIAMgAikCWDcD2AEgAyACKQJgNwPAASADIAIpAmg3A8gBIAQgA0HQAWogA0HAAWoQBSACIAMpAogCNwJoIAIgAykCgAI3AmAgAyAAKQIANwOwASADIAApAgg3A7gBIAMgAikCUDcDoAEgAyACKQJYNwOoASAEIANBsAFqIANBoAFqEAUgAiADKQKIAjcCWCACIAMpAoACNwJQIAMgAikCMDcDkAEgAyACKQI4NwOYASADIAApAgA3A4ABIAMgACkCCDcDiAEgBCADQZABaiADQYABahAFIAAgAykCiAI3AgggACADKQKAAjcCACADIAIpAiA3A3AgAyACKQIoNwN4IAMgAikCMDcDYCADIAIpAjg3A2ggBCADQfAAaiADQeAAahAFIAIgAykCiAI3AjggAiADKQKAAjcCMCADIAIpAhA3A1AgAyACKQIYNwNYIAMgAikCIDcDQCADIAIpAig3A0ggBCADQdAAaiADQUBrEAUgAiADKQKIAjcCKCACIAMpAoACNwIgIAMgAikCADcDMCADIAIpAgg3AzggAyACKQIQNwMgIAMgAikCGDcDKCAEIANBMGogA0EgahAFIAIgAykCiAI3AhggAiADKQKAAjcCECADIAMpA5ACNwMQIAMgAykDmAI3AxggAyACKQIANwMAIAMgAikCCDcDCCAEIANBEGogAxAFIAIgAykCiAI3AgggAiADKQKAAjcCACACIAIoAgwgDHM2AgwgAiACKAIIIAtzNgIIIAIgAigCBCAKczYCBCACIAIoAgAgDXM2AgAgACAAKAIAIAFzNgIAIAIgAigCRCAGczYCRCACIAIoAkggB3M2AkggAiACKAJMIAhzNgJMIAVBAWoiBUEKRw0ACyADQaACaiQAC7UFAQl/IwBBgAFrIgMkAEHixAItAAAhBCAAQgA3AgQgAEEBNgIAIABCADcCDCAAQgA3AhQgAEIANwIcIABCgICAgBA3AiQgAEEsakEAQcwA/AsAIAAgAUHAB2xBkBVqIgFB4sQCLQAAQQJ2IAIgAkEAIARBAnYgAkGAAXFBB3ZzIgRrcUEBdGsiAkEBc0H/AXFBAWtBH3ZzEB0gACABQfgAakHixAItAABBAnYgAkECc0H/AXFBAWtBH3ZzEB0gACABQfABakHixAItAABBAnYgAkEDc0H/AXFBAWtBH3ZzEB0gACABQegCakHixAItAABBAnYgAkEEc0H/AXFBAWtBH3ZzEB0gACABQeADakHixAItAABBAnYgAkEFc0H/AXFBAWtBH3ZzEB0gACABQdgEakHixAItAABBAnYgAkEGc0H/AXFBAWtBH3ZzEB0gACABQdAFakHixAItAABBAnYgAkEHc0H/AXFBAWtBH3ZzEB0gACABQcgGakHixAItAABBAnYgAkEIc0H/AXFBAWtBH3ZzEB0gAyAAKQJINwMoIAMgAEFAaykCADcDICADIAApAjg3AxggAyAAKQIwNwMQIAMgACkCKDcDCCADIAApAgA3AzAgAyAAKQIINwM4IAMgACkCEDcDQCADIAApAhg3A0ggAyAAKQIgNwNQIAAoAlAhASAAKAJUIQIgACgCWCEFIAAoAlwhBiAAKAJgIQcgACgCZCEIIAAoAmghCSAAKAJsIQogACgCcCELIANBACAAKAJ0azYCfCADQQAgC2s2AnggA0EAIAprNgJ0IANBACAJazYCcCADQQAgCGs2AmwgA0EAIAdrNgJoIANBACAGazYCZCADQQAgBWs2AmAgA0EAIAJrNgJcIANBACABazYCWCAAIANBCGogBBAdIANBgAFqJAAL8AkBHn8gASgCKCEDIAEoAgQhBCABKAIsIQUgASgCCCEGIAEoAjAhByABKAIMIQggASgCNCEJIAEoAhAhCiABKAI4IQsgASgCFCEMIAEoAjwhDSABKAIYIQ4gAUFAayIPKAIAIRAgASgCHCERIAEoAkQhEiABKAIgIRMgASgCSCEUIAEoAgAhFSAAIAEoAiQgASgCTGo2AiQgACATIBRqNgIgIAAgESASajYCHCAAIA4gEGo2AhggACAMIA1qNgIUIAAgCiALajYCECAAIAggCWo2AgwgACAGIAdqNgIIIAAgBCAFajYCBCAAIAMgFWo2AgAgASgCKCEFIAEoAgQhAyABKAIsIQYgASgCCCEHIAEoAjAhCCABKAIMIQkgASgCNCEKIAEoAhAhCyABKAI4IQwgASgCFCENIAEoAjwhDiABKAIYIRAgDygCACEPIAEoAhwhBCABKAJEIREgASgCICESIAEoAkghEyABKAIAIRQgACABKAJMIAEoAiRrNgJMIAAgEyASazYCSCAAIBEgBGs2AkQgAEFAayIEIA8gEGs2AgAgACAOIA1rNgI8IAAgDCALazYCOCAAIAogCWs2AjQgACAIIAdrNgIwIAAgBiADazYCLCAAQShqIgMgBSAUazYCACAAQdAAaiAAIAJBKGoQBiADIAMgAhAGIABB+ABqIAJB+ABqIAFB+ABqEAYgACABQdAAaiACQdAAahAGIAAoAgQhFSAAKAIIIRYgACgCDCEXIAAoAhAhGCAAKAIUIRkgACgCGCEaIAAoAhwhGyAAKAIgIRwgACgCJCEdIAMoAgAhASAAKAJQIQIgACgCLCEFIAAoAlQhBiAAKAIwIQcgACgCWCEIIAAoAjQhCSAAKAJcIQogACgCOCELIAAoAmAhDCAAKAI8IQ0gACgCZCEOIAQoAgAhDyAAKAJoIRAgACgCRCERIAAoAmwhEiAAKAJIIRMgACgCcCEUIAAoAgAhHiAAIAAoAkwiHyAAKAJ0IiBqNgJMIAAgEyAUajYCSCAAIBEgEmo2AkQgBCAPIBBqNgIAIAAgDSAOajYCPCAAIAsgDGo2AjggACAJIApqNgI0IAAgByAIajYCMCAAIAUgBmo2AiwgAyABIAJqNgIAIAAgICAfazYCJCAAIBQgE2s2AiAgACASIBFrNgIcIAAgECAPazYCGCAAIA4gDWs2AhQgACAMIAtrNgIQIAAgCiAJazYCDCAAIAggB2s2AgggACAGIAVrNgIEIAAgAiABazYCACAAIAAoApwBIgEgHUEBdCICajYCnAEgACAAKAKYASIDIBxBAXQiBGo2ApgBIAAgACgClAEiBSAbQQF0IgZqNgKUASAAIAAoApABIgcgGkEBdCIIajYCkAEgACAAKAKMASIJIBlBAXQiCmo2AowBIAAgACgCiAEiCyAYQQF0IgxqNgKIASAAIAAoAoQBIg0gF0EBdCIOajYChAEgACAAKAKAASIPIBZBAXQiEGo2AoABIAAgACgCfCIRIBVBAXQiEmo2AnwgACAAKAJ4IhMgHkEBdCIUajYCeCAAIAQgA2s2AnAgACAGIAVrNgJsIAAgCCAHazYCaCAAIAogCWs2AmQgACAMIAtrNgJgIAAgDiANazYCXCAAIBAgD2s2AlggACASIBFrNgJUIAAgFCATazYCUCAAIAIgAWs2AnQLEgAgACABIAKtIAOtQiCGhBAYC64OARd/IwBBwAJrIgMkACAAQShqIgkgARCAASAAQgA3AlQgAEEBNgJQIABCADcCXCAAQgA3AmQgAEIANwJsIABBADYCdCADQfABaiIIIAkQBCADQcABaiIGIAhBwAoQBkF/IQogAyADKALwAUEBayILNgLwASADIAMoAsABQQFqNgLAASADKAL0ASEMIAMoAvgBIQ0gAygC/AEhDiADKAKAAiEPIAMoAoQCIRAgAygCiAIhESADKAKMAiESIAMoApACIRMgAygClAIhFCADQZABaiIHIAYQBCAHIAcgBhAGIAAgBxAEIAAgACAGEAYgACAAIAgQBiMAQZABayIEJAAgBEHgAGoiBSAAEAQgBEEwaiICIAUQBCACIAIQBCACIAAgAhAGIAUgBSACEAYgBSAFEAQgBSACIAUQBiACIAUQBCACIAIQBCACIAIQBCACIAIQBCACIAIQBCAFIAIgBRAGIAIgBRAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAiAFEAYgBCACEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgBCAEEAQgAiAEIAIQBiACIAIQBCACIAIQBCACIAIQBCACIAIQBCACIAIQBCACIAIQBCACIAIQBCACIAIQBCACIAIQBCACIAIQBCAFIAIgBRAGIAIgBRAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAhAEIAIgAiAFEAYgBCACEARBASECA0AgBCAEEAQgAkEBaiICQeQARw0ACyAEQTBqIgIgBCACEAYgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgAiACEAQgBEHgAGoiBSACIAUQBiAFIAUQBCAFIAUQBCAAIAUgABAGIARBkAFqJAAgACAAIAcQBiAAIAAgCBAGIANB4ABqIgIgABAEIAIgAiAGEAYgAyADKAKEASICIBRrNgJUIAMgAygCgAEiBCATazYCUCADIAMoAnwiBSASazYCTCADIAMoAngiBiARazYCSCADIAMoAnQiByAQazYCRCADIAMoAnAiCCAPazYCQCADIAMoAmwiFSAOazYCPCADIAMoAmgiFiANazYCOCADIAMoAmQiFyAMazYCNCADIAMoAmAiGCALazYCMCADIANBMGoQGgJAIANBIBAoRQRAIAMgAiAUajYCJCADIAQgE2o2AiAgAyAFIBJqNgIcIAMgBiARajYCGCADIAcgEGo2AhQgAyAIIA9qNgIQIAMgDiAVajYCDCADIA0gFmo2AgggAyAMIBdqNgIEIAMgCyAYajYCACADQaACaiICIAMQGiACQSAQKEUNASAAIABB8AoQBgsgA0GgAmogABAaIAMtAKACQQFxIAEtAB9BB3ZGBEAgAEEAIAAoAgBrNgIAIABBACAAKAIkazYCJCAAQQAgACgCIGs2AiAgAEEAIAAoAhxrNgIcIABBACAAKAIYazYCGCAAQQAgACgCFGs2AhQgAEEAIAAoAhBrNgIQIABBACAAKAIMazYCDCAAQQAgACgCCGs2AgggAEEAIAAoAgRrNgIECyAAQfgAaiAAIAkQ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ACADIAApAgA3A9ABIAMgACkCCDcD2AEgAyACQUBrKQIANwPAASADIAIpAkg3A8gBIAEgA0HQAWogA0HAAWoQBSAAIAMpAsgCNwIIIAAgAykCwAI3AgAgAyAAKQIANwOwASADIAApAgg3A7gBIAMgAikCUDcDoAEgAyACKQJYNwOoASABIANBsAFqIANBoAFqEAUgACADKQLIAjcCCCAAIAMpAsACNwIAIAMgACkCADcDkAEgAyAAKQIINwOYASADIAIpAmA3A4ABIAMgAikCaDcDiAEgASADQZABaiADQYABahAFIAAgAykCyAI3AgggACADKQLAAjcCACADIAApAgA3A3AgAyAAKQIINwN4IAMgAikCcDcDYCADIAIpAng3A2ggASADQfAAaiADQeAAahAFIAAgAykCyAI3AgggACADKQLAAjcCACADIAApAgA3A1AgAyAAKQIINwNYIAMgAikCgAE3A0AgAyACKQKIATcDSCABIANB0ABqIANBQGsQBSAAIAMpAsgCNwIIIAAgAykCwAI3AgAgAyAAKQIANwMwIAMgACkCCDcDOCADIAIpApABNwMgIAMgAikCmAE3AyggASADQTBqIANBIGoQBSAAIAMpAsgCNwIIIAAgAykCwAI3AgAgAyAAKQIANwMQIAMgACkCCDcDGCADIAIpAqABNwMAIAMgAikCqAE3AwggASADQRBqIAMQISAAIAMpAsgCNwIIIAAgAykCwAI3AgAgA0HQAmokAAuwAwEFfyMAQaAfayIDJAAgA0GgHWoiBEHgACACQiAQSRogAyADKQPYHTcDmB0gAyADKQPQHTcDkB0gAyADKQPIHTcDiB0gAyADKQPAHTcDgB0gAyADKQO4HTcD+BwgAyADKQOwHTcD8BwgAyADKQOoHTcD6BwgAyADKQOgHTcD4BwgAyADKQPgHTcDICADIAMpA+gdNwMoIAMgAykD8B03AzAgAyADKQP4HTcDOCADQcATaiADQeAAaiIGIANB4BxqIgUQNRogA0FAayADQSBqIgdBzLkCKAIAEQEAGiAEQeAAEAcgBUHAABAHQX8hAiAFIAEgBhCRAUUEQCADIAcgAUHACGoiBBApBH8gBQUgA0GgHWoiAUEAQcgB/AsAIAFBADoA7AEgAUEgNgLoASABQoCAgICAETcD4AEgASADQeAcaiICQiAQGBog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CiALKQI4NwOYASAKIBApAgA3A4ABIAogCykCSDcDiAEgASAKQZABaiAKQYABahAFIAsgCikC2AE3AkggECAKKQLQATcCACAKIAspAiA3A3AgCiALKQIoNwN4IAogCykCMDcDYCAKIAspAjg3A2ggASAKQfAAaiAKQeAAahAFIAsgCikC2AE3AjggCyAKKQLQATcCMCAKIAspAhA3A1AgCiALKQIYNwNYIAogCykCIDcDQCAKIAspAig3A0ggASAKQdAAaiAKQUBrEAUgCyAKKQLYATcCKCALIAopAtABNwIgIAogCykCADcDMCAKIAspAgg3AzggCiALKQIQNwMgIAogCykCGDcDKCABIApBMGogCkEgahAFIAsgCikC2AE3AhggCyAKKQLQATcCECAKIAopA+ABNwMQIAogCikD6AE3AxggCiALKQIANwMAIAogCykCCDcDCCABIApBEGogChAFIAooAtABIQcgCigC1AEhBSAKKALYASEBIAsgCCAKKALcAXM2AgwgCyABIAxzNgIIIAsgBSANczYCBCALIAcgD3M2AgAgCkHwAWokAAsgCUGAA2ogBCAGrSACrSAJQbADahBrQX8hBwJAAkACQAJ/AkACQCAEQRBrDhEAAwMDAwMDAwMDAwMDAwMDAQMLIAlBgANqIAMQKwwBCyAJQYADaiADEEwLIgdFDQELIABFDQEgAkUNASAAQQAgAvwLAAwBC0EAIQcLIAlBoARqJAAgBwvaAQEDfyMAQRBrIgUkAAJAAkAgA0UEQEF/IQEMAQsCfyADIANBAWsiBnFFBEAgBiACQX9zIgdxDAELIAJBf3MhByAGIAIgA3BrCyIGIAdPDQEgBCACIAZqIgJNBEBBfyEBDAELIAAEQCAAIAJBAWo2AgALIAEgAmohAEEAIQEgBUEAOgAPQQAhAgNAIAAgAmsiBCAELQAAIAUtAA9xIAIgBnNBAWtBGHYiBEGAAXFyOgAAIAUgBS0ADyAEcjoADyACQQFqIgIgA0cNAAsLIAVBEGokACABDwsQCgALogwCBX8CfiMAQZAEayIJJAAgCCAHIAlBkANqEG5BACEIIAZBH0sEQEEgIQcDQCAFIAhqIAlBkANqEG0gByIIQSBqIgcgBk0NAAsLIAYgCEEQciIHTwRAA0AgBSAIaiIIKAAAIQsgCCgABCEMIAgoAAghDSAI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AGogBBBAIAGnIgZBA3EhB0EAIQMgAUIEWgRAIAZBPHEhCEEAIQYDQCAAIANqIARBIGoiCSIFIANqLQAAOgAAIAAgA0EBciIKaiAFIApqLQAAOgAAIAAgA0ECciIFaiAFIAlqLQAAOgAAIAAgA0EDciIFaiAEQSBqIAVqLQAAOgAAIANBBGohAyAGQQRqIgYgCEcNAAsgB0UNAQsDQCAAIANqIARBIGogA2otAAA6AAAgA0EBaiEDIAJBAWoiAiAHRw0ACwsgBEEgakHAABAHIARBIBAHCyAEQfAAaiQAQQALhgYBFH8jAEGwAmsiAiQAIAAgAS0AADoAACAAIAEtAAE6AAEgACABLQACOgACIAAgAS0AAzoAAyAAIAEtAAQ6AAQgACABLQAFOgAFIAAgAS0ABjoABiAAIAEtAAc6AAcgACABLQAIOgAIIAAgAS0ACToACSAAIAEtAAo6AAogACABLQALOgALIAAgAS0ADDoADCAAIAEtAA06AA0gACABLQAOOgAOIAAgAS0ADzoADyAAIAEtABA6ABAgACABLQAROgARIAAgAS0AEjoAEiAAIAEtABM6ABMgACABLQAUOgAUIAAgAS0AFToAFSAAIAEtABY6ABYgACABLQAXOgAXIAAgAS0AGDoAGCAAIAEtABk6ABkgACABLQAaOgAaIAAgAS0AGzoAGyAAIAEtABw6ABwgACABLQAdOgAdIAAgAS0AHjoAHiABLQAfIQEgACAALQAAQfgBcToAACAAIAFBP3FBwAByOgAfIAJBMGogABBCIAIoAoABIQEgAigCWCEDIAIoAoQBIQQgAigCXCEFIAIoAogBIQYgAigCYCEHIAIoAowBIQggAigCZCEJIAIoApABIQogAigCaCELIAIoApQBIQwgAigCbCENIAIoApgBIQ4gAigCcCEPIAIoApwBIRAgAigCdCERIAIoAqABIRIgAigCeCETIAIgAigCfCIUIAIoAqQBIhVqNgKkAiACIBIgE2o2AqACIAIgECARajYCnAIgAiAOIA9qNgKYAiACIAwgDWo2ApQCIAIgCiALajYCkAIgAiAIIAlqNgKMAiACIAYgB2o2AogCIAIgBCAFajYChAIgAiABIANqNgKAAiACIBUgFGs2AvQBIAIgEiATazYC8AEgAiAQIBFrNgLsASACIA4gD2s2AugBIAIgDCAN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AsQBIAMgBCAMajYCwAEgAyAHIA9qNgLMASADQeAAaiIaIANBMGoiDCADQfABaiIFEAYgA0HAAWoiBCAEIAMQBiAMIAMQBCADIAUQBCADKALAASECIAMoAmAhBiADKALEASEKIAMoAmQhByADKALIASEIIAMoAmghCSADKALMASELIAMoAmwhDSADKALQASEXIAMoAnAhDiADKALUASEPIAMoAnQhECADKALYASEUIAMoAnghESADKALcASESIAMoAnwhEyADKALgASEVIAMoAoABIRggAyADKALkASIZIAMoAoQBIhtqNgK0ASADIBUgGGo2ArABIAMgEiATajYCrAEgAyARIBRqNgKoASADIA8gEGo2AqQBIAMgDiAXajYCoAEgAyALIA1qNgKcASADIAggCWo2ApgBIAMgByAKajYClAEgAyACIAZqNgKQASADIBsgGWs2AuQBIAMgGCAVazYC4AEgAyATIBJrNgLcASADIBEgFGs2AtgBIAMgECAPazYC1AEgAyAOIBdrNgLQASADIA0gC2s2AswBIAMgCSAIazYCyAEgAyAHIAprNgLEASADIAYgAms2AsABIAUgAyAMEAYgAygCSCECIAMoAhghDiADKAJEIQYgAygCFCEPIAMoAkAhCiADKAIQIRAgAygCPCEHIAMoAgwhFCADKAI4IQggAygCCCERIAMoAjQhCSADKAIEIRIgAygCVCELIAMoAiQhEyADKAIwIQ0gAygCACEVIAMoAkwhFyADKAIcIRggAyADKAIgIAMoAlAiGWsiGzYCICADIBggF2siGDYCHCADIBUgDWsiFTYCACADIBMgC2siEzYCJCADIBIgCWsiEjYCBCADIBEgCGsiETYCCCADIBQgB2siFDYCDCADIBAgCmsiEDYCECADIA8gBmsiDzYCFCADIA4gAmsiDjYCGCAEIAQQBCADQZABaiIcIBwQBCADIBkgG6xCwrYHfiAYrELCtgd+IkBCgICACHwiQkIZh3wiQSBBQoCAgBB8IkFCgICA4A+DfadqNgJQIAMgAiAOrELCtgd+IA+sQsK2B34iRkKAgIAIfCJHQhmHfCJDIENCgICAEHwiQ0KAgIDgD4N9p2o2AkggAyAKIBCsQsK2B34gFKxCwrYHfiJIQoCAgAh8IklCGYd8IkQgREKAgIAQfCJEQoCAgOAPg32najYCQCADIAggEaxCwrYHfiASrELCtgd+IkpCgICACHwiS0IZh3wiRSBFQoCAgBB8IkVCgICA4A+DfadqNgI4IAMgCyATrELCtgd+IkwgQUIaiHwgTEKAgIAIfCJBQoCAgPAPg32najYCVCADIBcgQ0IaiCBAfCBCQoCAgPAPg32najYCTCADIAYgREIaiCBGfCBHQoCAgPAPg32najYCRCADIAcgRUIaiCBIfCBJQoCAgPAPg32najYCPCADIAkgSiBLQoCAgPAPg30gQUIZh0ITfiAVrELCtgd+fCJAQoCAgBB8IkJCGoh8p2o2AjQgAyANIEAgQkKAgIDgD4N9p2o2AjAgAUEBayECIBogA0GgAmogBBAGIAQgAyAMEAYgAQ0ACyADKAKQASEXIAMoAvABIQIgAygClAEhDiADKAL0ASEMIAMoApgBIQ8gAygC+AEhBiADKAKcASEQIAMoAvwBIQogAygCoAEhFCADKAKAAiEHIAMoAqQBIREgAygChAIhCCADKAKoASESIAMoAogCIQkgAygCrAEhEyADKAKMAiELIAMoArABIRUgAygCkAIhDSADQQAgFmsiASADKAKUAiIWIAMoArQBc3EgFnM2ApQCIAMgDSANIBVzIAFxczYCkAIgAyALIAsgE3MgAXFzNgKMAiADIAkgCSAScyABcXM2AogCIAMgCCAIIBFzIAFxczYChAIgAyAHIAcgFHMgAXFzNgKAAiADIAogCiAQcyABcXM2AvwBIAMgBiAGIA9zIAFxczYC+AEgAyAMIAwgDnMgAXFzNgL0ASADIAIgAiAXcyABcXM2AvABIAMoAsABIQIgAygCYCENIAMoAsQBIRYgAygCZCEXIAMoAsgBIQwgAygCaCEOIAMoAswBIQYgAygCbCEPIAMoAtABIQogAygCcCEQIAMoAtQBIQcgAygCdCEUIAMoAtgBIQggAygCeCERIAMoAtwBIQkgAygCfCESIAMoAuABIQsgAygCgAEhEyADIAMoAuQBIhUgAygChAFzIAFxIBVzNgLkASADIAsgCyATcyABcXM2AuABIAMgCSAJIBJzIAFxczYC3AEgAyAIIAggEXMgAXFzNgLYASADIAcgByAUcyABcXM2AtQBIAMgCiAKIBBzIAFxczYC0AEgAyAGIAYgD3MgAXFzNgLMASADIAwgDCAOcyABcXM2AsgB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JyAFLQADczoAJyAAIAAtACggBS0ABHM6ACggACAALQApIAUtAAVzOgApIAAgAC0AKiAFLQAGczoAKiAAIAAtACsgBS0AB3M6ACsgCRBxAkAgB0ECcUUEQCAJQQQQKEUNAQsgBSAAKQAYNwP4AiAFIAApABA3A/ACIAUgACkACDcD6AIgBSAAKQAANwPgAiAFIAApACQ3A4ADIAVB4AJqIgEgAUIoIAlBACAAQfS5AigCABEOABogACAFKQP4AjcAGCAAIAUpA/ACNwAQIAAgBSkD6AI3AAggACAFKQPgAjcAACAFKQOAAyEKIABBATYAICAAIAo3ACQLIAIEQCACIAs3AwALQQAhDSADRQ0AIAMgBzoAAAsgBUGQA2okACANDAELEAoACwvhBQECfgJ/IAStIAWtQiCGhCEKIAetIAitQiCGhCELIwBBgANrIgQkACACBEAgAkIANwMACyAKQu////8PVARAIARBEGoiCELAACAAQSBqIgcgABAmIARB0ABqIgUgCEG8uQIoAgARAQAaIAhBwAAQByAFIAYgC0HAuQIoAgARAAAaIAVB0LMCQgAgC31CD4NBwLkCKAIAEQAAGiAEQgA3AxAgBEIANwNIIARCADcDQCAEQgA3AzggBEIANwMwIARCADcDKCAEQgA3AyAgBEIANwMYIAQgCToAECAIIAhCwAAgB0EBIAAQJyAFIAhCwABBwLkCKAIAEQAAGiABIAQtABA6AAAgAUEBaiIBIAMgCiAHQQIgABAnIAUgASAKQcC5AigCABEAABogBUHQswIgCkIPg0HAuQIoAgARAAAaIAQgCzcDCCAFIARBCGoiA0IIQcC5AigCABEAABogBCAKQkB9NwMIIAUgA0IIQcC5AigCABEAABogBSABIAqnaiIBQcS5AigCABEBABogBUGAAhAHIAAgAC0AJCABLQAAczoAJCAAIAAtACUgAS0AAXM6ACUgACAALQAmIAEtAAJzOgAmIAAgAC0AJyABLQADczoAJyAAIAAtACggAS0ABHM6ACggACAALQApIAEtAAVzOgApIAAgAC0AKiABLQAGczoAKiAAIAAtACsgAS0AB3M6ACsgBxBxAkAgCUECcUUEQCAHQQQQKEUNAQsgBCAAKQAYNwPoAiAEIAApABA3A+ACIAQgACkACDcD2AIgBCAAKQAANwPQAiAEIAApACQ3A/ACIARB0AJqIgEgAUIoIAdBACAAQfS5AigCABEOABogACAEKQPoAjcAGCAAIAQpA+ACNwAQIAAgBCkD2AI3AAggACAEKQPQAjcAACAEKQPwAiELIAdBATYAACAAIAs3ACQLIAIEQCACIApCEXw3AwALIARBgANqJABBAAwBCxAKAAsLMQEBfiACrSADrUIghoQiBkLw////D1oEQBAKAAsgAEEQaiAAIAEgBiAEIAUQMxpBAAv8AwICfwR+IwBBIGsiBiQAIAQpAAAhCCAGQgA3AxggBiAINwMQIAZCADcDCCAGIAKtIAOtQiCGhDcDAAJ/IAFBwQBrQU5NBEBB0MACQRw2AgBBfwwBCyABQcEAayIEQUBPBH8CfyAGQRBqIQMjACICIQcgAkGABGtBQHEiAiQAAkAgAEUNACAEQf8BcUG/AU0NACAFRSIEDQAgBA0AAn4gBkUEQEKf2PnZwpHagpt/IQhC0YWa7/rPlIfRAAwBCyAGKQAIQp/Y+dnCkdqCm3+FIQggBikAAELRhZrv+s+Uh9EAhQshCgJ+IANFBEBC+cL4m5Gjs/DbACEJQuv6htq/tfbBHwwBCyADKQAIQvnC+JuRo7Pw2wCFIQkgAykAAELr+obav7X2wR+FCyELIAJBQGtBAEGlAvwLACACIAk3AzggAiALNwMwIAIgCDcDKCACIAo3AyAgAkLx7fT4paf9p6V/NwMYIAJCq/DT9K/uvLc8NwMQIAJCu86qptjQ67O7fzcDCCACIAGtQoDAAIRCiJL3lf/M+YTqAIU3AwAgAkGgA2pBAEHgAPwLACACQYADaiIDIAVBIPwKAAAgAkHgAGogA0GAAfwKAAAgAkGAATYC4AIgA0GAARAHIAIgACABEGYaIAckAEEADAELEAoACwVBfwsLIAZBIGokAAsSACAAIAEgAq0gA61CIIaEEEsLEgAgACABIAKtIAOtQiCGhBBkCxIAIAAgASACrSADrUIghoQQLwuCDAEIfwJAIABFDQAgAEEIayIDIABBBGsoAgAiAkF4cSIAaiEFAkAgAkEBcQ0AIAJBAnFFDQEgAyADKAIAIgRrIgNB5MACKAIASQ0BIAAgBGohAAJAAkACQEHowAIoAgAgA0cEQCADKAIMIQEgBEH/AU0EQCABIAMoAggiAkcNAkHUwAJB1MACKAIAQX4gBEEDdndxNgIADAULIAMoAhghByABIANHBEAgAygCCCICIAE2AgwgASACNgIIDAQLIAMoAhQiAgR/IANBFGoFIAMoAhAiAkUNAyADQRBqCyEEA0AgBCEGIAIiAUEUaiEEIAEoAhQiAg0AIAFBEGohBCABKAIQIgINAAsgBkEANgIADAMLIAUoAgQiAkEDcUEDRw0DQdzAAiAANgIAIAUgAkF+cTYCBCADIABBAXI2AgQgBSAANgIADwsgAiABNgIMIAEgAjYCCAwCC0EAIQELIAdFDQACQCADKAIcIgRBAnQiAigChMMCIANGBEAgAkGEwwJqIAE2AgAgAQ0BQdjAAkHYwAIoAgBBfiAEd3E2AgAMAgsCQCADIAcoAhBGBEAgByABNgIQDAELIAcgATYCFAsgAUUNAQsgASAHNgIYIAMoAhAiAgRAIAEgAjYCECACIAE2AhgLIAMoAhQiAkUNACABIAI2AhQgAiABNgIYCyADIAVPDQAgBSgCBCIEQQFxRQ0AAkACQAJAAkAgBEECcUUEQEHswAIoAgAgBUYEQEHswAIgAzYCAEHgwAJB4MACKAIAIABqIgA2AgAgAyAAQQFyNgIEIANB6MACKAIARw0GQdzAAkEANgIAQejAAkEANgIADwtB6MACKAIAIgcgBUYEQEHowAIgAzYCAEHcwAJB3MACKAIAIABqIgA2AgAgAyAAQQFyNgIEIAAgA2ogADYCAA8LIARBeHEgAGohACAFKAIMIQEgBEH/AU0EQCAFKAIIIgIgAUYEQEHUwAJB1MACKAIAQX4gBEEDdndxNgIADAULIAIgATYCDCABIAI2AggMBAsgBSgCGCEIIAEgBUcEQCAFKAIIIgIgATYCDCABIAI2AggMAwsgBSgCFCICBH8gBUEUagUgBSgCECICRQ0CIAVBEGoLIQQDQCAEIQYgAiIBQRRqIQQgASgCFCICDQAgAUEQaiEEIAEoAhAiAg0ACyAGQQA2AgAMAgsgBSAEQX5xNgIEIAMgAEEBcjYCBCAAIANqIAA2AgAMAwtBACEBCyAIRQ0AAkAgBSgCHCIEQQJ0IgIoAoTDAiAFRgRAIAJBhMMCaiABNgIAIAENAUHYwAJB2MACKAIAQX4gBHdxNgIADAILAkAgBSAIKAIQRgRAIAggATYCEAwBCyAIIAE2AhQLIAFFDQELIAEgCDYCGCAFKAIQIgIEQCABIAI2AhAgAiABNgIYCyAFKAIUIgJFDQAgASACNgIUIAIgATYCGAsgAyAAQQFyNgIEIAAgA2ogADYCACADIAdHDQBB3MACIAA2AgAPCyAAQf8BTQRAIABB+AFxQfzAAmohAgJ/QdTAAigCACIEQQEgAEEDdnQiAHFFBEBB1MACIAAgBHI2AgAgAgwBCyACKAIICyEAIAIgAzYCCCAAIAM2AgwgAyACNgIMIAMgADYCCA8LQR8hASAAQf///wdNBEAgAEEmIABBCHZnIgJrdkEBcSACQQF0ckE+cyEBCyADIAE2AhwgA0IANwIQIAFBAnRBhMMCaiEEAn8CQAJ/QdjAAigCACIGQQEgAXQiAnFFBEBB2MACIAIgBnI2AgAgBCADNgIAQRghAUEIDAELIABBGSABQQF2a0EAIAFBH0cbdCEBIAQoAgAhBANAIAQiAigCBEF4cSAARg0CIAFBHXYhBCABQQF0IQEgAiAEQQRxaiIGKAIQIgQNAAsgBiADNgIQQRghASACIQRBCAshACADIgIMAQsgAigCCCIEIAM2AgwgAiADNgIIQRghAEEIIQFBAAshBiABIANqIAQ2AgAgAyACNgIMIAAgA2ogBjYCAEH0wAJB9MACKAIAQQFrIgBBfyAAGzYCAAsLEgAgACABIAKtIAOtQiCGhBAZCxkAIAAgASACIAOtIAStQiCGhCAFIAYQmQELdwIDfwF+IwAiBiAGQcADa0FAcSIGJABBfyEHIAKtIAOtQiCGhCIJQjBaBEAgBkFAayICQQBBAEEYEDkaIAIgAUIgEBkaIAIgBEIgEBkaIAIgBkEgaiICQRgQOhogACABQSBqIAlCIH0gAiABIAUQfSEHCyQAIAcLyAECA38BfgJ/IwAiBSEGIAVBgARrQUBxIgUkACACrSADrUIghoQiCELw////D1QEQEF/IQIgBUFAayIHIAVBIGoiAxBbRQRAIAVBgAFqIgJBAEEAQRgQORogAiAHQiAQGRogAiAEQiAQGRogAiAFQeAAaiICQRgQOhogAEEgaiABIAggAiAEIAMQfiECIAAgBSkDWDcAGCAAIAUpA1A3ABAgACAFKQNINwAIIAAgBSkDQDcAACADQSAQBwsgBiQAIAIMAQsQCgALCxgAIAAgASACrSADrUIghoQgBCAFIAYQfQtIAQF+IAOtIAStQiCGhCEIIwBBIGsiAyQAQX8hBCADIAYgBxAxRQRAIAAgASACIAggBSADEEUhBCADQSAQBwsgA0EgaiQAIAQLGAAgACABIAKtIAOtQiCGhCAEIAUgBhB+Cy4BAX4gAq0gA61CIIaEIgZC8P///w9aBEAQCgALIABBEGogACABIAYgBCAFEDMLSAEBfiADrSAErUIghoQhCCMAQSBrIgMkAEF/IQQgAyAGIAcQMUUEQCAAIAEgAiAIIAUgAxAzIQQgA0EgEAcLIANBIGokACAEC48BAQJ/IwBBgARrIgUkACAFQSBqIgYgBEEgEC4aIAYgASACrSADrUIghoQQGxogBiAFQcADaiIBEC0gBSAFKQPYAzcDGCAFIAUpA9ADNwMQIAUgBSkDyAM3AwggBSAFKQPAAzcDACABQcAAEAcgACAFEEwhASAFIABBIBBBIAVBgARqJABBfyABIAAgBUYbcgtxAQF/IwBB4ANrIgUkACAFIARBIBAuGiAFIAEgAq0gA61CIIaEEBsaIAUgBUGgA2oiARAtIAAgBSkDuAM3ABggACAFKQOwAzcAECAAIAUpA6gDNwAIIAAgBSkDoAM3AAAgAUHAABAHIAVB4ANqJABBAAtbAQJ+IAetIAitQiCGhCEMQX8hAiAErSAFrUIghoQiC0IQWgRAIAAgAyALQhB9IAMgC6dqQRBrIAYgDCAJIAoQhwEhAgsgAQRAIAFCACALQhB9IAIbNwMACyACCyUAIAAgAiADrSAErUIghoQgBSAGIAetIAitQiCGhCAJIAoQhwELWQECfgJ/IAatIAetQiCGhCEMIAOtIAStQiCGhCILQvD///8PVARAIAAgACALp2pBACACIAsgBSAMIAkgChCIARogAQRAIAEgC0IQfDcDAAtBAAwBCxAKAAsLJwAgACABIAIgAyAErSAFrUIghoQgBiAHrSAIrUIghoQgCiALEIgBC1sBAn4gB60gCK1CIIaEIQxBfyECIAStIAWtQiCGhCILQhBaBEAgACADIAtCEH0gAyALp2pBEGsgBiAMIAkgChCCASECCyABBEAgAUIAIAtCEH0gAhs3AwALIAILJQAgACACIAOtIAStQiCGhCAFIAYgB60gCK1CIIaEIAkgChCCAQtbAQJ+IAetIAitQiCGhCEMQX8hAiAErSAFrUIghoQiC0IQWgRAIAAgAyALQhB9IAMgC6dqQRBrIAYgDCAJIAoQgwEhAgsgAQRAIAFCACALQhB9IAIbNwMACyACCyUAIAAgAiADrSAErUIghoQgBSAGIAetIAitQiCGhCAJIAoQgwELWQECfgJ/IAatIAetQiCGhCEMIAOtIAStQiCGhCILQvD///8PVARAIAAgACALp2pBACACIAsgBSAMIAkgChCEARogAQRAIAEgC0IQfDcDAAtBAAwBCxAKAAsLJwAgACABIAIgAyAErSAFrUIghoQgBiAHrSAIrUIghoQgCiALEIQBC1kBAn4CfyAGrSAHrUIghoQhDCADrSAErUIghoQiC0Lw////D1QEQCAAIAAgC6dqQQAgAiALIAUgDCAJIAoQhQEaIAEEQCABIAtCEHw3AwALQQAMAQsQCgALCycAIAAgASACIAMgBK0gBa1CIIaEIAYgB60gCK1CIIaEIAogCxCFAQtZAQJ+IAetIAitQiCGhCELQX8hAQJAIAOtIAStQiCGhCIMQt////8PVg0AIAtC3////w9WDQAgACACIAynIAVBICAGIAunIAkgCkHkuQIoAgARCgAhAQsgAQuAAQEDfiAHrSAIrUIghoQhDEF/IQICQCAErSAFrUIghoQiC0IgVA0AIAtCIH0iDULf////D1YNACAMQt////8PVg0AIAAgAyANpyADIAunakEga0EgIAYgDKcgCSAKQeS5AigCABEKACECCyABBEAgAUIAIAtCIH0gAhs3AwALIAILYAECfiAErSAFrUIghoQhDCAHrSAIrUIghoQhDSACBEAgAkIgNwMACyANQuD///8PVCAMQt////8PWHFFBEAQCgALIAAgAUEgIAMgDKcgBiANpyAKIAtB4LkCKAIAEQoAC3YBAn4CfyAGrSAHrUIghoQhCwJAIAOtIAStQiCGhCIMQuD///8PWg0AIAtC4P///w9aDQAgACAAIAynIgNqQSAgAiADIAUgC6cgCSAKQeC5AigCABEKACEAIAEEQCABQgAgDEIgfCAAGzcDAAsgAAwBCxAKAAsLWQECfiAHrSAIrUIghoQhC0F/IQECQCADrSAErUIghoQiDELf////D1YNACALQt////8PVg0AIAAgAiAMpyAFQSAgBiALpyAJIApB3LkCKAIAEQoAIQELIAELgAEBA34gB60gCK1CIIaEIQxBfyECAkAgBK0gBa1CIIaE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//8HSw0AIAEgA0EBdE0NAEEAIQEgAwR/A0AgACABQQF0aiIEIAEgAmotAAAiBUEPcSIGQQh0IAZB9v8DakGAsgNxakGArgFqQQh2OgABIAQgBUEEdiIEIARB9v8DakEIdkHZAXFqQdcAajoAACABQQFqIgEgA0cNAAsgA0EBdAVBAAsgAGpBADoAACAADwsQCgALCgAgACABIAIQMQsIACAAIAEQWwtaAQF/IwBBQGoiAyQAIAMgAkIgEC8aIAEgAykDGDcAGCABIAMpAxA3ABAgASADKQMINwAIIAEgAykDADcAACADQcAAEAcgACABQcy5AigCABEBACADQUBrJAALCwAgACABIAIQgQELCwAgACABIAIQigELCwAgACABIAIQiwELCQAgACABEI0BCwsAIAAgASACEI4BCwUAQcMICwQAQQwLJwEBfyMAQUBqIgMkACAAIAMQHCABIANCwAAgAkEBEF0gA0FAayQACykBAX8jAEFAaiIEJAAgACAEEBwgASACIARCwAAgA0EBEF4gBEFAayQACwgAIAAQJUEAC7sBAgJ/A34jAEHAAWsiAiQAIAJBIBAVIAEgAkIgEC8aIAEgAS0AAEH4AXE6AAAgASABLQAfQT9xQcAAcjoAHyACQSBqIgMgARBCIAAgAxBDIAEgAikDGDcAGCABIAIpAxA3ABAgASACKQMINwAIIAEgAikDADcAACAAKQAAIQQgACkACCEFIAApABAhBiABIAApABg3ADggASAGNwAwIAEgBTcAKCABIAQ3ACAgAkEgEAcgAkHAAWokAEEAC7YBAgF/A34jAEGgAWsiAyQAIAEgAkIgEC8aIAEgAS0AAEH4AXE6AAAgASABLQAfQT9xQcAAcjoAHyADIAEQQiAAIAMQQyACKQAAIQQgAikACCEFIAIpABAhBiABIAIpABg3ABggASAGNwAQIAEgBTcACCABIAQ3AAAgACkAACEEIAApAAghBSAAKQAQIQYgASAAKQAYNwA4IAEgBjcAMCABIAU3ACggASAENwAgIANBoAFqJABBAAsFAEG/fwsKACAAIAEQYEEAC20BAX8jAEFAaiICJAAgAiABQiAQLxogAiACLQAAQfgBcToAACACIAItAB9BP3FBwAByOgAfIAAgAikDEDcAECAAIAIpAwg3AAggACACKQMANwAAIAAgAikDGDcAGCACQcAAEAcgAkFAayQAQQALohYCFX8ofiMAQYACayIDJABBfyETAkAgARBYDQAgA0HgAGoiBCABEHkNACMAQYAQayICJAAgAkGABWoiASAEEBIgAiAEKQIgNwPgAiACIAQpAhg3A9gCIAIgBCkCEDcD0AIgAiAEKQIINwPIAiACIAQpAgA3A8ACIAIgBCkCKDcD6AIgAiAEKQIwNwPwAiACIAQpAjg3A/gCIAIgBEFAaykCADcDgAMgAiAEKQJINwOIAyACIAQpAlA3A5ADIAIgBCkCWDcDmAMgAiAEKQJgNwOgAyACIAQpAmg3A6gDIAIgBCkCcDcDsAMgAkHgA2oiBSACQcACaiIJECIgAkGgAWoiBCAFIAJB2ARqIgYQBiACQcgBaiACQYgEaiIHIAJBsARqIggQBiACQfABaiAIIAYQBiACQZgCaiAFIAcQBiAFIAQgARATIAkgBSAGEAYgAkHoAmoiCiAHIAgQBiACQZADaiILIAggBhAGIAJBuANqIgwgBSAHEAYgAkGgBmoiASAJEBIgBSAEIAEQEyAJIAUgBhAGIAogByAIEAYgCyAIIAYQBiAMIAUgBxAGIAJBwAdqIgEgCRASIAUgBCABEBMgCSAFIAYQBiAKIAcgCBAGIAsgCCAGEAYgDCAFIAcQBiACQeAIaiIBIAkQEiAFIAQgARATIAkgBSAGEAYgCiAHIAgQBiALIAggBhAGIAwgBSAHEAYgAkGACmoiASAJEBIgBSAEIAEQEyAJIAUgBhAGIAogByAIEAYgCyAIIAYQBiAMIAUgBxAGIAJBoAtqIgEgCRASIAUgBCABEBMgCSAFIAYQBiAKIAcgCBAGIAsgCCAGEAYgDCAFIAcQBiACQcAMaiIBIAkQEiAFIAQgARATIAkgBSAGEAYgCiAHIAgQBiALIAggBhAGIAwgBSAHEAYgAkHgDWogCRASIAJCADcDICACQgA3AxggAkIANwMQIAJCADcDCCACQgA3AwAgAkIANwIsIAJBATYCKCACQgA3AjQgAkIANwI8IAJCADcCRCACQoCAgIAQNwJMIAJB1ABqQQBBzAD8CwAgAkH4AGohCSACQdgPaiEPIAJBsA9qIRAgAkHQAGohDSACQShqIQ5B/AEhBANAIAIgAikDIDcDqA8gAiACKQMYNwOgDyACIAIpAxA3A5gPIAIgAikDCDcDkA8gAiACKQMANwOIDyAQIA4pAiA3AiAgECAOKQIYNwIYIBAgDikCEDcCECAQIA4pAgg3AgggECAOKQIANwIAIA8gDSkCIDcCICAPIA0pAhg3AhggDyANKQIQNwIQIA8gDSkCCDcCCCAPIA0pAgA3AgAgBCIBQZCFAmosAAAhESACQeADaiIFIAJBiA9qECICQCARQQBKBEAgAkHAAmoiBCAFIAYQBiAKIAcgCBAGIAsgCCAGEAYgDCAFIAcQBiAFIAQgAkGABWogEUH+AXFBAXZBoAFsahATDAELIBFBAE4NACACQcACaiIEIAJB4ANqIgUgBhAGIAogByAIEAYgCyAIIAYQBiAMIAUgBxAGIAUgBCACQYAFakEAIBFrQf4BcUEBdkGgAWxqEHcLIAIgAkHgA2oiEiAGEAYgDiAHIAgQBiANIAggBhAGIAkgEiAHEAYgAUEBayEEIAENAAsgAigCKCEUIAIoAlAhFSACKAIsIRYgAigCVCEGIAIoAjAhByACKAJYIQggAigCNCEKIAIoAlwhCyACKAI4IQwgAigCYCENIAIoAjwhDiACKAJkIQ8gAigCQCEQIAIoAmghESACKAJEIQUgAigCbCEJIAIoAkghBCACKAJwIQEgAiACKAJMIAIoAnRrNgKkBSACIAQgAWs2AqAFIAIgBSAJazYCnAUgAiAQIBFrNgKYBSACIA4gD2s2ApQFIAIgDCANazYCkAUgAiAKIAtrNgKMBSACIAcgCGs2AogFIAIgFiAGazYChAUgAiAUIBVrNgKABSASIAIQGiASQSAQKCEEIBIgAkGABWoQGiASQSAQKCACQYAQaiQAIARxRQ0AQQAhEyADQQAgAygCrAEiBms2AiQgA0EAIAMoAqgBIgxrNgIgIANBACADKAKkASIHazYCHCADQQAgAygCoAEiBWs2AhggA0EAIAMoApwBIghrNgIUIANBACADKAKYASIJazYCECADQQAgAygClAEiCms2AgwgA0EAIAMoApABIgRrNgIIIANBACADKAKMASILazYCBCADQQEgAygCiAEiAWs2AgAgAyADEEQgAyADKAIEIg2sIh8gCEEBdKwiKX4gAzQCACIZIAWsIhp+fCADKAIIIg6sIiEgCawiG358IAMoAgwiD6wiIyAKQQF0rCIqfnwgAygCECIQrCIlIASsIhx+fCADKAIUIhGsIisgC0EBdKwiLH58IAMoAhgiBawiNSABQQFqrCIdfnwgAygCHCIJQRNsrCIkIAZBAXSsIi1+fCADKAIgIgRBE2ysIiIgDKwiHn58IAMoAiQiAUETbKwiICAHQQF0rCIufnwgGyAffiAZIAisIi9+fCAhIAqsIjB+fCAcICN+fCAlIAusIjF+fCAdICt+fCAFQRNsrCImIAasIjJ+fCAeICR+fCAiIAesIjN+fCAaICB+fCAfICp+IBkgG358IBwgIX58ICMgLH58IB0gJX58IBFBE2ysIjQgLX58IB4gJn58ICQgLn58IBogIn58ICAgKX58IjdCgICAEHwiOEIah3wiOUKAgIAIfCI6QhmHfCIXIBdCgICAEHwiJ0KAgIDgD4N9PgJIIAMgHyAsfiAZIBx+fCAdICF+fCAPQRNsrCIYIC1+fCAQQRNsrCIoIB5+fCAuIDR+fCAaICZ+fCAkICl+fCAbICJ+fCAgICp+fCAdIB9+IBkgMX58IA5BE2ysIhcgMn58IBggHn58ICggM358IBogNH58ICYgL358IBsgJH58ICIgMH58IBwgIH58IA1BE2ysIC1+IBkgHX58IBcgHn58IBggLn58IBogKH58ICkgNH58IBsgJn58ICQgKn58IBwgIn58ICAgLH58IjtCgICAEHwiPEIah3wiPUKAgIAIfCI+QhmHfCIXIBdCgICAEHwiGEKAgIDgD4N9PgI4IAMgGiAffiAZIDN+fCAhIC9+fCAbICN+fCAlIDB+fCAcICt+fCAxIDV+fCAJrCI2IB1+fCAiIDJ+fCAeICB+fCAnQhqHfCIXIBdCgICACHwiJ0KAgIDwD4N9PgJMIAMgHCAffiAZIDB+fCAhIDF+fCAdICN+fCAoIDJ+fCAeIDR+fCAmIDN+fCAaICR+fCAiIC9+fCAbICB+fCAYQhqHfCIXIBdCgICACHwiGEKAgIDwD4N9PgI8IAMgHyAufiAZIB5+fCAaICF+fCAjICl+fCAbICV+fCAqICt+fCAcIDV+fCAsIDZ+fCAErCIoIB1+fCAgIC1+fCAnQhmHfCIXIBdCgICAEHwiJ0KAgIDgD4N9PgJQIAMgOSA6QoCAgPAPg30gNyA4QoCAgGCDfSAYQhmHfCIYQoCAgBB8IhdCGoh8PgJEIAMgGCAXQoCAgOAPg30+AkAgAyAeIB9+IBkgMn58ICEgM358IBogI358ICUgL358IBsgK358IDAgNX58IBwgNn58ICggMX58IAGsIB1+fCAnQhqHfCIXIBdCgICACHwiF0KAgIDwD4N9PgJUIAMgPSA+QoCAgPAPg30gOyA8QoCAgGCDfSAXQhmHQhN+fCIYQoCAgBB8IhdCGoh8PgI0IAMgGCAXQoCAgOAPg30+AjAgACADQTBqEBoLIANBgAJqJAAgEwsLACAAIAEgAhCGAQsEAEEECwQAQRoLBQBBrwoLDAAgACABIAIQYkEACxIAIAAgASACQZS6AigCABEEAAsSACAAIAEgAkGQugIoAgARBAALEgAgACABIAJBjLoCKAIAEQQACxQAIAAgASACIANBiLoCKAIAEQsACxIAIAAgASACQYS6AigCABEEAAsUACAAIAEgAiADQYC6AigCABELAAsSACAAIAEgAkH8uQIoAgARBAALtAEBAX8gACABKAAAQf///x9xNgIAIAAgASgAA0ECdkGD/v8fcTYCBCAAIAEoAAZBBHZB/4H/H3E2AgggACABKAAJQQZ2Qf//wB9xNgIMIAEoAAwhAiAAQgA3AhQgAEIANwIcIABBADYCJCAAIAJBCHZB//8/cTYCECAAIAEoABA2AiggACABKAAUNgIsIAAgASgAGDYCMCABKAAcIQEgAEEAOgBQIABCADcDOCAAIAE2AjRBAAvFKAELfyMAQRBrIgokAAJAAkACQAJAAkACQAJAAkACQAJAIABB9AFNBEBB1MACKAIAIgRBECAAQQtqQfgDcSAAQQtJGyIGQQN2IgB2IgFBA3EEQAJAIAFBf3NBAXEgAGoiA0EDdCIBQfzAAmoiACABKAKEwQIiAigCCCIFRgRAQdTAAiAEQX4gA3dxNgIADAELIAUgADYCDCAAIAU2AggLIAJBCGohACACIAFBA3I2AgQgASACaiIBIAEoAgRBAXI2AgQMCwsgBkHcwAIoAgAiCE0NASABBEACQEECIAB0IgJBACACa3IgASAAdHFoIgNBA3QiAUH8wAJqIgIgASgChMECIgAoAggiBUYEQEHUwAIgBEF+IAN3cSIENgIADAELIAUgAjYCDCACIAU2AggLIAAgBkEDcjYCBCAAIAZqIgcgASAGayIFQQFyNgIEIAAgAWogBTYCACAIBEAgCEF4cUH8wAJqIQFB6MACKAIAIQIC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QZAIaiEUIANBgAhqIRUgA0GgCGohFkEAIQdBACEIA0AgAyADKAKMByACczYCrAUgAyANQf8BcSATQRh0IhcgD0H/AXFBEHRyIA5B/wFxQQh0cnIiBCADKAKIB3M2AqgFIAMgCkH/AXEgEkEYdCIYIAxB/wFxQRB0ciALQf8BcUEIdHJyIgkgAygChAdzNgKkBSADIBFB/wFxIAZBGHQiGSAIQf8BcUEQdHIgB0H/AXFBCHRyciIQIAMoAoAHczYCoAUgAyADKALcBSACczYCnAUgAyADKALYBSAEczYCmAUgAyADKALUBSAJczYClAUgAyADKALQBSAQczYCkAUgAyADKQOoBTcD+AQgAyADKQOgBTcD8AQgAyADKQKYBzcD6AQgAyADKQKQBzcD4AQgA0GABWoiBCADQfAEaiADQeAEahAFIAMgAykCiAU3A6gFIAMgAykCgAU3A6AFIAMgAykDkAU3A9AEIAMgAykDmAU3A9gEIAMgAykC4AU3A8AEIAMgAykC6AU3A8gEIAQgA0HQBGogA0HABGoQBSADIAMpAogFNwOYBSADIAMpAoAFNwOQBSADIAMpA6AFNwOwBCADIAMpA6gFNwO4BCADIAMpAqAHNwOgBCADIAMpAqgHNwOoBCAEIANBsARqIANBoARqEAUgAyADKQKIBTcDqAUgAyADKQKABTcDoAUgAyADKQOQBTcDkAQgAyADKQOYBTcDmAQgAyADKQLwBTcDgAQgAyADKQL4BTcDiAQgBCADQZAEaiADQYAEahAFIAMgAykCiAU3A5gFIAMgAykCgAU3A5AFIAMgAykDoAU3A/ADIAMgAykDqAU3A/gDIAMgAykCsAc3A+ADIAMgAykCuAc3A+gDIAQgA0HwA2ogA0HgA2oQBSADIAMpAogFNwOoBSADIAMpAoAFNwOgBSADIAMpA5AFNwPQAyADIAMpA5gFNwPYAyADIAMpAoAGNwPAAyADIAMpAogGNwPIAyAEIANB0ANqIANBwANqEAUgAyADKQKIBTcDmAUgAyADKQKABTcDkAUgAyADKQOgBTcDsAMgAyADKQOoBTcDuAMgAyADKQLABzcDoAMgAyADKQLIBzcDqAMgBCADQbADaiADQaADahAFIAMgAykCiAU3A6gFIAMgAykCgAU3A6AFIAMgAykDkAU3A5ADIAMgAykDmAU3A5gDIAMgAykCkAY3A4ADIAMgAykCmAY3A4gDIAQgA0GQA2ogA0GAA2oQBSADIAMpAogFNwOYBSADIAMpAoAFNwOQBSADIAMpA6AFNwPwAiADIAMpA6gFNwP4AiADIAMpAtAHNwPgAiADIAMpAtgHNwPoAiAEIANB8AJqIANB4AJqEAUgAyADKQKIBTcDqAUgAyADKQKABTcDoAUgAyADKQOQBTcD0AIgAyADKQOYBTcD2AIgAyADKQKgBjcDwAIgAyADKQKoBjcDyAIgBCADQdACaiADQcACahAFIAMgAykCiAU3A5gFIAMgAykCgAU3A5AFIAMgAykDoAU3A7ACIAMgAykDqAU3A7gCIAMgAykC4Ac3A6ACIAMgAykC6Ac3A6gCIAQgA0GwAmogA0GgAmoQBSADIAMpAogFNwOoBSADIAMpAoAFNwOgBSADIAMpA5AFNwOQAiADIAMpA5gFNwOYAiADIAMpArAGNwOAAiADIAMpArgGNwOIAiAEIANBkAJqIANBgAJqEAUgAyADKQKIBTcDmAUgAyADKQKABTcDkAUgAyADKQOgBTcD8AEgAyADKQOoBTcD+AEgAyADKQLwBzcD4AEgAyADKQL4BzcD6AEgBCADQfABaiADQeABahAFIAMgAykCiAU3A6gFIAMgAykCgAU3A6AFIAMgAykDkAU3A9ABIAMgAykDmAU3A9gBIAMgAykCwAY3A8ABIAMgAykCyAY3A8gBIAQgA0HQAWogA0HAAWoQBSADIAMpAogFNwOYBSADIAMpAoAFNwOQBSADIAMpA6AFNwOwASADIAMpA6gFNwO4ASADIBUpAgA3A6ABIAMgFSkCCDcDqAEgBCADQbABaiADQaABahAFIAMgAykCiAU3A6gFIAMgAykCgAU3A6AFIAMgAykDkAU3A5ABIAMgAykDmAU3A5gBIAMgAykC0AY3A4ABIAMgAykC2AY3A4gBIAQgA0GQAWogA0GAAWoQBSADIAMpAogFNwOYBSADIAMpAoAFNwOQBSADIAMpA6AFNwNwIAMgAykDqAU3A3ggAyAUKQIANwNgIAMgFCkCCDcDaCAEIANB8ABqIANB4ABqEAUgAyADKQKIBTcDqAUgAyADKQKABTcDoAUgAyADKQOQBTcDUCADIAMpA5gFNwNYIAMgAykC4AY3A0AgAyADKQLoBjcDSCAEIANB0ABq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BzcD6AMgBCADQfADaiADQeADahAFIAMgAykCiAU3A6gFIAMgAykCgAU3A6AFIAMgAykDkAU3A9ADIAMgAykDmAU3A9gDIAMgAykCgAY3A8ADIAMgAykCiAY3A8gDIAQgA0HQA2ogA0HAA2oQBSADIAMpAogFNwOYBSADIAMpAoAFNwOQBSADIAMpA6AFNwOwAyADIAMpA6gFNwO4AyADIAMpAsAHNwOgAyADIAMpAsgHNwOoAyAEIANBsANqIANBoANqEAUgAyADKQKIBTcDqAUgAyADKQKABTcDoAUgAyADKQOQBTcDkAMgAyADKQOYBTcDmAMgAyADKQKQBjcDgAMgAyADKQKYBjcDiAMgBCADQZADaiADQYADahAFIAMgAykCiAU3A5gFIAMgAykCgAU3A5AFIAMgAykDoAU3A/ACIAMgAykDqAU3A/gCIAMgAykC0Ac3A+ACIAMgAykC2Ac3A+gCIAQgA0HwAmogA0HgAmoQBSADIAMpAogFNwOoBSADIAMpAoAFNwOgBSADIAMpA5AFNwPQAiADIAMpA5gFNwPYAiADIAMpAqAGNwPAAiADIAMpAqgGNwPIAiAEIANB0AJqIANBwAJqEAUgAyADKQKIBTcDmAUgAyADKQKABTcDkAUgAyADKQOgBTcDsAIgAyADKQOoBTcDuAIgAyADKQLgBzcDoAIgAyADKQLoBzcDqAIgBCADQbACaiADQaACahAFIAMgAykCiAU3A6gFIAMgAykCgAU3A6AFIAMgAykDkAU3A5ACIAMgAykDmAU3A5gCIAMgAykCsAY3A4ACIAMgAykCuAY3A4gCIAQgA0GQAmogA0GAAmoQBSADIAMpAogFNwOYBSADIAMpAoAFNwOQBSADIAMpA6AFNwPwASADIAMpA6gFNwP4ASADIAMpAvAHNwPgASADIAMpAvgHNwPoASAEIANB8AFqIANB4AFqEAUgAyADKQKIBTcDqAUgAyADKQKABTcDoAUgAyADKQOQBTcD0AEgAyADKQOYBTcD2AEgAyADKQLABjcDwAEgAyADKQLIBjcDyAEgBCADQdABaiADQcABahAFIAMgAykCiAU3A5gFIAMgAykCgAU3A5AFIAMgAykDoAU3A7ABIAMgAykDqAU3A7gBIAMgFSkCADcDoAEgAyAVKQIINwOoASAEIANBsAFqIANBoAFqEAUg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AiAEIAMtAAdB2gBzOgDHAiAEIAMtAAhB2gBzOgDIAiAEIAMtAAlB2gBzOgDJAiAEIAMtAApB2gBzOgDKAiAEIAMtAAtB2gBzOgDLAiAEIAMtAAxB2gBzOgDMAiAEIAMtAA1B2gBzOgDNAiAEIAMtAA5B2gBzOgDOAiAEIAMtAA9B2gBzOgDPAiAJIARBwAJqEBELIAAgAikACDcACCAAIAIpAAA3AAAgBEHgBWogAiAEQYAEahCJASABKAAIIQIgASgADCEDIAEoAAAhBSAEIAQoAuQFIgYgASgABCAEKALUAnNzNgLUBSAEIAQoAuAFIgEgBSAEKALQAnNzNgLQBSAEIAQoAuwFIgUgAyAEKALcAnNzNgLcBSAEIAQoAugFIgMgAiAEKALYAnNzNgLYBSAEIAQpA9AFNwOwAiAEIAQpA9gFNwO4AiAEIAQpA+gCNwOoAiAEIAQpA+ACNwOgAiAEQcAFaiICIARBsAJqIARBoAJqEAUgBCAEKQLIBSIKNwPYBSAEIAQpAsAFIgs3A9AFIAQgCzcDkAIgBCAKNwOYAiAEIAQpA/ACNwOAAiAEIAQpA/gCNwOIAiACIARBkAJqIARBgAJqEAUgBCAEKQLIBSIKNwPYBSAEIAQpAsAFIgs3A9AFIAQgCzcD8AEgBCAKNwP4ASAEIAQpA4ADNwPgASAEIAQpA4gDNwPoASACIARB8AFqIARB4AFqEAUgBCAEKQLIBSIKNwPYBSAEIAQpAsAFIgs3A9AFIAQgCzcD0AEgBCAKNwPYASAEIAQpA5ADNwPAASAEIAQpA5gDNwPIASACIARB0AFqIARBwAFqEAUgBCAEKQLIBSIKNwPYBSAEIAQpAsAFIgs3A9AFIAQgCzcDsAEgBCAKNwO4ASAEIAQpAqADNwOgASAEIAQpAqgDNwOoASACIARBsAFqIARBoAFqEAUgBCAEKQLIBSIKNwPYBSAEIAQpAsAFIgs3A9AFIAQgCzcDkAEgBCAKNwOYASAEIAQpA7ADNwOAASAEIAQpA7gDNwOIASACIARBkAFqIARBgAFqEAUgBCAEKQLIBSIKNwPYBSAEIAQpAsAFIgs3A9AFIAQgCzcDcCAEIAo3A3ggBCAEKQPAAzcDYCAEIAQpA8gDNwNoIAIgBEHwAGogBEHgAGoQBSAEIAQpAsgFIgo3A9gFIAQgBCkCwAUiCzcD0AUgBCALNwNQIAQgCjcDWCAEIAQpA9ADNwNAIAQgBCkD2AM3A0ggAiAEQdAAaiAEQUBrEAUgBCAEKQLIBSIKNwPYBSAEIAQpAsAFIgs3A9AFIAQgCzcDMCAEIAo3AzggBCAEKQPgAzcDICAEIAQpA+gDNwMoIAIgBEEwaiAEQSBqEAUgBCAFIAQoAvwDczYCvAUgBCADIAQoAvgDczYCuAUgBCAGIAQoAvQDczYCtAUgBCABIAQoAvADczYCsAUgBCAEKQLIBSIKNwPYBSAEIAQpAsAFIgs3A9AFIAQgCzcDECAEIAo3AxggBCAEKQK4BTcDCCAEIAQpArAFNwMAIAIgBEEQaiAEECEgBCAEKQLIBSIKNwPYBSAEIAQpAsAFIgs3A9AFIAAgCjcAGCAAIAs3ABAgBEHwBWokAAvZDgIHfwJ+IwBBkAZrIgMkACADQdACaiIEIAIQESADIAEvAAAiAjYC0AQgAyABLwACIgY2AtQEIAMgAS8ABCIHNgLYBCADIAEvAAYiCDYC3AQgAyADKQLQBDcDwAIgAyADKQLYBDcDyAIgAyADKALAAhAINgLABCADIAMoAsQCEAg2AsQEIAMgAygCyAIQCDYCyAQgAyADKALMAhAINgLMBCADQeAEaiIFIARBsAH8CgAAIAUQViABKAAQIQQgASgAFCEFIAEoAAghCSADIAYgASgADCADKAKEBnNzNgK0BCADIAIgCSADKAKABnNzNgKwBCADIAggBSADKAKMBnNzNgK8BCADIAcgBCADKAKIBnNzNgK4BCADIAMoAsQEIAMoAvQFczYClAQgAyADKALABCADKALwBXM2ApAEIAMoAvgFIQEgAygCyAQhBCADIAMoAswEIAMoAvwFczYCnAQgAyABIARzNgKYBCADIAMpA7gENwO4AiADIAMpA7AENwOwAiADIAMpApgENwOoAiADIAMpApAENwOgAiADQaAEaiIBIANBsAJqIANBoAJqEAsgAyADKQKoBCIKNwO4BCADIAMpAqAEIgs3A7AEIAMgAygCxAQgAygC5AVzNgKUBCADIAMoAsAEIAMoAuAFczYCkAQgAyADKALMBCADKALsBXM2ApwEIAMgAygCyAQgAygC6AVzNgKYBCADIAo3A5gCIAMgCzcDkAIgAyADKQKYBDcDiAIgAyADKQKQBDcDgAIgASADQZACaiADQYACahALIAMgAykCqAQiCjcDuAQgAyADKQKgBCILNwOwBCADIAMoAsQEIAMoAtQFczYClAQgAyADKALABCADKALQBXM2ApAEIAMgAygCzAQgAygC3AVzNgKcBCADIAMoAsgEIAMoAtgFczYCmAQgAyAKNwP4ASADIAs3A/ABIAMgAykCmAQ3A+gBIAMgAykCkAQ3A+ABIAEgA0HwAWogA0HgAWoQCyADIAMpAqgEIgo3A7gEIAMgAykCoAQiCzcDsAQgAyADKALEBCADKALEBXM2ApQEIAMgAygCwAQgAygCwAVzNgKQBCADIAMoAswEIAMoAswFczYCnAQgAyADKALIBCADKALIBXM2ApgEIAMgCjcD2AEgAyALNwPQASADIAMpApgENwPIASADIAMpApAENwPAASABIANB0AFqIANBwAFqEAsgAyADKQKoBCIKNwO4BCADIAMpAqAEIgs3A7AEIAMgAygCxAQgAygCtAVzNgKUBCADIAMoAsAEIAMoArAFczYCkAQgAyADKALMBCADKAK8BXM2ApwEIAMgAygCyAQgAygCuAVzNgKYBCADIAo3A7gBIAMgCzcDsAEgAyADKQKYBDcDqAEgAyADKQKQBDcDoAEgASADQbABaiADQaABahALIAMgAykCqAQiCjcDuAQgAyADKQKgBCILNwOwBCADIAMoAsQEIAMoAqQFczYClAQgAyADKALABCADKAKgBXM2ApAEIAMgAygCzAQgAygCrAVzNgKcBCADIAMoAsgEIAMoAqgFczYCmAQgAyAKNwOYASADIAs3A5ABIAMgAykCmAQ3A4gBIAMgAykCkAQ3A4ABIAEgA0GQAWogA0GAAWoQCyADIAMpAqgEIgo3A7gEIAMgAykCoAQiCzcDsAQgAyADKALEBCADKAKUBXM2ApQEIAMgAygCwAQgAygCkAVzNgKQBCADIAMoAswEIAMoApwFczYCnAQgAyADKALIBCADKAKYBXM2ApgEIAMgCjcDeCADIAs3A3AgAyADKQKYBDcDaCADIAMpApAENwNgIAEgA0HwAGogA0HgAGoQCyADIAMpAqgEIgo3A7gEIAMgAykCoAQiCzcDsAQgAyADKALEBCADKAKEBXM2ApQEIAMgAygCwAQgAygCgAVzNgKQBCADIAMoAswEIAMoAowFczYCnAQgAyADKALIBCAD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KCAEIAQpAoAENwMgIAEgBEEwaiAEQSBqEAUgBCAFIAQoAuwDczYC/AMgBCADIAQoAugDczYC+AMgBCACIAQoAuQDczYC9AMgBCAGIAQoAuADczYC8AMgBCAEKQKYBCIKNwOoBCAEIAQpApAEIgs3A6AEIAQgCzcDECAEIAo3AxggBCAEKQL4AzcDCCAEIAQpAvADNwMAIAEgBEEQaiAEECEgBCAEKQKYBCIKNwOoBCAEIAQpApAEIgs3A6AEIAAgCjcAECAAIAs3AAggBEGwBGokAAvZBwIDfwJ+IwBBwAVrIgMkACADQcACaiIEIAIQESADQZAEaiICIARBsAH8CgAAIAIQViABKAAIIQIgASgADCEEIAEoAAAhBSADIAMoArQFIAEoAARzNgKEBCADIAUgAygCsAVzNgKABCADIAQgAygCvAVzNgKMBCADIAIgAygCuAVzNgKIBCADIAMpA6AFNwOgAiADIAMpA6gFNwOoAiADIAMpA4AENwOwAiADIAMpA4gENwO4AiADQfADaiIBIANBsAJqIANBoAJqEAsgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDkAIgAyAGNwOYAiADIAMpA5AFNwOAAiADIAMpA5gFNwOIAiABIANBkAJqIANBgAJqEAsgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcD8AEgAyAGNwP4ASADIAMpA4AFNwPgASADIAMpA4gFNwPoASABIANB8AFqIANB4AFqEAsgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcD0AEgAyAGNwPYASADIAMpA/AENwPAASADIAMpA/gENwPIASABIANB0AFqIANBwAFqEAsgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDsAEgAyAGNwO4ASADIAMpA+AENwOgASADIAMpA+gENwOoASABIANBsAFqIANBoAFqEAsgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDkAEgAyAGNwOYASADIAMpA9AENwOAASADIAMpA9gENwOIASABIANBkAFqIANBgAFqEAsgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDcCADIAY3A3ggAyADKQPABDcDYCADIAMpA8gENwNoIAEgA0HwAGogA0HgAGoQCyADIAMpAvgDIgY3A4gEIAMgAykC8AMiBzcDgAQgAyAHNwNQIAMgBjcDWCADIAMpA7AENwNAIAMgAykDuAQ3A0ggASADQdAAaiADQUBrEAsgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDMCADIAY3AzggAyADKQOgBDcDICADIAMpA6gENwMoIAEgA0EwaiADQSBqEAsgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDECADIAY3AxggAyADKQOQBDcDACADIAMpA5gENwMIIAEgA0EQaiADEFUgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAAgBjcACCAAIAc3AAAgA0HABWokAAvkAQEDfyMAIgVBwAFrQUBxIgQkACAEIAMoAABB////H3E2AkAgBCADKAADQQJ2QYP+/x9xNgJEIAQgAygABkEEdkH/gf8fcTYCSCAEIAMoAAlBBnZB///AH3E2AkwgAygADCEGIARCADcCVCAEQgA3AlwgBEEANgJkIAQgBkEIdkH//z9xNgJQIAQgAygAEDYCaCAEIAMoABQ2AmwgBCADKAAYNgJwIAMoABwhAyAEQQA6AJABIARCADcDeCAEIAM2AnQgBEFAayIDIAEgAhBiIAMgBEEwaiIBEGAgACABECsgBSQAC8IHAgN/An4jAEGQBGsiAyQAIANBwAJqIAIQESABKAAIIQIgASgADCEEIAEoAAAhBSADIAMoAsQCIAEoAARzNgKEBCADIAUgAygCwAJzNgKABCADIAQgAygCzAJzNgKMBCADIAIgAygCyAJzNgKIBCADIAMpA4AENwOwAiADIAMpA4gENwO4AiADIAMpA9ACNwOgAiADIAMpA9gCNwOoAiADQfADaiIBIANBsAJqIANBoAJqEAUgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDkAIgAyAGNwOYAiADIAMpA+ACNwOAAiADIAMpA+gCNwOIAiABIANBkAJqIANBgAJqEAUgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcD8AEgAyAGNwP4ASADIAMpA/ACNwPgASADIAMpA/gCNwPoASABIANB8AFqIANB4AFqEAUgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcD0AEgAyAGNwPYASADIAMpA4ADNwPAASADIAMpA4gDNwPIASABIANB0AFqIANBwAFqEAUgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDsAEgAyAGNwO4ASADIAMpA5ADNwOgASADIAMpA5gDNwOoASABIANBsAFqIANBoAFqEAUgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDkAEgAyAGNwOYASADIAMpA6ADNwOAASADIAMpA6gDNwOIASABIANBkAFqIANBgAFqEAUgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDcCADIAY3A3ggAyADKQOwAzcDYCADIAMpA7gDNwNoIAEgA0HwAGogA0HgAGoQBSADIAMpAvgDIgY3A4gEIAMgAykC8AMiBzcDgAQgAyAHNwNQIAMgBjcDWCADIAMpA8ADNwNAIAMgAykDyAM3A0ggASADQdAAaiADQUBrEAUgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDMCADIAY3AzggAyADKQPQAzcDICADIAMpA9gDNwMoIAEgA0EwaiADQSBqEAUgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAMgBzcDECADIAY3AxggAyADKQPgAzcDACADIAMpA+gDNwMIIAEgA0EQaiADECEgAyADKQL4AyIGNwOIBCADIAMpAvADIgc3A4AEIAAgBjcACCAAIAc3AAAgA0GQBGokAAsLACAAIAEgAhCRAQsMACAAIAEgAiADEGMLKgEBfyMAQSBrIgMkACADQSAQFSAAIAEgAiADEGMgA0EgEAcgA0EgaiQACy0BAX8jAEFAaiICJAAgAkHAABAVIAAgASACEDUaIAJBwAAQByACQUBrJABBAAsKACAAIAEgAhA1CwUAQcAICwUAQeASCwUAQaAJCwoAIAAgASACEEoL1QEBA38jACIFQYABa0FAcSIEJAAgBCADKAAAQf///x9xNgIAIAQgAygAA0ECdkGD/v8fcTYCBCAEIAMoAAZBBHZB/4H/H3E2AgggBCADKAAJQQZ2Qf//wB9xNgIMIAMoAAwhBiAEQgA3AhQgBEIANwIcIARBADYCJCAEIAZBCHZB//8/cTYCECAEIAMoABA2AiggBCADKAAUNgIsIAQgAygAGDYCMCADKAAcIQMgBEEAOgBQIARCADcDOCAEIAM2AjQgBCABIAIQYiAEIAAQYCAFJABBAAssACAAQQBByAH8CwAgAEEAOgDsASAAQcAANgLoASAAQoCAgICACTcD4AFBAAsrACAAQQBByAH8CwAgAEEAOgDsASAAQSA2AugBIABCgICAgIARNwPgAUEACwUAQeA/C6sCAgR/AX4jAEGAAmsiBSQAIAVBAToADwJ/IAFB4D9NBEAgAUEgTwRAIAOtIQlBICEGA0AgBiEHIAVBMGoiBiAEQSAQThogCARAIAYgACAIakEga0IgECMaCyAFQTBqIgYgAiAJECMaIAYgBUEPakIBECMaIAYgACAIahBNIAUgBS0AD0EBajoADyAHIQggB0EgaiIGIAFNDQALCyABQR9xIgEEQCAFQTBqIgggBEEgEE4aIAcEQCAIIAAgB2pBIGtCIBAjGgsgBUEwaiIEIAIgA60QIxogBCAFQQ9qQgEQIxogBCAFQRBqIgIQTSABBEAgACAHaiACIAH8CgAACyAFQRBqQSAQBwsgBUEwakHQARAHQQAMAQtB0MACQRw2AgBBfwsgBUGAAmokAAs4AQF/IwBB0AFrIgUkACAFIAEgAhBOGiAFIAMgBK0QIxogBSAAEE0gBUHQARAHIAVB0AFqJABBAAsRACAAIAEQTSAAQdABEAdBAAsLACAAIAEgAq0QIwsKACAAIAEgAhBOCwoAIAAgASACECQLBABBAwsEAEECCwQAQW4LBABBEQsEAEE0C58BAgF/AX4jAEEwayIBJAAgASAAKQAYNwMYIAEgACkAEDcDECABIAApAAg3AwggASAAKQAANwMAIAEgACkAJDcDICABIAFCKCAAQSBqQQAgAEH0uQIoAgARDgAaIAAgASkDGDcAGCAAIAEpAxA3ABAgACABKQMINwAIIAAgASkDADcAACABKQMgIQIgAEEBNgAgIAAgAjcAJCABQTBqJAALKgEBfiAAIAEgAhBUIABBATYAICABKQAQIQMgAEIANwAsIAAgAzcAJEEACzABAX4gAUEYEBUgACABIAIQVCAAQQE2ACAgASkAECEDIABCADcALCAAIAM3ACRBAAsMACAAIAEgAiADEDkLBQBBgAMLBQBBoAMLBgBBwP8AC7gCAgR/AX4jAEHwA2siBSQAIAVBAToADwJ/IAFBwP8ATQRAIAFBwABPBEAgA60hCUHAACEGA0AgBiEHIAVB0ABqIgYgBEHAABAuGiAIBEAgBiAAIAhqQUBqQsAAEBsaCyAFQdAAaiIGIAIgCRAbGiAGIAVBD2pCARAbGiAGIAAgCGoQLSAFIAUtAA9BAWo6AA8gByEIIAdBQGsiBiABTQ0ACwsgAUE/cSIBBEAgBUHQAGoiCCAEQcAAEC4aIAcEQCAIIAAgB2pBQGpCwAAQGxoLIAVB0ABqIgQgAiADrRAbGiAEIAVBD2pCARAbGiAEIAVBEGoiAhAtIAEEQCAAIAdqIAIgAfwKAAALIAVBEGpBwAAQBwsgBUHQAGpBoAMQB0EADAELQdDAAkEcNgIAQX8LIAVB8ANqJAALCQAgAEHAABAVCzgBAX8jAEGgA2siBSQAIAUgASACEC4aIAUgAyAErRAbGiAFIAAQLSAFQaADEAcgBUGgA2okAEEACxEAIAAgARAtIABBoAMQB0EACwsAIAAgASACrRAbCwoAIAAgASACEC4LC7SuAg4AQYAIC7UCanMAcmFuZG9tYnl0ZXMAYjY0X3BvcyA8PSBiNjRfbGVuAGNyeXB0b19nZW5lcmljaGFzaF9ibGFrZTJiX2ZpbmFsAHh3aW5nAHJhbmRvbWJ5dGVzL3JhbmRvbWJ5dGVzLmMAc29kaXVtL2NvZGVjcy5jAGNyeXB0b19nZW5lcmljaGFzaC9ibGFrZTJiL3JlZi9ibGFrZTJiLXJlZi5jAGNyeXB0b19nZW5lcmljaGFzaC9ibGFrZTJiL3JlZi9nZW5lcmljaGFzaF9ibGFrZTJiLmMAYnVmX2xlbiA8PSBTSVpFX01BWABvdXRsZW4gPD0gVUlOVDhfTUFYAFMtPmJ1ZmxlbiA8PSBCTEFLRTJCX0JMT0NLQllURVMAc29kaXVtX2JpbjJiYXNlNjQAMS4wLjIyAEHACgtXtnhZ/4Vy0wC9bhX/DwpqACnAAQCY6Hn/vDyg/5lxzv8At+L+tA1I/wAAAAAAAAAAsKAO/tPJhv+eGI8Af2k1AGAMvQCn1/v/n0yA/mpl4f8e/AQAkgyuAEGgCwsnWfGy/grlpv973Sr+HhTUAFKAAwAw0fMAd3lA/zLjnP8AbsUBZxuQAEHQCwvAB4U7jAG98ST/+CXDAWDcNwC3TD7/w0I9ADJMpAHhpEz/TD2j/3U+HwBRkUD/dkEOAKJz1v8Gii4AfOb0/wqKjwA0GsIAuPRMAIGPKQG+9BP/e6p6/2KBRAB51ZMAVmUe/6FnmwCMWUP/7+W+AUMLtQDG8In+7kW8/0OX7gATKmz/5VVxATJEh/8RagkAMmcB/1ABqAEjmB7/EKi5AThZ6P9l0vwAKfpHAMyqT/8OLu//UE3vAL3WS/8RjfkAJlBM/75VdQBW5KoAnNjQAcPPpP+WQkz/r+EQ/41QYgFM2/IAxqJyAC7amACbK/H+m6Bo/zO7pQACEa8AQlSgAfc6HgAjQTX+Rey/AC2G9QGje90AIG4U/zQXpQC61kcA6bBgAPLvNgE5WYoAUwBU/4igZABcjnj+aHy+ALWxPv/6KVUAmIIqAWD89gCXlz/+74U+ACA4nAAtp73/joWzAYNW0wC7s5b++qoO/9KjTgAlNJcAY00aAO6c1f/VwNEBSS5UABRBKQE2zk8AyYOS/qpvGP+xITL+qybL/073dADR3ZkAhYCyATosGQDJJzsBvRP8ADHl0gF1u3UAtbO4AQBy2wAwXpMA9Sk4AH0NzP70rXcALN0g/lTqFAD5oMYB7H7q/y9jqP6q4pn/ZrPYAOKNev96Qpn+tvWGAOPkGQHWOev/2K04/7Xn0gB3gJ3/gV+I/25+MwACqbf/B4Ji/kWwXv90BOMB2fKR/8qtHwFpASf/Lq9FAOQvOv/X4EX+zzhF/xD+i/8Xz9T/yhR+/1/VYP8JsCEAyAXP//EqgP4jIcD/+OXEAYEReAD7Z5f/BzRw/4w4Qv8o4vX/2UYl/qzWCf9IQ4YBksDW/ywmcABEuEv/zlr7AJXrjQC1qjoAdPTvAFydAgBmrWIA6YlgAX8xywAFm5QAF5QJ/9N6DAAihhr/28yIAIYIKf/gUyv+VRn3AG1/AP6piDAA7nfb/+et1QDOEv7+CLoH/34JBwFvKkgAbzTs/mA/jQCTv3/+zU7A/w5q7QG720wAr/O7/mlZrQBVGVkBovOUAAJ20f4hngkAi6Mu/11GKABsKo7+b/yO/5vfkAAz5af/Sfyb/150DP+YoNr/nO4l/7Pqz//FALP/mqSNAOHEaAAKIxn+0dTy/2H93v64ZeUA3hJ/AaSIh/8ez4z+kmHzAIHAGv7JVCH/bwpO/5NRsv8EBBgAoe7X/waNIQA11w7/KbXQ/+eLnQCzy93//7lxAL3irP9xQtb/yj4t/2ZACP9OrhD+hXVE/wBBsBMLAQEAQdATC7ABJuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/AXHF2pwPU3YT7o8C3YNEGcPKiBT+iw5zMZOx/13kqwDeuz///////////////////////////////////////9/7f///////////////////////////////////////3/u////////////////////////////////////////f+3T9VwaYxJY1pz3ot753hQAQY8VC/zwARCFO4wBvfEk//glwwFg3DcAt0w+/8NCPQAyTKQB4aRM/0w9o/91Ph8AUZFA/3ZBDgCic9b/BoouAHzm9P8Kio8ANBrCALj0TACBjykBvvQT/3uqev9igUQAedWTAFZlHv+hZ5sAjFlD/+/lvgFDC7UAxvCJ/u5FvP/qcTz/Jf85/0Wytv6A0LMAdhp9/gMH1v/xMk3/VcvF/9OH+v8ZMGT/u9W0/hFYaQBT0Z4BBXNiAASuPP6rN27/2bUR/xS8qgCSnGb+V9au/3J6mwHpLKoAfwjvAdbs6gCvBdsAMWo9/wZC0P8Cam7/UeoT/9drwP9Dl+4AEyps/+VVcQEyRIf/EWoJADJnAf9QAagBI5ge/xCouQE4Wej/ZdL8ACn6RwDMqk//Di7v/1BN7wC91kv/EY35ACZQTP++VXUAVuSqAJzY0AHDz6T/lkJM/6/hEP+NUGIBTNvyAMaicgAu2pgAmyvx/pugaP+yCfz+ZG7UAA4FpwDp76P/HJedAWWSCv/+nkb+R/nkAFgeMgBEOqD/vxhoAYFCgf/AMlX/CLOK/yb6yQBzUKAAg+ZxAH1YkwBaRMcA/UyeABz/dgBx+v4AQksuAObaKwDleLoBlEQrAIh87gG7a8X/VDX2/zN0/v8zu6UAAhGvAEJUoAH3Oh4AI0E1/kXsvwAthvUBo3vdACBuFP80F6UAutZHAOmwYADy7zYBOVmKAFMAVP+IoGQAXI54/mh8vgC1sT7/+ilVAJiCKgFg/PYAl5c//u+FPgAgOJwALae9/46FswGDVtMAu7OW/vqqDv9EcRX/3ro7/0IH8QFFBkgAVpxs/jenWQBtNNv+DbAX/8Qsav/vlUf/pIx9/5+tAQAzKecAkT4hAIpvXQG5U0UAkHMuAGGXEP8Y5BoA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zLwm/vVzNP+/cUn+v2xF/xZF9QEXy7IAqmOqAEH4bwAlbJn/QCVFAABYPv5ZlJD/v0TgAfEnNQApy+3/kX7C/90q/f8ZY5cAYf3fAUpzMf8Gr0j/O7DLAHy3+QHk5GMAgQzP/qjAw//MsBD+mOqrAE0lVf8heIf/jsLjAR/WOgDVu33/6C48/750Kv6XshP/Mz7t/szswQDC6DwArCKd/70QuP5nA1//jekk/ikZC/8Vw6YAdvUtAEPVlf+fDBL/u6TjAaAZBQAMTsMBK8XhADCOKf7Emzz/38cSAZGInAD8dan+keLuAO8XawBttbz/5nAx/kmq7f/nt+P/UNwUAMJrfwF/zWUALjTFAdKrJP9YA1r/OJeNAGC7//8qTsgA/kZGAfR9qADMRIoBfNdGAGZCyP4RNOQAddyP/sv4ewA4Eq7/upek/zPo0AGg5Cv/+R0ZAUS+PwANAAAAAP8AAAAA9QAAAAAAAPsAAAAAAAD9AAAAAPMAAAAABwAAAAAAAwAAAADzAAAAAAUAAAAAAAAAAAsAAAAAAAsAAAAA8wAAAAAAAP0AAAAAAP8AAAAAAwAAAAD1AAAAAAAAAA8AAAAAAP8AAAAA/wAAAAAHAAAAAAUAQYyHAgsBAQBBsIcCCwEBAEHQhwILgSvg63p8O0G4rhZW4/rxn8Rq2gmN65wysf2GYgUWX0m4AF+clbyjUIwksdCxVZyD71sERFzEWByOhtgiTt3QnxFX7P///////////////////////////////////////3/t////////////////////////////////////////f+7///////////////////////////////////////9/AAECBAgQIECAGzYAAAAAAMZjY6X4fHyE7nd3mfZ7e43/8vIN1mtrvd5vb7GRxcVUYDAwUAIBAQPOZ2epVisrfef+/hm119diTaur5ux2dpqPyspFH4KCnYnJyUD6fX2H7/r6FbJZWeuOR0fJ+/DwC0Gtreyz1NRnX6Ki/UWvr+ojnJy/U6Sk9+RycpabwMBbdbe3wuH9/Rw9k5OuTCYmamw2Nlp+Pz9B9ff3AoPMzE9oNDRcUaWl9NHl5TT58fEI4nFxk6vY2HNiMTFTKhUVPwgEBAyVx8dSRiMjZZ3Dw14wGBgoN5aWoQoFBQ8vmpq1DgcHCSQSEjYb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"), A4((await (async function(A5, g3, C4) {
      return (async function(A6, g4) {
        try {
          var C5 = await (async function(A7) {
            return (function(A8) {
              if (ArrayBuffer.isView(A8)) return A8;
              if (A8 == F2 && E2) return new Uint8Array(E2);
              if (I2) return I2(A8);
              throw "both async and sync fetching of the wasm failed";
            })(A7);
          })(A6);
          return await WebAssembly.instantiate(C5, g4);
        } catch (A7) {
          M2(`failed to asynchronously prepare wasm: ${A7}`), Y2(A7);
        }
      })(g3, C4);
    })(0, F2, C3)).instance));
  })(), (function() {
    function A4() {
      g2.calledRun = true, U2 || (G2 = true, i2?.(g2), g2.onRuntimeInitialized?.(), (function() {
        if (g2.postRun) for ("function" == typeof g2.postRun && (g2.postRun = [g2.postRun]); g2.postRun.length; ) H2(g2.postRun.shift());
        N2(K2);
      })());
    }
    !(function() {
      if (g2.preRun) for ("function" == typeof g2.preRun && (g2.preRun = [g2.preRun]); g2.preRun.length; ) f2(g2.preRun.shift());
      N2(a2);
    })(), g2.setStatus ? (g2.setStatus("Running..."), setTimeout(() => {
      setTimeout(() => g2.setStatus(""), 1), A4();
    }, 1)) : A4();
  })(), G2 ? g2 : new Promise((A4, I3) => {
    i2 = A4, D2 = I3;
  });
}
var libsodium_default = A;

// ../../node_modules/.pnpm/libsodium-wrappers@0.8.4/node_modules/libsodium-wrappers/dist/modules-esm/libsodium-wrappers.mjs
var r;
var t = {};
if (void 0 === globalThis.crypto || "function" != typeof globalThis.crypto.getRandomValues) throw new Error("globalThis.crypto.getRandomValues is not available. The ESM build of libsodium requires a secure random source (available in all browsers and Node.js 19+).");
var a = "function" == typeof (_ = libsodium_default) ? _ : null != _ && "function" == typeof _.default ? _.default : null;
var _;
var n = (function(e) {
  return null != e && void 0 !== e.ready ? e : null != e && null != e.default && void 0 !== e.default.ready ? e.default : null;
})(libsodium_default);
var s = (null != a ? a({ getRandomValue: function() {
  var e = new Uint32Array(1);
  return globalThis.crypto.getRandomValues(e), e[0] >>> 0;
} }) : null != n ? n.ready.then(function() {
  return n;
}) : Promise.reject(new Error("Unsupported libsodium ESM export shape"))).then(function(e) {
  r = e, t.libsodium = r, (function() {
    if (r._sodium_init() < 0) throw new Error("libsodium was not correctly initialized.");
    for (var e2 = ["crypto_aead_aegis128l_decrypt", "crypto_aead_aegis128l_decrypt_detached", "crypto_aead_aegis128l_encrypt", "crypto_aead_aegis128l_encrypt_detached", "crypto_aead_aegis128l_keygen", "crypto_aead_aegis256_decrypt", "crypto_aead_aegis256_decrypt_detached", "crypto_aead_aegis256_encrypt", "crypto_aead_aegis256_encrypt_detached", "crypto_aead_aegis256_keygen", "crypto_aead_chacha20poly1305_decrypt", "crypto_aead_chacha20poly1305_decrypt_detached", "crypto_aead_chacha20poly1305_encrypt", "crypto_aead_chacha20poly1305_encrypt_detached", "crypto_aead_chacha20poly1305_ietf_decrypt", "crypto_aead_chacha20poly1305_ietf_decrypt_detached", "crypto_aead_chacha20poly1305_ietf_encrypt", "crypto_aead_chacha20poly1305_ietf_encrypt_detached", "crypto_aead_chacha20poly1305_ietf_keygen", "crypto_aead_chacha20poly1305_keygen", "crypto_aead_xchacha20poly1305_ietf_decrypt", "crypto_aead_xchacha20poly1305_ietf_decrypt_detached", "crypto_aead_xchacha20poly1305_ietf_encrypt", "crypto_aead_xchacha20poly1305_ietf_encrypt_detached", "crypto_aead_xchacha20poly1305_ietf_keygen", "crypto_auth", "crypto_auth_hmacsha256", "crypto_auth_hmacsha256_final", "crypto_auth_hmacsha256_init", "crypto_auth_hmacsha256_keygen", "crypto_auth_hmacsha256_update", "crypto_auth_hmacsha256_verify", "crypto_auth_hmacsha512", "crypto_auth_hmacsha512256", "crypto_auth_hmacsha512256_final", "crypto_auth_hmacsha512256_init", "crypto_auth_hmacsha512256_keygen", "crypto_auth_hmacsha512256_update", "crypto_auth_hmacsha512256_verify", "crypto_auth_hmacsha512_final", "crypto_auth_hmacsha512_init", "crypto_auth_hmacsha512_keygen", "crypto_auth_hmacsha512_update", "crypto_auth_hmacsha512_verify", "crypto_auth_keygen", "crypto_auth_verify", "crypto_box_beforenm", "crypto_box_curve25519xchacha20poly1305_beforenm", "crypto_box_curve25519xchacha20poly1305_detached", "crypto_box_curve25519xchacha20poly1305_detached_afternm", "crypto_box_curve25519xchacha20poly1305_easy", "crypto_box_curve25519xchacha20poly1305_easy_afternm", "crypto_box_curve25519xchacha20poly1305_keypair", "crypto_box_curve25519xchacha20poly1305_open_detached", "crypto_box_curve25519xchacha20poly1305_open_detached_afternm", "crypto_box_curve25519xchacha20poly1305_open_easy", "crypto_box_curve25519xchacha20poly1305_open_easy_afternm", "crypto_box_curve25519xchacha20poly1305_seal", "crypto_box_curve25519xchacha20poly1305_seal_open", "crypto_box_curve25519xchacha20poly1305_seed_keypair", "crypto_box_detached", "crypto_box_easy", "crypto_box_easy_afternm", "crypto_box_keypair", "crypto_box_open_detached", "crypto_box_open_easy", "crypto_box_open_easy_afternm", "crypto_box_seal", "crypto_box_seal_open", "crypto_box_seed_keypair", "crypto_core_ed25519_add", "crypto_core_ed25519_from_hash", "crypto_core_ed25519_from_uniform", "crypto_core_ed25519_is_valid_point", "crypto_core_ed25519_random", "crypto_core_ed25519_scalar_add", "crypto_core_ed25519_scalar_complement", "crypto_core_ed25519_scalar_invert", "crypto_core_ed25519_scalar_mul", "crypto_core_ed25519_scalar_negate", "crypto_core_ed25519_scalar_random", "crypto_core_ed25519_scalar_reduce", "crypto_core_ed25519_scalar_sub", "crypto_core_ed25519_sub", "crypto_core_hchacha20", "crypto_core_hsalsa20", "crypto_core_ristretto255_add", "crypto_core_ristretto255_from_hash", "crypto_core_ristretto255_is_valid_point", "crypto_core_ristretto255_random", "crypto_core_ristretto255_scalar_add", "crypto_core_ristretto255_scalar_complement", "crypto_core_ristretto255_scalar_invert", "crypto_core_ristretto255_scalar_mul", "crypto_core_ristretto255_scalar_negate", "crypto_core_ristretto255_scalar_random", "crypto_core_ristretto255_scalar_reduce", "crypto_core_ristretto255_scalar_sub", "crypto_core_ristretto255_sub", "crypto_generichash", "crypto_generichash_blake2b_salt_personal", "crypto_generichash_final", "crypto_generichash_init", "crypto_generichash_keygen", "crypto_generichash_update", "crypto_hash", "crypto_hash_sha256", "crypto_hash_sha256_final", "crypto_hash_sha256_init", "crypto_hash_sha256_update", "crypto_hash_sha3256", "crypto_hash_sha3256_final", "crypto_hash_sha3256_init", "crypto_hash_sha3256_update", "crypto_hash_sha3512", "crypto_hash_sha3512_final", "crypto_hash_sha3512_init", "crypto_hash_sha3512_update", "crypto_hash_sha512", "crypto_hash_sha512_final", "crypto_hash_sha512_init", "crypto_hash_sha512_update", "crypto_ipcrypt_decrypt", "crypto_ipcrypt_encrypt", "crypto_ipcrypt_keygen", "crypto_ipcrypt_nd_decrypt", "crypto_ipcrypt_nd_encrypt", "crypto_ipcrypt_nd_keygen", "crypto_ipcrypt_ndx_decrypt", "crypto_ipcrypt_ndx_encrypt", "crypto_ipcrypt_ndx_keygen", "crypto_ipcrypt_pfx_decrypt", "crypto_ipcrypt_pfx_encrypt", "crypto_ipcrypt_pfx_keygen", "crypto_kdf_derive_from_key", "crypto_kdf_keygen", "crypto_kem_dec", "crypto_kem_enc", "crypto_kem_keypair", "crypto_kem_mlkem768_dec", "crypto_kem_mlkem768_enc", "crypto_kem_mlkem768_enc_deterministic", "crypto_kem_mlkem768_keypair", "crypto_kem_mlkem768_seed_keypair", "crypto_kem_primitive", "crypto_kem_seed_keypair", "crypto_kem_xwing_dec", "crypto_kem_xwing_enc", "crypto_kem_xwing_enc_deterministic", "crypto_kem_xwing_keypair", "crypto_kem_xwing_seed_keypair", "crypto_kx_client_session_keys", "crypto_kx_keypair", "crypto_kx_seed_keypair", "crypto_kx_server_session_keys", "crypto_onetimeauth", "crypto_onetimeauth_final", "crypto_onetimeauth_init", "crypto_onetimeauth_keygen", "crypto_onetimeauth_update", "crypto_onetimeauth_verify", "crypto_pwhash", "crypto_pwhash_scryptsalsa208sha256", "crypto_pwhash_scryptsalsa208sha256_ll", "crypto_pwhash_scryptsalsa208sha256_str", "crypto_pwhash_scryptsalsa208sha256_str_verify", "crypto_pwhash_str", "crypto_pwhash_str_needs_rehash", "crypto_pwhash_str_verify", "crypto_scalarmult", "crypto_scalarmult_base", "crypto_scalarmult_ed25519", "crypto_scalarmult_ed25519_base", "crypto_scalarmult_ed25519_base_noclamp", "crypto_scalarmult_ed25519_noclamp", "crypto_scalarmult_ristretto255", "crypto_scalarmult_ristretto255_base", "crypto_secretbox_detached", "crypto_secretbox_easy", "crypto_secretbox_keygen", "crypto_secretbox_open_detached", "crypto_secretbox_open_easy", "crypto_secretstream_xchacha20poly1305_init_pull", "crypto_secretstream_xchacha20poly1305_init_push", "crypto_secretstream_xchacha20poly1305_keygen", "crypto_secretstream_xchacha20poly1305_pull", "crypto_secretstream_xchacha20poly1305_push", "crypto_secretstream_xchacha20poly1305_rekey", "crypto_shorthash", "crypto_shorthash_keygen", "crypto_shorthash_siphashx24", "crypto_sign", "crypto_sign_detached", "crypto_sign_ed25519_pk_to_curve25519", "crypto_sign_ed25519_sk_to_curve25519", "crypto_sign_ed25519_sk_to_pk", "crypto_sign_ed25519_sk_to_seed", "crypto_sign_final_create", "crypto_sign_final_verify", "crypto_sign_init", "crypto_sign_keypair", "crypto_sign_open", "crypto_sign_seed_keypair", "crypto_sign_update", "crypto_sign_verify_detached", "crypto_stream_chacha20", "crypto_stream_chacha20_ietf_xor", "crypto_stream_chacha20_ietf_xor_ic", "crypto_stream_chacha20_keygen", "crypto_stream_chacha20_xor", "crypto_stream_chacha20_xor_ic", "crypto_stream_keygen", "crypto_stream_xchacha20_keygen", "crypto_stream_xchacha20_xor", "crypto_stream_xchacha20_xor_ic", "crypto_xof_shake128", "crypto_xof_shake128_init", "crypto_xof_shake128_init_with_domain", "crypto_xof_shake128_squeeze", "crypto_xof_shake128_update", "crypto_xof_shake256", "crypto_xof_shake256_init", "crypto_xof_shake256_init_with_domain", "crypto_xof_shake256_squeeze", "crypto_xof_shake256_update", "crypto_xof_turboshake128", "crypto_xof_turboshake128_init", "crypto_xof_turboshake128_init_with_domain", "crypto_xof_turboshake128_squeeze", "crypto_xof_turboshake128_update", "crypto_xof_turboshake256", "crypto_xof_turboshake256_init", "crypto_xof_turboshake256_init_with_domain", "crypto_xof_turboshake256_squeeze", "crypto_xof_turboshake256_update", "randombytes_buf", "randombytes_buf_deterministic", "randombytes_close", "randombytes_random", "randombytes_set_implementation", "randombytes_stir", "randombytes_uniform", "sodium_bin2ip", "sodium_ip2bin", "sodium_version_string"], a3 = [C, R, P, X, D, G, F, V, q, H, z, W, j, J, Q, Z, $, ee, re, te, ae, _e, ne, se, ce, pe, oe, he, ye, ie, le, ue, de, ve, ge, be, fe, me, ke, xe, Ee, Te, Se, we, Ye, Be, Ke, Ae, Ie, Me, Ne, Le, Ue, Oe, Ce, Re, Pe, Xe, De, Ge, Fe, Ve, qe, He, ze, We, je, Je, Qe, Ze, $e, er, rr, tr, ar, _r, nr, sr, cr, pr, or, hr, yr, ir, lr, ur, dr, vr, gr, br, fr, mr, kr, xr, Er, Tr, Sr, wr, Yr, Br, Kr, Ar, Ir, Mr, Nr, Lr, Ur, Or, Cr, Rr, Pr, Xr, Dr, Gr, Fr, Vr, qr, Hr, zr, Wr, jr, Jr, Qr, Zr, $r, et, rt, tt, at, _t, nt, st, ct, pt, ot, ht, yt, it, lt, ut, dt, vt, gt, bt, ft, mt, kt, xt, Et, Tt, St, wt, Yt, Bt, Kt, At, It, Mt, Nt, Lt, Ut, Ot, Ct, Rt, Pt, Xt, Dt, Gt, Ft, Vt, qt, Ht, zt, Wt, jt, Jt, Qt, Zt, $t, ea, ra, ta, aa, _a, na, sa, ca, pa, oa, ha, ya, ia, la, ua, da, va, ga, ba, fa, ma, ka, xa, Ea, Ta, Sa, wa, Ya, Ba, Ka, Aa, Ia, Ma, Na, La, Ua, Oa, Ca, Ra, Pa, Xa, Da, Ga, Fa, Va, qa, Ha, za, Wa, ja, Ja, Qa, Za, $a, e_, r_, t_, a_, __, n_, s_, c_, p_, o_, h_, y_], _3 = 0; _3 < a3.length; _3++) "function" == typeof r["_" + e2[_3]] && (t[e2[_3]] = a3[_3]);
    var n3 = ["SODIUM_LIBRARY_VERSION_MAJOR", "SODIUM_LIBRARY_VERSION_MINOR", "crypto_aead_aegis128l_ABYTES", "crypto_aead_aegis128l_KEYBYTES", "crypto_aead_aegis128l_MESSAGEBYTES_MAX", "crypto_aead_aegis128l_NPUBBYTES", "crypto_aead_aegis128l_NSECBYTES", "crypto_aead_aegis256_ABYTES", "crypto_aead_aegis256_KEYBYTES", "crypto_aead_aegis256_MESSAGEBYTES_MAX", "crypto_aead_aegis256_NPUBBYTES", "crypto_aead_aegis256_NSECBYTES", "crypto_aead_aes256gcm_ABYTES", "crypto_aead_aes256gcm_KEYBYTES", "crypto_aead_aes256gcm_MESSAGEBYTES_MAX", "crypto_aead_aes256gcm_NPUBBYTES", "crypto_aead_aes256gcm_NSECBYTES", "crypto_aead_chacha20poly1305_ABYTES", "crypto_aead_chacha20poly1305_IETF_ABYTES", "crypto_aead_chacha20poly1305_IETF_KEYBYTES", "crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX", "crypto_aead_chacha20poly1305_IETF_NPUBBYTES", "crypto_aead_chacha20poly1305_IETF_NSECBYTES", "crypto_aead_chacha20poly1305_KEYBYTES", "crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX", "crypto_aead_chacha20poly1305_NPUBBYTES", "crypto_aead_chacha20poly1305_NSECBYTES", "crypto_aead_chacha20poly1305_ietf_ABYTES", "crypto_aead_chacha20poly1305_ietf_KEYBYTES", "crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX", "crypto_aead_chacha20poly1305_ietf_NPUBBYTES", "crypto_aead_chacha20poly1305_ietf_NSECBYTES", "crypto_aead_xchacha20poly1305_IETF_ABYTES", "crypto_aead_xchacha20poly1305_IETF_KEYBYTES", "crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX", "crypto_aead_xchacha20poly1305_IETF_NPUBBYTES", "crypto_aead_xchacha20poly1305_IETF_NSECBYTES", "crypto_aead_xchacha20poly1305_ietf_ABYTES", "crypto_aead_xchacha20poly1305_ietf_KEYBYTES", "crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX", "crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", "crypto_aead_xchacha20poly1305_ietf_NSECBYTES", "crypto_auth_BYTES", "crypto_auth_KEYBYTES", "crypto_auth_hmacsha256_BYTES", "crypto_auth_hmacsha256_KEYBYTES", "crypto_auth_hmacsha512256_BYTES", "crypto_auth_hmacsha512256_KEYBYTES", "crypto_auth_hmacsha512_BYTES", "crypto_auth_hmacsha512_KEYBYTES", "crypto_box_BEFORENMBYTES", "crypto_box_MACBYTES", "crypto_box_MESSAGEBYTES_MAX", "crypto_box_NONCEBYTES", "crypto_box_PUBLICKEYBYTES", "crypto_box_SEALBYTES", "crypto_box_SECRETKEYBYTES", "crypto_box_SEEDBYTES", "crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES", "crypto_box_curve25519xchacha20poly1305_MACBYTES", "crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX", "crypto_box_curve25519xchacha20poly1305_NONCEBYTES", "crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES", "crypto_box_curve25519xchacha20poly1305_SEALBYTES", "crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES", "crypto_box_curve25519xchacha20poly1305_SEEDBYTES", "crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES", "crypto_box_curve25519xsalsa20poly1305_MACBYTES", "crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX", "crypto_box_curve25519xsalsa20poly1305_NONCEBYTES", "crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES", "crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES", "crypto_box_curve25519xsalsa20poly1305_SEEDBYTES", "crypto_core_ed25519_BYTES", "crypto_core_ed25519_HASHBYTES", "crypto_core_ed25519_NONREDUCEDSCALARBYTES", "crypto_core_ed25519_SCALARBYTES", "crypto_core_ed25519_UNIFORMBYTES", "crypto_core_hchacha20_CONSTBYTES", "crypto_core_hchacha20_INPUTBYTES", "crypto_core_hchacha20_KEYBYTES", "crypto_core_hchacha20_OUTPUTBYTES", "crypto_core_hsalsa20_CONSTBYTES", "crypto_core_hsalsa20_INPUTBYTES", "crypto_core_hsalsa20_KEYBYTES", "crypto_core_hsalsa20_OUTPUTBYTES", "crypto_core_ristretto255_BYTES", "crypto_core_ristretto255_HASHBYTES", "crypto_core_ristretto255_NONREDUCEDSCALARBYTES", "crypto_core_ristretto255_SCALARBYTES", "crypto_core_salsa2012_CONSTBYTES", "crypto_core_salsa2012_INPUTBYTES", "crypto_core_salsa2012_KEYBYTES", "crypto_core_salsa2012_OUTPUTBYTES", "crypto_core_salsa208_CONSTBYTES", "crypto_core_salsa208_INPUTBYTES", "crypto_core_salsa208_KEYBYTES", "crypto_core_salsa208_OUTPUTBYTES", "crypto_core_salsa20_CONSTBYTES", "crypto_core_salsa20_INPUTBYTES", "crypto_core_salsa20_KEYBYTES", "crypto_core_salsa20_OUTPUTBYTES", "crypto_generichash_BYTES", "crypto_generichash_BYTES_MAX", "crypto_generichash_BYTES_MIN", "crypto_generichash_KEYBYTES", "crypto_generichash_KEYBYTES_MAX", "crypto_generichash_KEYBYTES_MIN", "crypto_generichash_blake2b_BYTES", "crypto_generichash_blake2b_BYTES_MAX", "crypto_generichash_blake2b_BYTES_MIN", "crypto_generichash_blake2b_KEYBYTES", "crypto_generichash_blake2b_KEYBYTES_MAX", "crypto_generichash_blake2b_KEYBYTES_MIN", "crypto_generichash_blake2b_PERSONALBYTES", "crypto_generichash_blake2b_SALTBYTES", "crypto_hash_BYTES", "crypto_hash_sha256_BYTES", "crypto_hash_sha3256_BYTES", "crypto_hash_sha3512_BYTES", "crypto_hash_sha512_BYTES", "crypto_ipcrypt_BYTES", "crypto_ipcrypt_KEYBYTES", "crypto_ipcrypt_NDX_INPUTBYTES", "crypto_ipcrypt_NDX_KEYBYTES", "crypto_ipcrypt_NDX_OUTPUTBYTES", "crypto_ipcrypt_NDX_TWEAKBYTES", "crypto_ipcrypt_ND_INPUTBYTES", "crypto_ipcrypt_ND_KEYBYTES", "crypto_ipcrypt_ND_OUTPUTBYTES", "crypto_ipcrypt_ND_TWEAKBYTES", "crypto_ipcrypt_PFX_BYTES", "crypto_ipcrypt_PFX_KEYBYTES", "crypto_kdf_BYTES_MAX", "crypto_kdf_BYTES_MIN", "crypto_kdf_CONTEXTBYTES", "crypto_kdf_KEYBYTES", "crypto_kdf_blake2b_BYTES_MAX", "crypto_kdf_blake2b_BYTES_MIN", "crypto_kdf_blake2b_CONTEXTBYTES", "crypto_kdf_blake2b_KEYBYTES", "crypto_kdf_hkdf_sha256_BYTES_MAX", "crypto_kdf_hkdf_sha256_BYTES_MIN", "crypto_kdf_hkdf_sha256_KEYBYTES", "crypto_kdf_hkdf_sha512_BYTES_MAX", "crypto_kdf_hkdf_sha512_BYTES_MIN", "crypto_kdf_hkdf_sha512_KEYBYTES", "crypto_kem_CIPHERTEXTBYTES", "crypto_kem_PUBLICKEYBYTES", "crypto_kem_SECRETKEYBYTES", "crypto_kem_SEEDBYTES", "crypto_kem_SHAREDSECRETBYTES", "crypto_kem_mlkem768_CIPHERTEXTBYTES", "crypto_kem_mlkem768_PUBLICKEYBYTES", "crypto_kem_mlkem768_SECRETKEYBYTES", "crypto_kem_mlkem768_SEEDBYTES", "crypto_kem_mlkem768_SHAREDSECRETBYTES", "crypto_kem_xwing_CIPHERTEXTBYTES", "crypto_kem_xwing_PUBLICKEYBYTES", "crypto_kem_xwing_SECRETKEYBYTES", "crypto_kem_xwing_SEEDBYTES", "crypto_kem_xwing_SHAREDSECRETBYTES", "crypto_kx_PUBLICKEYBYTES", "crypto_kx_SECRETKEYBYTES", "crypto_kx_SEEDBYTES", "crypto_kx_SESSIONKEYBYTES", "crypto_onetimeauth_BYTES", "crypto_onetimeauth_KEYBYTES", "crypto_onetimeauth_poly1305_BYTES", "crypto_onetimeauth_poly1305_KEYBYTES", "crypto_pwhash_ALG_ARGON2I13", "crypto_pwhash_ALG_ARGON2ID13", "crypto_pwhash_ALG_DEFAULT", "crypto_pwhash_BYTES_MAX", "crypto_pwhash_BYTES_MIN", "crypto_pwhash_MEMLIMIT_INTERACTIVE", "crypto_pwhash_MEMLIMIT_MAX", "crypto_pwhash_MEMLIMIT_MIN", "crypto_pwhash_MEMLIMIT_MODERATE", "crypto_pwhash_MEMLIMIT_SENSITIVE", "crypto_pwhash_OPSLIMIT_INTERACTIVE", "crypto_pwhash_OPSLIMIT_MAX", "crypto_pwhash_OPSLIMIT_MIN", "crypto_pwhash_OPSLIMIT_MODERATE", "crypto_pwhash_OPSLIMIT_SENSITIVE", "crypto_pwhash_PASSWD_MAX", "crypto_pwhash_PASSWD_MIN", "crypto_pwhash_SALTBYTES", "crypto_pwhash_STRBYTES", "crypto_pwhash_argon2i_BYTES_MAX", "crypto_pwhash_argon2i_BYTES_MIN", "crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE", "crypto_pwhash_argon2i_MEMLIMIT_MAX", "crypto_pwhash_argon2i_MEMLIMIT_MIN", "crypto_pwhash_argon2i_MEMLIMIT_MODERATE", "crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE", "crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE", "crypto_pwhash_argon2i_OPSLIMIT_MAX", "crypto_pwhash_argon2i_OPSLIMIT_MIN", "crypto_pwhash_argon2i_OPSLIMIT_MODERATE", "crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE", "crypto_pwhash_argon2i_PASSWD_MAX", "crypto_pwhash_argon2i_PASSWD_MIN", "crypto_pwhash_argon2i_SALTBYTES", "crypto_pwhash_argon2i_STRBYTES", "crypto_pwhash_argon2id_BYTES_MAX", "crypto_pwhash_argon2id_BYTES_MIN", "crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE", "crypto_pwhash_argon2id_MEMLIMIT_MAX", "crypto_pwhash_argon2id_MEMLIMIT_MIN", "crypto_pwhash_argon2id_MEMLIMIT_MODERATE", "crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE", "crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE", "crypto_pwhash_argon2id_OPSLIMIT_MAX", "crypto_pwhash_argon2id_OPSLIMIT_MIN", "crypto_pwhash_argon2id_OPSLIMIT_MODERATE", "crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE", "crypto_pwhash_argon2id_PASSWD_MAX", "crypto_pwhash_argon2id_PASSWD_MIN", "crypto_pwhash_argon2id_SALTBYTES", "crypto_pwhash_argon2id_STRBYTES", "crypto_pwhash_scryptsalsa208sha256_BYTES_MAX", "crypto_pwhash_scryptsalsa208sha256_BYTES_MIN", "crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE", "crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX", "crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN", "crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE", "crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE", "crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX", "crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN", "crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE", "crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX", "crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN", "crypto_pwhash_scryptsalsa208sha256_SALTBYTES", "crypto_pwhash_scryptsalsa208sha256_STRBYTES", "crypto_scalarmult_BYTES", "crypto_scalarmult_SCALARBYTES", "crypto_scalarmult_curve25519_BYTES", "crypto_scalarmult_curve25519_SCALARBYTES", "crypto_scalarmult_ed25519_BYTES", "crypto_scalarmult_ed25519_SCALARBYTES", "crypto_scalarmult_ristretto255_BYTES", "crypto_scalarmult_ristretto255_SCALARBYTES", "crypto_secretbox_KEYBYTES", "crypto_secretbox_MACBYTES", "crypto_secretbox_MESSAGEBYTES_MAX", "crypto_secretbox_NONCEBYTES", "crypto_secretbox_xchacha20poly1305_KEYBYTES", "crypto_secretbox_xchacha20poly1305_MACBYTES", "crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX", "crypto_secretbox_xchacha20poly1305_NONCEBYTES", "crypto_secretbox_xsalsa20poly1305_KEYBYTES", "crypto_secretbox_xsalsa20poly1305_MACBYTES", "crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX", "crypto_secretbox_xsalsa20poly1305_NONCEBYTES", "crypto_secretstream_xchacha20poly1305_ABYTES", "crypto_secretstream_xchacha20poly1305_HEADERBYTES", "crypto_secretstream_xchacha20poly1305_KEYBYTES", "crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX", "crypto_secretstream_xchacha20poly1305_TAG_FINAL", "crypto_secretstream_xchacha20poly1305_TAG_MESSAGE", "crypto_secretstream_xchacha20poly1305_TAG_PUSH", "crypto_secretstream_xchacha20poly1305_TAG_REKEY", "crypto_shorthash_BYTES", "crypto_shorthash_KEYBYTES", "crypto_shorthash_siphash24_BYTES", "crypto_shorthash_siphash24_KEYBYTES", "crypto_shorthash_siphashx24_BYTES", "crypto_shorthash_siphashx24_KEYBYTES", "crypto_sign_BYTES", "crypto_sign_MESSAGEBYTES_MAX", "crypto_sign_PUBLICKEYBYTES", "crypto_sign_SECRETKEYBYTES", "crypto_sign_SEEDBYTES", "crypto_sign_ed25519_BYTES", "crypto_sign_ed25519_MESSAGEBYTES_MAX", "crypto_sign_ed25519_PUBLICKEYBYTES", "crypto_sign_ed25519_SECRETKEYBYTES", "crypto_sign_ed25519_SEEDBYTES", "crypto_stream_KEYBYTES", "crypto_stream_MESSAGEBYTES_MAX", "crypto_stream_NONCEBYTES", "crypto_stream_chacha20_IETF_KEYBYTES", "crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX", "crypto_stream_chacha20_IETF_NONCEBYTES", "crypto_stream_chacha20_KEYBYTES", "crypto_stream_chacha20_MESSAGEBYTES_MAX", "crypto_stream_chacha20_NONCEBYTES", "crypto_stream_chacha20_ietf_KEYBYTES", "crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX", "crypto_stream_chacha20_ietf_NONCEBYTES", "crypto_stream_salsa2012_KEYBYTES", "crypto_stream_salsa2012_MESSAGEBYTES_MAX", "crypto_stream_salsa2012_NONCEBYTES", "crypto_stream_salsa208_KEYBYTES", "crypto_stream_salsa208_MESSAGEBYTES_MAX", "crypto_stream_salsa208_NONCEBYTES", "crypto_stream_salsa20_KEYBYTES", "crypto_stream_salsa20_MESSAGEBYTES_MAX", "crypto_stream_salsa20_NONCEBYTES", "crypto_stream_xchacha20_KEYBYTES", "crypto_stream_xchacha20_MESSAGEBYTES_MAX", "crypto_stream_xchacha20_NONCEBYTES", "crypto_stream_xsalsa20_KEYBYTES", "crypto_stream_xsalsa20_MESSAGEBYTES_MAX", "crypto_stream_xsalsa20_NONCEBYTES", "crypto_verify_16_BYTES", "crypto_verify_32_BYTES", "crypto_verify_64_BYTES", "crypto_xof_shake128_BLOCKBYTES", "crypto_xof_shake128_STATEBYTES", "crypto_xof_shake256_BLOCKBYTES", "crypto_xof_shake256_STATEBYTES", "crypto_xof_turboshake128_BLOCKBYTES", "crypto_xof_turboshake128_STATEBYTES", "crypto_xof_turboshake256_BLOCKBYTES", "crypto_xof_turboshake256_STATEBYTES"];
    for (_3 = 0; _3 < n3.length; _3++) "function" == typeof (c3 = r["_" + n3[_3].toLowerCase()]) && (t[n3[_3]] = c3());
    var s3 = ["SODIUM_VERSION_STRING", "crypto_kem_PRIMITIVE", "crypto_pwhash_STRPREFIX", "crypto_pwhash_argon2i_STRPREFIX", "crypto_pwhash_argon2id_STRPREFIX", "crypto_pwhash_scryptsalsa208sha256_STRPREFIX"];
    for (_3 = 0; _3 < s3.length; _3++) {
      var c3;
      "function" == typeof (c3 = r["_" + s3[_3].toLowerCase()]) && (t[s3[_3]] = r.UTF8ToString(c3()));
    }
  })();
  var a2 = new Uint8Array([98, 97, 108, 108, 115]), _2 = t.randombytes_buf(t.crypto_secretbox_NONCEBYTES), n2 = t.randombytes_buf(t.crypto_secretbox_KEYBYTES), s2 = t.crypto_secretbox_easy(a2, _2, n2), c2 = t.crypto_secretbox_open_easy(s2, _2, n2);
  if (!t.memcmp(a2, c2)) throw new Error("Initialization self-test failed");
});
function c() {
  return Object.keys(t).sort();
}
function p(e) {
  if (!(e instanceof Uint8Array)) throw new TypeError("Only Uint8Array instances can be incremented");
  for (var r2 = 256, t2 = 0, a2 = e.length; t2 < a2; t2++) r2 >>= 8, r2 += e[t2], e[t2] = 255 & r2;
}
function o(e, r2) {
  if (!(e instanceof Uint8Array && r2 instanceof Uint8Array)) throw new TypeError("Only Uint8Array instances can be added");
  var t2 = e.length, a2 = 0, _2 = 0;
  if (r2.length !== e.length) throw new TypeError("Arguments must have the same length");
  for (_2 = 0; _2 < t2; _2++) a2 >>= 8, a2 += e[_2] + r2[_2], e[_2] = 255 & a2;
}
function h(e) {
  if (!(e instanceof Uint8Array)) throw new TypeError("Only Uint8Array instances can be checked");
  for (var r2 = 0, t2 = 0, a2 = e.length; t2 < a2; t2++) r2 |= e[t2];
  return 0 === r2;
}
function y(e) {
  if (!(e instanceof Uint8Array)) throw new TypeError("Only Uint8Array instances can be wiped");
  for (var r2 = 0, t2 = e.length; r2 < t2; r2++) e[r2] = 0;
}
function i(e, r2) {
  if (!(e instanceof Uint8Array && r2 instanceof Uint8Array)) throw new TypeError("Only Uint8Array instances can be compared");
  if (e.length !== r2.length) throw new TypeError("Only instances of identical length can be compared");
  for (var t2 = 0, a2 = 0, _2 = e.length; a2 < _2; a2++) t2 |= e[a2] ^ r2[a2];
  return 0 === t2;
}
function l(e, r2) {
  if (!(e instanceof Uint8Array && r2 instanceof Uint8Array)) throw new TypeError("Only Uint8Array instances can be compared");
  if (e.length !== r2.length) throw new TypeError("Only instances of identical length can be compared");
  for (var t2 = 0, a2 = 1, _2 = e.length; _2-- > 0; ) t2 |= r2[_2] - e[_2] >> 8 & a2, a2 &= (r2[_2] ^ e[_2]) - 1 >> 8;
  return t2 + t2 + a2 - 1;
}
function u(e, t2) {
  if (!(e instanceof Uint8Array)) throw new TypeError("buffer must be a Uint8Array");
  if ((t2 |= 0) <= 0) throw new Error("block size must be > 0");
  var a2, _2 = [], n2 = A2(4), s2 = 1, c2 = 0, p2 = 0 | e.length, o2 = new B(p2 + t2);
  _2.push(n2), _2.push(o2.address);
  for (var h2 = o2.address, y2 = o2.address + p2 + t2; h2 < y2; h2++) r.HEAPU8[h2] = e[c2], c2 += s2 = 1 & ~((65535 & ((p2 -= s2) >>> 48 | p2 >>> 32 | p2 >>> 16 | p2)) - 1 >> 16);
  return 0 !== r._sodium_pad(n2, o2.address, e.length, t2, o2.length) && N(_2, "internal error"), o2.length = r.getValue(n2, "i32"), a2 = o2.to_Uint8Array(), M(_2), a2;
}
function d(e, t2) {
  if (!(e instanceof Uint8Array)) throw new TypeError("buffer must be a Uint8Array");
  if ((t2 |= 0) <= 0) throw new Error("block size must be > 0");
  var a2 = [], _2 = K(e), n2 = A2(4);
  return a2.push(_2), a2.push(n2), 0 !== r._sodium_unpad(n2, _2, e.length, t2) && N(a2, "unsupported/invalid padding"), e = (e = new Uint8Array(e)).subarray(0, r.getValue(n2, "i32")), M(a2), e;
}
function v(e) {
  if ("function" == typeof TextEncoder) return new TextEncoder().encode(e);
  e = unescape(encodeURIComponent(e));
  for (var r2 = new Uint8Array(e.length), t2 = 0, a2 = e.length; t2 < a2; t2++) r2[t2] = e.charCodeAt(t2);
  return r2;
}
function g(e) {
  if ("function" == typeof TextDecoder) return new TextDecoder("utf-8", { fatal: true }).decode(e);
  var r2 = 8192, t2 = Math.ceil(e.length / r2);
  if (t2 <= 1) try {
    return decodeURIComponent(escape(String.fromCharCode.apply(null, e)));
  } catch (e2) {
    throw new TypeError("The encoded data was not valid.");
  }
  for (var a2 = "", _2 = 0, n2 = 0; n2 < t2; n2++) {
    var s2 = Array.prototype.slice.call(e, n2 * r2 + _2, (n2 + 1) * r2 + _2);
    if (0 !== s2.length) {
      var c2, p2 = s2.length, o2 = 0;
      do {
        var h2 = s2[--p2];
        h2 >= 240 ? (o2 = 4, c2 = true) : h2 >= 224 ? (o2 = 3, c2 = true) : h2 >= 192 ? (o2 = 2, c2 = true) : h2 < 128 && (o2 = 1, c2 = true);
      } while (!c2);
      for (var y2 = o2 - (s2.length - p2), i2 = 0; i2 < y2; i2++) _2--, s2.pop();
      a2 += g(s2);
    }
  }
  return a2;
}
function b(e) {
  var t2, a2 = [], _2 = new B((e = O(a2, e, "input")).length / 2), n2 = K(e), s2 = A2(4);
  return a2.push(n2), a2.push(_2.address), a2.push(s2), 0 !== r._sodium_hex2bin(_2.address, _2.length, n2, e.length, 0, 0, s2) && N(a2, "invalid input"), r.getValue(s2, "i32") - n2 !== e.length && N(a2, "incomplete input"), t2 = _2.to_Uint8Array(), M(a2), t2;
}
function f(e) {
  e = O(null, e, "input");
  for (var r2, t2, a2, _2 = "", n2 = 0; n2 < e.length; n2++) a2 = 87 + (t2 = 15 & e[n2]) + (t2 - 10 >> 8 & -39) << 8 | 87 + (r2 = e[n2] >>> 4) + (r2 - 10 >> 8 & -39), _2 += String.fromCharCode(255 & a2) + String.fromCharCode(a2 >>> 8);
  return _2;
}
var m = { ORIGINAL: 1, ORIGINAL_NO_PADDING: 3, URLSAFE: 5, URLSAFE_NO_PADDING: 7 };
function k(e) {
  if (void 0 === e) return m.URLSAFE_NO_PADDING;
  if (e !== m.ORIGINAL && e !== m.ORIGINAL_NO_PADDING && e !== m.URLSAFE && e !== m.URLSAFE_NO_PADDING) throw new Error("unsupported base64 variant");
  return e;
}
function x(e, t2) {
  t2 = k(t2);
  var a2, _2 = [], n2 = new B(3 * (e = O(_2, e, "input")).length / 4), s2 = K(e), c2 = A2(4), p2 = A2(4);
  return _2.push(s2), _2.push(n2.address), _2.push(c2), _2.push(p2), 0 !== r._sodium_base642bin(n2.address, n2.length, s2, e.length, 0, c2, p2, t2) && N(_2, "invalid input"), r.getValue(p2, "i32") - s2 !== e.length && N(_2, "incomplete input"), n2.length = r.getValue(c2, "i32"), a2 = n2.to_Uint8Array(), M(_2), a2;
}
function E(e, t2) {
  t2 = k(t2);
  var a2 = [];
  e = O(a2, e, "input");
  var _2, n2 = 0 | Math.floor(e.length / 3), s2 = e.length - 3 * n2, c2 = 4 * n2 + (0 !== s2 ? 2 & t2 ? 2 + (s2 >>> 1) : 4 : 0), p2 = new B(c2 + 1), o2 = K(e);
  return a2.push(o2), a2.push(p2.address), 0 === r._sodium_bin2base64(p2.address, p2.length, o2, e.length, t2) && N(a2, "conversion failed"), p2.length = c2, _2 = g(p2.to_Uint8Array()), M(a2), _2;
}
function T() {
  return ["uint8array", "text", "hex", "base64"];
}
function S(e, r2) {
  var t2 = r2 || "uint8array";
  if (!w(t2)) throw new Error(t2 + " output format is not available");
  if (e instanceof B) {
    if ("uint8array" === t2) return e.to_Uint8Array();
    if ("text" === t2) return g(e.to_Uint8Array());
    if ("hex" === t2) return f(e.to_Uint8Array());
    if ("base64" === t2) return E(e.to_Uint8Array(), m.URLSAFE_NO_PADDING);
    throw new Error('What is output format "' + t2 + '"?');
  }
  if ("object" == typeof e) {
    for (var a2 = Object.keys(e), _2 = {}, n2 = 0; n2 < a2.length; n2++) _2[a2[n2]] = S(e[a2[n2]], t2);
    return _2;
  }
  if ("string" == typeof e) return e;
  throw new TypeError("Cannot format output");
}
function w(e) {
  for (var r2 = ["uint8array", "text", "hex", "base64"], t2 = 0; t2 < r2.length; t2++) if (r2[t2] === e) return true;
  return false;
}
function Y(e) {
  if (e) {
    if ("string" != typeof e) throw new TypeError("When defined, the output format must be a string");
    if (!w(e)) throw new Error(e + " is not a supported output format");
  }
}
function B(e) {
  this.length = e, this.address = A2(e);
}
function K(e) {
  var t2 = A2(e.length);
  return r.HEAPU8.set(e, t2), t2;
}
function A2(e) {
  var t2 = r._malloc(e);
  if (0 === t2) throw { message: "_malloc() failed", length: e };
  return t2;
}
function I(e) {
  r._free(e);
}
function M(e) {
  if (e) for (var r2 = 0; r2 < e.length; r2++) I(e[r2]);
}
function N(e, r2) {
  throw M(e), new Error(r2);
}
function L(e, r2) {
  throw M(e), new TypeError(r2);
}
function U(e, r2, t2) {
  null == r2 && L(e, t2 + " cannot be null or undefined");
}
function O(e, r2, t2) {
  return U(e, r2, t2), r2 instanceof Uint8Array ? r2 : "string" == typeof r2 ? v(r2) : void L(e, "unsupported input type for " + t2);
}
function C(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = null;
  null != e && (p2 = K(e = O(c2, e, "secret_nonce")), e.length, c2.push(p2)), t2 = O(c2, t2, "ciphertext");
  var o2, h2 = r._crypto_aead_aegis128l_abytes(), y2 = t2.length;
  y2 < h2 && L(c2, "ciphertext is too short"), o2 = K(t2), c2.push(o2);
  var i2 = null, l2 = 0;
  null != a2 && (i2 = K(a2 = O(c2, a2, "additional_data")), l2 = a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var u2, d2 = 0 | r._crypto_aead_aegis128l_npubbytes();
  _2.length !== d2 && L(c2, "invalid public_nonce length"), u2 = K(_2), c2.push(u2), n2 = O(c2, n2, "key");
  var v2, g2 = 0 | r._crypto_aead_aegis128l_keybytes();
  n2.length !== g2 && L(c2, "invalid key length"), v2 = K(n2), c2.push(v2);
  var b2 = new B(y2 - r._crypto_aead_aegis128l_abytes() | 0), f2 = b2.address;
  if (c2.push(f2), 0 === r._crypto_aead_aegis128l_decrypt(f2, null, p2, o2, y2, 0, i2, l2, 0, u2, v2)) {
    var m2 = S(b2, s2);
    return M(c2), m2;
  }
  N(c2, "ciphertext cannot be decrypted using that key");
}
function R(e, t2, a2, _2, n2, s2, c2) {
  var p2 = [];
  Y(c2);
  var o2 = null;
  null != e && (o2 = K(e = O(p2, e, "secret_nonce")), e.length, p2.push(o2));
  var h2 = K(t2 = O(p2, t2, "ciphertext")), y2 = t2.length;
  p2.push(h2), a2 = O(p2, a2, "mac");
  var i2, l2 = 0 | r._crypto_aead_aegis128l_abytes();
  a2.length !== l2 && L(p2, "invalid mac length"), i2 = K(a2), p2.push(i2);
  var u2 = null, d2 = 0;
  null != _2 && (u2 = K(_2 = O(p2, _2, "additional_data")), d2 = _2.length, p2.push(u2)), n2 = O(p2, n2, "public_nonce");
  var v2, g2 = 0 | r._crypto_aead_aegis128l_npubbytes();
  n2.length !== g2 && L(p2, "invalid public_nonce length"), v2 = K(n2), p2.push(v2), s2 = O(p2, s2, "key");
  var b2, f2 = 0 | r._crypto_aead_aegis128l_keybytes();
  s2.length !== f2 && L(p2, "invalid key length"), b2 = K(s2), p2.push(b2);
  var m2 = new B(0 | y2), k2 = m2.address;
  if (p2.push(k2), 0 === r._crypto_aead_aegis128l_decrypt_detached(k2, o2, h2, y2, 0, i2, u2, d2, 0, v2, b2)) {
    var x2 = S(m2, c2);
    return M(p2), x2;
  }
  N(p2, "ciphertext cannot be decrypted using that key");
}
function P(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_aegis128l_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_aegis128l_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(o2 + r._crypto_aead_aegis128l_abytes() | 0), b2 = g2.address;
  if (c2.push(b2), 0 === r._crypto_aead_aegis128l_encrypt(b2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var f2 = S(g2, s2);
    return M(c2), f2;
  }
  N(c2, "invalid usage");
}
function X(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_aegis128l_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_aegis128l_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(0 | o2), b2 = g2.address;
  c2.push(b2);
  var f2 = new B(0 | r._crypto_aead_aegis128l_abytes()), m2 = f2.address;
  if (c2.push(m2), 0 === r._crypto_aead_aegis128l_encrypt_detached(b2, m2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var k2 = S({ ciphertext: g2, mac: f2 }, s2);
    return M(c2), k2;
  }
  N(c2, "invalid usage");
}
function D(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_aead_aegis128l_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_aead_aegis128l_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function G(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = null;
  null != e && (p2 = K(e = O(c2, e, "secret_nonce")), e.length, c2.push(p2)), t2 = O(c2, t2, "ciphertext");
  var o2, h2 = r._crypto_aead_aegis256_abytes(), y2 = t2.length;
  y2 < h2 && L(c2, "ciphertext is too short"), o2 = K(t2), c2.push(o2);
  var i2 = null, l2 = 0;
  null != a2 && (i2 = K(a2 = O(c2, a2, "additional_data")), l2 = a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var u2, d2 = 0 | r._crypto_aead_aegis256_npubbytes();
  _2.length !== d2 && L(c2, "invalid public_nonce length"), u2 = K(_2), c2.push(u2), n2 = O(c2, n2, "key");
  var v2, g2 = 0 | r._crypto_aead_aegis256_keybytes();
  n2.length !== g2 && L(c2, "invalid key length"), v2 = K(n2), c2.push(v2);
  var b2 = new B(y2 - r._crypto_aead_aegis256_abytes() | 0), f2 = b2.address;
  if (c2.push(f2), 0 === r._crypto_aead_aegis256_decrypt(f2, null, p2, o2, y2, 0, i2, l2, 0, u2, v2)) {
    var m2 = S(b2, s2);
    return M(c2), m2;
  }
  N(c2, "ciphertext cannot be decrypted using that key");
}
function F(e, t2, a2, _2, n2, s2, c2) {
  var p2 = [];
  Y(c2);
  var o2 = null;
  null != e && (o2 = K(e = O(p2, e, "secret_nonce")), e.length, p2.push(o2));
  var h2 = K(t2 = O(p2, t2, "ciphertext")), y2 = t2.length;
  p2.push(h2), a2 = O(p2, a2, "mac");
  var i2, l2 = 0 | r._crypto_aead_aegis256_abytes();
  a2.length !== l2 && L(p2, "invalid mac length"), i2 = K(a2), p2.push(i2);
  var u2 = null, d2 = 0;
  null != _2 && (u2 = K(_2 = O(p2, _2, "additional_data")), d2 = _2.length, p2.push(u2)), n2 = O(p2, n2, "public_nonce");
  var v2, g2 = 0 | r._crypto_aead_aegis256_npubbytes();
  n2.length !== g2 && L(p2, "invalid public_nonce length"), v2 = K(n2), p2.push(v2), s2 = O(p2, s2, "key");
  var b2, f2 = 0 | r._crypto_aead_aegis256_keybytes();
  s2.length !== f2 && L(p2, "invalid key length"), b2 = K(s2), p2.push(b2);
  var m2 = new B(0 | y2), k2 = m2.address;
  if (p2.push(k2), 0 === r._crypto_aead_aegis256_decrypt_detached(k2, o2, h2, y2, 0, i2, u2, d2, 0, v2, b2)) {
    var x2 = S(m2, c2);
    return M(p2), x2;
  }
  N(p2, "ciphertext cannot be decrypted using that key");
}
function V(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_aegis256_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_aegis256_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(o2 + r._crypto_aead_aegis256_abytes() | 0), b2 = g2.address;
  if (c2.push(b2), 0 === r._crypto_aead_aegis256_encrypt(b2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var f2 = S(g2, s2);
    return M(c2), f2;
  }
  N(c2, "invalid usage");
}
function q(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_aegis256_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_aegis256_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(0 | o2), b2 = g2.address;
  c2.push(b2);
  var f2 = new B(0 | r._crypto_aead_aegis256_abytes()), m2 = f2.address;
  if (c2.push(m2), 0 === r._crypto_aead_aegis256_encrypt_detached(b2, m2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var k2 = S({ ciphertext: g2, mac: f2 }, s2);
    return M(c2), k2;
  }
  N(c2, "invalid usage");
}
function H(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_aead_aegis256_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_aead_aegis256_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function z(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = null;
  null != e && (p2 = K(e = O(c2, e, "secret_nonce")), e.length, c2.push(p2)), t2 = O(c2, t2, "ciphertext");
  var o2, h2 = r._crypto_aead_chacha20poly1305_abytes(), y2 = t2.length;
  y2 < h2 && L(c2, "ciphertext is too short"), o2 = K(t2), c2.push(o2);
  var i2 = null, l2 = 0;
  null != a2 && (i2 = K(a2 = O(c2, a2, "additional_data")), l2 = a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var u2, d2 = 0 | r._crypto_aead_chacha20poly1305_npubbytes();
  _2.length !== d2 && L(c2, "invalid public_nonce length"), u2 = K(_2), c2.push(u2), n2 = O(c2, n2, "key");
  var v2, g2 = 0 | r._crypto_aead_chacha20poly1305_keybytes();
  n2.length !== g2 && L(c2, "invalid key length"), v2 = K(n2), c2.push(v2);
  var b2 = new B(y2 - r._crypto_aead_chacha20poly1305_abytes() | 0), f2 = b2.address;
  if (c2.push(f2), 0 === r._crypto_aead_chacha20poly1305_decrypt(f2, null, p2, o2, y2, 0, i2, l2, 0, u2, v2)) {
    var m2 = S(b2, s2);
    return M(c2), m2;
  }
  N(c2, "ciphertext cannot be decrypted using that key");
}
function W(e, t2, a2, _2, n2, s2, c2) {
  var p2 = [];
  Y(c2);
  var o2 = null;
  null != e && (o2 = K(e = O(p2, e, "secret_nonce")), e.length, p2.push(o2));
  var h2 = K(t2 = O(p2, t2, "ciphertext")), y2 = t2.length;
  p2.push(h2), a2 = O(p2, a2, "mac");
  var i2, l2 = 0 | r._crypto_box_macbytes();
  a2.length !== l2 && L(p2, "invalid mac length"), i2 = K(a2), p2.push(i2);
  var u2 = null, d2 = 0;
  null != _2 && (u2 = K(_2 = O(p2, _2, "additional_data")), d2 = _2.length, p2.push(u2)), n2 = O(p2, n2, "public_nonce");
  var v2, g2 = 0 | r._crypto_aead_chacha20poly1305_npubbytes();
  n2.length !== g2 && L(p2, "invalid public_nonce length"), v2 = K(n2), p2.push(v2), s2 = O(p2, s2, "key");
  var b2, f2 = 0 | r._crypto_aead_chacha20poly1305_keybytes();
  s2.length !== f2 && L(p2, "invalid key length"), b2 = K(s2), p2.push(b2);
  var m2 = new B(0 | y2), k2 = m2.address;
  if (p2.push(k2), 0 === r._crypto_aead_chacha20poly1305_decrypt_detached(k2, o2, h2, y2, 0, i2, u2, d2, 0, v2, b2)) {
    var x2 = S(m2, c2);
    return M(p2), x2;
  }
  N(p2, "ciphertext cannot be decrypted using that key");
}
function j(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_chacha20poly1305_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_chacha20poly1305_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(o2 + r._crypto_aead_chacha20poly1305_abytes() | 0), b2 = g2.address;
  if (c2.push(b2), 0 === r._crypto_aead_chacha20poly1305_encrypt(b2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var f2 = S(g2, s2);
    return M(c2), f2;
  }
  N(c2, "invalid usage");
}
function J(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_chacha20poly1305_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_chacha20poly1305_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(0 | o2), b2 = g2.address;
  c2.push(b2);
  var f2 = new B(0 | r._crypto_aead_chacha20poly1305_abytes()), m2 = f2.address;
  if (c2.push(m2), 0 === r._crypto_aead_chacha20poly1305_encrypt_detached(b2, m2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var k2 = S({ ciphertext: g2, mac: f2 }, s2);
    return M(c2), k2;
  }
  N(c2, "invalid usage");
}
function Q(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = null;
  null != e && (p2 = K(e = O(c2, e, "secret_nonce")), e.length, c2.push(p2)), t2 = O(c2, t2, "ciphertext");
  var o2, h2 = r._crypto_aead_chacha20poly1305_ietf_abytes(), y2 = t2.length;
  y2 < h2 && L(c2, "ciphertext is too short"), o2 = K(t2), c2.push(o2);
  var i2 = null, l2 = 0;
  null != a2 && (i2 = K(a2 = O(c2, a2, "additional_data")), l2 = a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var u2, d2 = 0 | r._crypto_aead_chacha20poly1305_ietf_npubbytes();
  _2.length !== d2 && L(c2, "invalid public_nonce length"), u2 = K(_2), c2.push(u2), n2 = O(c2, n2, "key");
  var v2, g2 = 0 | r._crypto_aead_chacha20poly1305_ietf_keybytes();
  n2.length !== g2 && L(c2, "invalid key length"), v2 = K(n2), c2.push(v2);
  var b2 = new B(y2 - r._crypto_aead_chacha20poly1305_ietf_abytes() | 0), f2 = b2.address;
  if (c2.push(f2), 0 === r._crypto_aead_chacha20poly1305_ietf_decrypt(f2, null, p2, o2, y2, 0, i2, l2, 0, u2, v2)) {
    var m2 = S(b2, s2);
    return M(c2), m2;
  }
  N(c2, "ciphertext cannot be decrypted using that key");
}
function Z(e, t2, a2, _2, n2, s2, c2) {
  var p2 = [];
  Y(c2);
  var o2 = null;
  null != e && (o2 = K(e = O(p2, e, "secret_nonce")), e.length, p2.push(o2));
  var h2 = K(t2 = O(p2, t2, "ciphertext")), y2 = t2.length;
  p2.push(h2), a2 = O(p2, a2, "mac");
  var i2, l2 = 0 | r._crypto_box_macbytes();
  a2.length !== l2 && L(p2, "invalid mac length"), i2 = K(a2), p2.push(i2);
  var u2 = null, d2 = 0;
  null != _2 && (u2 = K(_2 = O(p2, _2, "additional_data")), d2 = _2.length, p2.push(u2)), n2 = O(p2, n2, "public_nonce");
  var v2, g2 = 0 | r._crypto_aead_chacha20poly1305_ietf_npubbytes();
  n2.length !== g2 && L(p2, "invalid public_nonce length"), v2 = K(n2), p2.push(v2), s2 = O(p2, s2, "key");
  var b2, f2 = 0 | r._crypto_aead_chacha20poly1305_ietf_keybytes();
  s2.length !== f2 && L(p2, "invalid key length"), b2 = K(s2), p2.push(b2);
  var m2 = new B(0 | y2), k2 = m2.address;
  if (p2.push(k2), 0 === r._crypto_aead_chacha20poly1305_ietf_decrypt_detached(k2, o2, h2, y2, 0, i2, u2, d2, 0, v2, b2)) {
    var x2 = S(m2, c2);
    return M(p2), x2;
  }
  N(p2, "ciphertext cannot be decrypted using that key");
}
function $(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_chacha20poly1305_ietf_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_chacha20poly1305_ietf_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(o2 + r._crypto_aead_chacha20poly1305_ietf_abytes() | 0), b2 = g2.address;
  if (c2.push(b2), 0 === r._crypto_aead_chacha20poly1305_ietf_encrypt(b2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var f2 = S(g2, s2);
    return M(c2), f2;
  }
  N(c2, "invalid usage");
}
function ee(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_chacha20poly1305_ietf_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_chacha20poly1305_ietf_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(0 | o2), b2 = g2.address;
  c2.push(b2);
  var f2 = new B(0 | r._crypto_aead_chacha20poly1305_ietf_abytes()), m2 = f2.address;
  if (c2.push(m2), 0 === r._crypto_aead_chacha20poly1305_ietf_encrypt_detached(b2, m2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var k2 = S({ ciphertext: g2, mac: f2 }, s2);
    return M(c2), k2;
  }
  N(c2, "invalid usage");
}
function re(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_aead_chacha20poly1305_ietf_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_aead_chacha20poly1305_ietf_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function te(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_aead_chacha20poly1305_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_aead_chacha20poly1305_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function ae(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = null;
  null != e && (p2 = K(e = O(c2, e, "secret_nonce")), e.length, c2.push(p2)), t2 = O(c2, t2, "ciphertext");
  var o2, h2 = r._crypto_aead_xchacha20poly1305_ietf_abytes(), y2 = t2.length;
  y2 < h2 && L(c2, "ciphertext is too short"), o2 = K(t2), c2.push(o2);
  var i2 = null, l2 = 0;
  null != a2 && (i2 = K(a2 = O(c2, a2, "additional_data")), l2 = a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var u2, d2 = 0 | r._crypto_aead_xchacha20poly1305_ietf_npubbytes();
  _2.length !== d2 && L(c2, "invalid public_nonce length"), u2 = K(_2), c2.push(u2), n2 = O(c2, n2, "key");
  var v2, g2 = 0 | r._crypto_aead_xchacha20poly1305_ietf_keybytes();
  n2.length !== g2 && L(c2, "invalid key length"), v2 = K(n2), c2.push(v2);
  var b2 = new B(y2 - r._crypto_aead_xchacha20poly1305_ietf_abytes() | 0), f2 = b2.address;
  if (c2.push(f2), 0 === r._crypto_aead_xchacha20poly1305_ietf_decrypt(f2, null, p2, o2, y2, 0, i2, l2, 0, u2, v2)) {
    var m2 = S(b2, s2);
    return M(c2), m2;
  }
  N(c2, "ciphertext cannot be decrypted using that key");
}
function _e(e, t2, a2, _2, n2, s2, c2) {
  var p2 = [];
  Y(c2);
  var o2 = null;
  null != e && (o2 = K(e = O(p2, e, "secret_nonce")), e.length, p2.push(o2));
  var h2 = K(t2 = O(p2, t2, "ciphertext")), y2 = t2.length;
  p2.push(h2), a2 = O(p2, a2, "mac");
  var i2, l2 = 0 | r._crypto_box_macbytes();
  a2.length !== l2 && L(p2, "invalid mac length"), i2 = K(a2), p2.push(i2);
  var u2 = null, d2 = 0;
  null != _2 && (u2 = K(_2 = O(p2, _2, "additional_data")), d2 = _2.length, p2.push(u2)), n2 = O(p2, n2, "public_nonce");
  var v2, g2 = 0 | r._crypto_aead_xchacha20poly1305_ietf_npubbytes();
  n2.length !== g2 && L(p2, "invalid public_nonce length"), v2 = K(n2), p2.push(v2), s2 = O(p2, s2, "key");
  var b2, f2 = 0 | r._crypto_aead_xchacha20poly1305_ietf_keybytes();
  s2.length !== f2 && L(p2, "invalid key length"), b2 = K(s2), p2.push(b2);
  var m2 = new B(0 | y2), k2 = m2.address;
  if (p2.push(k2), 0 === r._crypto_aead_xchacha20poly1305_ietf_decrypt_detached(k2, o2, h2, y2, 0, i2, u2, d2, 0, v2, b2)) {
    var x2 = S(m2, c2);
    return M(p2), x2;
  }
  N(p2, "ciphertext cannot be decrypted using that key");
}
function ne(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_xchacha20poly1305_ietf_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_xchacha20poly1305_ietf_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(o2 + r._crypto_aead_xchacha20poly1305_ietf_abytes() | 0), b2 = g2.address;
  if (c2.push(b2), 0 === r._crypto_aead_xchacha20poly1305_ietf_encrypt(b2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var f2 = S(g2, s2);
    return M(c2), f2;
  }
  N(c2, "invalid usage");
}
function se(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "message")), o2 = e.length;
  c2.push(p2);
  var h2 = null, y2 = 0;
  null != t2 && (h2 = K(t2 = O(c2, t2, "additional_data")), y2 = t2.length, c2.push(h2));
  var i2 = null;
  null != a2 && (i2 = K(a2 = O(c2, a2, "secret_nonce")), a2.length, c2.push(i2)), _2 = O(c2, _2, "public_nonce");
  var l2, u2 = 0 | r._crypto_aead_xchacha20poly1305_ietf_npubbytes();
  _2.length !== u2 && L(c2, "invalid public_nonce length"), l2 = K(_2), c2.push(l2), n2 = O(c2, n2, "key");
  var d2, v2 = 0 | r._crypto_aead_xchacha20poly1305_ietf_keybytes();
  n2.length !== v2 && L(c2, "invalid key length"), d2 = K(n2), c2.push(d2);
  var g2 = new B(0 | o2), b2 = g2.address;
  c2.push(b2);
  var f2 = new B(0 | r._crypto_aead_xchacha20poly1305_ietf_abytes()), m2 = f2.address;
  if (c2.push(m2), 0 === r._crypto_aead_xchacha20poly1305_ietf_encrypt_detached(b2, m2, null, p2, o2, 0, h2, y2, 0, i2, l2, d2)) {
    var k2 = S({ ciphertext: g2, mac: f2 }, s2);
    return M(c2), k2;
  }
  N(c2, "invalid usage");
}
function ce(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_aead_xchacha20poly1305_ietf_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_aead_xchacha20poly1305_ietf_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function pe(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_auth_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_auth_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_auth(h2, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function oe(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_auth_hmacsha256_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_auth_hmacsha256_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_auth_hmacsha256(h2, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function he(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "state_address");
  var _2 = new B(0 | r._crypto_auth_hmacsha256_bytes()), n2 = _2.address;
  if (a2.push(n2), !(0 | r._crypto_auth_hmacsha256_final(e, n2))) {
    var s2 = (r._free(e), S(_2, t2));
    return M(a2), s2;
  }
  N(a2, "invalid usage");
}
function ye(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = null, n2 = 0;
  null != e && (_2 = K(e = O(a2, e, "key")), n2 = e.length, a2.push(_2));
  var s2 = new B(208).address;
  if (!(0 | r._crypto_auth_hmacsha256_init(s2, _2, n2))) {
    var c2 = s2;
    return M(a2), c2;
  }
  N(a2, "invalid usage");
}
function ie(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_auth_hmacsha256_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_auth_hmacsha256_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function le(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_auth_hmacsha256_update(e, n2, s2) && N(_2, "invalid usage"), M(_2);
}
function ue(e, t2, a2) {
  var _2 = [];
  e = O(_2, e, "tag");
  var n2, s2 = 0 | r._crypto_auth_hmacsha256_bytes();
  e.length !== s2 && L(_2, "invalid tag length"), n2 = K(e), _2.push(n2);
  var c2 = K(t2 = O(_2, t2, "message")), p2 = t2.length;
  _2.push(c2), a2 = O(_2, a2, "key");
  var o2, h2 = 0 | r._crypto_auth_hmacsha256_keybytes();
  a2.length !== h2 && L(_2, "invalid key length"), o2 = K(a2), _2.push(o2);
  var y2 = !(0 | r._crypto_auth_hmacsha256_verify(n2, c2, p2, 0, o2));
  return M(_2), y2;
}
function de(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_auth_hmacsha512_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_auth_hmacsha512_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_auth_hmacsha512(h2, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function ve(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_auth_hmacsha512256_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_auth_hmacsha512256_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_auth_hmacsha512256(h2, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function ge(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "state_address");
  var _2 = new B(0 | r._crypto_auth_hmacsha512256_bytes()), n2 = _2.address;
  if (a2.push(n2), !(0 | r._crypto_auth_hmacsha512256_final(e, n2))) {
    var s2 = (r._free(e), S(_2, t2));
    return M(a2), s2;
  }
  N(a2, "invalid usage");
}
function be(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = null, n2 = 0;
  null != e && (_2 = K(e = O(a2, e, "key")), n2 = e.length, a2.push(_2));
  var s2 = new B(416).address;
  if (!(0 | r._crypto_auth_hmacsha512256_init(s2, _2, n2))) {
    var c2 = s2;
    return M(a2), c2;
  }
  N(a2, "invalid usage");
}
function fe(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_auth_hmacsha512256_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_auth_hmacsha512256_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function me(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_auth_hmacsha512256_update(e, n2, s2) && N(_2, "invalid usage"), M(_2);
}
function ke(e, t2, a2) {
  var _2 = [];
  e = O(_2, e, "tag");
  var n2, s2 = 0 | r._crypto_auth_hmacsha512256_bytes();
  e.length !== s2 && L(_2, "invalid tag length"), n2 = K(e), _2.push(n2);
  var c2 = K(t2 = O(_2, t2, "message")), p2 = t2.length;
  _2.push(c2), a2 = O(_2, a2, "key");
  var o2, h2 = 0 | r._crypto_auth_hmacsha512256_keybytes();
  a2.length !== h2 && L(_2, "invalid key length"), o2 = K(a2), _2.push(o2);
  var y2 = !(0 | r._crypto_auth_hmacsha512256_verify(n2, c2, p2, 0, o2));
  return M(_2), y2;
}
function xe(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "state_address");
  var _2 = new B(0 | r._crypto_auth_hmacsha512_bytes()), n2 = _2.address;
  if (a2.push(n2), !(0 | r._crypto_auth_hmacsha512_final(e, n2))) {
    var s2 = (r._free(e), S(_2, t2));
    return M(a2), s2;
  }
  N(a2, "invalid usage");
}
function Ee(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = null, n2 = 0;
  null != e && (_2 = K(e = O(a2, e, "key")), n2 = e.length, a2.push(_2));
  var s2 = new B(416).address;
  if (!(0 | r._crypto_auth_hmacsha512_init(s2, _2, n2))) {
    var c2 = s2;
    return M(a2), c2;
  }
  N(a2, "invalid usage");
}
function Te(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_auth_hmacsha512_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_auth_hmacsha512_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function Se(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_auth_hmacsha512_update(e, n2, s2) && N(_2, "invalid usage"), M(_2);
}
function we(e, t2, a2) {
  var _2 = [];
  e = O(_2, e, "tag");
  var n2, s2 = 0 | r._crypto_auth_hmacsha512_bytes();
  e.length !== s2 && L(_2, "invalid tag length"), n2 = K(e), _2.push(n2);
  var c2 = K(t2 = O(_2, t2, "message")), p2 = t2.length;
  _2.push(c2), a2 = O(_2, a2, "key");
  var o2, h2 = 0 | r._crypto_auth_hmacsha512_keybytes();
  a2.length !== h2 && L(_2, "invalid key length"), o2 = K(a2), _2.push(o2);
  var y2 = !(0 | r._crypto_auth_hmacsha512_verify(n2, c2, p2, 0, o2));
  return M(_2), y2;
}
function Ye(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_auth_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_auth_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function Be(e, t2, a2) {
  var _2 = [];
  e = O(_2, e, "tag");
  var n2, s2 = 0 | r._crypto_auth_bytes();
  e.length !== s2 && L(_2, "invalid tag length"), n2 = K(e), _2.push(n2);
  var c2 = K(t2 = O(_2, t2, "message")), p2 = t2.length;
  _2.push(c2), a2 = O(_2, a2, "key");
  var o2, h2 = 0 | r._crypto_auth_keybytes();
  a2.length !== h2 && L(_2, "invalid key length"), o2 = K(a2), _2.push(o2);
  var y2 = !(0 | r._crypto_auth_verify(n2, c2, p2, 0, o2));
  return M(_2), y2;
}
function Ke(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "publicKey");
  var n2, s2 = 0 | r._crypto_box_publickeybytes();
  e.length !== s2 && L(_2, "invalid publicKey length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "privateKey");
  var c2, p2 = 0 | r._crypto_box_secretkeybytes();
  t2.length !== p2 && L(_2, "invalid privateKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_box_beforenmbytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_box_beforenm(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function Ae(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "publicKey");
  var n2, s2 = 0 | r._crypto_box_curve25519xchacha20poly1305_publickeybytes();
  e.length !== s2 && L(_2, "invalid publicKey length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "privateKey");
  var c2, p2 = 0 | r._crypto_box_curve25519xchacha20poly1305_secretkeybytes();
  t2.length !== p2 && L(_2, "invalid privateKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_box_curve25519xchacha20poly1305_beforenmbytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_box_curve25519xchacha20poly1305_beforenm(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function Ie(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2);
  var c2 = K(e = O(s2, e, "message")), p2 = e.length;
  s2.push(c2), t2 = O(s2, t2, "nonce");
  var o2, h2 = 0 | r._crypto_box_curve25519xchacha20poly1305_noncebytes();
  t2.length !== h2 && L(s2, "invalid nonce length"), o2 = K(t2), s2.push(o2), a2 = O(s2, a2, "publicKey");
  var y2, i2 = 0 | r._crypto_box_curve25519xchacha20poly1305_publickeybytes();
  a2.length !== i2 && L(s2, "invalid publicKey length"), y2 = K(a2), s2.push(y2), _2 = O(s2, _2, "privateKey");
  var l2, u2 = 0 | r._crypto_box_curve25519xchacha20poly1305_secretkeybytes();
  _2.length !== u2 && L(s2, "invalid privateKey length"), l2 = K(_2), s2.push(l2);
  var d2 = new B(0 | p2), v2 = d2.address;
  s2.push(v2);
  var g2 = new B(0 | r._crypto_box_curve25519xchacha20poly1305_macbytes()), b2 = g2.address;
  if (s2.push(b2), !(0 | r._crypto_box_curve25519xchacha20poly1305_detached(v2, b2, c2, p2, 0, o2, y2, l2))) {
    var f2 = S({ ciphertext: d2, mac: g2 }, n2);
    return M(s2), f2;
  }
  N(s2, "invalid usage");
}
function Me(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "message")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_box_curve25519xchacha20poly1305_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "sharedKey");
  var h2, y2 = 0 | r._crypto_box_curve25519xchacha20poly1305_beforenmbytes();
  a2.length !== y2 && L(n2, "invalid sharedKey length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(0 | c2), l2 = i2.address;
  n2.push(l2);
  var u2 = new B(0 | r._crypto_box_curve25519xchacha20poly1305_macbytes()), d2 = u2.address;
  if (n2.push(d2), !(0 | r._crypto_box_curve25519xchacha20poly1305_detached_afternm(l2, d2, s2, c2, 0, p2, h2))) {
    var v2 = S({ ciphertext: i2, mac: u2 }, _2);
    return M(n2), v2;
  }
  N(n2, "invalid usage");
}
function Ne(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2);
  var c2 = K(e = O(s2, e, "message")), p2 = e.length;
  s2.push(c2), t2 = O(s2, t2, "nonce");
  var o2, h2 = 0 | r._crypto_box_curve25519xchacha20poly1305_noncebytes();
  t2.length !== h2 && L(s2, "invalid nonce length"), o2 = K(t2), s2.push(o2), a2 = O(s2, a2, "publicKey");
  var y2, i2 = 0 | r._crypto_box_curve25519xchacha20poly1305_publickeybytes();
  a2.length !== i2 && L(s2, "invalid publicKey length"), y2 = K(a2), s2.push(y2), _2 = O(s2, _2, "privateKey");
  var l2, u2 = 0 | r._crypto_box_curve25519xchacha20poly1305_secretkeybytes();
  _2.length !== u2 && L(s2, "invalid privateKey length"), l2 = K(_2), s2.push(l2);
  var d2 = new B(p2 + r._crypto_box_curve25519xchacha20poly1305_macbytes() | 0), v2 = d2.address;
  if (s2.push(v2), !(0 | r._crypto_box_curve25519xchacha20poly1305_easy(v2, c2, p2, 0, o2, y2, l2))) {
    var g2 = S(d2, n2);
    return M(s2), g2;
  }
  N(s2, "invalid usage");
}
function Le(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "message")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_box_curve25519xchacha20poly1305_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "sharedKey");
  var h2, y2 = 0 | r._crypto_box_curve25519xchacha20poly1305_beforenmbytes();
  a2.length !== y2 && L(n2, "invalid sharedKey length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(c2 + r._crypto_box_curve25519xchacha20poly1305_macbytes() | 0), l2 = i2.address;
  if (n2.push(l2), !(0 | r._crypto_box_curve25519xchacha20poly1305_easy_afternm(l2, s2, c2, 0, p2, h2))) {
    var u2 = S(i2, _2);
    return M(n2), u2;
  }
  N(n2, "invalid usage");
}
function Ue(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_box_curve25519xchacha20poly1305_publickeybytes()), _2 = a2.address;
  t2.push(_2);
  var n2 = new B(0 | r._crypto_box_curve25519xchacha20poly1305_secretkeybytes()), s2 = n2.address;
  t2.push(s2), r._crypto_box_curve25519xchacha20poly1305_keypair(_2, s2);
  var c2 = S({ publicKey: a2, privateKey: n2, keyType: "curve25519" }, e);
  return M(t2), c2;
}
function Oe(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "ciphertext")), o2 = e.length;
  c2.push(p2), t2 = O(c2, t2, "mac");
  var h2, y2 = 0 | r._crypto_box_curve25519xchacha20poly1305_macbytes();
  t2.length !== y2 && L(c2, "invalid mac length"), h2 = K(t2), c2.push(h2), a2 = O(c2, a2, "nonce");
  var i2, l2 = 0 | r._crypto_box_curve25519xchacha20poly1305_noncebytes();
  a2.length !== l2 && L(c2, "invalid nonce length"), i2 = K(a2), c2.push(i2), _2 = O(c2, _2, "publicKey");
  var u2, d2 = 0 | r._crypto_box_curve25519xchacha20poly1305_publickeybytes();
  _2.length !== d2 && L(c2, "invalid publicKey length"), u2 = K(_2), c2.push(u2), n2 = O(c2, n2, "privateKey");
  var v2, g2 = 0 | r._crypto_box_curve25519xchacha20poly1305_secretkeybytes();
  n2.length !== g2 && L(c2, "invalid privateKey length"), v2 = K(n2), c2.push(v2);
  var b2 = new B(0 | o2), f2 = b2.address;
  if (c2.push(f2), !(0 | r._crypto_box_curve25519xchacha20poly1305_open_detached(f2, p2, h2, o2, 0, i2, u2, v2))) {
    var m2 = S(b2, s2);
    return M(c2), m2;
  }
  N(c2, "incorrect key pair for the given ciphertext");
}
function Ce(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2);
  var c2 = K(e = O(s2, e, "ciphertext")), p2 = e.length;
  s2.push(c2), t2 = O(s2, t2, "mac");
  var o2, h2 = 0 | r._crypto_box_curve25519xchacha20poly1305_macbytes();
  t2.length !== h2 && L(s2, "invalid mac length"), o2 = K(t2), s2.push(o2), a2 = O(s2, a2, "nonce");
  var y2, i2 = 0 | r._crypto_box_curve25519xchacha20poly1305_noncebytes();
  a2.length !== i2 && L(s2, "invalid nonce length"), y2 = K(a2), s2.push(y2), _2 = O(s2, _2, "sharedKey");
  var l2, u2 = 0 | r._crypto_box_curve25519xchacha20poly1305_beforenmbytes();
  _2.length !== u2 && L(s2, "invalid sharedKey length"), l2 = K(_2), s2.push(l2);
  var d2 = new B(0 | p2), v2 = d2.address;
  if (s2.push(v2), !(0 | r._crypto_box_curve25519xchacha20poly1305_open_detached_afternm(v2, c2, o2, p2, 0, y2, l2))) {
    var g2 = S(d2, n2);
    return M(s2), g2;
  }
  N(s2, "incorrect secret key for the given ciphertext");
}
function Re(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2), e = O(s2, e, "ciphertext");
  var c2, p2 = r._crypto_box_curve25519xchacha20poly1305_macbytes(), o2 = e.length;
  o2 < p2 && L(s2, "ciphertext is too short"), c2 = K(e), s2.push(c2), t2 = O(s2, t2, "nonce");
  var h2, y2 = 0 | r._crypto_box_curve25519xchacha20poly1305_noncebytes();
  t2.length !== y2 && L(s2, "invalid nonce length"), h2 = K(t2), s2.push(h2), a2 = O(s2, a2, "publicKey");
  var i2, l2 = 0 | r._crypto_box_curve25519xchacha20poly1305_publickeybytes();
  a2.length !== l2 && L(s2, "invalid publicKey length"), i2 = K(a2), s2.push(i2), _2 = O(s2, _2, "privateKey");
  var u2, d2 = 0 | r._crypto_box_curve25519xchacha20poly1305_secretkeybytes();
  _2.length !== d2 && L(s2, "invalid privateKey length"), u2 = K(_2), s2.push(u2);
  var v2 = new B(o2 - r._crypto_box_curve25519xchacha20poly1305_macbytes() | 0), g2 = v2.address;
  if (s2.push(g2), !(0 | r._crypto_box_curve25519xchacha20poly1305_open_easy(g2, c2, o2, 0, h2, i2, u2))) {
    var b2 = S(v2, n2);
    return M(s2), b2;
  }
  N(s2, "incorrect key pair for the given ciphertext");
}
function Pe(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "ciphertext")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_box_curve25519xchacha20poly1305_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "sharedKey");
  var h2, y2 = 0 | r._crypto_box_curve25519xchacha20poly1305_beforenmbytes();
  a2.length !== y2 && L(n2, "invalid sharedKey length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(c2 - r._crypto_box_curve25519xchacha20poly1305_macbytes() | 0), l2 = i2.address;
  if (n2.push(l2), !(0 | r._crypto_box_curve25519xchacha20poly1305_open_easy_afternm(l2, s2, c2, 0, p2, h2))) {
    var u2 = S(i2, _2);
    return M(n2), u2;
  }
  N(n2, "incorrect secret key for the given ciphertext");
}
function Xe(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "publicKey");
  var c2, p2 = 0 | r._crypto_box_curve25519xchacha20poly1305_publickeybytes();
  t2.length !== p2 && L(_2, "invalid publicKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(s2 + r._crypto_box_curve25519xchacha20poly1305_sealbytes() | 0), h2 = o2.address;
  _2.push(h2), r._crypto_box_curve25519xchacha20poly1305_seal(h2, n2, s2, 0, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function De(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), e = O(n2, e, "ciphertext");
  var s2, c2 = r._crypto_box_curve25519xchacha20poly1305_sealbytes(), p2 = e.length;
  p2 < c2 && L(n2, "ciphertext is too short"), s2 = K(e), n2.push(s2), t2 = O(n2, t2, "publicKey");
  var o2, h2 = 0 | r._crypto_box_curve25519xchacha20poly1305_publickeybytes();
  t2.length !== h2 && L(n2, "invalid publicKey length"), o2 = K(t2), n2.push(o2), a2 = O(n2, a2, "secretKey");
  var y2, i2 = 0 | r._crypto_box_curve25519xchacha20poly1305_secretkeybytes();
  a2.length !== i2 && L(n2, "invalid secretKey length"), y2 = K(a2), n2.push(y2);
  var l2 = new B(p2 - r._crypto_box_curve25519xchacha20poly1305_sealbytes() | 0), u2 = l2.address;
  n2.push(u2), r._crypto_box_curve25519xchacha20poly1305_seal_open(u2, s2, p2, 0, o2, y2);
  var d2 = S(l2, _2);
  return M(n2), d2;
}
function Ge(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "seed");
  var _2, n2 = 0 | r._crypto_box_curve25519xchacha20poly1305_seedbytes();
  e.length !== n2 && L(a2, "invalid seed length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_box_curve25519xchacha20poly1305_publickeybytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_box_curve25519xchacha20poly1305_secretkeybytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_box_curve25519xchacha20poly1305_seed_keypair(c2, o2, _2))) {
    var h2 = { publicKey: S(s2, t2), privateKey: S(p2, t2), keyType: "x25519" };
    return M(a2), h2;
  }
  N(a2, "invalid usage");
}
function Fe(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2);
  var c2 = K(e = O(s2, e, "message")), p2 = e.length;
  s2.push(c2), t2 = O(s2, t2, "nonce");
  var o2, h2 = 0 | r._crypto_box_noncebytes();
  t2.length !== h2 && L(s2, "invalid nonce length"), o2 = K(t2), s2.push(o2), a2 = O(s2, a2, "publicKey");
  var y2, i2 = 0 | r._crypto_box_publickeybytes();
  a2.length !== i2 && L(s2, "invalid publicKey length"), y2 = K(a2), s2.push(y2), _2 = O(s2, _2, "privateKey");
  var l2, u2 = 0 | r._crypto_box_secretkeybytes();
  _2.length !== u2 && L(s2, "invalid privateKey length"), l2 = K(_2), s2.push(l2);
  var d2 = new B(0 | p2), v2 = d2.address;
  s2.push(v2);
  var g2 = new B(0 | r._crypto_box_macbytes()), b2 = g2.address;
  if (s2.push(b2), !(0 | r._crypto_box_detached(v2, b2, c2, p2, 0, o2, y2, l2))) {
    var f2 = S({ ciphertext: d2, mac: g2 }, n2);
    return M(s2), f2;
  }
  N(s2, "invalid usage");
}
function Ve(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2);
  var c2 = K(e = O(s2, e, "message")), p2 = e.length;
  s2.push(c2), t2 = O(s2, t2, "nonce");
  var o2, h2 = 0 | r._crypto_box_noncebytes();
  t2.length !== h2 && L(s2, "invalid nonce length"), o2 = K(t2), s2.push(o2), a2 = O(s2, a2, "publicKey");
  var y2, i2 = 0 | r._crypto_box_publickeybytes();
  a2.length !== i2 && L(s2, "invalid publicKey length"), y2 = K(a2), s2.push(y2), _2 = O(s2, _2, "privateKey");
  var l2, u2 = 0 | r._crypto_box_secretkeybytes();
  _2.length !== u2 && L(s2, "invalid privateKey length"), l2 = K(_2), s2.push(l2);
  var d2 = new B(p2 + r._crypto_box_macbytes() | 0), v2 = d2.address;
  if (s2.push(v2), !(0 | r._crypto_box_easy(v2, c2, p2, 0, o2, y2, l2))) {
    var g2 = S(d2, n2);
    return M(s2), g2;
  }
  N(s2, "invalid usage");
}
function qe(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "message")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_box_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "sharedKey");
  var h2, y2 = 0 | r._crypto_box_beforenmbytes();
  a2.length !== y2 && L(n2, "invalid sharedKey length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(c2 + r._crypto_box_macbytes() | 0), l2 = i2.address;
  if (n2.push(l2), !(0 | r._crypto_box_easy_afternm(l2, s2, c2, 0, p2, h2))) {
    var u2 = S(i2, _2);
    return M(n2), u2;
  }
  N(n2, "invalid usage");
}
function He(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_box_publickeybytes()), _2 = a2.address;
  t2.push(_2);
  var n2 = new B(0 | r._crypto_box_secretkeybytes()), s2 = n2.address;
  if (t2.push(s2), !(0 | r._crypto_box_keypair(_2, s2))) {
    var c2 = { publicKey: S(a2, e), privateKey: S(n2, e), keyType: "x25519" };
    return M(t2), c2;
  }
  N(t2, "internal error");
}
function ze(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2);
  var p2 = K(e = O(c2, e, "ciphertext")), o2 = e.length;
  c2.push(p2), t2 = O(c2, t2, "mac");
  var h2, y2 = 0 | r._crypto_box_macbytes();
  t2.length !== y2 && L(c2, "invalid mac length"), h2 = K(t2), c2.push(h2), a2 = O(c2, a2, "nonce");
  var i2, l2 = 0 | r._crypto_box_noncebytes();
  a2.length !== l2 && L(c2, "invalid nonce length"), i2 = K(a2), c2.push(i2), _2 = O(c2, _2, "publicKey");
  var u2, d2 = 0 | r._crypto_box_publickeybytes();
  _2.length !== d2 && L(c2, "invalid publicKey length"), u2 = K(_2), c2.push(u2), n2 = O(c2, n2, "privateKey");
  var v2, g2 = 0 | r._crypto_box_secretkeybytes();
  n2.length !== g2 && L(c2, "invalid privateKey length"), v2 = K(n2), c2.push(v2);
  var b2 = new B(0 | o2), f2 = b2.address;
  if (c2.push(f2), !(0 | r._crypto_box_open_detached(f2, p2, h2, o2, 0, i2, u2, v2))) {
    var m2 = S(b2, s2);
    return M(c2), m2;
  }
  N(c2, "incorrect key pair for the given ciphertext");
}
function We(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2), e = O(s2, e, "ciphertext");
  var c2, p2 = r._crypto_box_macbytes(), o2 = e.length;
  o2 < p2 && L(s2, "ciphertext is too short"), c2 = K(e), s2.push(c2), t2 = O(s2, t2, "nonce");
  var h2, y2 = 0 | r._crypto_box_noncebytes();
  t2.length !== y2 && L(s2, "invalid nonce length"), h2 = K(t2), s2.push(h2), a2 = O(s2, a2, "publicKey");
  var i2, l2 = 0 | r._crypto_box_publickeybytes();
  a2.length !== l2 && L(s2, "invalid publicKey length"), i2 = K(a2), s2.push(i2), _2 = O(s2, _2, "privateKey");
  var u2, d2 = 0 | r._crypto_box_secretkeybytes();
  _2.length !== d2 && L(s2, "invalid privateKey length"), u2 = K(_2), s2.push(u2);
  var v2 = new B(o2 - r._crypto_box_macbytes() | 0), g2 = v2.address;
  if (s2.push(g2), !(0 | r._crypto_box_open_easy(g2, c2, o2, 0, h2, i2, u2))) {
    var b2 = S(v2, n2);
    return M(s2), b2;
  }
  N(s2, "incorrect key pair for the given ciphertext");
}
function je(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "ciphertext")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_box_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "sharedKey");
  var h2, y2 = 0 | r._crypto_box_beforenmbytes();
  a2.length !== y2 && L(n2, "invalid sharedKey length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(c2 - r._crypto_box_macbytes() | 0), l2 = i2.address;
  if (n2.push(l2), !(0 | r._crypto_box_open_easy_afternm(l2, s2, c2, 0, p2, h2))) {
    var u2 = S(i2, _2);
    return M(n2), u2;
  }
  N(n2, "incorrect secret key for the given ciphertext");
}
function Je(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "publicKey");
  var c2, p2 = 0 | r._crypto_box_publickeybytes();
  t2.length !== p2 && L(_2, "invalid publicKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(s2 + r._crypto_box_sealbytes() | 0), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_box_seal(h2, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function Qe(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), e = O(n2, e, "ciphertext");
  var s2, c2 = r._crypto_box_sealbytes(), p2 = e.length;
  p2 < c2 && L(n2, "ciphertext is too short"), s2 = K(e), n2.push(s2), t2 = O(n2, t2, "publicKey");
  var o2, h2 = 0 | r._crypto_box_publickeybytes();
  t2.length !== h2 && L(n2, "invalid publicKey length"), o2 = K(t2), n2.push(o2), a2 = O(n2, a2, "privateKey");
  var y2, i2 = 0 | r._crypto_box_secretkeybytes();
  a2.length !== i2 && L(n2, "invalid privateKey length"), y2 = K(a2), n2.push(y2);
  var l2 = new B(p2 - r._crypto_box_sealbytes() | 0), u2 = l2.address;
  if (n2.push(u2), !(0 | r._crypto_box_seal_open(u2, s2, p2, 0, o2, y2))) {
    var d2 = S(l2, _2);
    return M(n2), d2;
  }
  N(n2, "incorrect key pair for the given ciphertext");
}
function Ze(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "seed");
  var _2, n2 = 0 | r._crypto_box_seedbytes();
  e.length !== n2 && L(a2, "invalid seed length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_box_publickeybytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_box_secretkeybytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_box_seed_keypair(c2, o2, _2))) {
    var h2 = { publicKey: S(s2, t2), privateKey: S(p2, t2), keyType: "x25519" };
    return M(a2), h2;
  }
  N(a2, "invalid usage");
}
function $e(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "p");
  var n2, s2 = 0 | r._crypto_core_ed25519_bytes();
  e.length !== s2 && L(_2, "invalid p length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "q");
  var c2, p2 = 0 | r._crypto_core_ed25519_bytes();
  t2.length !== p2 && L(_2, "invalid q length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ed25519_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_core_ed25519_add(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "input is an invalid element");
}
function er(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = K(e = O(a2, e, "r"));
  e.length, a2.push(_2);
  var n2 = new B(0 | r._crypto_core_ed25519_bytes()), s2 = n2.address;
  if (a2.push(s2), !(0 | r._crypto_core_ed25519_from_hash(s2, _2))) {
    var c2 = S(n2, t2);
    return M(a2), c2;
  }
  N(a2, "invalid usage");
}
function rr(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = K(e = O(a2, e, "r"));
  e.length, a2.push(_2);
  var n2 = new B(0 | r._crypto_core_ed25519_bytes()), s2 = n2.address;
  if (a2.push(s2), !(0 | r._crypto_core_ed25519_from_uniform(s2, _2))) {
    var c2 = S(n2, t2);
    return M(a2), c2;
  }
  N(a2, "invalid usage");
}
function tr(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "repr");
  var _2, n2 = 0 | r._crypto_core_ed25519_bytes();
  e.length !== n2 && L(a2, "invalid repr length"), _2 = K(e), a2.push(_2);
  var s2 = 1 == (0 | r._crypto_core_ed25519_is_valid_point(_2));
  return M(a2), s2;
}
function ar(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_core_ed25519_bytes()), _2 = a2.address;
  t2.push(_2), r._crypto_core_ed25519_random(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function _r(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "x");
  var n2, s2 = 0 | r._crypto_core_ed25519_scalarbytes();
  e.length !== s2 && L(_2, "invalid x length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "y");
  var c2, p2 = 0 | r._crypto_core_ed25519_scalarbytes();
  t2.length !== p2 && L(_2, "invalid y length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ed25519_scalarbytes()), h2 = o2.address;
  _2.push(h2), r._crypto_core_ed25519_scalar_add(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function nr(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "s");
  var _2, n2 = 0 | r._crypto_core_ed25519_scalarbytes();
  e.length !== n2 && L(a2, "invalid s length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_core_ed25519_scalarbytes()), c2 = s2.address;
  a2.push(c2), r._crypto_core_ed25519_scalar_complement(c2, _2);
  var p2 = S(s2, t2);
  return M(a2), p2;
}
function sr(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "s");
  var _2, n2 = 0 | r._crypto_core_ed25519_scalarbytes();
  e.length !== n2 && L(a2, "invalid s length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_core_ed25519_scalarbytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_core_ed25519_scalar_invert(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid reciprocate");
}
function cr(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "x");
  var n2, s2 = 0 | r._crypto_core_ed25519_scalarbytes();
  e.length !== s2 && L(_2, "invalid x length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "y");
  var c2, p2 = 0 | r._crypto_core_ed25519_scalarbytes();
  t2.length !== p2 && L(_2, "invalid y length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ed25519_scalarbytes()), h2 = o2.address;
  _2.push(h2), r._crypto_core_ed25519_scalar_mul(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function pr(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "s");
  var _2, n2 = 0 | r._crypto_core_ed25519_scalarbytes();
  e.length !== n2 && L(a2, "invalid s length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_core_ed25519_scalarbytes()), c2 = s2.address;
  a2.push(c2), r._crypto_core_ed25519_scalar_negate(c2, _2);
  var p2 = S(s2, t2);
  return M(a2), p2;
}
function or(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_core_ed25519_scalarbytes()), _2 = a2.address;
  t2.push(_2), r._crypto_core_ed25519_scalar_random(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function hr(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "sample");
  var _2, n2 = 0 | r._crypto_core_ed25519_nonreducedscalarbytes();
  e.length !== n2 && L(a2, "invalid sample length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_core_ed25519_scalarbytes()), c2 = s2.address;
  a2.push(c2), r._crypto_core_ed25519_scalar_reduce(c2, _2);
  var p2 = S(s2, t2);
  return M(a2), p2;
}
function yr(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "x");
  var n2, s2 = 0 | r._crypto_core_ed25519_scalarbytes();
  e.length !== s2 && L(_2, "invalid x length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "y");
  var c2, p2 = 0 | r._crypto_core_ed25519_scalarbytes();
  t2.length !== p2 && L(_2, "invalid y length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ed25519_scalarbytes()), h2 = o2.address;
  _2.push(h2), r._crypto_core_ed25519_scalar_sub(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function ir(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "p");
  var n2, s2 = 0 | r._crypto_core_ed25519_bytes();
  e.length !== s2 && L(_2, "invalid p length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "q");
  var c2, p2 = 0 | r._crypto_core_ed25519_bytes();
  t2.length !== p2 && L(_2, "invalid q length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ed25519_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_core_ed25519_sub(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "input is an invalid element");
}
function lr(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), e = O(n2, e, "input");
  var s2, c2 = 0 | r._crypto_core_hchacha20_inputbytes();
  e.length !== c2 && L(n2, "invalid input length"), s2 = K(e), n2.push(s2), t2 = O(n2, t2, "privateKey");
  var p2, o2 = 0 | r._crypto_core_hchacha20_keybytes();
  t2.length !== o2 && L(n2, "invalid privateKey length"), p2 = K(t2), n2.push(p2);
  var h2 = null;
  null != a2 && (h2 = K(a2 = O(n2, a2, "constant")), a2.length, n2.push(h2));
  var y2 = new B(0 | r._crypto_core_hchacha20_outputbytes()), i2 = y2.address;
  if (n2.push(i2), !(0 | r._crypto_core_hchacha20(i2, s2, p2, h2))) {
    var l2 = S(y2, _2);
    return M(n2), l2;
  }
  N(n2, "invalid usage");
}
function ur(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), e = O(n2, e, "input");
  var s2, c2 = 0 | r._crypto_core_hsalsa20_inputbytes();
  e.length !== c2 && L(n2, "invalid input length"), s2 = K(e), n2.push(s2), t2 = O(n2, t2, "privateKey");
  var p2, o2 = 0 | r._crypto_core_hsalsa20_keybytes();
  t2.length !== o2 && L(n2, "invalid privateKey length"), p2 = K(t2), n2.push(p2);
  var h2 = null;
  null != a2 && (h2 = K(a2 = O(n2, a2, "constant")), a2.length, n2.push(h2));
  var y2 = new B(0 | r._crypto_core_hsalsa20_outputbytes()), i2 = y2.address;
  if (n2.push(i2), !(0 | r._crypto_core_hsalsa20(i2, s2, p2, h2))) {
    var l2 = S(y2, _2);
    return M(n2), l2;
  }
  N(n2, "invalid usage");
}
function dr(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "p");
  var n2, s2 = 0 | r._crypto_core_ristretto255_bytes();
  e.length !== s2 && L(_2, "invalid p length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "q");
  var c2, p2 = 0 | r._crypto_core_ristretto255_bytes();
  t2.length !== p2 && L(_2, "invalid q length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ristretto255_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_core_ristretto255_add(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "input is an invalid element");
}
function vr(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = K(e = O(a2, e, "r"));
  e.length, a2.push(_2);
  var n2 = new B(0 | r._crypto_core_ristretto255_bytes()), s2 = n2.address;
  if (a2.push(s2), !(0 | r._crypto_core_ristretto255_from_hash(s2, _2))) {
    var c2 = S(n2, t2);
    return M(a2), c2;
  }
  N(a2, "invalid usage");
}
function gr(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "repr");
  var _2, n2 = 0 | r._crypto_core_ristretto255_bytes();
  e.length !== n2 && L(a2, "invalid repr length"), _2 = K(e), a2.push(_2);
  var s2 = 1 == (0 | r._crypto_core_ristretto255_is_valid_point(_2));
  return M(a2), s2;
}
function br(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_core_ristretto255_bytes()), _2 = a2.address;
  t2.push(_2), r._crypto_core_ristretto255_random(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function fr(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "x");
  var n2, s2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  e.length !== s2 && L(_2, "invalid x length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "y");
  var c2, p2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  t2.length !== p2 && L(_2, "invalid y length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ristretto255_scalarbytes()), h2 = o2.address;
  _2.push(h2), r._crypto_core_ristretto255_scalar_add(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function mr(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "s");
  var _2, n2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  e.length !== n2 && L(a2, "invalid s length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_core_ristretto255_scalarbytes()), c2 = s2.address;
  a2.push(c2), r._crypto_core_ristretto255_scalar_complement(c2, _2);
  var p2 = S(s2, t2);
  return M(a2), p2;
}
function kr(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "s");
  var _2, n2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  e.length !== n2 && L(a2, "invalid s length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_core_ristretto255_scalarbytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_core_ristretto255_scalar_invert(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid reciprocate");
}
function xr(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "x");
  var n2, s2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  e.length !== s2 && L(_2, "invalid x length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "y");
  var c2, p2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  t2.length !== p2 && L(_2, "invalid y length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ristretto255_scalarbytes()), h2 = o2.address;
  _2.push(h2), r._crypto_core_ristretto255_scalar_mul(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function Er(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "s");
  var _2, n2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  e.length !== n2 && L(a2, "invalid s length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_core_ristretto255_scalarbytes()), c2 = s2.address;
  a2.push(c2), r._crypto_core_ristretto255_scalar_negate(c2, _2);
  var p2 = S(s2, t2);
  return M(a2), p2;
}
function Tr(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_core_ristretto255_scalarbytes()), _2 = a2.address;
  t2.push(_2), r._crypto_core_ristretto255_scalar_random(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function Sr(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "sample");
  var _2, n2 = 0 | r._crypto_core_ristretto255_nonreducedscalarbytes();
  e.length !== n2 && L(a2, "invalid sample length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_core_ristretto255_scalarbytes()), c2 = s2.address;
  a2.push(c2), r._crypto_core_ristretto255_scalar_reduce(c2, _2);
  var p2 = S(s2, t2);
  return M(a2), p2;
}
function wr(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "x");
  var n2, s2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  e.length !== s2 && L(_2, "invalid x length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "y");
  var c2, p2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  t2.length !== p2 && L(_2, "invalid y length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ristretto255_scalarbytes()), h2 = o2.address;
  _2.push(h2), r._crypto_core_ristretto255_scalar_sub(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function Yr(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "p");
  var n2, s2 = 0 | r._crypto_core_ristretto255_bytes();
  e.length !== s2 && L(_2, "invalid p length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "q");
  var c2, p2 = 0 | r._crypto_core_ristretto255_bytes();
  t2.length !== p2 && L(_2, "invalid q length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_core_ristretto255_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_core_ristretto255_sub(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "input is an invalid element");
}
function Br(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), U(n2, e, "hash_length"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(n2, "hash_length must be an unsigned integer");
  var s2 = K(t2 = O(n2, t2, "message")), c2 = t2.length;
  n2.push(s2);
  var p2 = null, o2 = 0;
  null != a2 && (p2 = K(a2 = O(n2, a2, "key")), o2 = a2.length, n2.push(p2));
  var h2 = new B(e |= 0), y2 = h2.address;
  if (n2.push(y2), !(0 | r._crypto_generichash(y2, e, s2, c2, 0, p2, o2))) {
    var i2 = S(h2, _2);
    return M(n2), i2;
  }
  N(n2, "invalid usage");
}
function Kr(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2), U(s2, e, "subkey_len"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(s2, "subkey_len must be an unsigned integer");
  var c2 = null, p2 = 0;
  null != t2 && (c2 = K(t2 = O(s2, t2, "key")), p2 = t2.length, s2.push(c2));
  var o2 = null, h2 = 0;
  null != a2 && (a2 = O(s2, a2, "id"), h2 = 0 | r._crypto_generichash_blake2b_saltbytes(), a2.length !== h2 && L(s2, "invalid id length"), o2 = K(a2), s2.push(o2));
  var y2 = null, i2 = 0;
  null != _2 && (_2 = O(s2, _2, "ctx"), i2 = 0 | r._crypto_generichash_blake2b_personalbytes(), _2.length !== i2 && L(s2, "invalid ctx length"), y2 = K(_2), s2.push(y2));
  var l2 = new B(0 | e), u2 = l2.address;
  if (s2.push(u2), !(0 | r._crypto_generichash_blake2b_salt_personal(u2, e, null, 0, 0, c2, p2, o2, y2))) {
    var d2 = S(l2, n2);
    return M(s2), d2;
  }
  N(s2, "invalid usage");
}
function Ar(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address"), U(_2, t2, "hash_length"), ("number" != typeof t2 || (0 | t2) !== t2 || t2 < 0) && L(_2, "hash_length must be an unsigned integer");
  var n2 = new B(t2 |= 0), s2 = n2.address;
  if (_2.push(s2), !(0 | r._crypto_generichash_final(e, s2, t2))) {
    var c2 = (r._free(e), S(n2, a2));
    return M(_2), c2;
  }
  N(_2, "invalid usage");
}
function Ir(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = null, s2 = 0;
  null != e && (n2 = K(e = O(_2, e, "key")), s2 = e.length, _2.push(n2)), U(_2, t2, "hash_length"), ("number" != typeof t2 || (0 | t2) !== t2 || t2 < 0) && L(_2, "hash_length must be an unsigned integer");
  var c2 = new B(357).address;
  if (!(0 | r._crypto_generichash_init(c2, n2, s2, t2))) {
    var p2 = c2;
    return M(_2), p2;
  }
  N(_2, "invalid usage");
}
function Mr(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_generichash_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_generichash_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function Nr(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_generichash_update(e, n2, s2) && N(_2, "invalid usage"), M(_2);
}
function Lr(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = K(e = O(a2, e, "message")), n2 = e.length;
  a2.push(_2);
  var s2 = new B(0 | r._crypto_hash_bytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_hash(c2, _2, n2, 0))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid usage");
}
function Ur(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = K(e = O(a2, e, "message")), n2 = e.length;
  a2.push(_2);
  var s2 = new B(0 | r._crypto_hash_sha256_bytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_hash_sha256(c2, _2, n2, 0))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid usage");
}
function Or(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "state_address");
  var _2 = new B(0 | r._crypto_hash_sha256_bytes()), n2 = _2.address;
  if (a2.push(n2), !(0 | r._crypto_hash_sha256_final(e, n2))) {
    var s2 = (r._free(e), S(_2, t2));
    return M(a2), s2;
  }
  N(a2, "invalid usage");
}
function Cr(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(104).address;
  if (!(0 | r._crypto_hash_sha256_init(a2))) {
    var _2 = a2;
    return M(t2), _2;
  }
  N(t2, "invalid usage");
}
function Rr(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_hash_sha256_update(e, n2, s2) && N(_2, "invalid usage"), M(_2);
}
function Pr(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = K(e = O(a2, e, "message")), n2 = e.length;
  a2.push(_2);
  var s2 = new B(0 | r._crypto_hash_sha3256_bytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_hash_sha3256(c2, _2, n2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid usage");
}
function Xr(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "state_address");
  var _2 = new B(0 | r._crypto_hash_sha3256_bytes()), n2 = _2.address;
  if (a2.push(n2), !(0 | r._crypto_hash_sha3256_final(e, n2))) {
    var s2 = (r._free(e), S(_2, t2));
    return M(a2), s2;
  }
  N(a2, "invalid usage");
}
function Dr(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(256).address;
  if (!(0 | r._crypto_hash_sha3256_init(a2))) {
    var _2 = a2;
    return M(t2), _2;
  }
  N(t2, "invalid usage");
}
function Gr(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_hash_sha3256_update(e, n2, s2) && N(_2, "invalid usage"), M(_2);
}
function Fr(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = K(e = O(a2, e, "message")), n2 = e.length;
  a2.push(_2);
  var s2 = new B(0 | r._crypto_hash_sha3512_bytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_hash_sha3512(c2, _2, n2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid usage");
}
function Vr(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "state_address");
  var _2 = new B(0 | r._crypto_hash_sha3512_bytes()), n2 = _2.address;
  if (a2.push(n2), !(0 | r._crypto_hash_sha3512_final(e, n2))) {
    var s2 = (r._free(e), S(_2, t2));
    return M(a2), s2;
  }
  N(a2, "invalid usage");
}
function qr(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(256).address;
  if (!(0 | r._crypto_hash_sha3512_init(a2))) {
    var _2 = a2;
    return M(t2), _2;
  }
  N(t2, "invalid usage");
}
function Hr(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_hash_sha3512_update(e, n2, s2) && N(_2, "invalid usage"), M(_2);
}
function zr(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = K(e = O(a2, e, "message")), n2 = e.length;
  a2.push(_2);
  var s2 = new B(0 | r._crypto_hash_sha512_bytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_hash_sha512(c2, _2, n2, 0))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid usage");
}
function Wr(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "state_address");
  var _2 = new B(0 | r._crypto_hash_sha512_bytes()), n2 = _2.address;
  if (a2.push(n2), !(0 | r._crypto_hash_sha512_final(e, n2))) {
    var s2 = (r._free(e), S(_2, t2));
    return M(a2), s2;
  }
  N(a2, "invalid usage");
}
function jr(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(208).address;
  if (!(0 | r._crypto_hash_sha512_init(a2))) {
    var _2 = a2;
    return M(t2), _2;
  }
  N(t2, "invalid usage");
}
function Jr(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_hash_sha512_update(e, n2, s2) && N(_2, "invalid usage"), M(_2);
}
function Qr(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "input");
  var n2, s2 = 0 | r._crypto_ipcrypt_bytes();
  e.length !== s2 && L(_2, "invalid input length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_ipcrypt_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_ipcrypt_bytes()), h2 = o2.address;
  _2.push(h2), r._crypto_ipcrypt_decrypt(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function Zr(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "input");
  var n2, s2 = 0 | r._crypto_ipcrypt_bytes();
  e.length !== s2 && L(_2, "invalid input length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_ipcrypt_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_ipcrypt_bytes()), h2 = o2.address;
  _2.push(h2), r._crypto_ipcrypt_encrypt(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function $r(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_ipcrypt_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_ipcrypt_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function et(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "input");
  var n2, s2 = 0 | r._crypto_ipcrypt_nd_outputbytes();
  e.length !== s2 && L(_2, "invalid input length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_ipcrypt_nd_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_ipcrypt_nd_inputbytes()), h2 = o2.address;
  _2.push(h2), r._crypto_ipcrypt_nd_decrypt(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function rt(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), e = O(n2, e, "input");
  var s2, c2 = 0 | r._crypto_ipcrypt_nd_inputbytes();
  e.length !== c2 && L(n2, "invalid input length"), s2 = K(e), n2.push(s2), t2 = O(n2, t2, "tweak");
  var p2, o2 = 0 | r._crypto_ipcrypt_nd_tweakbytes();
  t2.length !== o2 && L(n2, "invalid tweak length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "key");
  var h2, y2 = 0 | r._crypto_ipcrypt_nd_keybytes();
  a2.length !== y2 && L(n2, "invalid key length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(0 | r._crypto_ipcrypt_nd_outputbytes()), l2 = i2.address;
  n2.push(l2), r._crypto_ipcrypt_nd_encrypt(l2, s2, p2, h2);
  var u2 = S(i2, _2);
  return M(n2), u2;
}
function tt(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_ipcrypt_nd_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_ipcrypt_nd_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function at(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "input");
  var n2, s2 = 0 | r._crypto_ipcrypt_ndx_outputbytes();
  e.length !== s2 && L(_2, "invalid input length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_ipcrypt_ndx_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_ipcrypt_ndx_inputbytes()), h2 = o2.address;
  _2.push(h2), r._crypto_ipcrypt_ndx_decrypt(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function _t(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), e = O(n2, e, "input");
  var s2, c2 = 0 | r._crypto_ipcrypt_ndx_inputbytes();
  e.length !== c2 && L(n2, "invalid input length"), s2 = K(e), n2.push(s2), t2 = O(n2, t2, "tweak");
  var p2, o2 = 0 | r._crypto_ipcrypt_ndx_tweakbytes();
  t2.length !== o2 && L(n2, "invalid tweak length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "key");
  var h2, y2 = 0 | r._crypto_ipcrypt_ndx_keybytes();
  a2.length !== y2 && L(n2, "invalid key length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(0 | r._crypto_ipcrypt_ndx_outputbytes()), l2 = i2.address;
  n2.push(l2), r._crypto_ipcrypt_ndx_encrypt(l2, s2, p2, h2);
  var u2 = S(i2, _2);
  return M(n2), u2;
}
function nt(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_ipcrypt_ndx_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_ipcrypt_ndx_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function st(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "input");
  var n2, s2 = 0 | r._crypto_ipcrypt_pfx_bytes();
  e.length !== s2 && L(_2, "invalid input length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_ipcrypt_pfx_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_ipcrypt_pfx_bytes()), h2 = o2.address;
  _2.push(h2), r._crypto_ipcrypt_pfx_decrypt(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function ct(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "input");
  var n2, s2 = 0 | r._crypto_ipcrypt_pfx_bytes();
  e.length !== s2 && L(_2, "invalid input length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_ipcrypt_pfx_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_ipcrypt_pfx_bytes()), h2 = o2.address;
  _2.push(h2), r._crypto_ipcrypt_pfx_encrypt(h2, n2, c2);
  var y2 = S(o2, a2);
  return M(_2), y2;
}
function pt(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_ipcrypt_pfx_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_ipcrypt_pfx_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function ot(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2), U(s2, e, "subkey_len"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(s2, "subkey_len must be an unsigned integer"), U(s2, t2, "subkey_id");
  var c2, p2 = 0;
  if ("bigint" == typeof t2 && t2 >= BigInt(0)) {
    const e2 = t2 >> BigInt(32);
    e2 > BigInt(4294967295) && L(s2, "subkey_id cannot be more than 64 bits"), p2 = Number(e2), c2 = Number(t2 & BigInt(4294967295));
  } else "number" == typeof t2 && (0 | t2) === t2 && t2 >= 0 ? c2 = t2 : L(s2, "subkey_id must be an unsigned integer or bigint");
  "string" != typeof a2 && L(s2, "ctx must be a string"), (a2 = v(a2 + "\0")).length - 1 !== r._crypto_kdf_contextbytes() && L(s2, "invalid ctx length");
  var o2 = K(a2);
  a2.length, s2.push(o2), _2 = O(s2, _2, "key");
  var h2, y2 = 0 | r._crypto_kdf_keybytes();
  _2.length !== y2 && L(s2, "invalid key length"), h2 = K(_2), s2.push(h2);
  var i2 = new B(0 | e), l2 = i2.address;
  s2.push(l2), r._crypto_kdf_derive_from_key(l2, e, c2, p2, o2, h2);
  var u2 = S(i2, n2);
  return M(s2), u2;
}
function ht(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_kdf_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_kdf_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function yt(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "ciphertext");
  var n2, s2 = 0 | r._crypto_kem_ciphertextbytes();
  e.length !== s2 && L(_2, "invalid ciphertext length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "privateKey");
  var c2, p2 = 0 | r._crypto_kem_secretkeybytes();
  t2.length !== p2 && L(_2, "invalid privateKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_kem_sharedsecretbytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_kem_dec(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function it(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "publicKey");
  var _2, n2 = 0 | r._crypto_kem_publickeybytes();
  e.length !== n2 && L(a2, "invalid publicKey length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_kem_ciphertextbytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_kem_sharedsecretbytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_kem_enc(c2, o2, _2))) {
    var h2 = S({ ciphertext: s2, sharedSecret: p2 }, t2);
    return M(a2), h2;
  }
  N(a2, "invalid usage");
}
function lt(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_kem_publickeybytes()), _2 = a2.address;
  t2.push(_2);
  var n2 = new B(0 | r._crypto_kem_secretkeybytes()), s2 = n2.address;
  if (t2.push(s2), !(0 | r._crypto_kem_keypair(_2, s2))) {
    var c2 = { publicKey: S(a2, e), privateKey: S(n2, e), keyType: "xwing" };
    return M(t2), c2;
  }
  N(t2, "internal error");
}
function ut(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "ciphertext");
  var n2, s2 = 0 | r._crypto_kem_mlkem768_ciphertextbytes();
  e.length !== s2 && L(_2, "invalid ciphertext length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "privateKey");
  var c2, p2 = 0 | r._crypto_kem_mlkem768_secretkeybytes();
  t2.length !== p2 && L(_2, "invalid privateKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_kem_mlkem768_sharedsecretbytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_kem_mlkem768_dec(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function dt(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "publicKey");
  var _2, n2 = 0 | r._crypto_kem_mlkem768_publickeybytes();
  e.length !== n2 && L(a2, "invalid publicKey length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_kem_mlkem768_ciphertextbytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_kem_mlkem768_sharedsecretbytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_kem_mlkem768_enc(c2, o2, _2))) {
    var h2 = S({ ciphertext: s2, sharedSecret: p2 }, t2);
    return M(a2), h2;
  }
  N(a2, "invalid usage");
}
function vt(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "publicKey");
  var n2, s2, c2 = 0 | r._crypto_kem_mlkem768_publickeybytes();
  e.length !== c2 && L(_2, "invalid publicKey length"), n2 = K(e), _2.push(n2), 32 !== (t2 = O(_2, t2, "seed")).length && L(_2, "invalid seed length"), s2 = K(t2), _2.push(s2);
  var p2 = new B(0 | r._crypto_kem_mlkem768_ciphertextbytes()), o2 = p2.address;
  _2.push(o2);
  var h2 = new B(0 | r._crypto_kem_mlkem768_sharedsecretbytes()), y2 = h2.address;
  if (_2.push(y2), !(0 | r._crypto_kem_mlkem768_enc_deterministic(o2, y2, n2, s2))) {
    var i2 = S({ ciphertext: p2, sharedSecret: h2 }, a2);
    return M(_2), i2;
  }
  N(_2, "invalid usage");
}
function gt(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_kem_mlkem768_publickeybytes()), _2 = a2.address;
  t2.push(_2);
  var n2 = new B(0 | r._crypto_kem_mlkem768_secretkeybytes()), s2 = n2.address;
  if (t2.push(s2), !(0 | r._crypto_kem_mlkem768_keypair(_2, s2))) {
    var c2 = { publicKey: S(a2, e), privateKey: S(n2, e), keyType: "ml-kem-768" };
    return M(t2), c2;
  }
  N(t2, "internal error");
}
function bt(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "seed");
  var _2, n2 = 0 | r._crypto_kem_mlkem768_seedbytes();
  e.length !== n2 && L(a2, "invalid seed length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_kem_mlkem768_publickeybytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_kem_mlkem768_secretkeybytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_kem_mlkem768_seed_keypair(c2, o2, _2))) {
    var h2 = { publicKey: S(s2, t2), privateKey: S(p2, t2), keyType: "ml-kem-768" };
    return M(a2), h2;
  }
  N(a2, "invalid usage");
}
function ft() {
  var e = r._crypto_kem_primitive(), t2 = r.UTF8ToString(e);
  return M([]), t2;
}
function mt(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "seed");
  var _2, n2 = 0 | r._crypto_kem_seedbytes();
  e.length !== n2 && L(a2, "invalid seed length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_kem_publickeybytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_kem_secretkeybytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_kem_seed_keypair(c2, o2, _2))) {
    var h2 = { publicKey: S(s2, t2), privateKey: S(p2, t2), keyType: "xwing" };
    return M(a2), h2;
  }
  N(a2, "invalid usage");
}
function kt(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "ciphertext");
  var n2, s2 = 0 | r._crypto_kem_xwing_ciphertextbytes();
  e.length !== s2 && L(_2, "invalid ciphertext length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "privateKey");
  var c2, p2 = 0 | r._crypto_kem_xwing_secretkeybytes();
  t2.length !== p2 && L(_2, "invalid privateKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_kem_xwing_sharedsecretbytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_kem_xwing_dec(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function xt(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "publicKey");
  var _2, n2 = 0 | r._crypto_kem_xwing_publickeybytes();
  e.length !== n2 && L(a2, "invalid publicKey length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_kem_xwing_ciphertextbytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_kem_xwing_sharedsecretbytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_kem_xwing_enc(c2, o2, _2))) {
    var h2 = S({ ciphertext: s2, sharedSecret: p2 }, t2);
    return M(a2), h2;
  }
  N(a2, "invalid usage");
}
function Et(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "publicKey");
  var n2, s2, c2 = 0 | r._crypto_kem_xwing_publickeybytes();
  e.length !== c2 && L(_2, "invalid publicKey length"), n2 = K(e), _2.push(n2), 64 !== (t2 = O(_2, t2, "seed")).length && L(_2, "invalid seed length"), s2 = K(t2), _2.push(s2);
  var p2 = new B(0 | r._crypto_kem_xwing_ciphertextbytes()), o2 = p2.address;
  _2.push(o2);
  var h2 = new B(0 | r._crypto_kem_xwing_sharedsecretbytes()), y2 = h2.address;
  if (_2.push(y2), !(0 | r._crypto_kem_xwing_enc_deterministic(o2, y2, n2, s2))) {
    var i2 = S({ ciphertext: p2, sharedSecret: h2 }, a2);
    return M(_2), i2;
  }
  N(_2, "invalid usage");
}
function Tt(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_kem_xwing_publickeybytes()), _2 = a2.address;
  t2.push(_2);
  var n2 = new B(0 | r._crypto_kem_xwing_secretkeybytes()), s2 = n2.address;
  if (t2.push(s2), !(0 | r._crypto_kem_xwing_keypair(_2, s2))) {
    var c2 = { publicKey: S(a2, e), privateKey: S(n2, e), keyType: "xwing" };
    return M(t2), c2;
  }
  N(t2, "internal error");
}
function St(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "seed");
  var _2, n2 = 0 | r._crypto_kem_xwing_seedbytes();
  e.length !== n2 && L(a2, "invalid seed length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_kem_xwing_publickeybytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_kem_xwing_secretkeybytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_kem_xwing_seed_keypair(c2, o2, _2))) {
    var h2 = { publicKey: S(s2, t2), privateKey: S(p2, t2), keyType: "xwing" };
    return M(a2), h2;
  }
  N(a2, "invalid usage");
}
function wt(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), e = O(n2, e, "clientPublicKey");
  var s2, c2 = 0 | r._crypto_kx_publickeybytes();
  e.length !== c2 && L(n2, "invalid clientPublicKey length"), s2 = K(e), n2.push(s2), t2 = O(n2, t2, "clientSecretKey");
  var p2, o2 = 0 | r._crypto_kx_secretkeybytes();
  t2.length !== o2 && L(n2, "invalid clientSecretKey length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "serverPublicKey");
  var h2, y2 = 0 | r._crypto_kx_publickeybytes();
  a2.length !== y2 && L(n2, "invalid serverPublicKey length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(0 | r._crypto_kx_sessionkeybytes()), l2 = i2.address;
  n2.push(l2);
  var u2 = new B(0 | r._crypto_kx_sessionkeybytes()), d2 = u2.address;
  if (n2.push(d2), !(0 | r._crypto_kx_client_session_keys(l2, d2, s2, p2, h2))) {
    var v2 = S({ sharedRx: i2, sharedTx: u2 }, _2);
    return M(n2), v2;
  }
  N(n2, "invalid usage");
}
function Yt(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_kx_publickeybytes()), _2 = a2.address;
  t2.push(_2);
  var n2 = new B(0 | r._crypto_kx_secretkeybytes()), s2 = n2.address;
  if (t2.push(s2), !(0 | r._crypto_kx_keypair(_2, s2))) {
    var c2 = { publicKey: S(a2, e), privateKey: S(n2, e), keyType: "x25519" };
    return M(t2), c2;
  }
  N(t2, "internal error");
}
function Bt(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "seed");
  var _2, n2 = 0 | r._crypto_kx_seedbytes();
  e.length !== n2 && L(a2, "invalid seed length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_kx_publickeybytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_kx_secretkeybytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_kx_seed_keypair(c2, o2, _2))) {
    var h2 = { publicKey: S(s2, t2), privateKey: S(p2, t2), keyType: "x25519" };
    return M(a2), h2;
  }
  N(a2, "internal error");
}
function Kt(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), e = O(n2, e, "serverPublicKey");
  var s2, c2 = 0 | r._crypto_kx_publickeybytes();
  e.length !== c2 && L(n2, "invalid serverPublicKey length"), s2 = K(e), n2.push(s2), t2 = O(n2, t2, "serverSecretKey");
  var p2, o2 = 0 | r._crypto_kx_secretkeybytes();
  t2.length !== o2 && L(n2, "invalid serverSecretKey length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "clientPublicKey");
  var h2, y2 = 0 | r._crypto_kx_publickeybytes();
  a2.length !== y2 && L(n2, "invalid clientPublicKey length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(0 | r._crypto_kx_sessionkeybytes()), l2 = i2.address;
  n2.push(l2);
  var u2 = new B(0 | r._crypto_kx_sessionkeybytes()), d2 = u2.address;
  if (n2.push(d2), !(0 | r._crypto_kx_server_session_keys(l2, d2, s2, p2, h2))) {
    var v2 = S({ sharedRx: i2, sharedTx: u2 }, _2);
    return M(n2), v2;
  }
  N(n2, "invalid usage");
}
function At(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_onetimeauth_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_onetimeauth_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_onetimeauth(h2, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function It(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "state_address");
  var _2 = new B(0 | r._crypto_onetimeauth_bytes()), n2 = _2.address;
  if (a2.push(n2), !(0 | r._crypto_onetimeauth_final(e, n2))) {
    var s2 = (r._free(e), S(_2, t2));
    return M(a2), s2;
  }
  N(a2, "invalid usage");
}
function Mt(e, t2) {
  var a2 = [];
  Y(t2);
  var _2 = null;
  null != e && (_2 = K(e = O(a2, e, "key")), e.length, a2.push(_2));
  var n2 = new B(144).address;
  if (!(0 | r._crypto_onetimeauth_init(n2, _2))) {
    var s2 = n2;
    return M(a2), s2;
  }
  N(a2, "invalid usage");
}
function Nt(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_onetimeauth_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_onetimeauth_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function Lt(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_onetimeauth_update(e, n2, s2) && N(_2, "invalid usage"), M(_2);
}
function Ut(e, t2, a2) {
  var _2 = [];
  e = O(_2, e, "hash");
  var n2, s2 = 0 | r._crypto_onetimeauth_bytes();
  e.length !== s2 && L(_2, "invalid hash length"), n2 = K(e), _2.push(n2);
  var c2 = K(t2 = O(_2, t2, "message")), p2 = t2.length;
  _2.push(c2), a2 = O(_2, a2, "key");
  var o2, h2 = 0 | r._crypto_onetimeauth_keybytes();
  a2.length !== h2 && L(_2, "invalid key length"), o2 = K(a2), _2.push(o2);
  var y2 = !(0 | r._crypto_onetimeauth_verify(n2, c2, p2, 0, o2));
  return M(_2), y2;
}
function Ot(e, t2, a2, _2, n2, s2, c2) {
  var p2 = [];
  Y(c2), U(p2, e, "keyLength"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(p2, "keyLength must be an unsigned integer");
  var o2 = K(t2 = O(p2, t2, "password")), h2 = t2.length;
  p2.push(o2), a2 = O(p2, a2, "salt");
  var y2, i2 = 0 | r._crypto_pwhash_saltbytes();
  a2.length !== i2 && L(p2, "invalid salt length"), y2 = K(a2), p2.push(y2), U(p2, _2, "opsLimit"), ("number" != typeof _2 || (0 | _2) !== _2 || _2 < 0) && L(p2, "opsLimit must be an unsigned integer"), U(p2, n2, "memLimit"), ("number" != typeof n2 || (0 | n2) !== n2 || n2 < 0) && L(p2, "memLimit must be an unsigned integer"), U(p2, s2, "algorithm"), ("number" != typeof s2 || (0 | s2) !== s2 || s2 < 0) && L(p2, "algorithm must be an unsigned integer");
  var l2 = new B(0 | e), u2 = l2.address;
  if (p2.push(u2), !(0 | r._crypto_pwhash(u2, e, 0, o2, h2, 0, y2, _2, 0, n2, s2))) {
    var d2 = S(l2, c2);
    return M(p2), d2;
  }
  N(p2, "invalid usage");
}
function Ct(e, t2, a2, _2, n2, s2) {
  var c2 = [];
  Y(s2), U(c2, e, "keyLength"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(c2, "keyLength must be an unsigned integer");
  var p2 = K(t2 = O(c2, t2, "password")), o2 = t2.length;
  c2.push(p2), a2 = O(c2, a2, "salt");
  var h2, y2 = 0 | r._crypto_pwhash_scryptsalsa208sha256_saltbytes();
  a2.length !== y2 && L(c2, "invalid salt length"), h2 = K(a2), c2.push(h2), U(c2, _2, "opsLimit"), ("number" != typeof _2 || (0 | _2) !== _2 || _2 < 0) && L(c2, "opsLimit must be an unsigned integer"), U(c2, n2, "memLimit"), ("number" != typeof n2 || (0 | n2) !== n2 || n2 < 0) && L(c2, "memLimit must be an unsigned integer");
  var i2 = new B(0 | e), l2 = i2.address;
  if (c2.push(l2), !(0 | r._crypto_pwhash_scryptsalsa208sha256(l2, e, 0, p2, o2, 0, h2, _2, 0, n2))) {
    var u2 = S(i2, s2);
    return M(c2), u2;
  }
  N(c2, "invalid usage");
}
function Rt(e, t2, a2, _2, n2, s2, c2) {
  var p2 = [];
  Y(c2);
  var o2 = K(e = O(p2, e, "password")), h2 = e.length;
  p2.push(o2);
  var y2 = K(t2 = O(p2, t2, "salt")), i2 = t2.length;
  p2.push(y2), U(p2, a2, "opsLimit"), ("number" != typeof a2 || (0 | a2) !== a2 || a2 < 0) && L(p2, "opsLimit must be an unsigned integer"), U(p2, _2, "r"), ("number" != typeof _2 || (0 | _2) !== _2 || _2 < 0) && L(p2, "r must be an unsigned integer"), U(p2, n2, "p"), ("number" != typeof n2 || (0 | n2) !== n2 || n2 < 0) && L(p2, "p must be an unsigned integer"), U(p2, s2, "keyLength"), ("number" != typeof s2 || (0 | s2) !== s2 || s2 < 0) && L(p2, "keyLength must be an unsigned integer");
  var l2 = new B(0 | s2), u2 = l2.address;
  if (p2.push(u2), !(0 | r._crypto_pwhash_scryptsalsa208sha256_ll(o2, h2, y2, i2, a2, 0, _2, n2, u2, s2))) {
    var d2 = S(l2, c2);
    return M(p2), d2;
  }
  N(p2, "invalid usage");
}
function Pt(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "password")), c2 = e.length;
  n2.push(s2), U(n2, t2, "opsLimit"), ("number" != typeof t2 || (0 | t2) !== t2 || t2 < 0) && L(n2, "opsLimit must be an unsigned integer"), U(n2, a2, "memLimit"), ("number" != typeof a2 || (0 | a2) !== a2 || a2 < 0) && L(n2, "memLimit must be an unsigned integer");
  var p2 = new B(0 | r._crypto_pwhash_scryptsalsa208sha256_strbytes()).address;
  if (n2.push(p2), !(0 | r._crypto_pwhash_scryptsalsa208sha256_str(p2, s2, c2, 0, t2, 0, a2))) {
    var o2 = r.UTF8ToString(p2);
    return M(n2), o2;
  }
  N(n2, "invalid usage");
}
function Xt(e, t2, a2) {
  var _2 = [];
  Y(a2), "string" != typeof e && L(_2, "hashed_password must be a string");
  var n2 = K(e = v(e + "\0"));
  e.length, _2.push(n2);
  var s2 = K(t2 = O(_2, t2, "password")), c2 = t2.length;
  _2.push(s2);
  var p2 = !(0 | r._crypto_pwhash_scryptsalsa208sha256_str_verify(n2, s2, c2, 0));
  return M(_2), p2;
}
function Dt(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "password")), c2 = e.length;
  n2.push(s2), U(n2, t2, "opsLimit"), ("number" != typeof t2 || (0 | t2) !== t2 || t2 < 0) && L(n2, "opsLimit must be an unsigned integer"), U(n2, a2, "memLimit"), ("number" != typeof a2 || (0 | a2) !== a2 || a2 < 0) && L(n2, "memLimit must be an unsigned integer");
  var p2 = new B(0 | r._crypto_pwhash_strbytes()).address;
  if (n2.push(p2), !(0 | r._crypto_pwhash_str(p2, s2, c2, 0, t2, 0, a2))) {
    var o2 = r.UTF8ToString(p2);
    return M(n2), o2;
  }
  N(n2, "invalid usage");
}
function Gt(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), "string" != typeof e && L(n2, "hashed_password must be a string");
  var s2 = K(e = v(e + "\0"));
  e.length, n2.push(s2), U(n2, t2, "opsLimit"), ("number" != typeof t2 || (0 | t2) !== t2 || t2 < 0) && L(n2, "opsLimit must be an unsigned integer"), U(n2, a2, "memLimit"), ("number" != typeof a2 || (0 | a2) !== a2 || a2 < 0) && L(n2, "memLimit must be an unsigned integer");
  var c2 = !!(0 | r._crypto_pwhash_str_needs_rehash(s2, t2, 0, a2));
  return M(n2), c2;
}
function Ft(e, t2, a2) {
  var _2 = [];
  Y(a2), "string" != typeof e && L(_2, "hashed_password must be a string");
  var n2 = K(e = v(e + "\0"));
  e.length, _2.push(n2);
  var s2 = K(t2 = O(_2, t2, "password")), c2 = t2.length;
  _2.push(s2);
  var p2 = !(0 | r._crypto_pwhash_str_verify(n2, s2, c2, 0));
  return M(_2), p2;
}
function Vt(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "privateKey");
  var n2, s2 = 0 | r._crypto_scalarmult_scalarbytes();
  e.length !== s2 && L(_2, "invalid privateKey length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "publicKey");
  var c2, p2 = 0 | r._crypto_scalarmult_bytes();
  t2.length !== p2 && L(_2, "invalid publicKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_scalarmult_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_scalarmult(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "weak public key");
}
function qt(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "privateKey");
  var _2, n2 = 0 | r._crypto_scalarmult_scalarbytes();
  e.length !== n2 && L(a2, "invalid privateKey length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_scalarmult_bytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_scalarmult_base(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "unknown error");
}
function Ht(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "n");
  var n2, s2 = 0 | r._crypto_scalarmult_ed25519_scalarbytes();
  e.length !== s2 && L(_2, "invalid n length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "p");
  var c2, p2 = 0 | r._crypto_scalarmult_ed25519_bytes();
  t2.length !== p2 && L(_2, "invalid p length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_scalarmult_ed25519_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_scalarmult_ed25519(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid point or scalar is 0");
}
function zt(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "scalar");
  var _2, n2 = 0 | r._crypto_scalarmult_ed25519_scalarbytes();
  e.length !== n2 && L(a2, "invalid scalar length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_scalarmult_ed25519_bytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_scalarmult_ed25519_base(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "scalar is 0");
}
function Wt(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "scalar");
  var _2, n2 = 0 | r._crypto_scalarmult_ed25519_scalarbytes();
  e.length !== n2 && L(a2, "invalid scalar length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_scalarmult_ed25519_bytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_scalarmult_ed25519_base_noclamp(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "scalar is 0");
}
function jt(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "n");
  var n2, s2 = 0 | r._crypto_scalarmult_ed25519_scalarbytes();
  e.length !== s2 && L(_2, "invalid n length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "p");
  var c2, p2 = 0 | r._crypto_scalarmult_ed25519_bytes();
  t2.length !== p2 && L(_2, "invalid p length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_scalarmult_ed25519_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_scalarmult_ed25519_noclamp(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid point or scalar is 0");
}
function Jt(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "scalar");
  var n2, s2 = 0 | r._crypto_scalarmult_ristretto255_scalarbytes();
  e.length !== s2 && L(_2, "invalid scalar length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "element");
  var c2, p2 = 0 | r._crypto_scalarmult_ristretto255_bytes();
  t2.length !== p2 && L(_2, "invalid element length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_scalarmult_ristretto255_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_scalarmult_ristretto255(h2, n2, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "result is identity element");
}
function Qt(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "scalar");
  var _2, n2 = 0 | r._crypto_core_ristretto255_scalarbytes();
  e.length !== n2 && L(a2, "invalid scalar length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_core_ristretto255_bytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_scalarmult_ristretto255_base(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "scalar is 0");
}
function Zt(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "message")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_secretbox_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "key");
  var h2, y2 = 0 | r._crypto_secretbox_keybytes();
  a2.length !== y2 && L(n2, "invalid key length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(0 | c2), l2 = i2.address;
  n2.push(l2);
  var u2 = new B(0 | r._crypto_secretbox_macbytes()), d2 = u2.address;
  if (n2.push(d2), !(0 | r._crypto_secretbox_detached(l2, d2, s2, c2, 0, p2, h2))) {
    var v2 = S({ mac: u2, cipher: i2 }, _2);
    return M(n2), v2;
  }
  N(n2, "invalid usage");
}
function $t(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "message")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_secretbox_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "key");
  var h2, y2 = 0 | r._crypto_secretbox_keybytes();
  a2.length !== y2 && L(n2, "invalid key length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(c2 + r._crypto_secretbox_macbytes() | 0), l2 = i2.address;
  if (n2.push(l2), !(0 | r._crypto_secretbox_easy(l2, s2, c2, 0, p2, h2))) {
    var u2 = S(i2, _2);
    return M(n2), u2;
  }
  N(n2, "invalid usage");
}
function ea(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_secretbox_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_secretbox_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function ra(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2);
  var c2 = K(e = O(s2, e, "ciphertext")), p2 = e.length;
  s2.push(c2), t2 = O(s2, t2, "mac");
  var o2, h2 = 0 | r._crypto_secretbox_macbytes();
  t2.length !== h2 && L(s2, "invalid mac length"), o2 = K(t2), s2.push(o2), a2 = O(s2, a2, "nonce");
  var y2, i2 = 0 | r._crypto_secretbox_noncebytes();
  a2.length !== i2 && L(s2, "invalid nonce length"), y2 = K(a2), s2.push(y2), _2 = O(s2, _2, "key");
  var l2, u2 = 0 | r._crypto_secretbox_keybytes();
  _2.length !== u2 && L(s2, "invalid key length"), l2 = K(_2), s2.push(l2);
  var d2 = new B(0 | p2), v2 = d2.address;
  if (s2.push(v2), !(0 | r._crypto_secretbox_open_detached(v2, c2, o2, p2, 0, y2, l2))) {
    var g2 = S(d2, n2);
    return M(s2), g2;
  }
  N(s2, "wrong secret key for the given ciphertext");
}
function ta(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), e = O(n2, e, "ciphertext");
  var s2, c2 = r._crypto_secretbox_macbytes(), p2 = e.length;
  p2 < c2 && L(n2, "ciphertext is too short"), s2 = K(e), n2.push(s2), t2 = O(n2, t2, "nonce");
  var o2, h2 = 0 | r._crypto_secretbox_noncebytes();
  t2.length !== h2 && L(n2, "invalid nonce length"), o2 = K(t2), n2.push(o2), a2 = O(n2, a2, "key");
  var y2, i2 = 0 | r._crypto_secretbox_keybytes();
  a2.length !== i2 && L(n2, "invalid key length"), y2 = K(a2), n2.push(y2);
  var l2 = new B(p2 - r._crypto_secretbox_macbytes() | 0), u2 = l2.address;
  if (n2.push(u2), !(0 | r._crypto_secretbox_open_easy(u2, s2, p2, 0, o2, y2))) {
    var d2 = S(l2, _2);
    return M(n2), d2;
  }
  N(n2, "wrong secret key for the given ciphertext");
}
function aa(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "header");
  var n2, s2 = 0 | r._crypto_secretstream_xchacha20poly1305_headerbytes();
  e.length !== s2 && L(_2, "invalid header length"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_secretstream_xchacha20poly1305_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(52).address;
  if (!(0 | r._crypto_secretstream_xchacha20poly1305_init_pull(o2, n2, c2))) {
    var h2 = o2;
    return M(_2), h2;
  }
  N(_2, "invalid usage");
}
function _a(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "key");
  var _2, n2 = 0 | r._crypto_secretstream_xchacha20poly1305_keybytes();
  e.length !== n2 && L(a2, "invalid key length"), _2 = K(e), a2.push(_2);
  var s2 = new B(52).address, c2 = new B(0 | r._crypto_secretstream_xchacha20poly1305_headerbytes()), p2 = c2.address;
  if (a2.push(p2), !(0 | r._crypto_secretstream_xchacha20poly1305_init_push(s2, p2, _2))) {
    var o2 = { state: s2, header: S(c2, t2) };
    return M(a2), o2;
  }
  N(a2, "invalid usage");
}
function na(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_secretstream_xchacha20poly1305_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_secretstream_xchacha20poly1305_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function sa(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), U(n2, e, "state_address"), t2 = O(n2, t2, "cipher");
  var s2, c2 = r._crypto_secretstream_xchacha20poly1305_abytes(), p2 = t2.length;
  p2 < c2 && L(n2, "cipher is too short"), s2 = K(t2), n2.push(s2);
  var o2 = null, h2 = 0;
  null != a2 && (o2 = K(a2 = O(n2, a2, "ad")), h2 = a2.length, n2.push(o2));
  var y2 = new B(p2 - r._crypto_secretstream_xchacha20poly1305_abytes() | 0), i2 = y2.address;
  n2.push(i2);
  var l2, u2 = (l2 = A2(1), n2.push(l2), (u2 = 0 === r._crypto_secretstream_xchacha20poly1305_pull(e, i2, 0, l2, s2, p2, 0, o2, h2) && { tag: r.HEAPU8[l2], message: y2 }) && { message: S(u2.message, _2), tag: u2.tag });
  return M(n2), u2;
}
function ca(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2), U(s2, e, "state_address");
  var c2 = K(t2 = O(s2, t2, "message_chunk")), p2 = t2.length;
  s2.push(c2);
  var o2 = null, h2 = 0;
  null != a2 && (o2 = K(a2 = O(s2, a2, "ad")), h2 = a2.length, s2.push(o2)), U(s2, _2, "tag"), ("number" != typeof _2 || (0 | _2) !== _2 || _2 < 0) && L(s2, "tag must be an unsigned integer");
  var y2 = new B(p2 + r._crypto_secretstream_xchacha20poly1305_abytes() | 0), i2 = y2.address;
  if (s2.push(i2), !(0 | r._crypto_secretstream_xchacha20poly1305_push(e, i2, 0, c2, p2, 0, o2, h2, 0, _2))) {
    var l2 = S(y2, n2);
    return M(s2), l2;
  }
  N(s2, "invalid usage");
}
function pa(e, t2) {
  var a2 = [];
  return Y(t2), U(a2, e, "state_address"), r._crypto_secretstream_xchacha20poly1305_rekey(e), M(a2), true;
}
function oa(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_shorthash_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_shorthash_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_shorthash(h2, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function ha(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_shorthash_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_shorthash_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function ya(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "key");
  var c2, p2 = 0 | r._crypto_shorthash_siphashx24_keybytes();
  t2.length !== p2 && L(_2, "invalid key length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_shorthash_siphashx24_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_shorthash_siphashx24(h2, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function ia(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "privateKey");
  var c2, p2 = 0 | r._crypto_sign_secretkeybytes();
  t2.length !== p2 && L(_2, "invalid privateKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(e.length + r._crypto_sign_bytes() | 0), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_sign(h2, null, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function la(e, t2, a2) {
  var _2 = [];
  Y(a2);
  var n2 = K(e = O(_2, e, "message")), s2 = e.length;
  _2.push(n2), t2 = O(_2, t2, "privateKey");
  var c2, p2 = 0 | r._crypto_sign_secretkeybytes();
  t2.length !== p2 && L(_2, "invalid privateKey length"), c2 = K(t2), _2.push(c2);
  var o2 = new B(0 | r._crypto_sign_bytes()), h2 = o2.address;
  if (_2.push(h2), !(0 | r._crypto_sign_detached(h2, null, n2, s2, 0, c2))) {
    var y2 = S(o2, a2);
    return M(_2), y2;
  }
  N(_2, "invalid usage");
}
function ua(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "edPk");
  var _2, n2 = 0 | r._crypto_sign_publickeybytes();
  e.length !== n2 && L(a2, "invalid edPk length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_scalarmult_scalarbytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_sign_ed25519_pk_to_curve25519(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid key");
}
function da(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "edSk");
  var _2, n2 = 0 | r._crypto_sign_secretkeybytes();
  e.length !== n2 && L(a2, "invalid edSk length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_scalarmult_scalarbytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_sign_ed25519_sk_to_curve25519(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid key");
}
function va(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "privateKey");
  var _2, n2 = 0 | r._crypto_sign_secretkeybytes();
  e.length !== n2 && L(a2, "invalid privateKey length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_sign_publickeybytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_sign_ed25519_sk_to_pk(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid key");
}
function ga(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "privateKey");
  var _2, n2 = 0 | r._crypto_sign_secretkeybytes();
  e.length !== n2 && L(a2, "invalid privateKey length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_sign_seedbytes()), c2 = s2.address;
  if (a2.push(c2), !(0 | r._crypto_sign_ed25519_sk_to_seed(c2, _2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid key");
}
function ba(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address"), t2 = O(_2, t2, "privateKey");
  var n2, s2 = 0 | r._crypto_sign_secretkeybytes();
  t2.length !== s2 && L(_2, "invalid privateKey length"), n2 = K(t2), _2.push(n2);
  var c2 = new B(0 | r._crypto_sign_bytes()), p2 = c2.address;
  if (_2.push(p2), !(0 | r._crypto_sign_final_create(e, p2, null, n2))) {
    var o2 = (r._free(e), S(c2, a2));
    return M(_2), o2;
  }
  N(_2, "invalid usage");
}
function fa(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), U(n2, e, "state_address"), t2 = O(n2, t2, "signature");
  var s2, c2 = 0 | r._crypto_sign_bytes();
  t2.length !== c2 && L(n2, "invalid signature length"), s2 = K(t2), n2.push(s2), a2 = O(n2, a2, "publicKey");
  var p2, o2 = 0 | r._crypto_sign_publickeybytes();
  a2.length !== o2 && L(n2, "invalid publicKey length"), p2 = K(a2), n2.push(p2);
  var h2 = !(0 | r._crypto_sign_final_verify(e, s2, p2));
  return M(n2), h2;
}
function ma(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(208).address;
  if (!(0 | r._crypto_sign_init(a2))) {
    var _2 = a2;
    return M(t2), _2;
  }
  N(t2, "internal error");
}
function ka(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_sign_publickeybytes()), _2 = a2.address;
  t2.push(_2);
  var n2 = new B(0 | r._crypto_sign_secretkeybytes()), s2 = n2.address;
  if (t2.push(s2), !(0 | r._crypto_sign_keypair(_2, s2))) {
    var c2 = { publicKey: S(a2, e), privateKey: S(n2, e), keyType: "ed25519" };
    return M(t2), c2;
  }
  N(t2, "internal error");
}
function xa(e, t2, a2) {
  var _2 = [];
  Y(a2), e = O(_2, e, "signedMessage");
  var n2, s2 = r._crypto_sign_bytes(), c2 = e.length;
  c2 < s2 && L(_2, "signedMessage is too short"), n2 = K(e), _2.push(n2), t2 = O(_2, t2, "publicKey");
  var p2, o2 = 0 | r._crypto_sign_publickeybytes();
  t2.length !== o2 && L(_2, "invalid publicKey length"), p2 = K(t2), _2.push(p2);
  var h2 = new B(c2 - r._crypto_sign_bytes() | 0), y2 = h2.address;
  if (_2.push(y2), !(0 | r._crypto_sign_open(y2, null, n2, c2, 0, p2))) {
    var i2 = S(h2, a2);
    return M(_2), i2;
  }
  N(_2, "incorrect signature for the given public key");
}
function Ea(e, t2) {
  var a2 = [];
  Y(t2), e = O(a2, e, "seed");
  var _2, n2 = 0 | r._crypto_sign_seedbytes();
  e.length !== n2 && L(a2, "invalid seed length"), _2 = K(e), a2.push(_2);
  var s2 = new B(0 | r._crypto_sign_publickeybytes()), c2 = s2.address;
  a2.push(c2);
  var p2 = new B(0 | r._crypto_sign_secretkeybytes()), o2 = p2.address;
  if (a2.push(o2), !(0 | r._crypto_sign_seed_keypair(c2, o2, _2))) {
    var h2 = { publicKey: S(s2, t2), privateKey: S(p2, t2), keyType: "ed25519" };
    return M(a2), h2;
  }
  N(a2, "invalid usage");
}
function Ta(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_sign_update(e, n2, s2, 0) && N(_2, "invalid usage"), M(_2);
}
function Sa(e, t2, a2) {
  var _2 = [];
  e = O(_2, e, "signature");
  var n2, s2 = 0 | r._crypto_sign_bytes();
  e.length !== s2 && L(_2, "invalid signature length"), n2 = K(e), _2.push(n2);
  var c2 = K(t2 = O(_2, t2, "message")), p2 = t2.length;
  _2.push(c2), a2 = O(_2, a2, "publicKey");
  var o2, h2 = 0 | r._crypto_sign_publickeybytes();
  a2.length !== h2 && L(_2, "invalid publicKey length"), o2 = K(a2), _2.push(o2);
  var y2 = !(0 | r._crypto_sign_verify_detached(n2, c2, p2, 0, o2));
  return M(_2), y2;
}
function wa(e, t2, a2, _2) {
  var n2 = [];
  Y(_2), U(n2, e, "outLength"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(n2, "outLength must be an unsigned integer"), t2 = O(n2, t2, "key");
  var s2, c2 = 0 | r._crypto_stream_chacha20_keybytes();
  t2.length !== c2 && L(n2, "invalid key length"), s2 = K(t2), n2.push(s2), a2 = O(n2, a2, "nonce");
  var p2, o2 = 0 | r._crypto_stream_chacha20_noncebytes();
  a2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(a2), n2.push(p2);
  var h2 = new B(0 | e), y2 = h2.address;
  n2.push(y2), r._crypto_stream_chacha20(y2, e, 0, p2, s2);
  var i2 = S(h2, _2);
  return M(n2), i2;
}
function Ya(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "input_message")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_stream_chacha20_ietf_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "key");
  var h2, y2 = 0 | r._crypto_stream_chacha20_ietf_keybytes();
  a2.length !== y2 && L(n2, "invalid key length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(0 | c2), l2 = i2.address;
  if (n2.push(l2), 0 === r._crypto_stream_chacha20_ietf_xor(l2, s2, c2, 0, p2, h2)) {
    var u2 = S(i2, _2);
    return M(n2), u2;
  }
  N(n2, "invalid usage");
}
function Ba(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2);
  var c2 = K(e = O(s2, e, "input_message")), p2 = e.length;
  s2.push(c2), t2 = O(s2, t2, "nonce");
  var o2, h2 = 0 | r._crypto_stream_chacha20_ietf_noncebytes();
  t2.length !== h2 && L(s2, "invalid nonce length"), o2 = K(t2), s2.push(o2), U(s2, a2, "nonce_increment"), ("number" != typeof a2 || (0 | a2) !== a2 || a2 < 0) && L(s2, "nonce_increment must be an unsigned integer"), _2 = O(s2, _2, "key");
  var y2, i2 = 0 | r._crypto_stream_chacha20_ietf_keybytes();
  _2.length !== i2 && L(s2, "invalid key length"), y2 = K(_2), s2.push(y2);
  var l2 = new B(0 | p2), u2 = l2.address;
  if (s2.push(u2), 0 === r._crypto_stream_chacha20_ietf_xor_ic(u2, c2, p2, 0, o2, a2, y2)) {
    var d2 = S(l2, n2);
    return M(s2), d2;
  }
  N(s2, "invalid usage");
}
function Ka(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_stream_chacha20_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_stream_chacha20_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function Aa(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "input_message")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_stream_chacha20_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "key");
  var h2, y2 = 0 | r._crypto_stream_chacha20_keybytes();
  a2.length !== y2 && L(n2, "invalid key length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(0 | c2), l2 = i2.address;
  if (n2.push(l2), 0 === r._crypto_stream_chacha20_xor(l2, s2, c2, 0, p2, h2)) {
    var u2 = S(i2, _2);
    return M(n2), u2;
  }
  N(n2, "invalid usage");
}
function Ia(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2);
  var c2 = K(e = O(s2, e, "input_message")), p2 = e.length;
  s2.push(c2), t2 = O(s2, t2, "nonce");
  var o2, h2 = 0 | r._crypto_stream_chacha20_noncebytes();
  t2.length !== h2 && L(s2, "invalid nonce length"), o2 = K(t2), s2.push(o2), U(s2, a2, "nonce_increment"), ("number" != typeof a2 || (0 | a2) !== a2 || a2 < 0) && L(s2, "nonce_increment must be an unsigned integer"), _2 = O(s2, _2, "key");
  var y2, i2 = 0 | r._crypto_stream_chacha20_keybytes();
  _2.length !== i2 && L(s2, "invalid key length"), y2 = K(_2), s2.push(y2);
  var l2 = new B(0 | p2), u2 = l2.address;
  if (s2.push(u2), 0 === r._crypto_stream_chacha20_xor_ic(u2, c2, p2, 0, o2, a2, 0, y2)) {
    var d2 = S(l2, n2);
    return M(s2), d2;
  }
  N(s2, "invalid usage");
}
function Ma(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_stream_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_stream_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function Na(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(0 | r._crypto_stream_xchacha20_keybytes()), _2 = a2.address;
  t2.push(_2), r._crypto_stream_xchacha20_keygen(_2);
  var n2 = S(a2, e);
  return M(t2), n2;
}
function La(e, t2, a2, _2) {
  var n2 = [];
  Y(_2);
  var s2 = K(e = O(n2, e, "input_message")), c2 = e.length;
  n2.push(s2), t2 = O(n2, t2, "nonce");
  var p2, o2 = 0 | r._crypto_stream_xchacha20_noncebytes();
  t2.length !== o2 && L(n2, "invalid nonce length"), p2 = K(t2), n2.push(p2), a2 = O(n2, a2, "key");
  var h2, y2 = 0 | r._crypto_stream_xchacha20_keybytes();
  a2.length !== y2 && L(n2, "invalid key length"), h2 = K(a2), n2.push(h2);
  var i2 = new B(0 | c2), l2 = i2.address;
  if (n2.push(l2), 0 === r._crypto_stream_xchacha20_xor(l2, s2, c2, 0, p2, h2)) {
    var u2 = S(i2, _2);
    return M(n2), u2;
  }
  N(n2, "invalid usage");
}
function Ua(e, t2, a2, _2, n2) {
  var s2 = [];
  Y(n2);
  var c2 = K(e = O(s2, e, "input_message")), p2 = e.length;
  s2.push(c2), t2 = O(s2, t2, "nonce");
  var o2, h2 = 0 | r._crypto_stream_xchacha20_noncebytes();
  t2.length !== h2 && L(s2, "invalid nonce length"), o2 = K(t2), s2.push(o2), U(s2, a2, "nonce_increment"), ("number" != typeof a2 || (0 | a2) !== a2 || a2 < 0) && L(s2, "nonce_increment must be an unsigned integer"), _2 = O(s2, _2, "key");
  var y2, i2 = 0 | r._crypto_stream_xchacha20_keybytes();
  _2.length !== i2 && L(s2, "invalid key length"), y2 = K(_2), s2.push(y2);
  var l2 = new B(0 | p2), u2 = l2.address;
  if (s2.push(u2), 0 === r._crypto_stream_xchacha20_xor_ic(u2, c2, p2, 0, o2, a2, 0, y2)) {
    var d2 = S(l2, n2);
    return M(s2), d2;
  }
  N(s2, "invalid usage");
}
function Oa(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "out_length"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(_2, "out_length must be an unsigned integer");
  var n2 = K(t2 = O(_2, t2, "message")), s2 = t2.length;
  _2.push(n2);
  var c2 = new B(e |= 0), p2 = c2.address;
  if (_2.push(p2), !(0 | r._crypto_xof_shake128(p2, e, n2, s2, 0))) {
    var o2 = S(c2, a2);
    return M(_2), o2;
  }
  N(_2, "invalid usage");
}
function Ca(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(256).address;
  if (!(0 | r._crypto_xof_shake128_init(a2))) {
    var _2 = a2;
    return M(t2), _2;
  }
  N(t2, "invalid usage");
}
function Ra(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "domain"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(a2, "domain must be an unsigned integer");
  var _2 = new B(256).address;
  if (!(0 | r._crypto_xof_shake128_init_with_domain(_2, e))) {
    var n2 = _2;
    return M(a2), n2;
  }
  N(a2, "invalid usage");
}
function Pa(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address"), U(_2, t2, "out_length"), ("number" != typeof t2 || (0 | t2) !== t2 || t2 < 0) && L(_2, "out_length must be an unsigned integer");
  var n2 = new B(t2 |= 0), s2 = n2.address;
  if (_2.push(s2), !(0 | r._crypto_xof_shake128_squeeze(e, s2, t2))) {
    var c2 = S(n2, a2);
    return M(_2), c2;
  }
  N(_2, "invalid usage");
}
function Xa(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_xof_shake128_update(e, n2, s2, 0) && N(_2, "invalid usage"), M(_2);
}
function Da(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "out_length"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(_2, "out_length must be an unsigned integer");
  var n2 = K(t2 = O(_2, t2, "message")), s2 = t2.length;
  _2.push(n2);
  var c2 = new B(e |= 0), p2 = c2.address;
  if (_2.push(p2), !(0 | r._crypto_xof_shake256(p2, e, n2, s2, 0))) {
    var o2 = S(c2, a2);
    return M(_2), o2;
  }
  N(_2, "invalid usage");
}
function Ga(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(256).address;
  if (!(0 | r._crypto_xof_shake256_init(a2))) {
    var _2 = a2;
    return M(t2), _2;
  }
  N(t2, "invalid usage");
}
function Fa(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "domain"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(a2, "domain must be an unsigned integer");
  var _2 = new B(256).address;
  if (!(0 | r._crypto_xof_shake256_init_with_domain(_2, e))) {
    var n2 = _2;
    return M(a2), n2;
  }
  N(a2, "invalid usage");
}
function Va(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address"), U(_2, t2, "out_length"), ("number" != typeof t2 || (0 | t2) !== t2 || t2 < 0) && L(_2, "out_length must be an unsigned integer");
  var n2 = new B(t2 |= 0), s2 = n2.address;
  if (_2.push(s2), !(0 | r._crypto_xof_shake256_squeeze(e, s2, t2))) {
    var c2 = S(n2, a2);
    return M(_2), c2;
  }
  N(_2, "invalid usage");
}
function qa(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_xof_shake256_update(e, n2, s2, 0) && N(_2, "invalid usage"), M(_2);
}
function Ha(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "out_length"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(_2, "out_length must be an unsigned integer");
  var n2 = K(t2 = O(_2, t2, "message")), s2 = t2.length;
  _2.push(n2);
  var c2 = new B(e |= 0), p2 = c2.address;
  if (_2.push(p2), !(0 | r._crypto_xof_turboshake128(p2, e, n2, s2, 0))) {
    var o2 = S(c2, a2);
    return M(_2), o2;
  }
  N(_2, "invalid usage");
}
function za(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(256).address;
  if (!(0 | r._crypto_xof_turboshake128_init(a2))) {
    var _2 = a2;
    return M(t2), _2;
  }
  N(t2, "invalid usage");
}
function Wa(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "domain"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(a2, "domain must be an unsigned integer");
  var _2 = new B(256).address;
  if (!(0 | r._crypto_xof_turboshake128_init_with_domain(_2, e))) {
    var n2 = _2;
    return M(a2), n2;
  }
  N(a2, "invalid usage");
}
function ja(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address"), U(_2, t2, "out_length"), ("number" != typeof t2 || (0 | t2) !== t2 || t2 < 0) && L(_2, "out_length must be an unsigned integer");
  var n2 = new B(t2 |= 0), s2 = n2.address;
  if (_2.push(s2), !(0 | r._crypto_xof_turboshake128_squeeze(e, s2, t2))) {
    var c2 = S(n2, a2);
    return M(_2), c2;
  }
  N(_2, "invalid usage");
}
function Ja(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_xof_turboshake128_update(e, n2, s2, 0) && N(_2, "invalid usage"), M(_2);
}
function Qa(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "out_length"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(_2, "out_length must be an unsigned integer");
  var n2 = K(t2 = O(_2, t2, "message")), s2 = t2.length;
  _2.push(n2);
  var c2 = new B(e |= 0), p2 = c2.address;
  if (_2.push(p2), !(0 | r._crypto_xof_turboshake256(p2, e, n2, s2, 0))) {
    var o2 = S(c2, a2);
    return M(_2), o2;
  }
  N(_2, "invalid usage");
}
function Za(e) {
  var t2 = [];
  Y(e);
  var a2 = new B(256).address;
  if (!(0 | r._crypto_xof_turboshake256_init(a2))) {
    var _2 = a2;
    return M(t2), _2;
  }
  N(t2, "invalid usage");
}
function $a(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "domain"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(a2, "domain must be an unsigned integer");
  var _2 = new B(256).address;
  if (!(0 | r._crypto_xof_turboshake256_init_with_domain(_2, e))) {
    var n2 = _2;
    return M(a2), n2;
  }
  N(a2, "invalid usage");
}
function e_(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address"), U(_2, t2, "out_length"), ("number" != typeof t2 || (0 | t2) !== t2 || t2 < 0) && L(_2, "out_length must be an unsigned integer");
  var n2 = new B(t2 |= 0), s2 = n2.address;
  if (_2.push(s2), !(0 | r._crypto_xof_turboshake256_squeeze(e, s2, t2))) {
    var c2 = S(n2, a2);
    return M(_2), c2;
  }
  N(_2, "invalid usage");
}
function r_(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "state_address");
  var n2 = K(t2 = O(_2, t2, "message_chunk")), s2 = t2.length;
  _2.push(n2), 0 | r._crypto_xof_turboshake256_update(e, n2, s2, 0) && N(_2, "invalid usage"), M(_2);
}
function t_(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "length"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(a2, "length must be an unsigned integer");
  var _2 = new B(0 | e), n2 = _2.address;
  a2.push(n2), r._randombytes_buf(n2, e);
  var s2 = S(_2, t2);
  return M(a2), s2;
}
function a_(e, t2, a2) {
  var _2 = [];
  Y(a2), U(_2, e, "length"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(_2, "length must be an unsigned integer"), t2 = O(_2, t2, "seed");
  var n2, s2 = 0 | r._randombytes_seedbytes();
  t2.length !== s2 && L(_2, "invalid seed length"), n2 = K(t2), _2.push(n2);
  var c2 = new B(0 | e), p2 = c2.address;
  _2.push(p2), r._randombytes_buf_deterministic(p2, e, n2);
  var o2 = S(c2, a2);
  return M(_2), o2;
}
function __(e) {
  Y(e), r._randombytes_close();
}
function n_(e) {
  Y(e);
  var t2 = r._randombytes_random() >>> 0;
  return M([]), t2;
}
function s_(e, t2) {
  var a2 = [];
  Y(t2);
  for (var _2 = r._malloc(24), n2 = 0; n2 < 6; n2++) r.setValue(_2 + 4 * n2, r.Runtime.addFunction(e[["implementation_name", "random", "stir", "uniform", "buf", "close"][n2]]), "i32");
  0 | r._randombytes_set_implementation(_2) && N(a2, "unsupported implementation"), M(a2);
}
function c_(e) {
  Y(e), r._randombytes_stir();
}
function p_(e, t2) {
  var a2 = [];
  Y(t2), U(a2, e, "upper_bound"), ("number" != typeof e || (0 | e) !== e || e < 0) && L(a2, "upper_bound must be an unsigned integer");
  var _2 = r._randombytes_uniform(e) >>> 0;
  return M(a2), _2;
}
function o_(e) {
  var t2, a2 = [];
  16 !== (e = O(a2, e, "bin")).length && L(a2, "invalid bin length"), t2 = K(e), a2.push(t2);
  var _2 = new B(46).address;
  if (a2.push(_2), 0 !== r._sodium_bin2ip(_2, 46, t2)) {
    var n2 = r.UTF8ToString(_2);
    return M(a2), n2;
  }
  N(a2, "conversion failed");
}
function h_(e, t2) {
  var a2 = [];
  Y(t2), "string" != typeof e && L(a2, "ip must be a string");
  var _2 = K(e = v(e + "\0")), n2 = e.length - 1;
  a2.push(_2);
  var s2 = new B(16), c2 = s2.address;
  if (a2.push(c2), !(0 | r._sodium_ip2bin(c2, _2, n2))) {
    var p2 = S(s2, t2);
    return M(a2), p2;
  }
  N(a2, "invalid IP address");
}
function y_() {
  var e = r._sodium_version_string(), t2 = r.UTF8ToString(e);
  return M([]), t2;
}
B.prototype.to_Uint8Array = function() {
  var e = new Uint8Array(this.length);
  return e.set(r.HEAPU8.subarray(this.address, this.address + this.length)), e;
}, t.add = o, t.base64_variants = m, t.compare = l, t.from_base64 = x, t.from_hex = b, t.from_string = v, t.increment = p, t.is_zero = h, t.memcmp = i, t.memzero = y, t.output_formats = T, t.pad = u, t.unpad = d, t.ready = s, t.symbols = c, t.to_base64 = E, t.to_hex = f, t.to_string = g;
var libsodium_wrappers_default = t;

// ../backup-envelope/src/sodium.ts
var loaded = null;
function sodiumReady() {
  loaded ??= libsodium_wrappers_default.ready.then(() => libsodium_wrappers_default);
  return loaded;
}
function toB64(bytes) {
  let s2 = "";
  for (const b2 of bytes) s2 += String.fromCharCode(b2);
  return typeof btoa === "function" ? btoa(s2) : Buffer.from(bytes).toString("base64");
}
function fromB64(s2) {
  if (typeof atob === "function") {
    const raw = atob(s2);
    const out = new Uint8Array(raw.length);
    for (let i2 = 0; i2 < raw.length; i2++) out[i2] = raw.charCodeAt(i2);
    return out;
  }
  return new Uint8Array(Buffer.from(s2, "base64"));
}
function utf8(s2) {
  return new TextEncoder().encode(s2);
}

// ../backup-envelope/src/envelope.ts
var CHUNK_BYTES = 512 * 1024;
var STREAM_OVERHEAD = 17;
var FRAME_HEADER_BYTES = 4;
var MAX_FRAME_BYTES = CHUNK_BYTES + STREAM_OVERHEAD;
function bindingAad(b2) {
  return `controlclaw-backup/v1
org=${b2.orgId}
vm=${b2.vmId}
backup=${b2.backupId}
kind=${b2.kind}`;
}
function frame(body) {
  const out = new Uint8Array(FRAME_HEADER_BYTES + body.length);
  const n2 = body.length;
  out[0] = n2 >>> 24 & 255;
  out[1] = n2 >>> 16 & 255;
  out[2] = n2 >>> 8 & 255;
  out[3] = n2 & 255;
  out.set(body, FRAME_HEADER_BYTES);
  return out;
}
async function makeEncryptor(dataKeyB64, binding) {
  const sodium = await sodiumReady();
  const ad = utf8(bindingAad(binding));
  const { state, header: header2 } = sodium.crypto_secretstream_xchacha20poly1305_init_push(fromB64(dataKeyB64));
  let closed = false;
  return {
    header: toB64(header2),
    push(plain) {
      if (closed) throw new Error("the archive stream is already closed");
      if (plain.length > CHUNK_BYTES) throw new Error(`chunk of ${plain.length} bytes is over the ${CHUNK_BYTES} limit`);
      return frame(
        sodium.crypto_secretstream_xchacha20poly1305_push(state, plain, ad, sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
      );
    },
    final() {
      if (closed) throw new Error("the archive stream is already closed");
      closed = true;
      return frame(
        sodium.crypto_secretstream_xchacha20poly1305_push(
          state,
          new Uint8Array(0),
          ad,
          sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        )
      );
    }
  };
}
var WRONG_KEY = "This archive could not be opened: the key or the backup it names is wrong.";
var TRUNCATED = "This archive ended early \u2014 it is incomplete. Nothing was restored.";
async function makeDecryptor(dataKeyB64, headerB64, binding) {
  const sodium = await sodiumReady();
  const ad = utf8(bindingAad(binding));
  const header2 = fromB64(headerB64);
  if (header2.length !== sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES) throw new Error(WRONG_KEY);
  let state;
  try {
    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header2, fromB64(dataKeyB64));
  } catch {
    throw new Error(WRONG_KEY);
  }
  let buffer = new Uint8Array(0);
  let sawFinal = false;
  const take = (n2) => {
    const head = buffer.subarray(0, n2);
    buffer = buffer.subarray(n2);
    return head;
  };
  return {
    push(cipher) {
      if (cipher.length > 0) {
        const merged = new Uint8Array(buffer.length + cipher.length);
        merged.set(buffer);
        merged.set(cipher, buffer.length);
        buffer = merged;
      }
      const out = [];
      for (; ; ) {
        if (buffer.length < FRAME_HEADER_BYTES) return out;
        const len = (buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3]) >>> 0;
        if (len < STREAM_OVERHEAD || len > MAX_FRAME_BYTES) throw new Error(WRONG_KEY);
        if (buffer.length < FRAME_HEADER_BYTES + len) return out;
        take(FRAME_HEADER_BYTES);
        const body = take(len);
        if (sawFinal) throw new Error(WRONG_KEY);
        let r2;
        try {
          r2 = sodium.crypto_secretstream_xchacha20poly1305_pull(state, body, ad);
        } catch {
          throw new Error(WRONG_KEY);
        }
        if (!r2) throw new Error(WRONG_KEY);
        if (r2.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) sawFinal = true;
        if (r2.message.length > 0) out.push(r2.message);
      }
    },
    end() {
      if (!sawFinal || buffer.length > 0) throw new Error(TRUNCATED);
    }
  };
}

// ../backup-envelope/src/manifest.ts
var MANIFEST_PATH = ".controlclaw-backup-manifest.json";
function canonicalManifest(m2) {
  const entry = (e) => e.kind === "link" ? { bytes: e.bytes, kind: e.kind, mode: e.mode, path: e.path, target: e.target ?? "" } : { bytes: e.bytes, kind: e.kind, mode: e.mode, path: e.path };
  return JSON.stringify({
    entries: [...m2.entries].sort((a2, b2) => a2.path < b2.path ? -1 : a2.path > b2.path ? 1 : 0).map(entry),
    excluded: [...m2.excluded].sort((a2, b2) => a2.path < b2.path ? -1 : a2.path > b2.path ? 1 : 0).map((e) => ({ bytes: e.bytes, path: e.path })),
    kind: m2.kind,
    root: m2.root,
    takenAt: m2.takenAt,
    totalBytes: m2.totalBytes,
    version: m2.version
  });
}
async function manifestHash(m2) {
  const sodium = await sodiumReady();
  return [...sodium.crypto_generichash(32, utf8(canonicalManifest(m2)), null)].map((b2) => b2.toString(16).padStart(2, "0")).join("");
}
function parseManifest(json3) {
  const m2 = JSON.parse(json3);
  if (m2?.version !== 1 || !Array.isArray(m2.entries)) throw new Error("the archive's manifest is not readable");
  return { ...m2, excluded: Array.isArray(m2.excluded) ? m2.excluded : [] };
}

// ../backup-envelope/src/tar.ts
var BLOCK = 512;
var ZERO = new Uint8Array(BLOCK);
function octal(value, width) {
  return value.toString(8).padStart(width - 1, "0") + "\0";
}
function writeString(buf, at2, s2, width) {
  const bytes = new TextEncoder().encode(s2);
  if (bytes.length > width) throw new Error(`tar field does not fit: ${s2}`);
  buf.set(bytes, at2);
}
var TYPEFLAG = { file: "0", dir: "5", link: "2" };
function header(entry, typeflag = TYPEFLAG[entry.type], name = entry.path) {
  const h2 = new Uint8Array(BLOCK);
  writeString(h2, 0, name, 100);
  writeString(h2, 100, octal(entry.mode & 4095, 8), 8);
  writeString(h2, 108, octal(0, 8), 8);
  writeString(h2, 116, octal(0, 8), 8);
  writeString(h2, 124, octal(entry.type === "file" ? entry.size : 0, 12), 12);
  writeString(h2, 136, octal(Math.max(0, Math.floor(entry.mtime)), 12), 12);
  h2.fill(32, 148, 156);
  writeString(h2, 156, typeflag, 1);
  if (entry.target) writeString(h2, 157, entry.target, 100);
  writeString(h2, 257, "ustar", 6);
  writeString(h2, 263, "00", 2);
  let sum = 0;
  for (const b2 of h2) sum += b2;
  writeString(h2, 148, `${sum.toString(8).padStart(6, "0")}\0 `, 8);
  return h2;
}
function padding(size) {
  const rest = size % BLOCK;
  return rest === 0 ? new Uint8Array(0) : new Uint8Array(BLOCK - rest);
}
function longLink(value, typeflag) {
  const bytes = new TextEncoder().encode(value);
  const head = header({ path: "././@LongLink", type: "file", size: bytes.length + 1, mode: 420, mtime: 0 }, typeflag, "././@LongLink");
  const body = new Uint8Array(bytes.length + 1);
  body.set(bytes);
  return [head, body, padding(body.length)].filter((b2) => b2.length > 0);
}
function tarHeader(entry) {
  const name = new TextEncoder().encode(entry.path);
  const target = new TextEncoder().encode(entry.target ?? "");
  const out = [];
  if (target.length > 100) out.push(...longLink(entry.target, "K"));
  if (name.length > 100) out.push(...longLink(entry.path, "L"));
  out.push(
    header(
      // The real header's own fields must still fit; the long-link pair is what carries the value.
      { ...entry, path: name.length > 100 ? "././@LongLink" : entry.path, target: target.length > 100 ? "" : entry.target },
      TYPEFLAG[entry.type],
      name.length > 100 ? "././@LongLink" : entry.path
    )
  );
  return out;
}
function tarPadding(size) {
  const p2 = padding(size);
  return p2.length > 0 ? [p2] : [];
}
function tarEnd() {
  return [ZERO, ZERO];
}
function readString(buf, at2, width) {
  const slice = buf.subarray(at2, at2 + width);
  const end = slice.indexOf(0);
  return new TextDecoder().decode(end === -1 ? slice : slice.subarray(0, end));
}
function readOctal(buf, at2, width) {
  const s2 = readString(buf, at2, width).trim();
  if (s2 === "") return 0;
  const n2 = parseInt(s2, 8);
  if (!Number.isFinite(n2) || n2 < 0) throw new Error("this archive has a malformed tar header");
  return n2;
}
var TarReader = class {
  buffer = new Uint8Array(0);
  longName = null;
  longTarget = null;
  zeroBlocks = 0;
  ended = false;
  push(chunk) {
    if (chunk.length > 0) {
      const merged = new Uint8Array(this.buffer.length + chunk.length);
      merged.set(this.buffer);
      merged.set(chunk, this.buffer.length);
      this.buffer = merged;
    }
    const out = [];
    for (; ; ) {
      if (this.ended || this.buffer.length < BLOCK) return out;
      const head = this.buffer.subarray(0, BLOCK);
      if (head.every((b2) => b2 === 0)) {
        this.buffer = this.buffer.subarray(BLOCK);
        if (++this.zeroBlocks >= 2) this.ended = true;
        continue;
      }
      this.zeroBlocks = 0;
      if (readString(head, 257, 6).replace(/\0.*$/, "") !== "ustar") throw new Error("this archive is not a tar file we wrote");
      const size = readOctal(head, 124, 12);
      const bodyBlocks = Math.ceil(size / BLOCK) * BLOCK;
      if (this.buffer.length < BLOCK + bodyBlocks) return out;
      const body = this.buffer.subarray(BLOCK, BLOCK + size);
      const flag = readString(head, 156, 1);
      const path = this.longName ?? readString(head, 0, 100);
      this.buffer = this.buffer.subarray(BLOCK + bodyBlocks);
      if (flag === "L" || flag === "K") {
        const value = new TextDecoder().decode(body).replace(/\0+$/, "");
        if (flag === "L") this.longName = value;
        else this.longTarget = value;
        continue;
      }
      const longTarget = this.longTarget;
      this.longName = null;
      this.longTarget = null;
      const type = flag === "0" || flag === "" ? "file" : flag === "5" ? "dir" : flag === "2" ? "link" : null;
      if (!type) throw new Error(`this archive contains an entry type we do not restore (${flag})`);
      out.push({
        path,
        type,
        size: type === "file" ? size : 0,
        mode: readOctal(head, 100, 8) & 4095,
        mtime: readOctal(head, 136, 12),
        ...type === "link" ? { target: longTarget ?? readString(head, 157, 100) } : {},
        // A copy, not a view: the buffer it points into is reused as more chunks arrive.
        body: type === "file" ? new Uint8Array(body) : new Uint8Array(0)
      });
    }
  }
  /** True once both end-of-archive blocks arrived. A restore refuses an archive that never ends. */
  complete() {
    return this.ended;
  }
};
function safeEntryPath(path) {
  const clean = path.replace(/\\/g, "/").replace(/^\.\//, "");
  if (clean === "" || clean === ".") throw new Error("this archive contains an entry with no name");
  if (clean.startsWith("/")) throw new Error(`this archive contains an absolute path (${clean})`);
  const parts = clean.split("/");
  if (parts.some((p2) => p2 === "..")) throw new Error(`this archive contains a path that climbs out of it (${clean})`);
  if (clean.includes("\0")) throw new Error("this archive contains an entry name with a null byte");
  return parts.filter((p2) => p2 !== "" && p2 !== ".").join("/");
}

// ../backup-envelope/src/archive-file.ts
var ARCHIVE_FILE_MAGIC = "CCBKUP01";
var ARCHIVE_FILE_HEADER_BYTES = ARCHIVE_FILE_MAGIC.length + 4;
var MAX_PRELUDE_BYTES = 64 * 1024;

// ../backup-envelope/src/recovery-identity.ts
var RECOVERY_REPLAY_WINDOW_MS = 5 * 6e4;
var RECOVERY_BODY_MAGIC = "CCRCV001";
var RECOVERY_BODY_HEADER_BYTES = RECOVERY_BODY_MAGIC.length + 4;
var MAX_RECOVERY_HEAD_BYTES = 64 * 1024;

// ../backup-envelope/src/paths.ts
var ARCHIVE_ROOTS = {
  workspace: "workspace",
  state: "."
};
var EXCLUDED_SEGMENTS = new Set(
  [
    "node_modules",
    ".cache",
    "cache",
    "caches",
    "cachestorage",
    "code cache",
    "gpucache",
    "shadercache",
    "dawncache",
    "crashpad",
    "_cacache",
    ".pnpm-store",
    ".turbo",
    ".venv",
    "__pycache__",
    "logs",
    "tmp",
    ".tmp"
  ].map((s2) => s2.toLowerCase())
);
var IDENTITY_NAMES = ["openclaw_gateway_token", "saas_public_key.pem", "vm_private_key.pem", "vm_public_key.pem", "mitm_pinned_pubkey.pem", "session_secret"];
var EXCLUDED_NAMES = new Set([...IDENTITY_NAMES, ".DS_Store"].map((s2) => s2.toLowerCase()));
function keepOnRestore(kind) {
  return kind === "state" ? ["workspace", ...IDENTITY_NAMES] : [];
}
var EXCLUDED_SUFFIXES = [".log", ".log.gz", ".sock", ".pid", ".swp", ".core"];
var RESTORE_SCRATCH = /\.cc-(restoring|previous-\d+)$/;
function shouldExclude(relPath, kind) {
  const parts = relPath.split("/").filter((p2) => p2.length > 0 && p2 !== ".");
  if (parts.length === 0) return false;
  if (kind === "state" && parts[0] === "workspace") return true;
  if (parts.some((p2) => RESTORE_SCRATCH.test(p2))) return true;
  const name = parts[parts.length - 1].toLowerCase();
  if (EXCLUDED_NAMES.has(name)) return true;
  if (EXCLUDED_SUFFIXES.some((s2) => name.endsWith(s2))) return true;
  return parts.some((p2) => EXCLUDED_SEGMENTS.has(p2.toLowerCase()));
}
var FORBIDDEN_ROOTS = ["/opt/controlclaw/keys", "/opt/controlclaw/mitm", "/etc/ssh", "/root"];
function assertArchivableRoot(absolutePath) {
  const p2 = absolutePath.replace(/\/+$/, "") || "/";
  if (p2 === "/") throw new Error("refusing to archive the whole filesystem");
  for (const bad of FORBIDDEN_ROOTS) {
    if (p2 === bad || p2.startsWith(`${bad}/`)) throw new Error(`refusing to archive ${bad}: it is this box's identity, not its content`);
  }
}

// ../backup-envelope/src/retention.ts
var EXPIRY_GRACE_MS = 24 * 60 * 60 * 1e3;
var DAY_MS = 24 * 60 * 60 * 1e3;

// src/backup.ts
var MAX_ARCHIVE_BYTES = 5 * 1024 * 1024 * 1024;
function bytesLine(n2) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v2 = n2;
  let i2 = 0;
  while (v2 >= 1024 && i2 < units.length - 1) {
    v2 /= 1024;
    i2++;
  }
  return `${i2 > 0 && v2 < 10 && !Number.isInteger(v2) ? v2.toFixed(1) : Math.round(v2)} ${units[i2]}`;
}
var BackupService = class {
  constructor(opts) {
    this.opts = opts;
    this.home = opts.home ?? `${process.env.HOME ?? "/home/controlclaw"}/.openclaw`;
    this.spoolDir = opts.spoolDir ?? tmpdir();
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.now = opts.now ?? Date.now;
    this.log = opts.log ?? ((l2) => console.log(l2));
  }
  home;
  spoolDir;
  fetchImpl;
  now;
  log;
  /** One backup or restore at a time: both touch OpenClaw's files and one is enough load. */
  busy = null;
  rootFor(kind) {
    if (kind === "firewall") throw new Error("an agent box does not hold the firewall's own backup");
    const root = ARCHIVE_ROOTS[kind] === "." ? this.home : join7(this.home, ARCHIVE_ROOTS[kind]);
    assertArchivableRoot(root);
    return root;
  }
  /** What a backup of this kind would contain and cost, without producing it. */
  async plan(kind) {
    const root = this.rootFor(kind);
    const entries = [];
    const excluded = [];
    const dirBytes = /* @__PURE__ */ new Map();
    let plainBytes = 0;
    const walk = async (rel) => {
      let dir;
      try {
        dir = await opendir(rel === "" ? root : join7(root, rel));
      } catch {
        return;
      }
      for await (const item of dir) {
        const childRel = rel === "" ? item.name : `${rel}/${item.name}`;
        if (shouldExclude(childRel, kind)) {
          const bytes = item.isDirectory() ? await dirSize(join7(root, childRel)) : await fileSize(join7(root, childRel));
          excluded.push({ path: childRel, bytes });
          continue;
        }
        let st2;
        try {
          st2 = await lstat(join7(root, childRel));
        } catch {
          continue;
        }
        if (st2.isSymbolicLink()) {
          entries.push({ path: childRel, bytes: 0, mode: 511, kind: "link", target: await readlink(join7(root, childRel)) });
          continue;
        }
        if (st2.isDirectory()) {
          entries.push({ path: childRel, bytes: 0, mode: st2.mode & 4095, kind: "dir" });
          await walk(childRel);
          continue;
        }
        if (!st2.isFile()) continue;
        entries.push({ path: childRel, bytes: st2.size, mode: st2.mode & 4095, kind: "file" });
        plainBytes += st2.size;
        const top = childRel.split("/")[0];
        dirBytes.set(top, (dirBytes.get(top) ?? 0) + st2.size);
      }
    };
    await walk("");
    const manifest = {
      version: 1,
      kind,
      takenAt: new Date(this.now()).toISOString(),
      root,
      entries,
      totalBytes: plainBytes,
      excluded: excluded.sort((a2, b2) => b2.bytes - a2.bytes).slice(0, 20)
    };
    const largest = [...dirBytes.entries()].map(([path, bytes]) => ({ path, bytes })).sort((a2, b2) => b2.bytes - a2.bytes).slice(0, 5);
    return { kind, root, manifest, plainBytes, largest };
  }
  /** The message someone sees when their agent is too big for one presigned PUT. */
  overLimit(plan) {
    const worst = plan.largest.filter((d2) => d2.bytes > 0).map((d2) => `${d2.path} (${bytesLine(d2.bytes)})`);
    return new Error(
      `This agent's ${plan.kind} is ${bytesLine(plan.plainBytes)}, over the ${bytesLine(MAX_ARCHIVE_BYTES)} limit for one backup. ` + (worst.length ? `The biggest directories are ${worst.join(", ")}. ` : "") + `Move or delete what you do not need, or ask us to enable large backups.`
    );
  }
  async run(input) {
    const label = `${input.kind} of ${input.vmId}`;
    if (this.busy) throw new Error(`This agent is already backing up or restoring (${this.busy}). Wait for that to finish.`);
    this.busy = label;
    let spool = null;
    try {
      const plan = await this.plan(input.kind);
      if (plan.plainBytes > MAX_ARCHIVE_BYTES) throw this.overLimit(plan);
      const manifest = plan.manifest;
      const hash = await manifestHash(manifest);
      const enc = await makeEncryptor(input.dataKey, {
        orgId: input.orgId,
        vmId: input.vmId,
        backupId: input.backupId,
        kind: input.kind
      });
      const dir = await mkdtemp(join7(this.spoolDir, "cc-backup-"));
      spool = join7(dir, "archive.bin");
      await pipeline(
        Readable.from(tarOf(plan.root, manifest, input.kind)),
        createGzip({ level: 6 }),
        (src) => seal(src, enc),
        createWriteStream(spool, { mode: 384 })
      );
      const cipherBytes = (await stat(spool)).size;
      this.log(`[backup] ${label}: ${bytesLine(plan.plainBytes)} of content \u2192 ${bytesLine(cipherBytes)} sealed`);
      await this.put(input.uploadUrl, spool, cipherBytes);
      return {
        kind: input.kind,
        header: enc.header,
        manifestHash: hash,
        plainBytes: plan.plainBytes,
        cipherBytes,
        entries: manifest.entries.length,
        excludedBytes: manifest.excluded.reduce((n2, e) => n2 + e.bytes, 0),
        takenAt: manifest.takenAt
      };
    } finally {
      if (spool) await rm(dirname9(spool), { recursive: true, force: true }).catch(() => void 0);
      this.busy = null;
    }
  }
  async put(url2, path, size) {
    const res = await this.fetchImpl(url2, {
      method: "PUT",
      // Explicit, because the body is a stream: without it undici would send it chunked and S3
      // answers 411 to that. It is also the only bound the store has on what we are about to send.
      headers: { "content-length": String(size), "content-type": "application/octet-stream" },
      body: Readable.toWeb(createReadStream(path)),
      // Node wants to be told we will not read the response until the body is sent.
      ...{ duplex: "half" }
    });
    if (!res.ok) {
      throw new Error(`The backup store refused the upload (HTTP ${res.status}).`);
    }
  }
  /**
   * Download, open, verify, then swap. Nothing under `home` is touched until the archive has been
   * fully extracted and its manifest matched — so a wrong key, a truncated blob or a hash mismatch
   * costs a staging directory and nothing else.
   */
  async restore(input) {
    const label = `restore of ${input.kind} onto ${input.vmId}`;
    if (this.busy) throw new Error(`This agent is already backing up or restoring (${this.busy}). Wait for that to finish.`);
    this.busy = label;
    const target = this.rootFor(input.kind);
    const staging = `${target}.cc-restoring`;
    const aside = `${target}.cc-previous-${this.now()}`;
    try {
      await rm(staging, { recursive: true, force: true });
      await mkdir(staging, { recursive: true, mode: 448 });
      const extracted = await this.extract(input, staging);
      if (extracted.manifestHash !== input.manifestHash) {
        throw new Error("This backup does not match what was recorded for it. Nothing was restored.");
      }
      this.log(`[backup] ${label}: ${extracted.entries} entries verified, swapping`);
      const stopped = this.opts.service("stop");
      if (!stopped.ok) this.log(`[backup] could not stop OpenClaw cleanly: ${stopped.error ?? "unknown"}; continuing`);
      try {
        await swapDirectory({ target, staged: staging, aside, keep: keepOnRestore(input.kind) });
      } catch (err) {
        this.opts.service("start");
        throw err;
      }
      const started = this.opts.service("start");
      if (!started.ok) this.log(`[backup] OpenClaw did not start after the restore: ${started.error ?? "unknown"}`);
      await rm(aside, { recursive: true, force: true }).catch(() => void 0);
      return { kind: input.kind, entries: extracted.entries, plainBytes: extracted.plainBytes, restarted: started.ok };
    } finally {
      await rm(staging, { recursive: true, force: true }).catch(() => void 0);
      this.busy = null;
    }
  }
  /** Stream the blob into `into`, writing each entry as it arrives. Returns what the manifest said. */
  async extract(input, into) {
    const res = await this.fetchImpl(input.downloadUrl);
    if (!res.ok || !res.body) throw new Error(`The backup store would not serve this archive (HTTP ${res.status}).`);
    const dec = await makeDecryptor(input.dataKey, input.header, {
      orgId: input.orgId,
      vmId: input.vmId,
      backupId: input.backupId,
      kind: input.kind
    });
    const reader = new TarReader();
    let manifest = null;
    let entries = 0;
    let plainBytes = 0;
    const dirs = /* @__PURE__ */ new Map();
    const onTar = async (chunk) => {
      {
        for (const e of reader.push(chunk)) {
          const rel = safeEntryPath(e.path);
          if (rel === MANIFEST_PATH) {
            manifest = parseManifest(new TextDecoder().decode(e.body));
            continue;
          }
          const abs = join7(into, rel);
          if (e.type === "dir") {
            await mkdir(abs, { recursive: true, mode: 448 });
            dirs.set(abs, { mode: e.mode, mtime: e.mtime });
            continue;
          }
          await mkdir(dirname9(abs), { recursive: true, mode: 448 });
          if (e.type === "link") {
            await symlink(e.target ?? "", abs).catch(() => void 0);
            continue;
          }
          await writeFile(abs, e.body, { mode: e.mode & 4095 });
          if (e.mtime > 0) await utimes(abs, e.mtime, e.mtime).catch(() => void 0);
          entries++;
          plainBytes += e.body.length;
        }
      }
    };
    const gunzip = createGunzip();
    let consumeError = null;
    const consume = (async () => {
      for await (const chunk of gunzip) await onTar(chunk);
    })().catch((err) => {
      consumeError = err;
    });
    const throwIfConsumeFailed = () => {
      if (consumeError) throw consumeError;
    };
    const write = (plain) => new Promise((resolve2, reject) => {
      if (gunzip.write(plain)) return resolve2();
      const done = (err) => {
        gunzip.off("drain", onDrain);
        gunzip.off("error", onError);
        gunzip.off("close", onClose);
        if (err) reject(err);
        else resolve2();
      };
      const onDrain = () => done();
      const onClose = () => done();
      const onError = (err) => done(err);
      gunzip.once("drain", onDrain);
      gunzip.once("close", onClose);
      gunzip.once("error", onError);
    });
    try {
      for await (const chunk of res.body) {
        throwIfConsumeFailed();
        for (const plain of dec.push(new Uint8Array(chunk))) {
          await write(plain);
          throwIfConsumeFailed();
        }
      }
      dec.end();
    } catch (err) {
      gunzip.destroy();
      await consume;
      throw err;
    }
    gunzip.end();
    await consume;
    throwIfConsumeFailed();
    if (!reader.complete()) throw new Error("This archive ended early \u2014 it is incomplete. Nothing was restored.");
    if (!manifest) throw new Error("This archive has no manifest, so it cannot be checked. Nothing was restored.");
    for (const [abs, meta] of dirs) await chmod(abs, meta.mode & 4095).catch(() => void 0);
    return { manifestHash: await manifestHash(manifest), entries, plainBytes };
  }
};
async function* tarOf(root, manifest, kind) {
  const manifestBody = new TextEncoder().encode(JSON.stringify(manifest));
  const mtime = Math.floor(Date.parse(manifest.takenAt) / 1e3);
  yield* tarHeader({ path: MANIFEST_PATH, type: "file", size: manifestBody.length, mode: 384, mtime });
  yield manifestBody;
  yield* tarPadding(manifestBody.length);
  for (const e of manifest.entries) {
    const abs = join7(root, e.path);
    if (e.kind === "dir") {
      yield* tarHeader({ path: `${e.path}/`, type: "dir", size: 0, mode: e.mode, mtime });
      continue;
    }
    if (e.kind === "link") {
      yield* tarHeader({ path: e.path, type: "link", size: 0, mode: e.mode, mtime, target: e.target ?? "" });
      continue;
    }
    let st2;
    try {
      st2 = await stat(abs);
    } catch {
      st2 = null;
    }
    yield* tarHeader({ path: e.path, type: "file", size: e.bytes, mode: e.mode, mtime });
    let sent = 0;
    if (st2?.isFile()) {
      for await (const chunk of createReadStream(abs)) {
        const buf = chunk;
        const room = e.bytes - sent;
        if (room <= 0) break;
        const take = buf.length <= room ? buf : buf.subarray(0, room);
        yield take;
        sent += take.length;
      }
    }
    if (sent < e.bytes) yield new Uint8Array(e.bytes - sent);
    yield* tarPadding(e.bytes);
  }
  void kind;
  yield* tarEnd();
}
async function* seal(src, enc) {
  let pending = new Uint8Array(CHUNK_BYTES);
  let at2 = 0;
  for await (const chunk of src) {
    let offset = 0;
    while (offset < chunk.length) {
      const take = Math.min(CHUNK_BYTES - at2, chunk.length - offset);
      pending.set(chunk.subarray(offset, offset + take), at2);
      at2 += take;
      offset += take;
      if (at2 === CHUNK_BYTES) {
        yield enc.push(pending);
        pending = new Uint8Array(CHUNK_BYTES);
        at2 = 0;
      }
    }
  }
  if (at2 > 0) yield enc.push(pending.subarray(0, at2));
  yield enc.final();
}
async function swapDirectory(opts) {
  const moved = [];
  const undoKept = async () => {
    for (const m2 of moved.reverse()) await rename(m2.to, m2.from).catch(() => void 0);
  };
  try {
    for (const rel of opts.keep ?? []) {
      const from = join7(opts.target, rel);
      const to = join7(opts.staged, rel);
      const exists2 = await lstat(from).then(
        () => true,
        () => false
      );
      if (!exists2) continue;
      await rm(to, { recursive: true, force: true });
      await mkdir(dirname9(to), { recursive: true, mode: 448 });
      await rename(from, to);
      moved.push({ from, to });
    }
  } catch (err) {
    await undoKept();
    throw err;
  }
  const targetExisted = await lstat(opts.target).then(
    () => true,
    () => false
  );
  if (targetExisted) {
    try {
      await rename(opts.target, opts.aside);
    } catch (err) {
      await undoKept();
      throw err;
    }
  }
  try {
    await rename(opts.staged, opts.target);
  } catch (err) {
    if (targetExisted) await rename(opts.aside, opts.target).catch(() => void 0);
    await undoKept();
    throw err;
  }
}
async function fileSize(path) {
  return stat(path).then(
    (s2) => s2.isFile() ? s2.size : 0,
    () => 0
  );
}
async function dirSize(path) {
  let total = 0;
  let dir;
  try {
    dir = await opendir(path);
  } catch {
    return 0;
  }
  for await (const item of dir) {
    const child = join7(path, item.name);
    if (item.isDirectory()) total += await dirSize(child);
    else if (item.isFile()) total += await fileSize(child);
  }
  return total;
}

// src/routes/backup.ts
var KINDS2 = /* @__PURE__ */ new Set(["workspace", "state"]);
var B64 = /^[A-Za-z0-9+/]+={0,2}$/;
var ID = /^[A-Za-z0-9_-]{1,64}$/;
var HEX64 = /^[0-9a-f]{64}$/;
function str5(body, key) {
  const v2 = body[key];
  return typeof v2 === "string" && v2.length > 0 ? v2 : null;
}
function url(body, key) {
  const v2 = str5(body, key);
  if (!v2 || v2.length > 4096) return null;
  try {
    return new URL(v2).protocol === "https:" ? v2 : null;
  } catch {
    return null;
  }
}
function common(body) {
  const orgId = str5(body, "orgId");
  const vmId = str5(body, "vmId");
  const backupId = str5(body, "backupId");
  const kind = str5(body, "kind");
  const dataKey = str5(body, "dataKey");
  if (!orgId || orgId.length > 64) return "orgId is required";
  if (!vmId || !ID.test(vmId)) return "vmId is required";
  if (!backupId || !ID.test(backupId)) return "backupId is required";
  if (!kind || !KINDS2.has(kind)) return "kind must be workspace or state";
  if (!dataKey || dataKey.length !== 44 || !B64.test(dataKey)) return "dataKey is required";
  return { orgId, vmId, backupId, kind, dataKey };
}
function parseRun(body) {
  const c2 = common(body);
  if (typeof c2 === "string") return c2;
  const uploadUrl = url(body, "uploadUrl");
  if (!uploadUrl) return "uploadUrl must be an https URL";
  return { ...c2, uploadUrl };
}
function parseRestore(body) {
  const c2 = common(body);
  if (typeof c2 === "string") return c2;
  const downloadUrl = url(body, "downloadUrl");
  if (!downloadUrl) return "downloadUrl must be an https URL";
  const header2 = str5(body, "header");
  const hash = str5(body, "manifestHash");
  if (!header2 || header2.length !== 32 || !B64.test(header2)) return "header is required";
  if (!hash || !HEX64.test(hash)) return "manifestHash is required";
  return { ...c2, downloadUrl, header: header2, manifestHash: hash };
}
async function handleBackup(req, res, url2, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "backup") : await verifyMitmRequest(req, "backup") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "backups must come from the org firewall" : "Unauthorized" });
    return;
  }
  if (!service) {
    sendJson(res, 503, { ok: false, error: "This agent cannot back itself up" });
    return;
  }
  try {
    if (url2.pathname === "/backup/plan" && req.method === "GET") {
      const kind = url2.searchParams.get("kind") ?? "";
      if (!KINDS2.has(kind)) return sendJson(res, 400, { ok: false, error: "kind must be workspace or state" });
      const plan = await service.plan(kind);
      sendJson(res, 200, {
        ok: true,
        kind: plan.kind,
        plainBytes: plan.plainBytes,
        entries: plan.manifest.entries.length,
        largest: plan.largest,
        excluded: plan.manifest.excluded
      });
      return;
    }
    if (!write) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    const body = await readJsonBody(req);
    if (!body) {
      sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
      return;
    }
    if (url2.pathname === "/backup/run") {
      const input = parseRun(body);
      if (typeof input === "string") return sendJson(res, 400, { ok: false, error: input });
      sendJson(res, 200, { ok: true, ...await service.run(input) });
      return;
    }
    if (url2.pathname === "/backup/restore") {
      const input = parseRestore(body);
      if (typeof input === "string") return sendJson(res, 400, { ok: false, error: input });
      sendJson(res, 200, { ok: true, ...await service.restore(input) });
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    sendJson(res, /already backing up|already restoring/i.test(message) ? 409 : 500, { ok: false, error: message });
  }
}

// src/routes/files.ts
import { createReadStream as createReadStream2 } from "fs";
import { chmod as chmod2, lstat as lstat2, mkdir as mkdir2, open, readdir, realpath, rename as rename2, rm as rm2, stat as stat2, unlink } from "fs/promises";
import { randomUUID as randomUUID2 } from "crypto";
import { basename as basename2, dirname as dirname10, join as join8, resolve, sep } from "path";
import { Transform } from "stream";
import { pipeline as pipeline2 } from "stream/promises";
var TEXT_PREVIEW_BYTES = 1024 * 1024;
var IMAGE_PREVIEW_BYTES = 20 * 1024 * 1024;
var UPLOAD_MAX_BYTES = 100 * 1024 * 1024;
var RECURSIVE_DELETE_MAX_ENTRIES = 1e4;
var LIST_MAX_ENTRIES = 5e3;
var DEFAULT_DENIED = [
  "/opt/controlclaw",
  "/opt/controlclaw/keys",
  "/opt/controlclaw/keys/openclaw_gateway_token",
  "/opt/controlclaw/state",
  "/opt/controlclaw/agent",
  // The account's own credentials. OpenClaw can read them anyway, but the explorer must not be a
  // second way to read or rewrite them: `~/.ssh/authorized_keys` is what rescue access writes, and
  // a key dropped in there through this page would be a shell with no grant behind it.
  `${process.env.HOME ?? "/home/controlclaw"}/.ssh`,
  `${process.env.HOME ?? "/home/controlclaw"}/.openclaw/credentials`
];
var EXT_MIME = {
  ".txt": "text/plain",
  ".md": "text/markdown",
  ".markdown": "text/markdown",
  ".json": "application/json",
  ".jsonl": "application/json",
  ".ndjson": "application/json",
  ".yaml": "text/yaml",
  ".yml": "text/yaml",
  ".toml": "text/plain",
  ".ini": "text/plain",
  ".conf": "text/plain",
  ".log": "text/plain",
  ".csv": "text/csv",
  ".tsv": "text/tab-separated-values",
  ".xml": "text/xml",
  ".html": "text/html",
  ".htm": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".cjs": "text/javascript",
  ".jsx": "text/javascript",
  ".ts": "text/typescript",
  ".tsx": "text/typescript",
  ".py": "text/x-python",
  ".rb": "text/x-ruby",
  ".go": "text/x-go",
  ".rs": "text/x-rust",
  ".java": "text/x-java",
  ".c": "text/x-c",
  ".h": "text/x-c",
  ".cpp": "text/x-c++",
  ".sh": "text/x-shellscript",
  ".bash": "text/x-shellscript",
  ".zsh": "text/x-shellscript",
  ".sql": "text/x-sql",
  ".php": "text/x-php",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".avif": "image/avif",
  ".bmp": "image/bmp",
  ".ico": "image/x-icon",
  ".pdf": "application/pdf",
  ".zip": "application/zip",
  ".gz": "application/gzip",
  ".tgz": "application/gzip",
  ".tar": "application/x-tar",
  ".mp3": "audio/mpeg",
  ".mp4": "video/mp4",
  ".webm": "video/webm",
  ".wav": "audio/wav"
};
var TEXT_BASENAMES = /* @__PURE__ */ new Set([
  "dockerfile",
  "makefile",
  "procfile",
  "license",
  "readme",
  "changelog",
  "authors",
  "notice",
  ".gitignore",
  ".dockerignore",
  ".npmrc",
  ".bashrc",
  ".profile",
  ".bash_profile",
  ".editorconfig"
]);
function mimeFor(name) {
  const lower = name.toLowerCase();
  const dot = lower.lastIndexOf(".");
  const ext = dot > 0 ? lower.slice(dot) : "";
  if (lower === ".env" || lower.startsWith(".env.")) return "text/plain";
  if (ext && EXT_MIME[ext]) return EXT_MIME[ext];
  if (TEXT_BASENAMES.has(lower)) return "text/plain";
  return "application/octet-stream";
}
function isTextual(mime) {
  return mime.startsWith("text/") || mime === "application/json" || mime === "image/svg+xml";
}
function isPreviewableImage(mime) {
  return mime.startsWith("image/") && mime !== "image/svg+xml";
}
function humanBytes(n2) {
  if (n2 < 1e3) return `${n2} B`;
  const units = ["kB", "MB", "GB", "TB"];
  let v2 = n2 / 1e3;
  let i2 = 0;
  while (v2 >= 1e3 && i2 < units.length - 1) {
    v2 /= 1e3;
    i2++;
  }
  return `${v2 < 10 ? v2.toFixed(1) : Math.round(v2)} ${units[i2]}`;
}
var FilesError = class extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
};
function normalizeRelative(input) {
  const raw = (input ?? "").replace(/\0/g, "");
  const parts = [];
  for (const seg of raw.split(/[\\/]+/)) {
    if (!seg || seg === ".") continue;
    if (seg === "..") {
      parts.pop();
      continue;
    }
    parts.push(seg);
  }
  return parts.join("/");
}
function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(root.endsWith(sep) ? root : root + sep);
}
async function realpathLenient(path) {
  const missing = [];
  let cursor = resolve(path);
  for (; ; ) {
    try {
      const real = await realpath(cursor);
      return missing.length ? join8(real, ...missing.reverse()) : real;
    } catch {
      const parent = dirname10(cursor);
      if (parent === cursor) return resolve(path);
      missing.push(basename2(cursor));
      cursor = parent;
    }
  }
}
var FilesService = class {
  constructor(opts) {
    this.opts = opts;
    this.denied = (opts.denied ?? DEFAULT_DENIED).map((p2) => resolve(p2));
    this.limits = {
      textPreviewBytes: TEXT_PREVIEW_BYTES,
      imagePreviewBytes: IMAGE_PREVIEW_BYTES,
      uploadMaxBytes: UPLOAD_MAX_BYTES,
      recursiveDeleteMaxEntries: RECURSIVE_DELETE_MAX_ENTRIES,
      listMaxEntries: LIST_MAX_ENTRIES,
      ...opts.limits
    };
  }
  /** The root's own realpath, resolved once: /home may itself be a symlink. */
  rootReal = null;
  denied;
  limits;
  get vmId() {
    return this.opts.vmId;
  }
  get openToAnyone() {
    return this.opts.insecureDevNoAuth === true;
  }
  /** What an `openToAnyone` box pretends the session said. Writable unless told otherwise. */
  get openToAnyoneCanWrite() {
    return this.opts.insecureDevReadOnly !== true;
  }
  /**
   * Who may call the file routes with this box's cookie: the box's own page (/__cc/files), and the
   * console only while it is the same *site* as the box — a `vm.controlclaw.com` box, whose console
   * still renders the explorer itself. For a `ccl.bot` box the browser would not send the cookie
   * cross-site anyway; listing the console there would be an exception with nothing to gain.
   */
  get origins() {
    const { box, console: consoleOrigin2 } = allowedOrigins();
    const consoleIfSameSite = sameSite(box, consoleOrigin2) ? consoleOrigin2 : null;
    return [box, consoleIfSameSite, ...this.opts.extraOrigins ?? []].filter((o2) => !!o2);
  }
  async root() {
    this.rootReal ??= await realpath(this.opts.root);
    return this.rootReal;
  }
  /**
   * The deny list, each entry as a real path. `assertAllowed` is handed real paths, so an entry
   * under a symlinked directory (macOS's /var → /private/var, or a /home that is a link) would
   * otherwise never match and the credentials it names would be browsable.
   *
   * An entry that does not exist yet (`~/.ssh` on a fresh box) is resolved through its nearest
   * existing ancestor. Falling back to the unresolved path, and caching that, meant the first
   * request to the box decided for good whether that entry could ever match: it could not, and a
   * later write into it was allowed.
   */
  deniedReal = null;
  async deniedList() {
    this.deniedReal ??= await Promise.all(this.denied.map(realpathLenient));
    return this.deniedReal;
  }
  async assertAllowed(real) {
    for (const d2 of await this.deniedList()) {
      if (isInside(d2, real)) {
        throw new FilesError(403, "denied", "That path is part of the box's own credentials and is not browsable.");
      }
    }
  }
  /**
   * Resolve a path that must already exist. `realpath` is what follows symlinks, so a link the
   * agent planted at `~/notes -> /opt/controlclaw/keys` lands outside the root and is refused
   * here rather than read.
   */
  async resolveExisting(rel) {
    const root = await this.root();
    const normalized = normalizeRelative(rel);
    let real;
    try {
      real = await realpath(normalized ? join8(root, normalized) : root);
    } catch {
      throw new FilesError(404, "not_found", "No such file or folder.");
    }
    if (!isInside(root, real)) {
      throw new FilesError(403, "outside_root", "That path leaves the agent's workspace.");
    }
    await this.assertAllowed(real);
    return { rel: normalized, abs: real };
  }
  /**
   * Resolve a path WITHOUT following a symlink in its last segment: the PARENT is resolved the
   * strict way above and the name is appended, so a symlinked parent cannot smuggle the path out
   * of the root, while the entry itself stays the entry.
   *
   * That distinction is the whole point for a write. Deleting `notes -> /etc` must unlink the
   * link, not touch /etc; renaming it must move the link. Reading it, on the other hand, goes
   * through `resolveExisting` and is refused, because reading it really would read /etc.
   */
  async resolveEntry(rel) {
    const normalized = normalizeRelative(rel);
    if (!normalized) {
      const root = await this.root();
      return { rel: "", abs: root, parent: root, name: "" };
    }
    const name = basename2(normalized);
    if (!name || name === "." || name === "..") throw new FilesError(400, "bad_path", "That name is not allowed.");
    const parentRel = dirname10(normalized) === "." ? "" : dirname10(normalized);
    const parent = await this.resolveExisting(parentRel);
    const st2 = await stat2(parent.abs).catch(() => null);
    if (!st2?.isDirectory()) throw new FilesError(400, "not_a_directory", "The destination is not a folder.");
    const abs = join8(parent.abs, name);
    await this.assertAllowed(abs);
    return { rel: normalized, abs, parent: parent.abs, name };
  }
  /** The same, for a path that must not be the workspace root (an upload, a new folder, a move). */
  async resolveForCreate(rel) {
    const entry = await this.resolveEntry(rel);
    if (!entry.rel) throw new FilesError(400, "bad_path", "A name is required.");
    return entry;
  }
  async list(rel) {
    const root = await this.root();
    const { rel: relPath, abs } = await this.resolveExisting(rel);
    const dirStat = await stat2(abs);
    if (!dirStat.isDirectory()) throw new FilesError(400, "not_a_directory", "That is a file, not a folder.");
    const names = await readdir(abs);
    const truncated = names.length > this.limits.listMaxEntries;
    const entries = [];
    for (const name of names.slice(0, this.limits.listMaxEntries)) {
      const entry = await describe(root, join8(abs, name), name);
      if (entry) entries.push(entry);
    }
    entries.sort((a2, b2) => {
      if (a2.kind === "dir" !== (b2.kind === "dir")) return a2.kind === "dir" ? -1 : 1;
      return a2.name.localeCompare(b2.name, "en", { numeric: true, sensitivity: "base" });
    });
    return { path: relPath, entries, truncated };
  }
  /** The file a read/download is about, with the checks both of them share. */
  async fileFor(rel) {
    const { rel: relPath, abs } = await this.resolveExisting(rel);
    const st2 = await stat2(abs);
    if (st2.isDirectory()) throw new FilesError(400, "is_a_directory", "That is a folder, not a file.");
    if (!st2.isFile()) throw new FilesError(400, "not_a_file", "That is not a regular file.");
    return { rel: relPath, abs, size: st2.size, mtime: st2.mtime.toISOString(), mime: mimeFor(basename2(abs)) };
  }
  async mkdir(rel) {
    const target = await this.resolveForCreate(rel);
    try {
      await mkdir2(target.abs);
    } catch (err) {
      if (err.code === "EEXIST") {
        throw new FilesError(409, "exists", "Something with that name is already there.");
      }
      throw new FilesError(500, "mkdir_failed", "Could not create the folder.");
    }
    this.announce({ op: "mkdir", path: target.rel, size: null });
    return { path: target.rel };
  }
  async rename(fromRel, toRel) {
    const from = await this.resolveEntry(fromRel);
    if (!from.rel) throw new FilesError(400, "bad_path", "The workspace root cannot be renamed.");
    if (!await exists(from.abs)) throw new FilesError(404, "not_found", "No such file or folder.");
    const to = await this.resolveForCreate(toRel);
    if (await exists(to.abs)) throw new FilesError(409, "exists", "Something with that name is already there.");
    if (isInside(from.abs, to.abs)) throw new FilesError(400, "bad_path", "A folder cannot be moved into itself.");
    try {
      await rename2(from.abs, to.abs);
    } catch {
      throw new FilesError(500, "rename_failed", "Could not rename that.");
    }
    this.announce({ op: "rename", path: `${from.rel} \u2192 ${to.rel}`, size: null });
    return { from: from.rel, to: to.rel };
  }
  async delete(rel, recursive) {
    const { rel: relPath, abs } = await this.resolveEntry(rel);
    if (!relPath) throw new FilesError(400, "bad_path", "The workspace root cannot be deleted.");
    const st2 = await lstat2(abs).catch(() => null);
    if (!st2) throw new FilesError(404, "not_found", "No such file or folder.");
    if (st2.isSymbolicLink() || !st2.isDirectory()) {
      await unlink(abs).catch(() => {
        throw new FilesError(500, "delete_failed", "Could not delete that.");
      });
      this.announce({ op: "delete", path: relPath, size: st2.isSymbolicLink() ? null : st2.size });
      return { path: relPath, entries: 1 };
    }
    const names = await readdir(abs);
    if (names.length > 0 && !recursive) {
      throw new FilesError(409, "not_empty", "That folder is not empty. Delete it with its contents to remove it.");
    }
    const entries = await countEntries(abs, this.limits.recursiveDeleteMaxEntries);
    if (entries === null) {
      throw new FilesError(
        413,
        "too_many_entries",
        `That folder holds more than ${this.limits.recursiveDeleteMaxEntries.toLocaleString("en-US")} items. Delete it from the agent's terminal instead.`
      );
    }
    await rm2(abs, { recursive: true, force: true });
    this.announce({ op: "delete", path: relPath, size: null });
    return { path: relPath, entries };
  }
  /**
   * Stream the request body into a temp file NEXT TO the target and rename it into place, so a
   * connection that dies halfway leaves the old file untouched rather than a half-written one.
   * The rename is atomic because both live in the same directory, i.e. the same filesystem.
   */
  async upload(req, rel, overwrite) {
    const target = await this.resolveForCreate(rel);
    if (!overwrite && await exists(target.abs)) {
      throw new FilesError(409, "exists", "A file with that name is already there.");
    }
    const spooled = await this.spool(req, target.parent, this.limits.uploadMaxBytes, "upload");
    if (!overwrite && await exists(target.abs)) {
      await unlink(spooled.tmp).catch(() => {
      });
      throw new FilesError(409, "exists", "A file with that name is already there.");
    }
    await commit(spooled.tmp, target.abs, "upload_failed");
    this.announce({ op: "upload", path: target.rel, size: spooled.written });
    return { path: target.rel, size: spooled.written };
  }
  /**
   * An edit made in the console, written back. The same temp-file-and-rename as an upload, with
   * two differences.
   *
   * The cap is the text preview's, because what the editor holds is the preview: saving a file
   * bigger than that would write back the first megabyte and silently drop the rest.
   *
   * And the write is optimistic: `expectMtime` is the file's date as the editor loaded it. The
   * agent writes to this tree too, so a file can change while someone is typing into it, and
   * overwriting that blindly would lose the agent's work with nothing to say so. Mismatched, the
   * write is refused and the console offers Reload or Overwrite; `expectMtime` null is that
   * Overwrite. `create` is New file: nothing may be there at all.
   */
  async write(req, rel, opts) {
    const target = await this.resolveForCreate(rel);
    if (opts.create && await exists(target.abs)) {
      throw new FilesError(409, "exists", "Something with that name is already there.");
    }
    if (!opts.create) await this.assertWritableFile(target.abs, opts.expectMtime);
    const spooled = await this.spool(req, target.parent, this.limits.textPreviewBytes, "write");
    try {
      if (opts.create && await exists(target.abs)) {
        throw new FilesError(409, "exists", "Something with that name is already there.");
      }
      if (!opts.create) await this.assertWritableFile(target.abs, opts.expectMtime);
    } catch (err) {
      await unlink(spooled.tmp).catch(() => {
      });
      throw err;
    }
    const previous = await stat2(target.abs).catch(() => null);
    await chmod2(spooled.tmp, previous ? previous.mode & 511 : 420).catch(() => {
    });
    await commit(spooled.tmp, target.abs, "write_failed");
    const st2 = await stat2(target.abs).catch(() => null);
    this.announce({ op: "write", path: target.rel, size: spooled.written });
    return { path: target.rel, size: spooled.written, mtime: (st2?.mtime ?? /* @__PURE__ */ new Date()).toISOString() };
  }
  /**
   * What must be true of the thing on disk before an edit is renamed over it.
   *
   * `lstat`, not `stat`: renaming over a symlink replaces the LINK, so saving an edit to one
   * would quietly turn it into a plain file and break whatever it pointed at. A folder is a 400
   * rather than the EISDIR the rename would otherwise raise.
   *
   * Then the optimistic check. A null `expect` is the console saying "overwrite whatever is
   * there", which is what the conflict dialog's second button sends.
   */
  async assertWritableFile(abs, expect) {
    const st2 = await lstat2(abs).catch(() => null);
    if (st2 && !st2.isFile()) {
      throw new FilesError(400, "not_a_file", "Only a plain file can be edited here.");
    }
    if (expect === null) return;
    if (!st2) throw new FilesError(404, "not_found", "That file is no longer on the box.");
    if (st2.mtime.toISOString() !== expect) {
      throw new FilesError(409, "changed", "The agent changed this file while you were editing it.");
    }
  }
  /**
   * The request body, on disk in a temp file next to where it is going, capped at `max`. Nothing
   * is renamed into place here: the caller re-checks its own preconditions first, because the
   * body took time to arrive and the tree may have moved under it.
   */
  async spool(req, parent, max, op) {
    const declared = Number(req.headers["content-length"] ?? "");
    if (Number.isFinite(declared) && declared > max) throw tooLargeError(op, max);
    const tmp = join8(parent, `.cc-${op}-${randomUUID2()}.part`);
    let written = 0;
    let tooBig = false;
    const meter = new Transform({
      transform(chunk, _enc, done) {
        written += chunk.length;
        if (written > max) {
          tooBig = true;
          done(new Error("body too large"));
          return;
        }
        done(null, chunk);
      }
    });
    const handle = await open(tmp, "wx", 384);
    const sink = handle.createWriteStream({ autoClose: false });
    try {
      await pipeline2(req, meter, sink);
      await handle.sync();
    } catch (err) {
      sink.destroy();
      await handle.close().catch(() => {
      });
      await unlink(tmp).catch(() => {
      });
      if (tooBig) throw tooLargeError(op, max);
      console.error(`[files] ${op} failed:`, err.message);
      throw op === "write" ? new FilesError(400, "write_failed", "The edit did not reach the box.") : new FilesError(400, "upload_failed", "The upload did not finish.");
    }
    sink.destroy();
    await handle.close().catch(() => {
    });
    return { tmp, written };
  }
  announce(write) {
    try {
      this.opts.onWrite?.(write);
    } catch (err) {
      console.error("[files] activity report failed:", err.message);
    }
  }
};
async function commit(tmp, abs, code) {
  try {
    await rename2(tmp, abs);
  } catch {
    await unlink(tmp).catch(() => {
    });
    throw new FilesError(500, code, "Could not save the file.");
  }
}
function tooLargeError(op, max) {
  return op === "write" ? new FilesError(413, "too_large", `The editor saves files up to ${humanBytes(max)}. Download this one, change it, and upload it back.`) : new FilesError(413, "too_large", `Files are limited to ${humanBytes(max)}.`);
}
async function exists(path) {
  return lstat2(path).then(
    () => true,
    () => false
  );
}
async function countEntries(dir, max) {
  let count = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    let names;
    try {
      names = await readdir(current);
    } catch {
      continue;
    }
    for (const name of names) {
      count++;
      if (count > max) return null;
      const child = join8(current, name);
      const st2 = await lstat2(child).catch(() => null);
      if (st2?.isDirectory()) stack.push(child);
    }
  }
  return count;
}
async function describe(root, abs, name) {
  const link = await lstat2(abs).catch(() => null);
  if (!link) return null;
  if (!link.isSymbolicLink()) {
    return {
      name,
      kind: link.isDirectory() ? "dir" : link.isFile() ? "file" : "other",
      size: link.size,
      mtime: link.mtime.toISOString(),
      mode: modeOf(link.mode)
    };
  }
  const real = await realpath(abs).catch(() => null);
  const inside = real !== null && isInside(root, real);
  const target = inside ? await stat2(abs).catch(() => null) : null;
  return {
    name,
    kind: target?.isDirectory() ? "dir" : target?.isFile() ? "file" : "other",
    size: target?.size ?? 0,
    mtime: (target ?? link).mtime.toISOString(),
    mode: modeOf(link.mode),
    symlink: true,
    ...inside ? {} : { blocked: true }
  };
}
function modeOf(mode) {
  return (mode & 511).toString(8).padStart(4, "0");
}
function contentDisposition(name) {
  const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}
function corsHeaders(req, origins2) {
  const origin = req.headers.origin;
  if (!origin || !origins2.includes(origin)) return { Vary: "Origin" };
  return {
    Vary: "Origin",
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true"
  };
}
function originAllowed2(req, origins2) {
  const verdict = checkOrigin(nodeRequestFacts(req), { allowed: origins2, allowTopLevelNavigation: true });
  if (verdict.ok) return true;
  console.warn(`[files] ${denialMessage(verdict)}`);
  return false;
}
function devCorsHeaders(req) {
  const origin = req.headers.origin;
  return { Vary: "Origin", ...origin ? { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true" } : {} };
}
var JSON_OPS = /* @__PURE__ */ new Set(["/files/mkdir", "/files/rename", "/files/delete"]);
var WRITE_OPS = /* @__PURE__ */ new Set(["/files/upload", "/files/write", "/files/mkdir", "/files/rename", "/files/delete"]);
async function handleFiles(req, res, url2, service) {
  if (!service) {
    sendJson(res, 503, { error: "The file explorer is not ready yet.", code: "unavailable" });
    return;
  }
  const origins2 = service.origins;
  const cors = service.openToAnyone ? devCorsHeaders(req) : corsHeaders(req, origins2);
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      ...cors,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "600"
    });
    res.end();
    return;
  }
  if (!service.openToAnyone && !originAllowed2(req, origins2)) {
    sendJson(res, 403, { error: "This request did not come from your console.", code: "bad_origin" }, cors);
    return;
  }
  const session = service.openToAnyone ? { canWrite: service.openToAnyoneCanWrite } : service.vmId ? await readSession(req.headers.cookie, service.vmId) : null;
  if (!session) {
    sendJson(res, 401, { error: "This browser is not signed in to the agent.", code: "unpaired" }, cors);
    return;
  }
  try {
    await dispatch(req, res, url2, service, cors, session);
  } catch (err) {
    if (res.headersSent || res.writableEnded) {
      res.destroy();
      return;
    }
    if (err instanceof FilesError) {
      sendJson(res, err.status, { error: err.message, code: err.code }, cors);
      return;
    }
    console.error("[files]", err.message);
    sendJson(res, 500, { error: "The file explorer could not read that.", code: "internal" }, cors);
  }
}
async function streamFile(path, res) {
  try {
    await pipeline2(createReadStream2(path), res);
  } catch (err) {
    const code = err.code;
    if (code === "ERR_STREAM_PREMATURE_CLOSE" || code === "ECONNRESET" || code === "EPIPE") return;
    throw err;
  }
}
async function dispatch(req, res, url2, service, cors, session) {
  const path = url2.pathname;
  const q2 = url2.searchParams.get("path");
  if (WRITE_OPS.has(path) && !session.canWrite) {
    sendJson(
      res,
      403,
      { error: "Your pass for this agent can read its files but not change them.", code: "read_only" },
      cors
    );
    return;
  }
  if (path === "/files/list" && req.method === "GET") {
    sendJson(res, 200, await service.list(q2 ?? ""), cors);
    return;
  }
  if (path === "/files/read" && req.method === "GET") {
    const file = await service.fileFor(q2 ?? "");
    const meta = { path: file.rel, name: basename2(file.abs), mime: file.mime, size: file.size, mtime: file.mtime };
    if (isPreviewableImage(file.mime)) {
      if (file.size > service.limits.imagePreviewBytes) {
        sendJson(res, 200, { ...meta, kind: "binary", reason: "too_large" }, cors);
        return;
      }
      res.writeHead(200, {
        ...cors,
        "Content-Type": file.mime,
        "Content-Length": String(file.size),
        // The body is bytes, so the file's own date has to ride a header. Exposed explicitly:
        // Last-Modified is not CORS-safelisted, and the console reads it cross-origin.
        "Last-Modified": new Date(file.mtime).toUTCString(),
        "Access-Control-Expose-Headers": "Last-Modified",
        "Cache-Control": "no-store",
        // The bytes are a customer's file: never let a browser sniff one into a script.
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox"
      });
      await streamFile(file.abs, res);
      return;
    }
    if (!isTextual(file.mime)) {
      sendJson(res, 200, { ...meta, kind: "binary" }, cors);
      return;
    }
    const slice = await readHead(file.abs, Math.min(file.size, service.limits.textPreviewBytes));
    sendJson(res, 200, { ...meta, kind: "text", truncated: file.size > service.limits.textPreviewBytes, content: slice }, cors);
    return;
  }
  if (path === "/files/download" && req.method === "GET") {
    const file = await service.fileFor(q2 ?? "");
    const name = basename2(file.abs);
    res.writeHead(200, {
      ...cors,
      "Content-Type": "application/octet-stream",
      "Content-Length": String(file.size),
      "Content-Disposition": contentDisposition(name),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    });
    await streamFile(file.abs, res);
    return;
  }
  if (path === "/files/upload" && req.method === "POST") {
    const overwrite = url2.searchParams.get("overwrite") === "1";
    sendJson(res, 200, await service.upload(req, q2 ?? "", overwrite), cors);
    return;
  }
  if (path === "/files/write" && req.method === "POST") {
    const expectMtime = url2.searchParams.get("mtime");
    const create = url2.searchParams.get("create") === "1";
    sendJson(res, 200, await service.write(req, q2 ?? "", { expectMtime, create }), cors);
    return;
  }
  if (JSON_OPS.has(path) && req.method === "POST") {
    const body = await readJsonBody(req, 8192);
    if (!body) throw new FilesError(400, "bad_body", "That request was not understood.");
    const str8 = (v2) => typeof v2 === "string" ? v2 : "";
    if (path === "/files/mkdir") {
      sendJson(res, 200, await service.mkdir(str8(body.path)), cors);
      return;
    }
    if (path === "/files/rename") {
      sendJson(res, 200, await service.rename(str8(body.from), str8(body.to)), cors);
      return;
    }
    sendJson(res, 200, await service.delete(str8(body.path), body.recursive === true || body.recursive === 1), cors);
    return;
  }
  sendJson(res, 404, { error: "Not found", code: "not_found" }, cors);
}
async function readHead(path, max) {
  if (max <= 0) return "";
  const handle = await open(path, "r");
  try {
    const buf = Buffer.alloc(max);
    const { bytesRead } = await handle.read(buf, 0, max, 0);
    return buf.subarray(0, bytesRead).toString("utf-8");
  } finally {
    await handle.close();
  }
}

// src/ssh.ts
import { createHash as createHash2 } from "crypto";
import { mkdirSync as mkdirSync9, mkdtempSync, readFileSync as readFileSync17, rmSync as rmSync2, writeFileSync as writeFileSync11 } from "fs";
import { tmpdir as tmpdir2 } from "os";
import { dirname as dirname11, join as join9 } from "path";
var MIN_SECONDS = 5 * 60;
var MAX_SECONDS = 72 * 60 * 60;
var KEYGEN_TIMEOUT_MS = 2e4;
var SUDO_TIMEOUT_MS = 3e4;
var SUPPORT_USER = "ccsupport";
function fingerprintOf(publicKey) {
  const blob = publicKey.trim().split(/\s+/)[1] ?? "";
  const digest = createHash2("sha256").update(Buffer.from(blob, "base64")).digest("base64");
  return `SHA256:${digest.replace(/=+$/, "")}`;
}
var MARK = "controlclaw-rescue";
function markerFor(grantId) {
  return `${MARK}-${grantId}`;
}
var OPEN_OK = "key=installed";
var SshAccessService = class {
  constructor(opts) {
    this.opts = opts;
    this.user = opts.user ?? SUPPORT_USER;
    this.exec = opts.exec ?? defaultExec;
    this.log = opts.log ?? ((line) => console.log(line));
    this.now = opts.now ?? Date.now;
  }
  user;
  exec;
  log;
  now;
  status() {
    const state = this.readState();
    if (!state) return { open: false, user: this.user, grantId: null, fingerprint: null, endsAt: null };
    const open2 = Date.parse(state.endsAt) > this.now();
    return { open: open2, user: this.user, grantId: state.grantId, fingerprint: state.fingerprint, endsAt: state.endsAt };
  }
  /**
   * Mint a key, install its public half, open the port and arm the timer. The private half is in
   * the reply and nowhere else.
   *
   * **Not idempotent, and it cannot be.** A second `open` for the same grant mints a second key
   * and replaces the first, which silently invalidates the key the control plane already sealed.
   * There is nothing better available: this box keeps no private key, so a repeat cannot be
   * answered from the state file either. What stops it is upstream — `ConsentCodes.verify` drops
   * the proposal on the first success, so the firewall has nothing left to send a second time.
   */
  async open(input) {
    const seconds = Math.round(input.seconds);
    if (!Number.isFinite(seconds) || seconds < MIN_SECONDS || seconds > MAX_SECONDS) {
      throw new Error(`a shell access window must be between ${MIN_SECONDS} and ${MAX_SECONDS} seconds`);
    }
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(input.grantId)) throw new Error("malformed grant id");
    const { publicKey, privateKey } = await this.mint(input.grantId);
    const endsAt = new Date(this.now() + seconds * 1e3).toISOString();
    const opened = await this.exec("sudo", ["/usr/local/bin/cc-ssh-open", String(seconds)], SUDO_TIMEOUT_MS, `${publicKey}
`);
    if (!opened.stdout.includes(OPEN_OK)) {
      await this.exec("sudo", ["/usr/local/bin/cc-ssh-close"], SUDO_TIMEOUT_MS).catch(() => void 0);
      throw new Error("this box is running a cc-ssh-open that predates root support access; re-provision it and try again");
    }
    const fingerprint2 = fingerprintOf(publicKey);
    this.writeState({ grantId: input.grantId, fingerprint: fingerprint2, endsAt, openedAt: new Date(this.now()).toISOString() });
    this.log(`[ssh] opened for ${this.user} until ${endsAt} (${fingerprint2})`);
    return { user: this.user, fingerprint: fingerprint2, publicKey, privateKey, endsAt, sudo: true };
  }
  /**
   * Take root away, take the key out and shut the port. Safe to call when nothing is open — the
   * console offers "Close now" whatever the box thinks, and a close that finds nothing should
   * still succeed.
   *
   * **`cc-ssh-close` is now the only thing that can revoke, and this reports honestly when it
   * cannot be run.** Before T-70 this process removed the key itself and the root script was best
   * effort on top; it cannot any more, because the account holding the key is one it deliberately
   * cannot write. What stands behind a failure here is the box's own `cc-ssh-close.timer`, the
   * `cc-ssh-close-at-boot` unit, and the control plane shutting port 22 at the provider — which
   * it does whatever this answers, so a close that throws still ends the session from outside.
   */
  async close() {
    const was = this.readState();
    await this.exec("sudo", ["/usr/local/bin/cc-ssh-close"], SUDO_TIMEOUT_MS);
    rmSync2(this.opts.statePath, { force: true });
    if (was) this.log(`[ssh] closed for ${this.user} (was ${was.fingerprint})`);
    return { user: this.user, closed: !!was };
  }
  // ---- internals ----
  async mint(grantId) {
    const dir = mkdtempSync(join9(this.opts.workDir ?? tmpdir2(), "cc-ssh-"));
    const path = join9(dir, "key");
    try {
      await this.exec(
        "ssh-keygen",
        ["-q", "-t", "ed25519", "-N", "", "-C", markerFor(grantId), "-f", path],
        KEYGEN_TIMEOUT_MS
      );
      return {
        publicKey: readFileSync17(`${path}.pub`, "utf8").trim(),
        privateKey: readFileSync17(path, "utf8")
      };
    } finally {
      rmSync2(dir, { recursive: true, force: true });
    }
  }
  readState() {
    try {
      const parsed = JSON.parse(readFileSync17(this.opts.statePath, "utf8"));
      if (typeof parsed.grantId !== "string" || typeof parsed.endsAt !== "string") return null;
      return {
        grantId: parsed.grantId,
        fingerprint: typeof parsed.fingerprint === "string" ? parsed.fingerprint : "",
        endsAt: parsed.endsAt,
        openedAt: typeof parsed.openedAt === "string" ? parsed.openedAt : parsed.endsAt
      };
    } catch {
      return null;
    }
  }
  writeState(state) {
    mkdirSync9(dirname11(this.opts.statePath), { recursive: true });
    writeFileSync11(this.opts.statePath, JSON.stringify(state), { mode: 384 });
  }
};

// src/routes/ssh.ts
async function handleSsh(req, res, pathname, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "ssh") : await verifyMitmRequest(req, "ssh") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "shell access must come from the org firewall" : "Unauthorized" });
    return;
  }
  if (!service) {
    sendJson(res, 503, { ok: false, error: "This box cannot open a shell session" });
    return;
  }
  try {
    if (pathname === "/ssh/status" && req.method === "GET") {
      sendJson(res, 200, { ok: true, ...service.status() });
      return;
    }
    if (pathname === "/ssh/open" && req.method === "POST") {
      const body = await readJsonBody(req);
      if (!body || typeof body.grantId !== "string" || typeof body.seconds !== "number") {
        sendJson(res, 400, { ok: false, error: "grantId and seconds required" });
        return;
      }
      sendJson(res, 200, { ok: true, ...await service.open({ grantId: body.grantId, seconds: body.seconds }) });
      return;
    }
    if (pathname === "/ssh/close" && req.method === "POST") {
      sendJson(res, 200, { ok: true, ...await service.close() });
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) });
  }
}

// src/ssh-logins.ts
import { createHash as createHash3 } from "crypto";
import { execFile as execFile4 } from "child_process";
var POLL_TIMEOUT_MS = 15e3;
var MAX_PER_TICK = 50;
var MAX_BUFFERED = 500;
function parseSshdLine(line) {
  const m2 = /Accepted publickey for (\S+) from (\S+) port \d+ ssh2:\s+\S+\s+(SHA256:\S+)/.exec(line);
  if (!m2) return null;
  const stamp2 = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?)/.exec(line);
  const at2 = stamp2 ? Date.parse(stamp2[1].replace(/([+-]\d{2})(\d{2})$/, "$1:$2")) : NaN;
  return { user: m2[1], fromIp: m2[2], fingerprint: m2[3], at: Number.isFinite(at2) ? at2 : null };
}
function journal(cursorPath) {
  return new Promise((resolve2) => {
    execFile4(
      "journalctl",
      ["-u", "ssh", "-u", "sshd", "--no-pager", "-q", "-o", "short-iso", `--cursor-file=${cursorPath}`],
      { timeout: POLL_TIMEOUT_MS, maxBuffer: 2 * 1024 * 1024 },
      (err, stdout) => {
        if (err && !stdout) return resolve2([]);
        resolve2(String(stdout ?? "").split("\n").filter(Boolean));
      }
    );
  });
}
var SshLoginWatcher = class {
  constructor(opts) {
    this.opts = opts;
    this.readJournal = opts.readJournal ?? (() => journal(opts.cursorPath));
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.log = opts.log ?? ((line) => console.log(line));
    this.now = opts.now ?? Date.now;
  }
  readJournal;
  fetchImpl;
  log;
  now;
  /**
   * Records read but not yet accepted. `journalctl --cursor-file` moves the cursor when it READS,
   * so a failed POST would otherwise lose those logins for good — a hole in the one audit trail
   * this feature exists to produce.
   */
  pending = [];
  /** One pass. Returns how many sessions it reported, for the tests. */
  async tick() {
    const lines = await this.readJournal();
    const tickTs = Math.round(this.now() / 1e3);
    for (const line of lines) {
      const parsed = parseSshdLine(line);
      if (!parsed) continue;
      this.pending.push({
        source: "ssh_login",
        // The line itself is the identity of the session: same second, same port, same key means
        // the same login. The journal cursor already stops the common repeat; this stops the rest.
        login_id: createHash3("sha256").update(line).digest("hex").slice(0, 32),
        // The journal's own stamp, so a backlog shipped after a restart does not land as "now"
        // and sort wrongly against the grant it belongs to.
        ts: parsed.at !== null ? Math.round(parsed.at / 1e3) : tickTs,
        user: parsed.user,
        fingerprint: parsed.fingerprint,
        from_ip: parsed.fromIp
      });
    }
    if (this.pending.length > MAX_BUFFERED) this.pending = this.pending.slice(-MAX_BUFFERED);
    if (this.pending.length === 0) return 0;
    const records = this.pending.slice(0, MAX_PER_TICK);
    const res = await this.fetchImpl(this.opts.activityUrl, {
      method: "POST",
      headers: { Authorization: `Bearer ${await this.opts.getToken()}`, "content-type": "application/json" },
      body: JSON.stringify({ records })
    });
    if (!res.ok) {
      this.log(`[ssh] could not report ${records.length} login(s): HTTP ${res.status}; keeping them for the next pass`);
      return 0;
    }
    this.pending = this.pending.slice(records.length);
    this.log(`[ssh] reported ${records.length} login(s)`);
    return records.length;
  }
};

// src/tailscale.ts
var UP_TIMEOUT_MS = 12e4;
var CLI_TIMEOUT_MS4 = TAILSCALE_STATUS_MS;
var JOIN_SETTLE_TRIES = 10;
var JOIN_SETTLE_DELAY_MS = 1500;
var sleep5 = (ms) => new Promise((r2) => setTimeout(r2, ms));
var TAILSCALE_UNSUPPORTED_MESSAGE = "This agent was built before Tailscale support. Update the agent (or rebuild it) to use Tailscale.";
var TailscaleUnsupportedError = class extends Error {
  unsupported = true;
  constructor() {
    super(TAILSCALE_UNSUPPORTED_MESSAGE);
    this.name = "TailscaleUnsupportedError";
  }
};
function isTailscaleUnsupported(err) {
  return err instanceof Error && err.unsupported === true;
}
var UNSUPPORTED_RE = /a password is required|a terminal is required|command not found|\/tailscale: not found|tailscale: No such file/i;
function looksUnsupported(err) {
  const e = err;
  if (e.code === "ENOENT") return true;
  return UNSUPPORTED_RE.test(`${e.stderr ?? ""}
${e.stdout ?? ""}
${e.message ?? ""}`);
}
var HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
function str6(v2) {
  return typeof v2 === "string" && v2.length > 0 ? v2 : null;
}
function trimDot(name) {
  return name ? name.replace(/\.$/, "") : null;
}
function health(v2) {
  return Array.isArray(v2) ? v2.map(str6).find((l2) => !!l2) ?? null : str6(v2);
}
function pickIp(ips) {
  if (!Array.isArray(ips)) return null;
  const v4 = ips.find((i2) => typeof i2 === "string" && /^\d+\.\d+\.\d+\.\d+$/.test(i2));
  return typeof v4 === "string" ? v4 : str6(ips[0]) ?? null;
}
var TailscaleService = class {
  constructor(opts = {}) {
    this.opts = opts;
    this.exec = opts.execImpl ?? defaultExec;
    this.log = opts.log ?? ((line) => console.log(line));
  }
  exec;
  log;
  helper() {
    return this.opts.helper ?? "/usr/local/bin/cc-tailscale";
  }
  /** Join the tailnet. Resolves with what the box became; the key is gone when this returns. */
  async apply(input) {
    if (!HOSTNAME_RE.test(input.hostname)) throw new Error("that hostname is not one a tailnet will accept");
    try {
      await this.exec("sudo", ["-n", this.helper(), "up", input.hostname, input.ssh ? "ssh1" : "ssh0"], UP_TIMEOUT_MS, `${input.authKey}
`);
    } catch (err) {
      if (looksUnsupported(err)) throw new TailscaleUnsupportedError();
      throw new Error(`Tailscale could not join the network: ${execFailureLine(err)}`);
    }
    let status = await this.status();
    for (let i2 = 1; i2 < JOIN_SETTLE_TRIES && status.state !== "joined" && status.state !== "off"; i2++) {
      await sleep5(JOIN_SETTLE_DELAY_MS);
      status = await this.status();
    }
    if (status.state !== "joined") {
      throw new Error(status.message ?? "Tailscale accepted the key but the box has no address on the tailnet yet.");
    }
    this.log(`[tailscale] joined as ${status.name ?? status.ip ?? "an unnamed node"} (ssh ${input.ssh ? "on" : "off"})`);
    return { ok: true, ssh: input.ssh, node: { name: status.name, ip: status.ip } };
  }
  /** Leave the tailnet. Needs no key, which is why the console can offer it unconditionally. */
  async logout() {
    try {
      await this.exec("sudo", ["-n", this.helper(), "logout"], CLI_TIMEOUT_MS4);
    } catch (err) {
      if (looksUnsupported(err)) throw new TailscaleUnsupportedError();
      throw new Error(`Tailscale could not leave the network: ${execFailureLine(err)}`);
    }
    this.log("[tailscale] left the tailnet");
    return { ok: true };
  }
  /**
   * What the box is on the tailnet right now. Never throws: a box without Tailscale installed, or
   * with the daemon down, answers `unavailable` so the console can say so rather than showing an
   * error where a status belongs.
   */
  async status() {
    let raw;
    try {
      raw = (await this.exec("sudo", ["-n", this.helper(), "status"], CLI_TIMEOUT_MS4)).stdout;
    } catch (err) {
      const message = looksUnsupported(err) ? TAILSCALE_UNSUPPORTED_MESSAGE : execFailureLine(err);
      return { state: "unavailable", name: null, ip: null, ssh: false, backendState: null, message };
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { state: "unavailable", name: null, ip: null, ssh: false, backendState: null, message: "Tailscale did not report a status this box could read." };
    }
    const self2 = parsed.Self ?? {};
    const backendState = str6(parsed.BackendState);
    const name = trimDot(str6(self2.DNSName)) ?? str6(self2.HostName);
    const ip = pickIp(self2.TailscaleIPs);
    const ssh2 = Array.isArray(self2.sshHostKeys) && self2.sshHostKeys.length > 0;
    if (backendState === "Running" && ip) return { state: "joined", name, ip, ssh: ssh2, backendState, message: null };
    if (backendState === "Starting" || backendState === "NoState") {
      return { state: "starting", name, ip, ssh: ssh2, backendState, message: "Tailscale is still starting on this box." };
    }
    return {
      state: "off",
      name: null,
      ip: null,
      ssh: false,
      backendState,
      // `Stopped` is what the helper reports while tailscaled is installed but not running, which
      // is how every box sits until its owner joins it (tailscale-linux.yml in the Ansible role).
      message: backendState === "NeedsLogin" || backendState === "Stopped" ? "This box is not signed in to a tailnet." : health(parsed.Health)
    };
  }
};

// src/routes/tailscale.ts
var AUTH_KEY_RE = /^tskey-auth-[A-Za-z0-9]+-[A-Za-z0-9]+$/;
function parseApply6(body) {
  if (typeof body.authKey !== "string" || !AUTH_KEY_RE.test(body.authKey)) return "authKey must be a Tailscale auth key";
  if (typeof body.hostname !== "string" || !body.hostname) return "hostname required";
  return { authKey: body.authKey, ssh: body.ssh === true, hostname: body.hostname };
}
async function handleTailscale(req, res, url2, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "tailscale") : await verifyMitmRequest(req, "tailscale") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "network changes must come from the org firewall" : "Unauthorized" });
    return;
  }
  try {
    if (url2.pathname === "/tailscale/status" && req.method === "GET") {
      sendJson(res, 200, await service.status());
      return;
    }
    if (!write) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    if (url2.pathname === "/tailscale/logout") {
      sendJson(res, 200, await service.logout());
      return;
    }
    if (url2.pathname === "/tailscale/apply") {
      const body = await readJsonBody(req);
      if (!body) {
        sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
        return;
      }
      const input = parseApply6(body);
      if (typeof input === "string") {
        sendJson(res, 400, { ok: false, error: input });
        return;
      }
      sendJson(res, 200, await service.apply(input));
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    if (isTailscaleUnsupported(err)) {
      sendJson(res, 409, { ok: false, code: "tailscale_unsupported", error: err.message });
      return;
    }
    sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) });
  }
}

// src/devices.ts
var LIST_CACHE_MS = 4e3;
var LIST_ERROR_CACHE_MS = 2e3;
var CLI_ATTEMPTS = 3;
var CLI_RETRY_MS = [400, 1200];
var LIST_KEY = "devices";
function wait(ms) {
  return new Promise((r2) => setTimeout(r2, ms));
}
function str7(v2) {
  return typeof v2 === "string" && v2.length > 0 ? v2 : null;
}
function num(v2) {
  return typeof v2 === "number" && Number.isFinite(v2) ? v2 : null;
}
function strings(v2) {
  return Array.isArray(v2) ? v2.filter((s2) => typeof s2 === "string") : [];
}
function looksBusy3(message) {
  return /\b(EBUSY|EAGAIN|ECONNREFUSED|SQLITE_BUSY)\b|database is locked|gateway (is )?(not (running|connected)|unavailable|starting|restarting)|connection refused|socket hang up|disconnected/i.test(
    message
  );
}
function toPending(r2) {
  const requestId = str7(r2.requestId);
  const deviceId = str7(r2.deviceId);
  if (!requestId || !deviceId) return null;
  return {
    requestId,
    deviceId,
    displayName: str7(r2.displayName),
    platform: str7(r2.platform),
    deviceFamily: str7(r2.deviceFamily),
    clientId: str7(r2.clientId),
    clientMode: str7(r2.clientMode),
    role: str7(r2.role),
    scopes: strings(r2.scopes),
    remoteIp: str7(r2.remoteIp),
    at: num(r2.ts) ?? num(r2.refreshedAtMs)
  };
}
function toPaired(r2) {
  const deviceId = str7(r2.deviceId);
  if (!deviceId) return null;
  return {
    deviceId,
    displayName: str7(r2.displayName),
    label: str7(r2.operatorLabel),
    platform: str7(r2.platform),
    deviceFamily: str7(r2.deviceFamily),
    clientId: str7(r2.clientId),
    clientMode: str7(r2.clientMode),
    role: str7(r2.role),
    scopes: strings(r2.scopes),
    approvedVia: str7(r2.approvedVia),
    browserOrigin: str7(r2.browserOrigin),
    connected: r2.connected === true,
    approvedAt: num(r2.approvedAtMs) ?? num(r2.createdAtMs),
    lastSeenAt: num(r2.lastSeenAtMs)
  };
}
function parseList(payload) {
  const p2 = payload ?? {};
  const pending = (Array.isArray(p2.pending) ? p2.pending : []).map((r2) => toPending(r2 ?? {})).filter((d2) => d2 !== null);
  const paired = (Array.isArray(p2.paired) ? p2.paired : []).map((r2) => toPaired(r2 ?? {})).filter((d2) => d2 !== null);
  return { pending, paired };
}
var DevicesService = class {
  constructor(opts = {}) {
    this.opts = opts;
    this.exec = opts.execImpl ?? defaultExec;
    this.log = opts.log ?? ((line) => console.log(line));
    this.now = opts.now ?? Date.now;
    const fresh = opts.listCacheMs ?? LIST_CACHE_MS;
    this.listOnce = new Once({ ttlMs: fresh, errorTtlMs: Math.min(LIST_ERROR_CACHE_MS, fresh), now: this.now });
  }
  exec;
  log;
  now;
  listOnce;
  get client() {
    return this.opts.client?.() ?? null;
  }
  /** Pending and paired devices, single-flighted and reused for a few seconds. */
  async list() {
    return this.listOnce.get(LIST_KEY, () => this.readList());
  }
  async approve(requestId) {
    const r2 = await this.callBoth("device.pair.approve", { requestId }, ["approve", requestId]);
    this.listOnce.invalidate(LIST_KEY);
    const deviceId = str7(r2.deviceId) ?? str7(r2.device?.deviceId);
    this.log(`[devices] approved request ${requestId}${deviceId ? ` as device ${deviceId}` : ""}`);
    return { ok: true, deviceId };
  }
  async reject(requestId) {
    await this.callBoth("device.pair.reject", { requestId }, ["reject", requestId]);
    this.listOnce.invalidate(LIST_KEY);
    this.log(`[devices] rejected request ${requestId}`);
    return { ok: true };
  }
  async remove(deviceId) {
    await this.callBoth("device.pair.remove", { deviceId }, ["remove", deviceId]);
    this.listOnce.invalidate(LIST_KEY);
    this.log(`[devices] removed device ${deviceId}`);
    return { ok: true };
  }
  /**
   * One write, over the socket when it is up and through the CLI when it is not. A write is never
   * retried: `device.pair.approve` is not idempotent (the request is consumed), so a second
   * attempt after an ambiguous failure could approve a device whose first approval actually
   * landed. The caller sees the error and the next listing says what really happened.
   */
  async callBoth(method, params, argv) {
    const client = this.client;
    if (client?.connected) return client.call(method, params, DEVICES_ACTION_MS);
    return this.cli(argv, DEVICES_ACTION_CLI_MS, 1);
  }
  async readList() {
    const deadline = this.now() + DEVICES_LIST_TOTAL_MS;
    const left = () => deadline - this.now();
    const client = this.client;
    let last = "";
    let bridgeFailed = false;
    if (client?.connected) {
      try {
        const payload = await client.call("device.pair.list", {}, Math.min(DEVICES_LIST_MS, left()));
        return { ...parseList(payload), error: null };
      } catch (err) {
        bridgeFailed = true;
        last = err instanceof Error ? err.message : String(err);
        this.log(`[devices] device.pair.list over the bridge failed: ${last}`);
      }
    }
    let tries = 0;
    for (let attempt = 0; attempt < CLI_ATTEMPTS; attempt++) {
      if (attempt > 0) {
        const backoff = CLI_RETRY_MS[attempt - 1] ?? 1e3;
        if (left() <= backoff) break;
        await wait(backoff);
      }
      const budget = Math.min(DEVICES_LIST_CLI_MS, left());
      if (budget <= 0) break;
      tries++;
      try {
        return { ...parseList(await this.cli(["list"], budget, 1)), error: null };
      } catch (err) {
        last = err instanceof Error ? err.message : String(err);
      }
    }
    const busy = bridgeFailed || looksBusy3(last);
    this.log(`[devices] listing failed after ${tries} ${tries === 1 ? "try" : "tries"}: ${last}`);
    return {
      pending: [],
      paired: [],
      error: busy ? { busy: true, message: "The agent is busy right now, so its paired devices could not be read." } : { busy: false, message: `The agent could not list its paired devices: ${last}` }
    };
  }
  /** `openclaw devices <argv> --json`, parsed. `attempts` is 1 for writes; see `callBoth`. */
  async cli(argv, timeoutMs, attempts) {
    const bin = this.opts.openclawBin ?? "/usr/bin/openclaw";
    let last = new Error("command failed");
    for (let i2 = 0; i2 < attempts; i2++) {
      try {
        const { stdout } = await this.exec(bin, ["devices", ...argv, "--json"], timeoutMs);
        const start = stdout.indexOf("{");
        if (start < 0) throw new Error("the openclaw CLI printed no JSON");
        return JSON.parse(stdout.slice(start));
      } catch (err) {
        last = new Error(execFailureLine(err));
      }
    }
    throw last;
  }
};

// src/routes/devices.ts
var ID_RE3 = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
function idOf(body, field) {
  const v2 = body[field];
  return typeof v2 === "string" && ID_RE3.test(v2) ? v2 : null;
}
async function handleDevices(req, res, url2, service) {
  const write = req.method === "POST";
  const auth = write ? await verifyMitmRequest(req, "devices") : await verifyMitmRequest(req, "devices") ?? await verifyRequest(req);
  if (!auth) {
    sendJson(res, 401, { error: write ? "device approvals must come from the org firewall" : "Unauthorized" });
    return;
  }
  try {
    if (url2.pathname === "/devices" && req.method === "GET") {
      sendJson(res, 200, await service.list());
      return;
    }
    if (!write) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    const body = await readJsonBody(req);
    if (!body) {
      sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
      return;
    }
    if (url2.pathname === "/devices/approve" || url2.pathname === "/devices/reject") {
      const requestId = idOf(body, "requestId");
      if (!requestId) {
        sendJson(res, 400, { ok: false, error: "requestId required" });
        return;
      }
      const r2 = url2.pathname.endsWith("approve") ? await service.approve(requestId) : await service.reject(requestId);
      sendJson(res, 200, r2);
      return;
    }
    if (url2.pathname === "/devices/remove") {
      const deviceId = idOf(body, "deviceId");
      if (!deviceId) {
        sendJson(res, 400, { ok: false, error: "deviceId required" });
        return;
      }
      sendJson(res, 200, await service.remove(deviceId));
      return;
    }
    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    sendJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) });
  }
}

// src/routes/hooks.ts
import { request as httpRequest2 } from "http";

// src/gmail-watch.ts
import { execFile as execFile5 } from "child_process";
import { existsSync as existsSync11, mkdirSync as mkdirSync10, readFileSync as readFileSync18, rmSync as rmSync3, writeFileSync as writeFileSync12 } from "fs";
import { dirname as dirname12 } from "path";
import { promisify } from "util";
var run2 = promisify(execFile5);
var UNIT = "cc-gmail-watch.service";
function envSafe(value) {
  return !/[\r\n=]/.test(value);
}
function parseGmailWatch(body) {
  const audience = typeof body.audience === "string" ? body.audience : "";
  if (!/^https:\/\/[^\s]+$/.test(audience)) return "audience must be the registration's https URL";
  const path = typeof body.path === "string" && body.path.startsWith("/") ? body.path : null;
  if (!path) return "path must start with /";
  for (const [field, value] of Object.entries({ audience, path, account: body.account, topic: body.topic, subjectEmail: body.subjectEmail })) {
    if (typeof value === "string" && !envSafe(value)) return `${field} may not contain a newline or an =`;
  }
  const port = Number(body.port);
  if (!Number.isInteger(port) || port < 8700 || port > 8799) return "port must be between 8700 and 8799";
  return {
    audience,
    path,
    port,
    account: typeof body.account === "string" ? body.account : null,
    topic: typeof body.topic === "string" ? body.topic : null,
    subjectEmail: typeof body.subjectEmail === "string" ? body.subjectEmail : null
  };
}
var GmailWatchService = class {
  constructor(opts) {
    this.opts = opts;
    this.exec = opts.exec ?? run2;
    this.log = opts.log ?? ((l2) => console.log(l2));
    this.gogBin = opts.gogBin ?? "/usr/local/bin/gog";
    this.unit = opts.unit ?? UNIT;
  }
  exec;
  log;
  gogBin;
  unit;
  /** Whether this box has `gog` at all. A file check, so a box updated in place picks it up. */
  supported() {
    return existsSync11(this.gogBin);
  }
  /**
   * Write the watcher's configuration and (re)start it.
   *
   * The environment file is the whole interface: the unit is static and ships with the Ansible
   * role, so nothing here writes a systemd unit at runtime.
   */
  async apply(cfg) {
    mkdirSync10(dirname12(this.opts.envPath), { recursive: true });
    const lines = [
      "# Managed by the ControlClaw vm-agent. Do not edit.",
      "# The audience is the firewall's public URL for this webhook, set explicitly: derived from",
      "# forwarded headers it would be one proxy hop from accepting somebody else's token.",
      `CC_GMAIL_AUDIENCE=${cfg.audience}`,
      `CC_GMAIL_PATH=${cfg.path}`,
      `CC_GMAIL_PORT=${cfg.port}`,
      ...cfg.account ? [`CC_GMAIL_ACCOUNT=${cfg.account}`] : [],
      ...cfg.topic ? [`CC_GMAIL_TOPIC=${cfg.topic}`] : [],
      ...cfg.subjectEmail ? [`CC_GMAIL_OIDC_EMAIL=${cfg.subjectEmail}`] : [],
      // Keeps the OpenClaw gateway from starting a second watcher on the same port.
      "OPENCLAW_SKIP_GMAIL_WATCHER=1",
      ""
    ];
    writeFileSync12(this.opts.envPath, lines.join("\n"), { mode: 384 });
    writeFileSync12(this.opts.statePath, JSON.stringify({ ...cfg, at: (/* @__PURE__ */ new Date()).toISOString() }), { mode: 384 });
    await this.systemctl("restart");
    this.log(`[gmail-watch] serving ${cfg.path} on 127.0.0.1:${cfg.port} for ${cfg.audience}`);
    return this.status();
  }
  /** Stop watching and forget the configuration. Used when the registration is revoked. */
  async clear() {
    rmSync3(this.opts.envPath, { force: true });
    rmSync3(this.opts.statePath, { force: true });
    await this.systemctl("stop").catch(() => void 0);
    return this.status();
  }
  async status() {
    let cfg = null;
    try {
      cfg = JSON.parse(readFileSync18(this.opts.statePath, "utf8"));
    } catch {
      cfg = null;
    }
    let running = false;
    try {
      const { stdout } = await this.exec("systemctl", ["is-active", this.unit]);
      running = stdout.trim() === "active";
    } catch {
      running = false;
    }
    let gogVersion = null;
    try {
      const { stdout } = await this.exec(this.gogBin, ["--version"]);
      gogVersion = stdout.trim().slice(0, 64) || null;
    } catch {
      gogVersion = null;
    }
    return {
      configured: cfg !== null,
      running,
      audience: cfg?.audience ?? null,
      port: cfg?.port ?? null,
      gogVersion,
      at: cfg?.at ?? null
    };
  }
  /**
   * Renew the Gmail watch. Google expires one after seven days, so the timer runs this every
   * twelve hours; it is an ordinary Gmail API call and goes out through the proxy with the
   * placeholder like everything else `gog` does.
   */
  async renew() {
    let cfg = null;
    try {
      cfg = JSON.parse(readFileSync18(this.opts.statePath, "utf8"));
    } catch {
      return { ok: false, message: "This box is not watching a mailbox." };
    }
    if (!cfg.account || !cfg.topic) return { ok: false, message: "No account or topic to renew with." };
    try {
      await this.exec(this.gogBin, ["gmail", "watch", "start", "--account", cfg.account, "--label", "INBOX", "--topic", cfg.topic]);
      return { ok: true, message: "Watch renewed." };
    } catch (error) {
      this.log(`[gmail-watch] renew failed: ${error.message}`);
      return { ok: false, message: "The watch could not be renewed." };
    }
  }
  async systemctl(action) {
    await this.exec("sudo", ["systemctl", action, this.unit]);
  }
};

// src/routes/hooks.ts
var HOOK_TARGET_PORT_MIN = 8700;
var HOOK_TARGET_PORT_MAX = 8799;
var HOOK_DELIVER_TIMEOUT_MS = 3e3;
var MAX_ENVELOPE_BYTES = Math.ceil(1024 * 1024 * 4 / 3) + 64 * 1024;
var MAX_REPLY_BYTES = 8 * 1024;
function hookPortAllowed(port) {
  return typeof port === "number" && Number.isInteger(port) && port >= HOOK_TARGET_PORT_MIN && port <= HOOK_TARGET_PORT_MAX;
}
function parse(body) {
  const port = body.port;
  if (!hookPortAllowed(port)) return `port must be between ${HOOK_TARGET_PORT_MIN} and ${HOOK_TARGET_PORT_MAX}`;
  const path = typeof body.path === "string" && body.path.startsWith("/") ? body.path : null;
  if (!path) return "path must start with /";
  const method = typeof body.method === "string" ? body.method.toUpperCase() : "POST";
  if (method !== "POST" && method !== "PUT") return "method must be POST or PUT";
  if (typeof body.bodyB64 !== "string") return "bodyB64 required";
  let decoded;
  try {
    decoded = Buffer.from(body.bodyB64, "base64");
  } catch {
    return "bodyB64 must be base64";
  }
  const headers = {};
  const raw = body.headers ?? {};
  for (const [name, value] of Object.entries(raw)) {
    const lower = name.toLowerCase();
    if (lower === "content-length" || lower === "host" || lower === "connection" || lower === "transfer-encoding") continue;
    if (typeof value === "string") headers[lower] = value;
  }
  return { port, path, method, headers, body: decoded };
}
function replay(d2) {
  return new Promise((resolve2, reject) => {
    const req = httpRequest2(
      {
        host: "127.0.0.1",
        port: d2.port,
        path: d2.path,
        method: d2.method,
        headers: { ...d2.headers, "content-length": String(d2.body.byteLength) },
        timeout: HOOK_DELIVER_TIMEOUT_MS
      },
      (res) => {
        let read = 0;
        res.on("data", (chunk) => {
          read += chunk.length;
          if (read > MAX_REPLY_BYTES) res.destroy();
        });
        res.on("end", () => resolve2({ status: res.statusCode ?? 502 }));
        res.on("close", () => resolve2({ status: res.statusCode ?? 502 }));
      }
    );
    req.on("timeout", () => req.destroy(new Error("the listener did not answer in time")));
    req.on("error", (error) => reject(error));
    req.end(d2.body);
  });
}
async function handleHooks(req, res, url2, gmail = null) {
  const known = url2.pathname === "/hooks/deliver" || url2.pathname === "/hooks/gmail" || url2.pathname === "/hooks/gmail/status";
  if (!known) {
    sendJson(res, 404, { error: "Not found" });
    return;
  }
  const auth = await verifyMitmRequest(req, "hooks");
  if (!auth) {
    sendJson(res, 401, { error: "a webhook delivery must come from the org firewall" });
    return;
  }
  if (url2.pathname === "/hooks/gmail/status") {
    if (!gmail) return sendJson(res, 501, { error: "This agent does not have gog yet." });
    return sendJson(res, 200, await gmail.status());
  }
  if (url2.pathname === "/hooks/gmail") {
    if (!gmail) return sendJson(res, 501, { error: "This agent does not have gog yet, so it cannot watch a mailbox. Update it." });
    if (req.method !== "POST") return sendJson(res, 405, { error: "Use POST." });
    const body2 = await readJsonBody(req);
    if (!body2) return sendJson(res, 400, { error: "Invalid JSON" });
    if (body2.stop === true) return sendJson(res, 200, await gmail.clear());
    if (body2.renew === true) return sendJson(res, 200, await gmail.renew());
    const cfg = parseGmailWatch(body2);
    if (typeof cfg === "string") return sendJson(res, 400, { error: cfg });
    try {
      return sendJson(res, 200, await gmail.apply(cfg));
    } catch (error) {
      console.error(`[gmail-watch] apply failed: ${error.message}`);
      return sendJson(res, 500, { error: "The watcher could not be started on this box." });
    }
  }
  if (req.method !== "POST") {
    sendJson(res, 405, { error: "Use POST." });
    return;
  }
  const body = await readJsonBody(req, MAX_ENVELOPE_BYTES);
  if (!body) {
    sendJson(res, 400, { error: "Invalid JSON" });
    return;
  }
  const parsed = parse(body);
  if (typeof parsed === "string") {
    sendJson(res, 400, { error: parsed });
    return;
  }
  try {
    const { status } = await replay(parsed);
    sendJson(res, 200, { status });
  } catch (error) {
    console.error(`[hooks] delivery to 127.0.0.1:${parsed.port} failed: ${error.message}`);
    sendJson(res, 502, { error: "the listener on this box did not take that delivery" });
  }
}

// src/routes/kill.ts
async function handleKill(req, res, url2) {
  const auth = await verifyMitmRequest(req, "kill");
  if (!auth) {
    sendJson(res, 401, { error: "an emergency stop must come from the org firewall" });
    return;
  }
  if (url2.pathname === "/kill/status" && req.method === "GET") {
    sendJson(res, 200, { ok: true, active: isOpenClawActive() });
    return;
  }
  if (url2.pathname !== "/kill/apply" || req.method !== "POST") {
    sendJson(res, 404, { error: "Not found" });
    return;
  }
  const body = await readJsonBody(req);
  if (!body || typeof body.locked !== "boolean") {
    sendJson(res, 400, { ok: false, error: "locked must be a boolean" });
    return;
  }
  const locked = body.locked;
  const result = runAction(locked ? "stop" : "start");
  const active = isOpenClawActive();
  const answer = {
    // The truth, not the ask: a stop that "succeeded" while the unit is still active is a failure
    // the firewall has to see, because the console is about to tell somebody their agent is off.
    ok: result.ok && active === !locked,
    locked,
    active,
    message: result.ok ? "" : result.error ?? "systemctl failed"
  };
  sendJson(res, answer.ok ? 200 : 500, answer);
}

// src/routes/access-push.ts
function json2(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}
async function handleAccessPush(req, res, pathname) {
  if (req.method !== "POST") return json2(res, 405, { error: "Method not allowed" });
  if (!await verifyMitmRequest(req, "access")) return json2(res, 401, { error: "Unauthorized" });
  const body = await readJsonBody(req, 64 * 1024);
  if (!body) return json2(res, 400, { error: "Invalid JSON body" });
  if (pathname === "/access/config") {
    const origin = typeof body.firewallOrigin === "string" ? body.firewallOrigin.toLowerCase() : "";
    if (!validFirewallOrigin(origin)) return json2(res, 400, { error: "firewallOrigin must be https://<hostname>" });
    setFirewallOrigin(origin);
    console.log(`[access] the firewall for Opens is ${origin}`);
    return json2(res, 200, { ok: true, firewallOrigin: origin });
  }
  if (pathname === "/access/revoke") {
    if (body.all === true) {
      rotateSessionSecret();
      return json2(res, 200, { ok: true, all: true });
    }
    const ids = Array.isArray(body.deviceIds) ? body.deviceIds.filter((x2) => typeof x2 === "string" && x2.length > 0 && x2.length <= 64) : [];
    if (ids.length === 0 || ids.length > 1e3) return json2(res, 400, { error: "deviceIds must be a non-empty list" });
    revokeDevices(ids);
    console.log(`[access] revoked ${ids.length} browser(s); their sessions here end now`);
    return json2(res, 200, { ok: true, revoked: ids.length });
  }
  return json2(res, 404, { error: "Not found" });
}

// src/brain-mcp.ts
var BRAIN_MCP_NAME = "gbrain";
var BRAIN_URL_RE = /^http:\/\/10\.(?:\d{1,3}\.){2}\d{1,3}:3131\/mcp$/;
function parseBrainApply(body) {
  if (!body) return "a JSON body is required";
  if (body.remove === true) return { remove: true };
  if (typeof body.url !== "string" || !BRAIN_URL_RE.test(body.url)) return "url must be the brain's private address (http://10.x.x.x:3131/mcp)";
  return { url: body.url };
}
var BrainMcpService = class {
  constructor(client) {
    this.client = client;
  }
  gateway() {
    const c2 = this.client();
    if (!c2 || !c2.connected) throw new Error("OpenClaw is not running on this box");
    return c2;
  }
  async apply(input) {
    const gw = this.gateway();
    const entry = "remove" in input ? null : { url: input.url, transport: "streamable-http" };
    const snapshot = await gw.call("config.get", {}, GATEWAY_READ_MS);
    const current = snapshot.parsed?.mcp?.servers?.[BRAIN_MCP_NAME];
    if (entry ? current?.url === entry.url : !current) return { ok: true, configured: entry !== null, changed: false };
    const hash = typeof snapshot.hash === "string" && snapshot.hash ? snapshot.hash : void 0;
    await patchConfig(gw, { mcp: { servers: { [BRAIN_MCP_NAME]: entry } } }, { baseHash: hash, timeoutMs: CONFIG_PATCH_RESTART_MS, readTimeoutMs: GATEWAY_READ_MS });
    return { ok: true, configured: entry !== null, changed: true };
  }
};

// src/routes/gbrain.ts
async function handleGbrain(req, res, url2, service) {
  if (url2.pathname !== "/gbrain/apply" || req.method !== "POST") {
    sendJson(res, 404, { error: "Not found" });
    return;
  }
  if (!await verifyMitmRequest(req, "gbrain")) {
    sendJson(res, 401, { error: "brain changes must come from the org firewall" });
    return;
  }
  const input = parseBrainApply(await readJsonBody(req));
  if (typeof input === "string") {
    sendJson(res, 400, { ok: false, error: input });
    return;
  }
  try {
    const r2 = await service.apply(input);
    console.log(`[gbrain] ${r2.configured ? "connected to" : "disconnected from"} the organization's brain`);
    sendJson(res, 200, { ...r2, applied: [] });
  } catch (err) {
    const message = err.message;
    sendJson(res, /not running/i.test(message) ? 503 : 500, { ok: false, error: message });
  }
}

// src/index.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var BIND = process.env.AGENT_BIND ?? "127.0.0.1";
var KEYS_DIR2 = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
var STATE_DIR = process.env.STATE_DIR ?? "/opt/controlclaw/state";
var GATEWAY_PORT = parseInt(process.env.OPENCLAW_GATEWAY_PORT ?? "18789", 10);
var GATEWAY_READY_TIMEOUT_MS2 = parseInt(process.env.GATEWAY_READY_TIMEOUT_MS ?? "120000", 10);
var AUDIT_POLL_MS = parseInt(process.env.AUDIT_POLL_MS ?? "5000", 10);
var CONNECTOR_RELAY_PORT = parseInt(process.env.CONNECTOR_RELAY_PORT ?? "3111", 10);
var APPROVAL_POLL_MS = parseInt(process.env.APPROVAL_POLL_MS ?? "3000", 10);
var SSH_LOGIN_POLL_MS = parseInt(process.env.SSH_LOGIN_POLL_MS ?? "60000", 10);
try {
  const saasPublicKey2 = readFileSync19(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8");
  setSaasPublicKey(saasPublicKey2);
  console.log("Loaded SaaS public key");
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
  process.exit(1);
}
try {
  setOwnVmId(readFileSync19(`${KEYS_DIR2}/vm_id`, "utf-8").trim());
} catch {
  console.warn("No vm_id in KEYS_DIR: tokens are checked by signature only");
}
setMitmPinnedKeyLoader(() => readKeyFile(KEYS_DIR2, "mitm_pinned_pubkey.pem"));
try {
  ensureSessionSecret(KEYS_DIR2);
} catch (err) {
  console.error("Failed to prepare the session secret:", err);
  process.exit(1);
}
console.log(`Loaded ${loadRedactionSecrets(KEYS_DIR2)} secret(s) for log redaction`);
async function bootstrap(client, readSsh) {
  ensureVmKeypair(KEYS_DIR2);
  await registerPublicKey(KEYS_DIR2);
  const caReady = (await ensureMitmCaInstalled(KEYS_DIR2)).trusted;
  if (!caReady) {
    console.error("[bootstrap] mitm CA not installed \u2014 skipping ready report (box stays initializing)");
    return;
  }
  const egressReady = await enableTransparentEgress(KEYS_DIR2);
  if (!egressReady) {
    console.error("[bootstrap] transparent egress not active \u2014 skipping ready report (box stays initializing)");
    return;
  }
  if (client && !await client.whenConnected(GATEWAY_READY_TIMEOUT_MS2)) {
    console.warn("[bootstrap] OpenClaw's gateway is still down \u2014 reporting ready without it");
  }
  await reportReady(readSsh);
}
function startSshLoginWatch() {
  const base = saasBaseUrl(KEYS_DIR2);
  if (!base) {
    console.log("[ssh] no config_api_url in KEYS_DIR: login reporting off");
    return;
  }
  const watcher = new SshLoginWatcher({
    activityUrl: `${base}/api/vm-agent/activity`,
    getToken: makeBoxTokenSigner(KEYS_DIR2),
    cursorPath: `${STATE_DIR}/ssh-logins.cursor`
  });
  setInterval(() => void watcher.tick().catch((err) => console.error(`[ssh] login watch failed: ${err.message}`)), SSH_LOGIN_POLL_MS);
}
function startGatewayBridge() {
  const token = readKeyFile(KEYS_DIR2, "openclaw_gateway_token");
  const base = saasBaseUrl(KEYS_DIR2);
  if (!token || !base) {
    console.log("[gateway] no openclaw_gateway_token / config_api_url in KEYS_DIR: audit + approvals bridge off");
    return null;
  }
  const client = new GatewayClient({ url: `ws://127.0.0.1:${GATEWAY_PORT}`, token });
  const getToken = makeBoxTokenSigner(KEYS_DIR2);
  const audit = new AuditShipper({
    client,
    cursorPath: `${STATE_DIR}/audit.cursor`,
    activityUrl: `${base}/api/vm-agent/activity`,
    getToken
  });
  const approvals = new ApprovalsBridge({ client, permissionUrl: `${base}/api/vm-agent/permission`, getToken });
  approvals.start();
  client.start();
  const oneLine = (tag) => (err) => console.error(`${tag} tick failed: ${err.message}`);
  setInterval(() => void audit.tick().catch(oneLine("[audit]")), AUDIT_POLL_MS);
  setInterval(() => void approvals.tick().catch(oneLine("[approvals]")), APPROVAL_POLL_MS);
  return client;
}
var channels = null;
var llm = null;
var search = null;
var connectors = null;
var drive = null;
var google = null;
var gmailWatch = null;
var gateway = null;
var devices = new DevicesService({ client: () => gateway });
var brainMcp = new BrainMcpService(() => gateway);
var update = new UpdateService({ statePath: `${STATE_DIR}/update.json` });
var ssh = new SshAccessService({ statePath: `${STATE_DIR}/ssh.json` });
var tailscale = new TailscaleService({});
var backup = new BackupService({
  home: `${process.env.HOME ?? "/home/controlclaw"}/.openclaw`,
  spoolDir: process.env.BACKUP_SPOOL_DIR ?? STATE_DIR,
  service: (action) => runAction(action)
});
var fileWriteSequence = 0;
var getBoxToken = makeBoxTokenSigner(KEYS_DIR2);
var files = new FilesService({
  root: process.env.FILES_ROOT ?? process.env.HOME ?? "/home/controlclaw",
  vmId: readKeyFile(KEYS_DIR2, "vm_id"),
  onWrite: (write) => void reportFileWrite(write).catch((err) => console.error("[files]", err.message))
});
async function reportFileWrite(write) {
  const base = saasBaseUrl(KEYS_DIR2);
  if (!base) return;
  const id = randomUUID3();
  const size = write.size === null ? "" : ` (${humanBytes(write.size)})`;
  const res = await fetch(`${base}/api/vm-agent/activity`, {
    method: "POST",
    headers: { Authorization: `Bearer ${await getBoxToken()}`, "content-type": "application/json" },
    body: JSON.stringify({
      records: [
        {
          source: "tool_action",
          event_id: `files-${id}`,
          sequence: ++fileWriteSequence,
          occurred_at: Date.now(),
          status: "succeeded",
          action: write.op,
          tool_name: `files.${write.op} \xB7 ${write.path}${size}`.slice(0, 120),
          tool_call_id: `files:${id}`,
          agent_id: "console"
        }
      ]
    })
  });
  if (!res.ok) console.error(`[files] activity report: HTTP ${res.status}`);
}
var server = createServer2(async (req, res) => {
  const url2 = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  if (url2.pathname.startsWith("/__cc/")) {
    await handleAccess(req, res, url2.pathname);
    return;
  }
  if (url2.pathname.startsWith("/channels/")) {
    await handleChannels(req, res, url2.pathname, channels);
    return;
  }
  if (url2.pathname.startsWith("/llm/")) {
    await handleLlm(req, res, url2, llm);
    return;
  }
  if (url2.pathname.startsWith("/search/")) {
    await handleSearch(req, res, url2, search);
    return;
  }
  if (url2.pathname.startsWith("/connectors/")) {
    await handleConnectors(req, res, url2, connectors);
    return;
  }
  if (url2.pathname.startsWith("/drive/")) {
    await handleDrive(req, res, url2, drive);
    return;
  }
  if (url2.pathname.startsWith("/google/")) {
    await handleGoogle(req, res, url2, google);
    return;
  }
  if (url2.pathname === "/update") {
    await handleUpdate(req, res, url2.pathname, update);
    return;
  }
  if (url2.pathname.startsWith("/backup/")) {
    await handleBackup(req, res, url2, backup);
    return;
  }
  if (url2.pathname.startsWith("/ssh/")) {
    await handleSsh(req, res, url2.pathname, ssh);
    return;
  }
  if (url2.pathname.startsWith("/tailscale/")) {
    await handleTailscale(req, res, url2, tailscale);
    return;
  }
  if (url2.pathname === "/devices" || url2.pathname.startsWith("/devices/")) {
    await handleDevices(req, res, url2, devices);
    return;
  }
  if (url2.pathname.startsWith("/hooks/")) {
    await handleHooks(req, res, url2, gmailWatch);
    return;
  }
  if (url2.pathname.startsWith("/kill/")) {
    await handleKill(req, res, url2);
    return;
  }
  if (url2.pathname.startsWith("/gbrain/")) {
    await handleGbrain(req, res, url2, brainMcp);
    return;
  }
  if (url2.pathname.startsWith("/access/")) {
    await handleAccessPush(req, res, url2.pathname);
    return;
  }
  if (url2.pathname.startsWith("/files/")) {
    await handleFiles(req, res, url2, files);
    return;
  }
  if (!await requireAuth(req, res)) return;
  if (url2.pathname === "/health" && req.method === "GET") {
    handleHealth(res);
    return;
  }
  if (url2.pathname === "/start" && req.method === "POST") {
    handleStart(res);
    return;
  }
  if (url2.pathname === "/stop" && req.method === "POST") {
    handleStop(res);
    return;
  }
  if (url2.pathname === "/restart" && req.method === "POST") {
    handleRestart(res);
    return;
  }
  if (url2.pathname === "/status" && req.method === "GET") {
    handleStatus(res, drive?.summary() ?? null);
    return;
  }
  if (url2.pathname === "/mitm-ca/refresh" && req.method === "POST") {
    const r2 = await ensureMitmCaInstalled(KEYS_DIR2, 4);
    res.writeHead(r2.trusted ? 200 : 503, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: r2.trusted, installed: r2.installed, message: r2.message }));
    return;
  }
  if (url2.pathname === "/logs" && req.method === "GET") {
    await handleLogs(url2, res);
    return;
  }
  if (url2.pathname === "/logs/stream" && req.method === "GET") {
    await handleLogStream(req, res);
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});
server.listen(PORT, BIND, () => {
  console.log(`ControlClaw agent listening on ${BIND}:${PORT}`);
  const client = startGatewayBridge();
  gateway = client;
  startSshLoginWatch();
  void bootstrap(client, () => ssh.status()).catch((err) => console.error("[bootstrap] failed:", err));
  channels = new ChannelsService({
    client,
    credentialsDir: `${process.env.HOME ?? "/home/controlclaw"}/.openclaw/credentials`,
    statePath: `${STATE_DIR}/channels.json`,
    // OpenClaw's own state database, read read-only for its DM allow list (`openclaw-allow.ts`).
    stateDbPath: `${process.env.HOME ?? "/home/controlclaw"}/.openclaw/state/openclaw.sqlite`,
    restartService: () => runAction("restart"),
    mitmCaPath: `${KEYS_DIR2}/mitm-ca.crt`
  });
  llm = new LlmService({ client, restartService: () => runAction("restart"), statePath: `${STATE_DIR}/memory-index.json`, mitmCaPath: `${KEYS_DIR2}/mitm-ca.crt` });
  search = new SearchService({ client, restartService: () => runAction("restart") });
  const home = process.env.HOME ?? "/home/controlclaw";
  connectors = new ConnectorsService({
    client,
    relayPort: CONNECTOR_RELAY_PORT,
    statePath: `${STATE_DIR}/connectors.json`,
    cliEnvPath: `${home}/.config/oomol/connector.env`
  });
  connectors.startRelay();
  const driveService = new DriveService({
    desiredPath: `${STATE_DIR}/drive.json`,
    statePath: `${STATE_DIR}/drive-mounts.json`
  });
  drive = driveService.supported() ? driveService : null;
  if (!drive) console.log("[drive] cc-drive-apply is not on this box: Drive folders off until it is re-provisioned");
  const googleService = new GoogleService({
    envPath: `${STATE_DIR}/gog.env`,
    statePath: `${STATE_DIR}/google.json`
  });
  google = googleService.supported() ? googleService : null;
  if (!google) console.log("[google] gog is not on this box: the org Google account is off until it is re-provisioned");
  const gmailService = new GmailWatchService({
    envPath: "/etc/controlclaw/gmail-watch.env",
    statePath: `${STATE_DIR}/gmail-watch.json`
  });
  gmailWatch = gmailService.supported() ? gmailService : null;
  if (!gmailWatch) console.log("[gmail-watch] gog is not on this box: Gmail push is off until it is re-provisioned");
  client?.onConnected(() => void channels?.reconcile());
});
