// src/index.ts
import { createServer } from "http";
import { readFileSync as readFileSync8 } from "fs";

// src/auth.ts
import { importSPKI, jwtVerify } from "jose";
var saasPublicKey = null;
var ownVmId = null;
function setSaasPublicKey(key) {
  saasPublicKey = key;
}
function setOwnVmId(id) {
  ownVmId = id;
}
async function verifySaasToken(token) {
  if (!saasPublicKey) return null;
  try {
    const key = await importSPKI(saasPublicKey, "EdDSA");
    const { payload } = await jwtVerify(token, key, { algorithms: ["EdDSA"] });
    const p = payload;
    if (ownVmId && p.vmId !== ownVmId) return null;
    return p;
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
async function verifyLoginToken(token, vmId) {
  const payload = await verifySaasToken(token);
  if (!payload || payload.purpose !== "browser-login" || payload.vmId !== vmId) return null;
  if (typeof payload.jti !== "string" || typeof payload.exp !== "number") return null;
  return payload;
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
import { existsSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { SignJWT, jwtVerify as jwtVerify2 } from "jose";
var SESSION_COOKIE = "__Host-cc_session";
var SESSION_TTL_SECONDS = 12 * 60 * 60;
var secret = null;
function ensureSessionSecret(keysDir2) {
  const path = join(keysDir2, "session_secret");
  if (!existsSync(path)) {
    writeFileSync(path, crypto.randomBytes(32).toString("hex"), { mode: 384 });
    console.log("[session] generated session secret");
  }
  secret = Buffer.from(readFileSync(path, "utf8").trim(), "hex");
}
async function issueSession(vmId) {
  if (!secret) throw new Error("session secret not initialised");
  return new SignJWT({ sub: vmId }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime(`${SESSION_TTL_SECONDS}s`).sign(secret);
}
function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
}
function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}
async function verifySession(cookieHeader, vmId) {
  if (!secret || !cookieHeader) return false;
  const token = parseCookie(cookieHeader, SESSION_COOKIE);
  if (!token) return false;
  try {
    const { payload } = await jwtVerify2(token, secret, { algorithms: ["HS256"] });
    return payload.sub === vmId;
  } catch {
    return false;
  }
}
function parseCookie(header, name) {
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return null;
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
import { execFile } from "child_process";
import { readFileSync as readFileSync2 } from "fs";
import { join as join2 } from "path";
var DASHBOARD_TIMEOUT_MS = 2e4;
function keysDir() {
  return process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
}
function readKey(name) {
  try {
    return readFileSync2(join2(keysDir(), name), "utf-8").trim() || null;
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
p.note{margin:1.25rem 0 0;font-size:13px;color:var(--ink2)}
.foot{margin-top:1.5rem;font-size:12px;color:var(--ink2);display:flex;align-items:center;gap:.4rem}
`;
var MARK_SVG = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>`;
var CONSOLE_URL = "https://controlclaw.com/dashboard/agents";
function shell(title, body, script = "") {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${title}</title><style>${PAGE_CSS}</style></head><body><main class="card"><div class="mark">${MARK_SVG}</div>${body}<div class="foot"><span style="width:6px;height:6px;border-radius:50%;background:var(--brand)"></span>Secured by ControlClaw</div></main>${script ? `<script>${script}</script>` : ""}</body></html>`;
}
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
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
<a class="btn" id="back" href="${CONSOLE_URL}" style="display:none">Back to the console</a>`,
    `
(async () => {
  const $ = (id) => document.getElementById(id);
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const step = (n) => { for (let i = 1; i <= 3; i++) { const el = $('s' + i); el.className = i < n ? 'done' : i === n ? 'active' : ''; } };
  const fail = (msg) => { $('h').textContent = 'Could not open the agent'; for (let i = 1; i <= 3; i++) $('s' + i).className = ''; $('err').textContent = msg; $('err').className = 'err show'; $('back').style.display = 'inline-block'; };
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
  step(2); await wait(450);
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
async function readJsonBody(req, limit = 8192) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (data.length > limit) {
        resolve(null);
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        resolve(null);
      }
    });
    req.on("error", () => resolve(null));
  });
}
function dashboardBootstrapUrl(hostname) {
  return new Promise((resolve) => {
    execFile(
      "/usr/bin/openclaw",
      ["dashboard", "--json", "--no-open"],
      { timeout: DASHBOARD_TIMEOUT_MS, env: { ...process.env, HOME: process.env.HOME ?? "/home/controlclaw" } },
      (err, stdout) => {
        if (err) {
          console.error("[access] openclaw dashboard failed:", err.message);
          return resolve(null);
        }
        try {
          const out = JSON.parse(stdout);
          if (!out.browserUrl) return resolve(null);
          const fragment = new URL(out.browserUrl).hash.slice(1);
          const params = new URLSearchParams(fragment);
          if (!params.get("bootstrapToken")) return resolve(null);
          params.set("gatewayUrl", `wss://${hostname}`);
          resolve(`/#${params.toString()}`);
        } catch (e) {
          console.error("[access] could not parse dashboard output:", e.message);
          resolve(null);
        }
      }
    );
  });
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
  if (pathname === "/__cc/verify" && req.method === "GET") {
    if (await verifySession(req.headers.cookie, vmId)) {
      res.writeHead(200, { "Cache-Control": "no-store" });
      res.end();
    } else {
      html(res, 401, DENIED_PAGE);
    }
    return;
  }
  if (pathname === "/__cc/session" && req.method === "POST") {
    const body = await readJsonBody(req);
    const token = typeof body?.token === "string" ? body.token : "";
    const payload = token ? await verifyLoginToken(token, vmId) : null;
    if (!payload) {
      json(res, 401, { error: "This link is not valid for this agent. Open it from your ControlClaw console again." });
      return;
    }
    if (!consumeJti(payload.jti, payload.exp)) {
      json(res, 401, { error: "This link was already used. Open the agent from your ControlClaw console again." });
      return;
    }
    const hostname = readKey("vm_hostname");
    let next = "/";
    if (hostname) next = await dashboardBootstrapUrl(hostname) ?? next;
    if (next === "/") {
      const gatewayToken = readKey("openclaw_gateway_token");
      if (gatewayToken) next = `/#token=${encodeURIComponent(gatewayToken)}`;
    }
    const session = await issueSession(vmId);
    json(res, 200, { next }, { "Set-Cookie": sessionCookie(session) });
    return;
  }
  if (pathname === "/__cc/logout" && req.method === "POST") {
    json(res, 200, { ok: true }, { "Set-Cookie": clearSessionCookie() });
    return;
  }
  json(res, 404, { error: "Not found" });
}

// src/ready.ts
import { readFileSync as readFileSync3 } from "fs";
import { importPKCS8, SignJWT as SignJWT2 } from "jose";
var KEYS_DIR = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
function readKeyFile(name) {
  try {
    return readFileSync3(`${KEYS_DIR}/${name}`, "utf-8").trim();
  } catch {
    return null;
  }
}
async function signReadyToken(vmId, privateKeyPem) {
  const key = await importPKCS8(privateKeyPem, "EdDSA");
  return new SignJWT2({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
}
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function reportReady() {
  const vmId = readKeyFile("vm_id");
  const readyUrl = readKeyFile("ready_api_url");
  const privateKey = readKeyFile("vm_private_key.pem");
  if (!vmId || !readyUrl || !privateKey) {
    console.warn(
      "[ready] missing vm_id / ready_api_url / vm_private_key.pem in KEYS_DIR \u2014 skipping ready report"
    );
    return;
  }
  const maxAttempts = 20;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const token = await signReadyToken(vmId, privateKey);
      const res = await fetch(readyUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
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
import { readFileSync as readFileSync4, writeFileSync as writeFileSync2, existsSync as existsSync2, mkdirSync } from "fs";
function readFile(path) {
  try {
    return readFileSync4(path, "utf8").trim();
  } catch {
    return null;
  }
}
function ensureVmKeypair(keysDir2) {
  const privPath = `${keysDir2}/vm_private_key.pem`;
  const pubPath = `${keysDir2}/vm_public_key.pem`;
  if (existsSync2(privPath)) {
    return readFile(pubPath) ?? derivePublicKey(readFileSync4(privPath, "utf8"));
  }
  const { publicKey, privateKey } = crypto2.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  mkdirSync(keysDir2, { recursive: true });
  writeFileSync2(privPath, privateKey, { mode: 384 });
  writeFileSync2(pubPath, publicKey, { mode: 420 });
  console.log("[keys] generated on-box vm keypair");
  return publicKey;
}
function derivePublicKey(privatePem) {
  const pub = crypto2.createPublicKey(privatePem);
  return pub.export({ type: "spki", format: "pem" }).toString();
}
var sleep2 = (ms) => new Promise((r) => setTimeout(r, ms));
async function registerPublicKey(keysDir2) {
  const vmId = readFile(`${keysDir2}/vm_id`);
  const token = readFile(`${keysDir2}/bootstrap_token`);
  const registerUrl = readFile(`${keysDir2}/register_api_url`);
  const publicKey = readFile(`${keysDir2}/vm_public_key.pem`);
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
function verifyDetached(message, signatureB64, publicKeyPem) {
  try {
    const key = crypto2.createPublicKey(publicKeyPem);
    return crypto2.verify(null, Buffer.from(message, "utf8"), key, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}
function sha256Hex(s) {
  return crypto2.createHash("sha256").update(s, "utf8").digest("hex");
}

// src/mitm-ca.ts
import { readFileSync as readFileSync5, writeFileSync as writeFileSync3, existsSync as existsSync3 } from "fs";
import { execFileSync } from "child_process";
import { importPKCS8 as importPKCS82, SignJWT as SignJWT3 } from "jose";
function readFile2(path) {
  try {
    return readFileSync5(path, "utf8").trim();
  } catch {
    return null;
  }
}
var sleep3 = (ms) => new Promise((r) => setTimeout(r, ms));
async function signVmToken(vmId, privateKeyPem) {
  const key = await importPKCS82(privateKeyPem, "EdDSA");
  return new SignJWT3({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
}
async function ensureMitmCaInstalled(keysDir2) {
  const mitmIp = readFile2(`${keysDir2}/mitm_box_private_ip`);
  if (!mitmIp) {
    return true;
  }
  const configUrl = readFile2(`${keysDir2}/config_api_url`);
  const vmId = readFile2(`${keysDir2}/vm_id`);
  const privateKey = readFile2(`${keysDir2}/vm_private_key.pem`);
  if (!configUrl || !vmId || !privateKey) {
    console.warn("[mitm-ca] missing config_api_url / vm_id / vm_private_key.pem \u2014 cannot install CA");
    return false;
  }
  const pinPath = `${keysDir2}/mitm_pinned_pubkey.pem`;
  const fprPath = `${keysDir2}/mitm_ca_fingerprint`;
  const caSrcPath = `${keysDir2}/mitm-ca.crt`;
  const maxAttempts = 60;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const token = await signVmToken(vmId, privateKey);
      const res = await fetch(configUrl, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const cfg = await res.json();
        const mitm = cfg.mitm;
        if (mitm?.caCert && mitm.caSig) {
          let pin = existsSync3(pinPath) ? readFile2(pinPath) : null;
          if (!pin && mitm.pubKey) {
            pin = mitm.pubKey;
            writeFileSync3(pinPath, pin, { mode: 420 });
            console.log("[mitm-ca] TOFU-pinned mitm public key (first box for this org)");
          }
          if (!pin) {
            console.warn(`[mitm-ca] attempt ${attempt}: CA present but no pin available yet`);
          } else if (!verifyDetached(mitm.caCert, mitm.caSig, pin)) {
            console.error(`[mitm-ca] attempt ${attempt}: CA signature does NOT match pinned key \u2014 refusing`);
          } else {
            const fpr = sha256Hex(mitm.caCert);
            if (readFile2(fprPath) === fpr) return true;
            installCa(caSrcPath, mitm.caCert);
            writeFileSync3(fprPath, fpr, { mode: 420 });
            console.log(`[mitm-ca] installed mitm CA (sha256=${fpr.slice(0, 16)}\u2026)`);
            return true;
          }
        } else {
          console.log(`[mitm-ca] attempt ${attempt}/${maxAttempts}: mitm CA not published yet`);
        }
      } else {
        console.warn(`[mitm-ca] attempt ${attempt}/${maxAttempts}: config HTTP ${res.status}`);
      }
    } catch (err) {
      console.warn(`[mitm-ca] attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
    }
    await sleep3(Math.min(3e3 * attempt, 15e3));
  }
  console.error("[mitm-ca] gave up waiting for a trusted mitm CA");
  return false;
}
function installCa(caSrcPath, caCert) {
  writeFileSync3(caSrcPath, caCert, { mode: 420 });
  execFileSync("sudo", ["/usr/local/bin/cc-install-ca"], { stdio: "inherit" });
}

// src/egress.ts
import { readFileSync as readFileSync6 } from "fs";
import { execFileSync as execFileSync2 } from "child_process";
import net from "net";
var MITM_PROXY_PORT = parseInt(process.env.MITM_PROXY_PORT ?? "8080", 10);
function readFile3(path) {
  try {
    return readFileSync6(path, "utf8").trim();
  } catch {
    return null;
  }
}
var sleep4 = (ms) => new Promise((r) => setTimeout(r, ms));
function probe(host, port, timeoutMs = 3e3) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    const done = (ok) => {
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}
async function enableTransparentEgress(keysDir2) {
  const mitmIp = readFile3(`${keysDir2}/mitm_box_private_ip`);
  if (!mitmIp) return true;
  const maxAttempts = 60;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (await probe(mitmIp, MITM_PROXY_PORT)) {
      try {
        execFileSync2("sudo", ["/usr/local/bin/cc-enable-egress"], { stdio: "inherit" });
        console.log("[egress] transparent egress activated (redirect + DNS \u2192 mitm box)");
        return true;
      } catch (err) {
        console.error(`[egress] cc-enable-egress failed: ${err.message}`);
        return false;
      }
    }
    console.log(`[egress] attempt ${attempt}/${maxAttempts}: mitm proxy ${mitmIp}:${MITM_PROXY_PORT} not reachable yet`);
    await sleep4(Math.min(3e3 * attempt, 15e3));
  }
  console.error("[egress] gave up waiting for the mitm proxy \u2014 NOT activating egress");
  return false;
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
var SERVICE = "openclaw";
var EXEC_TIMEOUT_MS = 5e3;
var ACTION_TIMEOUT_MS = 3e4;
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
function handleStatus(res) {
  const status = runIsActive();
  const summary = runStatusSummary();
  send(res, 200, {
    ok: true,
    action: "status",
    active: status === "active",
    status,
    message: summary
  });
}

// src/routes/logs.ts
import { execFile as execFile2, spawn } from "child_process";
import { closeSync, fstatSync, openSync, readSync, readdirSync, statSync } from "fs";
import { join as join4 } from "path";

// src/redact.ts
import { readFileSync as readFileSync7 } from "fs";
import { join as join3 } from "path";
var SECRET_FILES = ["openclaw_gateway_token", "session_secret", "bootstrap_token"];
var MIN_SECRET_LENGTH = 8;
var PARAM_RE = /\b(token|api[_-]?key|key|secret|password|passwd|code_challenge|code_verifier|access_token|refresh_token|client_secret|authorization)=([^&\s"'`,;]+)/gi;
var BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g;
var secrets = [];
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
var secretRe = null;
function loadRedactionSecrets(keysDir2) {
  const found = [];
  for (const name of SECRET_FILES) {
    try {
      const value = readFileSync7(join3(keysDir2, name), "utf-8").trim();
      if (value.length >= MIN_SECRET_LENGTH) found.push(value);
    } catch {
    }
  }
  setRedactionSecrets(found);
  return found.length;
}
function setRedactionSecrets(values) {
  secrets = values.filter((v) => v.length >= MIN_SECRET_LENGTH);
  secretRe = secrets.length ? new RegExp(secrets.map(escapeRegExp).join("|"), "g") : null;
}
function redact(text) {
  let out = text;
  if (secretRe) out = out.replace(secretRe, "[redacted]");
  out = out.replace(PARAM_RE, (_m, k) => `${k}=[redacted]`);
  out = out.replace(BEARER_RE, "Bearer [redacted]");
  return out;
}

// src/routes/logs.ts
var OPENCLAW_BIN = "/usr/bin/openclaw";
var SERVICE2 = "openclaw";
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
  return new Promise((resolve) => {
    execFile2(cmd, args, { timeout, maxBuffer, env: env(), encoding: "utf-8" }, (err, stdout, stderr) => {
      resolve({
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
      const s = ctx.subsystem ?? ctx.module;
      if (typeof s === "string" && s) subsystem = s;
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
    const candidates = readdirSync(LOG_DIR).filter((f) => f.startsWith("openclaw") && f.endsWith(".log"));
    let best = null;
    for (const f of candidates) {
      const path = join4(LOG_DIR, f);
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
    let text = buf.toString("utf-8");
    if (start > 0) text = text.slice(text.indexOf("\n") + 1);
    const out = [];
    for (const line of text.split("\n")) {
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
        const n = readSync(fd, buf, 0, buf.length, offset);
        offset += n;
        partial += buf.toString("utf-8", 0, n);
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
    OPENCLAW_BIN,
    ["logs", "--json", "--limit", String(lines), "--max-bytes", MAX_BYTES, "--timeout", String(CLI_TIMEOUT_MS)],
    SNAPSHOT_TIMEOUT_MS
  );
  const out = [];
  for (const line of stdout.split("\n")) {
    if (!line.trim()) continue;
    const mapped = mapCliRecord(line);
    if (mapped) out.push(mapped);
  }
  return { lines: out, warning: error && out.length === 0 ? `openclaw logs: ${error}` : null };
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
    const i = line.indexOf("=");
    if (i > 0) kv[line.slice(0, i)] = line.slice(i + 1).trim();
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
function parseLines(url) {
  const n = parseInt(url.searchParams.get("lines") ?? "", 10);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LINES;
  return Math.min(n, MAX_LINES);
}
async function handleLogs(url, res) {
  const lines = parseLines(url);
  const fromFile = readFileTail(lines);
  const [gateway, journal, service] = await Promise.all([
    fromFile ? Promise.resolve({ lines: fromFile.lines, warning: null }) : readCliSnapshot(lines),
    readJournal(),
    readServiceState()
  ]);
  const ts = (l) => Date.parse(l.time) || 0;
  const merged = [...gateway.lines, ...journal].sort((a, b) => ts(a) - ts(b)).slice(-lines);
  res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify({ service, lines: merged, ...gateway.warning ? { warning: gateway.warning } : {} }));
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
  const child = spawn(OPENCLAW_BIN, ["logs", "--json", "--follow", "--limit", String(FOLLOW_BACKLOG_LINES), "--max-bytes", MAX_BYTES], {
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

// src/index.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var BIND = process.env.AGENT_BIND ?? "127.0.0.1";
var KEYS_DIR2 = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
try {
  const saasPublicKey2 = readFileSync8(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8");
  setSaasPublicKey(saasPublicKey2);
  console.log("Loaded SaaS public key");
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
  process.exit(1);
}
try {
  setOwnVmId(readFileSync8(`${KEYS_DIR2}/vm_id`, "utf-8").trim());
} catch {
  console.warn("No vm_id in KEYS_DIR: tokens are checked by signature only");
}
try {
  ensureSessionSecret(KEYS_DIR2);
} catch (err) {
  console.error("Failed to prepare the session secret:", err);
  process.exit(1);
}
console.log(`Loaded ${loadRedactionSecrets(KEYS_DIR2)} secret(s) for log redaction`);
async function bootstrap() {
  ensureVmKeypair(KEYS_DIR2);
  await registerPublicKey(KEYS_DIR2);
  const caReady = await ensureMitmCaInstalled(KEYS_DIR2);
  if (!caReady) {
    console.error("[bootstrap] mitm CA not installed \u2014 skipping ready report (box stays initializing)");
    return;
  }
  const egressReady = await enableTransparentEgress(KEYS_DIR2);
  if (!egressReady) {
    console.error("[bootstrap] transparent egress not active \u2014 skipping ready report (box stays initializing)");
    return;
  }
  await reportReady();
}
var server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  if (url.pathname.startsWith("/__cc/")) {
    await handleAccess(req, res, url.pathname);
    return;
  }
  if (!await requireAuth(req, res)) return;
  if (url.pathname === "/health" && req.method === "GET") {
    handleHealth(res);
    return;
  }
  if (url.pathname === "/start" && req.method === "POST") {
    handleStart(res);
    return;
  }
  if (url.pathname === "/stop" && req.method === "POST") {
    handleStop(res);
    return;
  }
  if (url.pathname === "/restart" && req.method === "POST") {
    handleRestart(res);
    return;
  }
  if (url.pathname === "/status" && req.method === "GET") {
    handleStatus(res);
    return;
  }
  if (url.pathname === "/logs" && req.method === "GET") {
    await handleLogs(url, res);
    return;
  }
  if (url.pathname === "/logs/stream" && req.method === "GET") {
    await handleLogStream(req, res);
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});
server.listen(PORT, BIND, () => {
  console.log(`ControlClaw agent listening on ${BIND}:${PORT}`);
  void bootstrap().catch((err) => console.error("[bootstrap] failed:", err));
});
