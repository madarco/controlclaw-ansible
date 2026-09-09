// src/index.ts
import { createServer } from "http";
import { readFileSync as readFileSync9 } from "fs";

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

// src/box-token.ts
import { readFileSync as readFileSync3 } from "fs";
import { importPKCS8, SignJWT as SignJWT2 } from "jose";
function readKeyFile(keysDir2, name) {
  try {
    return readFileSync3(`${keysDir2}/${name}`, "utf-8").trim();
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

// src/ready.ts
var KEYS_DIR = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
var readKeyFile2 = (name) => readKeyFile(KEYS_DIR, name);
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function reportReady() {
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
function readFile2(path) {
  try {
    return readFileSync5(path, "utf8").trim();
  } catch {
    return null;
  }
}
var sleep3 = (ms) => new Promise((r) => setTimeout(r, ms));
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
      const token = await signBoxToken(vmId, privateKey);
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

// src/gateway.ts
var GATEWAY_SCOPES = ["operator.read", "operator.approvals", "operator.admin"];
var PROTOCOL = 4;
var CONNECT_TIMEOUT_MS = 1e4;
var DEFAULT_CALL_TIMEOUT_MS = 1e4;
var GatewayClient = class {
  constructor(opts) {
    this.opts = opts;
    this.backoff = opts.minBackoffMs ?? 1e3;
  }
  ws = null;
  seq = 0;
  pending = /* @__PURE__ */ new Map();
  handlers = /* @__PURE__ */ new Map();
  connectHandlers = /* @__PURE__ */ new Set();
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
  async call(method, params = {}, timeoutMs = DEFAULT_CALL_TIMEOUT_MS) {
    const ws = this.ws;
    if (!ws || ws.readyState !== ws.OPEN) throw new Error("gateway not connected");
    return this.send(ws, method, params, timeoutMs);
  }
  send(ws, method, params, timeoutMs) {
    const id = String(++this.seq);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`gateway call ${method} timed out`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
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
        this.backoff = this.opts.minBackoffMs ?? 1e3;
        this.outageLogged = false;
        this.log("connected");
        for (const h of this.connectHandlers) {
          try {
            h();
          } catch (err) {
            this.log(`connect handler failed: ${err.message}`);
          }
        }
      }).catch((err) => {
        this.log(`handshake failed: ${err.message}`);
        ws.close();
      });
    };
    ws.onmessage = (m) => {
      let frame;
      try {
        frame = JSON.parse(String(m.data));
      } catch {
        return;
      }
      if (frame.type === "res") {
        const p = this.pending.get(frame.id);
        if (!p) return;
        this.pending.delete(frame.id);
        clearTimeout(p.timer);
        if (frame.ok) p.resolve(frame.payload);
        else p.reject(new Error(frame.error?.message ?? frame.error?.code ?? "gateway error"));
        return;
      }
      if (frame.type === "event") {
        const set = this.handlers.get(frame.event);
        if (!set) return;
        for (const h of set) {
          try {
            h(frame.payload);
          } catch (err) {
            this.log(`handler for ${frame.event} failed: ${err.message}`);
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
      for (const [id, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new Error("gateway disconnected"));
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
    this.backoff = Math.min(this.backoff * 2, this.opts.maxBackoffMs ?? 3e4);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }
};

// src/audit.ts
import { existsSync as existsSync4, mkdirSync as mkdirSync2, readFileSync as readFileSync8, renameSync, writeFileSync as writeFileSync4 } from "fs";
import { dirname } from "path";
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
  const cut = (v, max) => v ? v.slice(0, max) : void 0;
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
      const c = JSON.parse(readFileSync8(this.opts.cursorPath, "utf-8"));
      if (typeof c.sequence === "number" && typeof c.occurredAt === "number") return { sequence: c.sequence, occurredAt: c.occurredAt };
    } catch {
    }
    return null;
  }
  saveCursor() {
    const tmp = `${this.opts.cursorPath}.tmp`;
    mkdirSync2(dirname(this.opts.cursorPath), { recursive: true });
    writeFileSync4(tmp, JSON.stringify(this.cursor), { mode: 384 });
    renameSync(tmp, this.opts.cursorPath);
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
    fresh.sort((a, b) => a.sequence - b.sequence);
    for (let i = 0; i < fresh.length; i += this.batchSize) {
      const batch = fresh.slice(i, i + this.batchSize);
      const records = batch.map(mapAuditEvent).filter((r) => r !== null);
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
function sanitizeTitle(text) {
  const flat = redact(text).replace(CONTROL_RE, " ").replace(/\s+/g, " ").trim();
  return flat.length > TITLE_MAX ? `${flat.slice(0, TITLE_MAX - 1)}\u2026` : flat;
}
function str(v) {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}
function summaryOf(kind, p) {
  const r = p.request ?? {};
  const pres = p.presentation ?? {};
  const candidate = str(r.command) ?? str(pres.commandText) ?? str(r.rawCommand) ?? str(r.summary) ?? str(pres.summary) ?? str(r.title) ?? str(pres.title) ?? str(r.toolName) ?? str(r.pluginId) ?? str(r.action);
  return sanitizeTitle(candidate ?? `${kind} approval`);
}
function detailOf(p) {
  const r = p.request ?? {};
  const rows = [];
  const add = (k, v) => {
    const s = str(v);
    if (s) rows.push([k, sanitizeTitle(s)]);
  };
  add("agent", r.agentId);
  add("session", r.sessionKey);
  add("cwd", r.cwd);
  add("host", r.host);
  add("plugin", r.pluginId ?? r.plugin);
  add("tool", r.toolName);
  const analysis = r.commandAnalysis;
  if (Array.isArray(analysis?.riskKinds) && analysis.riskKinds.length > 0) {
    rows.push(["risk", sanitizeTitle(analysis.riskKinds.map(String).join(", "))]);
  }
  add("warning", r.warningText);
  return rows;
}
function resolutionOf(p) {
  const d = (p.decision ?? p.status ?? "").toLowerCase();
  if (d.startsWith("allow")) return "approved";
  if (d === "deny" || d === "denied") return p.resolvedBy ? "denied" : "expired";
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
    let n = 0;
    for (const t of this.tracked.values()) if (!t.done) n++;
    return n;
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
    for (const u of this.unsubscribe) u();
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
      for (const p of list) {
        if (!p.id) continue;
        seen.add(p.id);
        if (!this.tracked.has(p.id)) await this.onRequested(APPROVAL_FAMILIES[family], p);
      }
    }
    for (const id of known) {
      const t = this.tracked.get(id);
      if (!t || t.done || seen.has(id)) continue;
      let resolution = "expired";
      try {
        const got = await this.opts.client.call("approval.get", {
          id,
          kind: t.approvalKind
        });
        const p = got.approval ?? got;
        if (p?.decision || p?.status) resolution = resolutionOf(p);
      } catch {
      }
      t.done = true;
      this.log(`${id} gone from the gateway: ${resolution}`);
      await this.postResolution(id, resolution);
    }
  }
  async onRequested(kind, p) {
    const id = p.id;
    if (!id || this.tracked.has(id)) return;
    this.tracked.set(id, {
      kind,
      approvalKind: p.approvalKind ?? (kind === "system" ? "openclaw" : kind),
      payload: p,
      expiresAt: typeof p.expiresAtMs === "number" ? p.expiresAtMs : null,
      raised: false,
      done: false,
      resolvedByUs: false
    });
    await this.raise(id);
  }
  /** POST the approval to the control plane; on failure tick() tries again. */
  async raise(id) {
    const t = this.tracked.get(id);
    if (!t || t.raised || t.done) return;
    const body = {
      permission_id: `oc:${id}`,
      kind: t.kind,
      title: summaryOf(t.kind, t.payload),
      detail: detailOf(t.payload),
      expires_at: t.expiresAt ? new Date(t.expiresAt).toISOString() : null
    };
    const res = await this.post(body);
    if (!res) return;
    t.raised = true;
    this.log(`raised ${t.kind} approval ${id} \u2192 ${res.status}`);
    await this.applyStatus(id, res.status);
  }
  async onResolved(p) {
    const id = p.id;
    if (!id) return;
    const t = this.tracked.get(id);
    if (!t) return;
    if (t.done && t.resolvedByUs) return;
    if (t.done) return;
    t.done = true;
    const resolution = resolutionOf(p);
    this.log(`${id} settled on the gateway: ${resolution}`);
    await this.postResolution(id, resolution);
  }
  /** Poll the console for decisions on pending approvals. Called on an interval. */
  async tick() {
    if (this.inFlight) return;
    this.inFlight = true;
    try {
      for (const [id, t] of this.tracked) {
        if (t.done) {
          if (!t.expiresAt || this.now() > t.expiresAt + 36e5) this.tracked.delete(id);
          continue;
        }
        if (t.expiresAt && this.now() > t.expiresAt + 6e4) {
          t.done = true;
          if (t.raised) await this.postResolution(id, "expired");
          continue;
        }
        if (!t.raised) {
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
    const t = this.tracked.get(id);
    if (!t || t.done) return;
    let decision;
    if (status === "approved") decision = "allow-once";
    else if (status === "denied") decision = "deny";
    else if (status === "expired") {
      t.done = true;
      return;
    } else return;
    try {
      await this.opts.client.call("approval.resolve", { id, kind: t.approvalKind, decision });
      t.done = true;
      t.resolvedByUs = true;
      this.log(`${id}: ${decision}`);
    } catch (err) {
      this.log(`approval.resolve ${id} failed: ${err.message}`);
    }
  }
  async getStatus(id) {
    try {
      const token = await this.opts.getToken();
      const url = `${this.opts.permissionUrl}?permission_id=${encodeURIComponent(`oc:${id}`)}`;
      const res = await this.fetchImpl(url, { headers: { Authorization: `Bearer ${token}` } });
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

// src/index.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var BIND = process.env.AGENT_BIND ?? "127.0.0.1";
var KEYS_DIR2 = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
var STATE_DIR = process.env.STATE_DIR ?? "/opt/controlclaw/state";
var GATEWAY_PORT = parseInt(process.env.OPENCLAW_GATEWAY_PORT ?? "18789", 10);
var AUDIT_POLL_MS = parseInt(process.env.AUDIT_POLL_MS ?? "5000", 10);
var APPROVAL_POLL_MS = parseInt(process.env.APPROVAL_POLL_MS ?? "3000", 10);
try {
  const saasPublicKey2 = readFileSync9(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8");
  setSaasPublicKey(saasPublicKey2);
  console.log("Loaded SaaS public key");
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
  process.exit(1);
}
try {
  setOwnVmId(readFileSync9(`${KEYS_DIR2}/vm_id`, "utf-8").trim());
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
function startGatewayBridge() {
  const token = readKeyFile(KEYS_DIR2, "openclaw_gateway_token");
  const base = saasBaseUrl(KEYS_DIR2);
  if (!token || !base) {
    console.log("[gateway] no openclaw_gateway_token / config_api_url in KEYS_DIR: audit + approvals bridge off");
    return;
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
  startGatewayBridge();
});
