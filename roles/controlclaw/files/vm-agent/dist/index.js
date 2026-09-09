// src/index.ts
import { createServer } from "http";
import { readFileSync as readFileSync7 } from "fs";

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
var PAGE_STYLE = "font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:32rem;margin:15vh auto;padding:0 1.5rem;color:#1f2937";
var LOGIN_PAGE = `<!doctype html><meta charset="utf-8"><title>Opening your agent\u2026</title>
<body style="${PAGE_STYLE}"><p id="m">Signing you in\u2026</p>
<script>
(async () => {
  const m = document.getElementById('m');
  const t = new URLSearchParams(location.hash.slice(1)).get('t');
  history.replaceState(null, '', location.pathname);
  if (!t) { m.textContent = 'Open this agent from your ControlClaw console.'; return; }
  try {
    const r = await fetch('/__cc/session', { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: t }) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { m.textContent = d.error || 'This link has expired. Open the agent from your ControlClaw console again.'; return; }
    location.replace(d.next || '/');
  } catch (e) { m.textContent = 'Could not reach the agent. Try again from your ControlClaw console.'; }
})();
</script>`;
var DENIED_PAGE = `<!doctype html><meta charset="utf-8"><title>ControlClaw</title>
<body style="${PAGE_STYLE}"><h1 style="font-size:1.25rem">This agent is private</h1>
<p>Open it from your ControlClaw console. Your session may have expired.</p>`;
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
    html(res, 200, LOGIN_PAGE);
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

// src/index.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var BIND = process.env.AGENT_BIND ?? "127.0.0.1";
var KEYS_DIR2 = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
try {
  const saasPublicKey2 = readFileSync7(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8");
  setSaasPublicKey(saasPublicKey2);
  console.log("Loaded SaaS public key");
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
  process.exit(1);
}
try {
  setOwnVmId(readFileSync7(`${KEYS_DIR2}/vm_id`, "utf-8").trim());
} catch {
  console.warn("No vm_id in KEYS_DIR: tokens are checked by signature only");
}
try {
  ensureSessionSecret(KEYS_DIR2);
} catch (err) {
  console.error("Failed to prepare the session secret:", err);
  process.exit(1);
}
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
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});
server.listen(PORT, BIND, () => {
  console.log(`ControlClaw agent listening on ${BIND}:${PORT}`);
  void bootstrap().catch((err) => console.error("[bootstrap] failed:", err));
});
