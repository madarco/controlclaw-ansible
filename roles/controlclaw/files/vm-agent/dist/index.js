// src/index.ts
import { createServer } from "http";
import { readFileSync as readFileSync6 } from "fs";

// src/auth.ts
import { importSPKI, jwtVerify } from "jose";
var saasPublicKey = null;
function setSaasPublicKey(key) {
  saasPublicKey = key;
}
async function verifyRequest(req) {
  if (!saasPublicKey) return null;
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  try {
    const key = await importSPKI(saasPublicKey, "EdDSA");
    const { payload } = await jwtVerify(token, key, { algorithms: ["EdDSA"] });
    return payload;
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

// src/ready.ts
import { readFileSync } from "fs";
import { importPKCS8, SignJWT } from "jose";
var KEYS_DIR = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
function readKeyFile(name) {
  try {
    return readFileSync(`${KEYS_DIR}/${name}`, "utf-8").trim();
  } catch {
    return null;
  }
}
async function signReadyToken(vmId, privateKeyPem) {
  const key = await importPKCS8(privateKeyPem, "EdDSA");
  return new SignJWT({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
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
import crypto from "crypto";
import { readFileSync as readFileSync2, writeFileSync, existsSync, mkdirSync } from "fs";
function readFile(path) {
  try {
    return readFileSync2(path, "utf8").trim();
  } catch {
    return null;
  }
}
function ensureVmKeypair(keysDir) {
  const privPath = `${keysDir}/vm_private_key.pem`;
  const pubPath = `${keysDir}/vm_public_key.pem`;
  if (existsSync(privPath)) {
    return readFile(pubPath) ?? derivePublicKey(readFileSync2(privPath, "utf8"));
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  mkdirSync(keysDir, { recursive: true });
  writeFileSync(privPath, privateKey, { mode: 384 });
  writeFileSync(pubPath, publicKey, { mode: 420 });
  console.log("[keys] generated on-box vm keypair");
  return publicKey;
}
function derivePublicKey(privatePem) {
  const pub = crypto.createPublicKey(privatePem);
  return pub.export({ type: "spki", format: "pem" }).toString();
}
var sleep2 = (ms) => new Promise((r) => setTimeout(r, ms));
async function registerPublicKey(keysDir) {
  const vmId = readFile(`${keysDir}/vm_id`);
  const token = readFile(`${keysDir}/bootstrap_token`);
  const registerUrl = readFile(`${keysDir}/register_api_url`);
  const publicKey = readFile(`${keysDir}/vm_public_key.pem`);
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
    const key = crypto.createPublicKey(publicKeyPem);
    return crypto.verify(null, Buffer.from(message, "utf8"), key, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}
function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

// src/mitm-ca.ts
import { readFileSync as readFileSync3, writeFileSync as writeFileSync2, existsSync as existsSync2 } from "fs";
import { execFileSync } from "child_process";
import { importPKCS8 as importPKCS82, SignJWT as SignJWT2 } from "jose";
function readFile2(path) {
  try {
    return readFileSync3(path, "utf8").trim();
  } catch {
    return null;
  }
}
var sleep3 = (ms) => new Promise((r) => setTimeout(r, ms));
async function signVmToken(vmId, privateKeyPem) {
  const key = await importPKCS82(privateKeyPem, "EdDSA");
  return new SignJWT2({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
}
async function ensureMitmCaInstalled(keysDir) {
  const mitmIp = readFile2(`${keysDir}/mitm_box_private_ip`);
  if (!mitmIp) {
    return true;
  }
  const configUrl = readFile2(`${keysDir}/config_api_url`);
  const vmId = readFile2(`${keysDir}/vm_id`);
  const privateKey = readFile2(`${keysDir}/vm_private_key.pem`);
  if (!configUrl || !vmId || !privateKey) {
    console.warn("[mitm-ca] missing config_api_url / vm_id / vm_private_key.pem \u2014 cannot install CA");
    return false;
  }
  const pinPath = `${keysDir}/mitm_pinned_pubkey.pem`;
  const fprPath = `${keysDir}/mitm_ca_fingerprint`;
  const caSrcPath = `${keysDir}/mitm-ca.crt`;
  const maxAttempts = 60;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const token = await signVmToken(vmId, privateKey);
      const res = await fetch(configUrl, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const cfg = await res.json();
        const mitm = cfg.mitm;
        if (mitm?.caCert && mitm.caSig) {
          let pin = existsSync2(pinPath) ? readFile2(pinPath) : null;
          if (!pin && mitm.pubKey) {
            pin = mitm.pubKey;
            writeFileSync2(pinPath, pin, { mode: 420 });
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
            writeFileSync2(fprPath, fpr, { mode: 420 });
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
  writeFileSync2(caSrcPath, caCert, { mode: 420 });
  execFileSync("sudo", ["/usr/local/bin/cc-install-ca"], { stdio: "inherit" });
}

// src/egress.ts
import { readFileSync as readFileSync4 } from "fs";
import { execFileSync as execFileSync2 } from "child_process";
import net from "net";
var MITM_PROXY_PORT = parseInt(process.env.MITM_PROXY_PORT ?? "8080", 10);
function readFile3(path) {
  try {
    return readFileSync4(path, "utf8").trim();
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
async function enableTransparentEgress(keysDir) {
  const mitmIp = readFile3(`${keysDir}/mitm_box_private_ip`);
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
import { readFileSync as readFileSync5 } from "fs";
import { join } from "path";
var SERVICE = "openclaw";
var EXEC_TIMEOUT_MS = 5e3;
var ACTION_TIMEOUT_MS = 3e4;
var GATEWAY_PORT = 18789;
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
function handleGatewayToken(res) {
  const keysDir = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
  let token;
  try {
    token = readFileSync5(join(keysDir, "openclaw_gateway_token"), "utf-8").trim();
  } catch {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "No gateway token on this box" }));
    return;
  }
  if (!token) {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "No gateway token on this box" }));
    return;
  }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ token, port: GATEWAY_PORT }));
}

// src/index.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var KEYS_DIR2 = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
try {
  const saasPublicKey2 = readFileSync6(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8");
  setSaasPublicKey(saasPublicKey2);
  console.log("Loaded SaaS public key");
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
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
  if (url.pathname === "/gateway-token" && req.method === "GET") {
    handleGatewayToken(res);
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});
server.listen(PORT, "0.0.0.0", () => {
  console.log(`ControlClaw agent listening on port ${PORT}`);
  void bootstrap().catch((err) => console.error("[bootstrap] failed:", err));
});
