import { createRequire as __ccCreateRequire } from "node:module"; import { fileURLToPath as __ccFileURLToPath } from "node:url"; import { dirname as __ccDirname } from "node:path"; const require = __ccCreateRequire(import.meta.url); const __filename = __ccFileURLToPath(import.meta.url); const __dirname = __ccDirname(__filename);

// src/gbrain.ts
import { createServer } from "http";
import { readFileSync as readFileSync7 } from "fs";

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
async function verifyMitmRequest(req, purpose = "channels") {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  if (!mitmPinnedKey && mitmPinnedKeyLoader) mitmPinnedKey = mitmPinnedKeyLoader();
  if (!mitmPinnedKey) return null;
  try {
    const key = await importSPKI(mitmPinnedKey, "EdDSA");
    const { payload } = await jwtVerify(authHeader.slice(7), key, { algorithms: ["EdDSA"] });
    const p = payload;
    if (p.purpose !== purpose || typeof p.vmId !== "string") return null;
    if (ownVmId && p.vmId !== ownVmId) return null;
    return { vmId: p.vmId, iss: typeof p.iss === "string" ? p.iss : "" };
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

// src/keys.ts
import crypto from "crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
function readFile(path) {
  try {
    return readFileSync(path, "utf8").trim();
  } catch {
    return null;
  }
}
function ensureVmKeypair(keysDir) {
  const privPath = `${keysDir}/vm_private_key.pem`;
  const pubPath = `${keysDir}/vm_public_key.pem`;
  if (existsSync(privPath)) {
    return readFile(pubPath) ?? derivePublicKey(readFileSync(privPath, "utf8"));
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
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
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
    await sleep(Math.min(2e3 * attempt, 15e3));
  }
  console.error(`[keys] gave up registering after ${maxAttempts} attempts`);
}
function spkiFromPem(pem) {
  const body = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
  return crypto.createPublicKey({ key: Buffer.from(body, "base64"), format: "der", type: "spki" });
}
function verifyDetached(message, signatureB64, publicKeyPem) {
  try {
    const key = spkiFromPem(publicKeyPem);
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
import { getCACertificates, setDefaultCACertificates } from "tls";

// src/box-token.ts
import { readFileSync as readFileSync2 } from "fs";
import { importPKCS8, SignJWT } from "jose";
function readKeyFile(keysDir, name) {
  try {
    return readFileSync2(`${keysDir}/${name}`, "utf-8").trim();
  } catch {
    return null;
  }
}
async function signBoxToken(vmId, privateKeyPem) {
  const key = await importPKCS8(privateKeyPem, "EdDSA");
  return new SignJWT({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
}

// src/mitm-ca.ts
function readFile2(path) {
  try {
    return readFileSync3(path, "utf8").trim();
  } catch {
    return null;
  }
}
var SYSTEM_MITM_CA_PATH = "/usr/local/share/ca-certificates/controlclaw-mitm.crt";
function trustMitmCaInProcess(path = SYSTEM_MITM_CA_PATH) {
  const pem = readFile2(path);
  if (!pem) return false;
  setDefaultCACertificates([...getCACertificates("bundled"), pem]);
  return true;
}
var sleep2 = (ms) => new Promise((r) => setTimeout(r, ms));
async function ensureMitmCaInstalled(keysDir, maxAttempts = 90) {
  const mitmIp = readFile2(`${keysDir}/mitm_box_private_ip`);
  if (!mitmIp) {
    return { trusted: true, installed: false, message: "This box is not behind a firewall proxy." };
  }
  trustMitmCaInProcess();
  const configUrl = readFile2(`${keysDir}/config_api_url`);
  const vmId = readFile2(`${keysDir}/vm_id`);
  const privateKey = readFile2(`${keysDir}/vm_private_key.pem`);
  if (!configUrl || !vmId || !privateKey) {
    console.warn("[mitm-ca] missing config_api_url / vm_id / vm_private_key.pem \u2014 cannot install CA");
    return { trusted: false, installed: false, message: "This box cannot ask for the firewall's certificate." };
  }
  const pinPath = `${keysDir}/mitm_pinned_pubkey.pem`;
  const fprPath = `${keysDir}/mitm_ca_fingerprint`;
  const caSrcPath = `${keysDir}/mitm-ca.crt`;
  let last = "The firewall has not published a certificate yet.";
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const token = await signBoxToken(vmId, privateKey);
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
            last = "This box has no pinned firewall key yet.";
          } else if (!verifyDetached(mitm.caCert, mitm.caSig, pin)) {
            console.error(`[mitm-ca] attempt ${attempt}: CA signature does NOT match pinned key \u2014 refusing`);
            last = "The certificate on offer is not signed by this box's pinned firewall key, so it was refused.";
          } else {
            const fpr = sha256Hex(mitm.caCert);
            if (readFile2(fprPath) === fpr) return { trusted: true, installed: false, message: "Already up to date." };
            installCa(caSrcPath, mitm.caCert);
            trustMitmCaInProcess();
            writeFileSync2(fprPath, fpr, { mode: 420 });
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
    if (attempt < maxAttempts) await sleep2(Math.min(1e3 * attempt, 1e4));
  }
  console.error("[mitm-ca] gave up waiting for a trusted mitm CA");
  return { trusted: false, installed: false, message: last };
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
var sleep3 = (ms) => new Promise((r) => setTimeout(r, ms));
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
      await sleep3(Math.min(1e3 * attempt, 1e4));
    }
    return false;
  })();
}

// src/http.ts
async function readJsonBody(req, limit = 16384) {
  return new Promise((resolve) => {
    let data = "";
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      resolve(v);
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

// src/exec.ts
import { execFile } from "child_process";
var defaultExec = (file, args, timeoutMs, stdin, opts) => new Promise((resolve, reject) => {
  const env2 = { ...process.env, HOME: process.env.HOME ?? "/home/controlclaw", ...opts?.env };
  const child = execFile(file, args, { timeout: timeoutMs, env: env2, maxBuffer: opts?.maxBuffer }, (err, stdout, stderr) => {
    if (err) {
      const e = err;
      e.stdout = String(stdout ?? "");
      e.stderr = String(stderr ?? "");
      reject(e);
    } else resolve({ stdout: String(stdout ?? ""), stderr: String(stderr ?? "") });
  });
  if (child.stdin) {
    child.stdin.on("error", () => void 0);
    if (stdin !== void 0) child.stdin.end(stdin);
    else child.stdin.end();
  }
});
function execFailureLine(err) {
  const e = err;
  const text = (e.stderr || e.stdout || e.message || "").replace(/\x1b\[[0-9;]*m/g, "").trim();
  return text.split("\n").filter((l) => l.trim()).pop() ?? "command failed";
}

// src/gbrain-key.ts
var BRAIN_KEY_PATTERN = /^vck-cc-included-[A-Za-z0-9]{8,64}$/;
var BRAIN_KEY_CLEAR = "-";
var HELPER = "/usr/local/bin/cc-gbrain-key";
var HELPER_TIMEOUT_MS = 6e4;
function parseBrainKey(body) {
  if (!body || !("memory" in body)) return "memory is required: a brain takes its model key from memory.apiKey";
  if (body.memory === null) return { clear: true };
  const memory = body.memory;
  const key = typeof memory?.apiKey === "string" ? memory.apiKey : "";
  if (!BRAIN_KEY_PATTERN.test(key)) return "memory.apiKey is not an included-key placeholder";
  return { key };
}
async function applyBrainKey(input, exec = defaultExec) {
  const value = "clear" in input ? BRAIN_KEY_CLEAR : input.key;
  try {
    const { stdout } = await exec("sudo", [HELPER], HELPER_TIMEOUT_MS, `${value}
`);
    return { changed: stdout.trim() === "changed" };
  } catch (err) {
    throw new Error(`could not set the brain's model key: ${execFailureLine(err)}`);
  }
}

// src/software.ts
import { readFileSync as readFileSync5, realpathSync } from "fs";
import { dirname } from "path";
var BUILD = {
  version: true ? "0.1.0" : "dev",
  commit: true ? "92deda8" : "unknown",
  builtAt: true ? "2026-09-30T13:21:24+01:00" : "unknown"
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
  const commit = clip(raw.commit);
  const commitDate = clip(raw.commitDate);
  const installedAt = clip(raw.installedAt);
  if (!commit || !commitDate || !installedAt) return null;
  return { commit, commitDate, installedAt };
}
function readOpenClawVersion(candidates = OPENCLAW_CANDIDATES, bin = OPENCLAW_BIN) {
  for (const path of candidates) {
    const version = clip(readJson(path)?.version);
    if (version) return version;
  }
  let dir;
  try {
    dir = dirname(realpathSync(bin));
  } catch {
    return null;
  }
  for (let i = 0; i < 4; i++) {
    const pkg = readJson(`${dir}/package.json`);
    if (pkg?.name === "openclaw") return clip(pkg.version);
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
function boxSoftware(opts = {}) {
  return {
    agent: { ...BUILD },
    release: readRelease(opts.releasePath ?? RELEASE_PATH),
    openclaw: readOpenClawVersion(opts.openclawCandidates)
  };
}

// src/ready.ts
var KEYS_DIR = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
var readKeyFile2 = (name) => readKeyFile(KEYS_DIR, name);
var sleep4 = (ms) => new Promise((r) => setTimeout(r, ms));
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
    await sleep4(Math.min(2e3 * attempt, 15e3));
  }
  console.error(`[ready] gave up reporting ready after ${maxAttempts} attempts`);
}

// src/routes/openclaw.ts
import { execSync } from "child_process";

// src/budgets.ts
var APPLY_RECORD_TTL_MS = 10 * 6e4;
var SERVICE_ACTION_MS = 3e4;

// src/routes/openclaw.ts
var SERVICE = process.env.CC_SERVICE ?? "openclaw";
var EXEC_TIMEOUT_MS = 5e3;
var ACTION_TIMEOUT_MS = SERVICE_ACTION_MS;
function runIsActive() {
  try {
    return execSync(`systemctl is-active ${SERVICE}`, { encoding: "utf-8", timeout: EXEC_TIMEOUT_MS }).trim();
  } catch (err) {
    const stdout = err.stdout;
    if (stdout) return stdout.toString().trim();
    return "unknown";
  }
}
function runStatusSummary() {
  try {
    return execSync(`systemctl status ${SERVICE} --no-pager -n 5`, {
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
    execSync(`sudo systemctl ${action} ${SERVICE}`, { encoding: "utf-8", timeout: ACTION_TIMEOUT_MS });
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
function handleStatus(res, drive) {
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
    ...drive ? { drive } : {}
  });
}

// src/routes/logs.ts
import { execFile as execFile2, spawn } from "child_process";
import { closeSync, fstatSync, openSync, readSync, readdirSync, statSync } from "fs";
import { join as join2 } from "path";

// src/redact.ts
import { readFileSync as readFileSync6 } from "fs";
import { join } from "path";
var SECRET_FILES = ["openclaw_gateway_token", "session_secret", "bootstrap_token"];
var MIN_SECRET_LENGTH = 8;
var PARAM_RE = /\b(token|api[_-]?key|key|secret|password|passwd|code_challenge|code_verifier|access_token|refresh_token|client_secret|authorization)=([^&\s"'`,;]+)/gi;
var BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g;
var secrets = [];
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
var secretRe = null;
function loadRedactionSecrets(keysDir) {
  const found = [];
  for (const name of SECRET_FILES) {
    try {
      const value = readFileSync6(join(keysDir, name), "utf-8").trim();
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
var SERVICE2 = process.env.CC_SERVICE ?? "openclaw";
var SNAPSHOT_TIMEOUT_MS = 15e3;
var DEFAULT_LINES = 200;
var MAX_LINES = 1e3;
var JOURNAL_LINES = 200;
var LOG_DIR = process.env.OPENCLAW_LOG_DIR ?? "/tmp/openclaw";
var TAIL_BYTES = 512 * 1024;
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
async function handleUnitLogs(url, res) {
  const lines = parseLines(url);
  const [journal, service] = await Promise.all([readJournal(), readServiceState()]);
  res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify({ service, lines: journal.slice(-lines) }));
}

// src/routes/health.ts
import { execSync as execSync2 } from "child_process";
function getServiceStatus(service) {
  try {
    const result = execSync2(`systemctl is-active ${service}`, { encoding: "utf-8", timeout: 5e3 }).trim();
    return result === "active" ? "running" : "stopped";
  } catch {
    try {
      execSync2(`systemctl cat ${service}`, { encoding: "utf-8", timeout: 5e3 });
      return "stopped";
    } catch {
      return "not-installed";
    }
  }
}

// src/gbrain.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var BIND = process.env.AGENT_BIND ?? "127.0.0.1";
var KEYS_DIR2 = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
if (process.env.CC_SERVICE !== "gbrain") {
  console.error("gbrain.js started without CC_SERVICE=gbrain; refusing (the lifecycle routes would act on the wrong unit)");
  process.exit(1);
}
try {
  setSaasPublicKey(readFileSync7(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8"));
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
  process.exit(1);
}
try {
  setOwnVmId(readFileSync7(`${KEYS_DIR2}/vm_id`, "utf-8").trim());
} catch {
  console.warn("No vm_id in KEYS_DIR: tokens are checked by signature only");
}
setMitmPinnedKeyLoader(() => readKeyFile(KEYS_DIR2, "mitm_pinned_pubkey.pem"));
console.log(`Loaded ${loadRedactionSecrets(KEYS_DIR2)} secret(s) for log redaction`);
var server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  if (url.pathname === "/llm/apply" && req.method === "POST") {
    if (!await verifyMitmRequest(req, "llm")) {
      sendJson(res, 401, { error: "model changes must come from the org firewall" });
      return;
    }
    const input = parseBrainKey(await readJsonBody(req));
    if (typeof input === "string") {
      sendJson(res, 400, { ok: false, error: input });
      return;
    }
    try {
      const { changed } = await applyBrainKey(input);
      console.log(`[llm] brain model key ${"clear" in input ? "removed" : "set"}${changed ? "" : " (unchanged)"}`);
      sendJson(res, 200, { ok: true, applied: [], changed });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
    return;
  }
  if (!await requireAuth(req, res)) return;
  if (url.pathname === "/health" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: "ok",
        role: "gbrain",
        uptime: process.uptime(),
        services: { gbrain: getServiceStatus("gbrain"), postgresql: getServiceStatus("postgresql@16-gbrain") }
      })
    );
    return;
  }
  if (url.pathname === "/status" && req.method === "GET") return handleStatus(res);
  if (url.pathname === "/start" && req.method === "POST") return handleStart(res);
  if (url.pathname === "/stop" && req.method === "POST") return handleStop(res);
  if (url.pathname === "/restart" && req.method === "POST") return handleRestart(res);
  if (url.pathname === "/logs" && req.method === "GET") return handleUnitLogs(url, res);
  if (url.pathname === "/mitm-ca/refresh" && req.method === "POST") {
    const r = await ensureMitmCaInstalled(KEYS_DIR2, 4);
    sendJson(res, r.trusted ? 200 : 503, { ok: r.trusted, installed: r.installed, message: r.message });
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});
server.listen(PORT, BIND, () => {
  console.log(`ControlClaw brain agent listening on ${BIND}:${PORT}`);
  void (async () => {
    ensureVmKeypair(KEYS_DIR2);
    await registerPublicKey(KEYS_DIR2);
    if (!(await ensureMitmCaInstalled(KEYS_DIR2)).trusted) {
      console.error("[bootstrap] mitm CA not installed \u2014 skipping ready report (box stays initializing)");
      return;
    }
    if (!await enableTransparentEgress(KEYS_DIR2)) {
      console.error("[bootstrap] transparent egress not active \u2014 skipping ready report (box stays initializing)");
      return;
    }
    const behindFirewall = !!readKeyFile(KEYS_DIR2, "mitm_box_private_ip");
    await reportReady(void 0, behindFirewall ? { egress: true } : {});
  })().catch((err) => console.error("[bootstrap] failed:", err));
});
