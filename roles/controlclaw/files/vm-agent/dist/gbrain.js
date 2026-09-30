import { createRequire as __ccCreateRequire } from "node:module"; import { fileURLToPath as __ccFileURLToPath } from "node:url"; import { dirname as __ccDirname } from "node:path"; const require = __ccCreateRequire(import.meta.url); const __filename = __ccFileURLToPath(import.meta.url); const __dirname = __ccDirname(__filename);

// src/gbrain.ts
import { createServer } from "http";
import { readFileSync as readFileSync5 } from "fs";

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

// src/software.ts
import { readFileSync as readFileSync3, realpathSync } from "fs";
import { dirname } from "path";
var BUILD = {
  version: true ? "0.1.0" : "dev",
  commit: true ? "6d926e2" : "unknown",
  builtAt: true ? "2026-09-30T10:21:38+01:00" : "unknown"
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
    const parsed = JSON.parse(readFileSync3(path, "utf8"));
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
var sleep2 = (ms) => new Promise((r) => setTimeout(r, ms));
function sshReading(readSsh) {
  const status = readSsh?.();
  return status ? { ...status, at: (/* @__PURE__ */ new Date()).toISOString() } : void 0;
}
async function reportReady(readSsh) {
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
        body: JSON.stringify({ software: boxSoftware(), ssh: sshReading(readSsh) })
      });
      if (res.ok) {
        console.log(`[ready] reported ready to SaaS (attempt ${attempt})`);
        return;
      }
      console.warn(`[ready] attempt ${attempt}/${maxAttempts}: HTTP ${res.status}`);
    } catch (err) {
      console.warn(`[ready] attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
    }
    await sleep2(Math.min(2e3 * attempt, 15e3));
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
import { execFile, spawn } from "child_process";
import { closeSync, fstatSync, openSync, readSync, readdirSync, statSync } from "fs";
import { join as join2 } from "path";

// src/redact.ts
import { readFileSync as readFileSync4 } from "fs";
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
      const value = readFileSync4(join(keysDir, name), "utf-8").trim();
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
    execFile(cmd, args, { timeout, maxBuffer, env: env(), encoding: "utf-8" }, (err, stdout, stderr) => {
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
  setSaasPublicKey(readFileSync5(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8"));
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
  process.exit(1);
}
try {
  setOwnVmId(readFileSync5(`${KEYS_DIR2}/vm_id`, "utf-8").trim());
} catch {
  console.warn("No vm_id in KEYS_DIR: tokens are checked by signature only");
}
console.log(`Loaded ${loadRedactionSecrets(KEYS_DIR2)} secret(s) for log redaction`);
var server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
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
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});
server.listen(PORT, BIND, () => {
  console.log(`ControlClaw brain agent listening on ${BIND}:${PORT}`);
  void (async () => {
    ensureVmKeypair(KEYS_DIR2);
    await registerPublicKey(KEYS_DIR2);
    await reportReady();
  })().catch((err) => console.error("[bootstrap] failed:", err));
});
