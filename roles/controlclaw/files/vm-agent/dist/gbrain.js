import { createRequire as __ccCreateRequire } from "node:module"; import { fileURLToPath as __ccFileURLToPath } from "node:url"; import { dirname as __ccDirname } from "node:path"; const require = __ccCreateRequire(import.meta.url); const __filename = __ccFileURLToPath(import.meta.url); const __dirname = __ccDirname(__filename);

// src/gbrain.ts
import { createServer as createServer2 } from "http";
import { readFileSync as readFileSync12 } from "fs";

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
    const p = payload;
    if (p.purpose !== purpose || typeof p.vmId !== "string") return null;
    if (ownVmId && p.vmId !== ownVmId) return null;
    return { vmId: p.vmId, iss: typeof p.iss === "string" ? p.iss : "" };
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
    const p = payload;
    if (p.purpose !== purpose || p.vmId !== vmId) return null;
    if (typeof p.iss !== "string" || !p.iss.startsWith("fw:")) return null;
    if (typeof p.jti !== "string" || typeof p.exp !== "number" || typeof p.iat !== "number") return null;
    if (p.exp - p.iat > FIREWALL_TICKET_MAX_S) return null;
    if (typeof p.c !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(p.c)) return null;
    if (typeof p.deviceId !== "string" || !p.deviceId) return null;
    return {
      vmId: p.vmId,
      purpose,
      jti: p.jti,
      exp: p.exp,
      c: p.c,
      deviceId: p.deviceId,
      canWrite: p.canWrite === true,
      ...p.next === "files" ? { next: "files" } : {}
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
function ensureVmKeypair(keysDir2) {
  const privPath = `${keysDir2}/vm_private_key.pem`;
  const pubPath = `${keysDir2}/vm_public_key.pem`;
  if (existsSync(privPath)) {
    return readFile(pubPath) ?? derivePublicKey(readFileSync(privPath, "utf8"));
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  mkdirSync(keysDir2, { recursive: true });
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
function readKeyFile(keysDir2, name) {
  try {
    return readFileSync2(`${keysDir2}/${name}`, "utf-8").trim();
  } catch {
    return null;
  }
}
async function signBoxToken(vmId, privateKeyPem) {
  const key = await importPKCS8(privateKeyPem, "EdDSA");
  return new SignJWT({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
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
async function ensureMitmCaInstalled(keysDir2, maxAttempts = 90) {
  const mitmIp = readFile2(`${keysDir2}/mitm_box_private_ip`);
  if (!mitmIp) {
    return { trusted: true, installed: false, message: "This box is not behind a firewall proxy." };
  }
  trustMitmCaInProcess();
  const configUrl = readFile2(`${keysDir2}/config_api_url`);
  const vmId = readFile2(`${keysDir2}/vm_id`);
  const privateKey = readFile2(`${keysDir2}/vm_private_key.pem`);
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
async function enableTransparentEgress(keysDir2) {
  const mitmIp = readFile3(`${keysDir2}/mitm_box_private_ip`);
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

// src/gbrain-activity.ts
import { createHash } from "crypto";
import { existsSync as existsSync3, mkdirSync as mkdirSync2, readFileSync as readFileSync5, renameSync, writeFileSync as writeFileSync3 } from "fs";
import { dirname } from "path";
var AGENT_RE = /^cc-([A-Za-z0-9_-]{1,64})$/;
var QUEUE_MAX = 2e3;
var BATCH = 200;
function mapBrainEvent(data) {
  let ev;
  try {
    ev = JSON.parse(data);
  } catch {
    return null;
  }
  const agent = typeof ev.agent === "string" ? AGENT_RE.exec(ev.agent) : null;
  const operation = typeof ev.operation === "string" ? ev.operation.slice(0, 80) : "";
  const at = typeof ev.timestamp === "string" ? Date.parse(ev.timestamp) : NaN;
  if (!agent || !operation || operation.includes("/") || !Number.isFinite(at)) return null;
  const status = typeof ev.status === "string" ? ev.status.slice(0, 32) : null;
  const latency = typeof ev.latency_ms === "number" && Number.isFinite(ev.latency_ms) ? Math.round(ev.latency_ms) : null;
  const call_id = createHash("sha256").update(`${ev.agent}|${ev.timestamp}|${operation}|${latency ?? ""}`).digest("hex").slice(0, 40);
  return { source: "brain_call", call_id, ts: at / 1e3, agent_vm_id: agent[1], operation, ok: status === "success", status, duration_ms: latency };
}
function readCycleReport(raw) {
  let d;
  try {
    d = JSON.parse(raw);
  } catch {
    return null;
  }
  const finished = typeof d.finished_at === "string" ? d.finished_at : null;
  const at = finished ? Date.parse(finished) : NaN;
  if (!finished || !Number.isFinite(at)) return null;
  const num = (v) => typeof v === "number" && Number.isFinite(v) ? v : null;
  const totals = {};
  if (d.totals && typeof d.totals === "object") {
    for (const [k, v] of Object.entries(d.totals).slice(0, 40)) {
      if (typeof v === "number" && Number.isFinite(v)) totals[k.slice(0, 64)] = v;
    }
  }
  const cost = num(d.cost_usd);
  return {
    source: "brain_cycle",
    cycle_id: finished.slice(0, 64),
    ts: at / 1e3,
    status: typeof d.status === "string" ? d.status.slice(0, 32) : "unknown",
    exit_code: num(d.exit_code),
    duration_ms: num(d.duration_ms) === null ? null : Math.round(num(d.duration_ms)),
    cost_usd: cost === null ? null : Math.max(0, cost),
    model_calls: num(d.model_calls) === null ? null : Math.round(num(d.model_calls)),
    totals
  };
}
function splitSse(buffer) {
  const events = [];
  const blocks = buffer.split(/\r?\n\r?\n/);
  const rest = blocks.pop() ?? "";
  for (const block of blocks) {
    const data = block.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
    if (data) events.push(data);
  }
  return { events, rest };
}
var BrainActivity = class {
  constructor(opts) {
    this.opts = opts;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.log = opts.log ?? ((l) => console.log(`[brain-activity] ${l}`));
  }
  queue = [];
  cookie = null;
  stopped = false;
  fetchImpl;
  log;
  start() {
    void this.followLoop();
    const flush = () => void this.flush().catch((e) => this.log(`ship failed: ${e.message}`));
    setInterval(flush, 1e4).unref();
    const cycle = () => void this.checkCycle().catch((e) => this.log(`nightly report: ${e.message}`));
    setInterval(cycle, 6e4).unref();
    cycle();
  }
  stop() {
    this.stopped = true;
  }
  pending() {
    return this.queue.length;
  }
  enqueue(r) {
    this.queue.push(r);
    if (this.queue.length > QUEUE_MAX) this.queue.splice(0, this.queue.length - QUEUE_MAX);
  }
  /** GBrain's admin cookie, from a fresh single-use link followed over loopback. */
  async adminCookie() {
    const path = await this.opts.loginPath();
    const res = await this.fetchImpl(`${this.opts.gbrainUrl}${path}`, { redirect: "manual" });
    const setCookie = res.headers.get("set-cookie") ?? "";
    const m = /gbrain_admin=([^;,\s]+)/.exec(setCookie);
    if (!m) throw new Error(`GBrain set no admin cookie (HTTP ${res.status})`);
    return m[1];
  }
  async followLoop() {
    let backoff = 5e3;
    while (!this.stopped) {
      try {
        if (!this.cookie) this.cookie = await this.adminCookie();
        const res = await this.fetchImpl(`${this.opts.gbrainUrl}/admin/events`, { headers: { cookie: `gbrain_admin=${this.cookie}`, accept: "text/event-stream" }, redirect: "manual" });
        if (res.status === 401 || res.status === 403 || res.status >= 300 && res.status < 400) {
          this.cookie = null;
          throw new Error(`admin feed refused the cookie (HTTP ${res.status})`);
        }
        if (!res.ok || !res.body) throw new Error(`admin feed answered HTTP ${res.status}`);
        backoff = 5e3;
        await this.readFeed(res.body);
        this.log("admin feed ended; reconnecting");
      } catch (err) {
        this.log(`${err.message}; retrying in ${Math.round(backoff / 1e3)} s`);
      }
      await new Promise((r) => setTimeout(r, backoff).unref());
      backoff = Math.min(backoff * 2, 6e4);
    }
  }
  async readFeed(body) {
    const decoder = new TextDecoder();
    const reader = body.getReader();
    let buffer = "";
    while (!this.stopped) {
      const { value, done } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      const { events, rest } = splitSse(buffer);
      buffer = rest.length > 1e6 ? "" : rest;
      for (const e of events) {
        const r = mapBrainEvent(e);
        if (r) this.enqueue(r);
      }
    }
  }
  /** The nightly summary, shipped once: the cursor is when the last shipped run finished. */
  async checkCycle() {
    if (!existsSync3(this.opts.reportPath)) return;
    const r = readCycleReport(readFileSync5(this.opts.reportPath, "utf-8"));
    if (!r) return;
    const last = existsSync3(this.opts.cursorPath) ? readFileSync5(this.opts.cursorPath, "utf-8").trim() : "";
    if (last === r.cycle_id) return;
    if (await this.post([r])) {
      mkdirSync2(dirname(this.opts.cursorPath), { recursive: true });
      const tmp = `${this.opts.cursorPath}.tmp`;
      writeFileSync3(tmp, r.cycle_id);
      renameSync(tmp, this.opts.cursorPath);
      this.log(`shipped the nightly run of ${r.cycle_id}`);
    }
  }
  async flush() {
    while (this.queue.length > 0) {
      const batch = this.queue.slice(0, BATCH);
      if (!await this.post(batch)) return;
      this.queue.splice(0, batch.length);
    }
  }
  async post(records) {
    const token = await this.opts.getToken();
    const res = await this.fetchImpl(this.opts.activityUrl, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ records })
    });
    if (res.status === 400 || res.status === 413) {
      this.log(`batch of ${records.length} rejected with HTTP ${res.status}; dropped`);
      return true;
    }
    if (!res.ok) {
      this.log(`ship failed: HTTP ${res.status}`);
      return false;
    }
    return true;
  }
};

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
import { readFileSync as readFileSync7, realpathSync } from "fs";
import { dirname as dirname3 } from "path";

// src/access-state.ts
import { mkdirSync as mkdirSync3, readFileSync as readFileSync6, renameSync as renameSync2, writeFileSync as writeFileSync4 } from "fs";
import { dirname as dirname2, join } from "path";
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
    const raw = JSON.parse(readFileSync6(path, "utf8"));
    state = {
      firewallOrigin: typeof raw.firewallOrigin === "string" && validFirewallOrigin(raw.firewallOrigin) ? raw.firewallOrigin : null,
      revoked: raw.revoked && typeof raw.revoked === "object" ? raw.revoked : {}
    };
  } catch {
  }
  cache = { path, state };
  return state;
}
function validFirewallOrigin(origin) {
  return /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(origin) && origin.length <= 261;
}
function firewallOrigin() {
  return load().firewallOrigin;
}
function isRevoked(deviceId, now = Date.now()) {
  const at = load().revoked[deviceId];
  return typeof at === "number" && now - at < REVOKED_KEEP_MS;
}

// src/software.ts
var BUILD = {
  version: true ? "0.1.0" : "dev",
  commit: true ? "ac969b4" : "unknown",
  builtAt: true ? "2026-09-30T17:33:19+01:00" : "unknown"
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
    const parsed = JSON.parse(readFileSync7(path, "utf8"));
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
    dir = dirname3(realpathSync(bin));
  } catch {
    return null;
  }
  for (let i = 0; i < 4; i++) {
    const pkg = readJson(`${dir}/package.json`);
    if (pkg?.name === "openclaw") return clip(pkg.version);
    const parent = dirname3(dir);
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

// src/openclaw-state.ts
var CRASH_WINDOW_MS = 12e4;
var CRASH_RESTARTS = 4;
function openClawState(unit, recentRestarts, gateway) {
  if (unit === "active" && gateway !== false) return "running";
  if (recentRestarts >= CRASH_RESTARTS) return "crashing";
  if (unit === "failed") return "failed";
  if (unit === "active") return "starting";
  if (unit === "activating" || unit === "deactivating" || unit === "reloading") return "restarting";
  return "stopped";
}

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
function recentAutoRestarts() {
  try {
    const out = execSync(
      `sudo -n journalctl -u ${SERVICE} --since "-${Math.round(CRASH_WINDOW_MS / 1e3)}s" --no-pager -o cat`,
      { encoding: "utf-8", timeout: EXEC_TIMEOUT_MS }
    );
    return out.split("\n").filter((l) => l.includes("Scheduled restart job")).length;
  } catch {
    return 0;
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
function handleStatus(res, drive, gateway) {
  const status = runIsActive();
  const summary = runStatusSummary();
  const connected = gateway ? gateway.connected : null;
  send(res, 200, {
    ok: true,
    action: "status",
    active: status === "active",
    status,
    state: openClawState(status, status === "active" && connected !== false ? 0 : recentAutoRestarts(), connected),
    ...connected !== null ? { gateway: connected } : {},
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
import { join as join3 } from "path";

// src/redact.ts
import { readFileSync as readFileSync8 } from "fs";
import { join as join2 } from "path";
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
      const value = readFileSync8(join2(keysDir2, name), "utf-8").trim();
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

// src/routes/access.ts
import { createHash as createHash2, randomBytes } from "crypto";
import { execFile as execFile3 } from "child_process";
import { readFileSync as readFileSync10 } from "fs";
import { join as join6 } from "path";

// src/session.ts
import crypto2 from "crypto";
import { existsSync as existsSync4, readFileSync as readFileSync9, writeFileSync as writeFileSync5 } from "fs";
import { join as join4 } from "path";
import { SignJWT as SignJWT2, jwtVerify as jwtVerify2 } from "jose";

// ../origin-guard/src/index.ts
var SAFE_METHODS = /* @__PURE__ */ new Set(["GET", "HEAD", "OPTIONS"]);
function normalizeOrigin(origin) {
  if (!origin) return null;
  const raw = origin.trim();
  if (!raw || raw === "null") return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "http:" && url.protocol !== "https:") return raw;
    const defaultPort = url.protocol === "https:" ? "443" : "80";
    const port = url.port && url.port !== defaultPort ? `:${url.port}` : "";
    return `${url.protocol}//${url.hostname.toLowerCase()}${port}`;
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
    const allowed = policy.allowed.map((o) => normalizeOrigin(o)).filter((o) => o !== null);
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
function cookieValues(header, name) {
  if (!header) return [];
  const out = [];
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    if (trimmed.slice(0, eq) !== name) continue;
    out.push(trimmed.slice(eq + 1));
  }
  return out;
}
function readUniqueCookie(header, name) {
  const values = cookieValues(header, name);
  if (values.length === 1) return { value: values[0] ?? null, duplicated: false };
  return { value: null, duplicated: values.length > 1 };
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
  const path = join4(keysDir2, "session_secret");
  if (!existsSync4(path)) {
    writeFileSync5(path, crypto2.randomBytes(32).toString("hex"), { mode: 384 });
    console.log("[session] generated session secret");
  }
  secret = Buffer.from(readFileSync9(path, "utf8").trim(), "hex");
}
async function issueSession(vmId, claims = { canWrite: false }) {
  if (!secret) throw new Error("session secret not initialised");
  return new SignJWT2({ sub: vmId, ...claims.canWrite ? { canWrite: true } : {}, ...claims.deviceId ? { dev: claims.deviceId } : {} }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime(`${SESSION_TTL_SECONDS}s`).sign(secret);
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
  return new SignJWT2({ sub: vmId, ...deviceId ? { dev: deviceId } : {} }).setProtectedHeader({ alg: "HS256" }).setAudience(VIEW_AUDIENCE).setIssuedAt().setExpirationTime(`${SESSION_TTL_SECONDS}s`).sign(secret);
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
function uniqueCookie(header, name) {
  const reading = readUniqueCookie(header, name);
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

// src/routes/files-page.ts
import { readFile as readFile4 } from "fs/promises";
import { basename, join as join5 } from "path";
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
    body = await readFile4(join5(uiDir(), file));
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
  return createHash2("sha256").update(gatewayToken ?? vmId).digest("hex").slice(0, 16);
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
    return readFileSync10(join6(keysDir(), name), "utf-8").trim() || null;
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
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
function loginPage(hostname, steps = ["Pairing this browser with the agent", "Loading OpenClaw"]) {
  const agent = hostname ? escapeHtml(hostname.split(".")[0]) : "your agent";
  const host = hostname ? escapeHtml(hostname) : "";
  return shell(
    `Opening ${agent}\u2026`,
    `<h1 id="h">Opening ${agent}</h1><p class="host">${host}</p>
<ol class="steps">
  <li id="s1" class="active"><span class="dot"></span>Checking your ControlClaw pass</li>
  <li id="s2"><span class="dot"></span>${escapeHtml(steps[0])}</li>
  <li id="s3"><span class="dot"></span>${escapeHtml(steps[1])}</li>
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
  if (d.view === 'direct') { step(3); location.replace(d.next); return; }
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
    const i = part.indexOf("=");
    if (i < 0) continue;
    const name = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    if (name.startsWith(BIND_COOKIE_PREFIX) && /^[A-Za-z0-9_-]{43}$/.test(value)) out.push({ name, value });
  }
  return out.slice(-BIND_READ_MAX);
}
function bindCookie(name, value) {
  return value ? `${name}=${value}; Path=/; Max-Age=${BIND_TTL_S}; HttpOnly; Secure; SameSite=Lax` : `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}
function bindingHash(value) {
  return createHash2("sha256").update(value).digest("base64url");
}
async function acceptTicket(req, token, vmId, purpose) {
  const invalid = { error: "This link is not valid for this agent. Open it from your ControlClaw console again." };
  if (!token) return invalid;
  const cp = await verifyLoginToken(token, vmId, purpose);
  if (cp) return { jti: cp.jti, exp: cp.exp, canWrite: cp.canWrite === true, ...cp.next ? { next: cp.next } : {}, issuer: "control-plane", cookies: [] };
  const fw = await verifyFirewallTicket(token, vmId, purpose);
  if (!fw) return invalid;
  const match = bindings(req.headers.cookie).find((b) => bindingHash(b.value) === fw.c);
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
  return new Promise((resolve) => {
    execFile3(
      openclawBin(),
      ["dashboard", "--json", "--no-open"],
      { timeout: timeoutMs, env: { ...process.env, HOME: process.env.HOME ?? "/home/controlclaw" } },
      (err, stdout) => resolve(parseDashboardOutput(String(stdout ?? ""), hostname, err))
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
  const run2 = opts.run ?? runDashboard;
  const deadline = Date.now() + (opts.budgetMs ?? DASHBOARD_BUDGET_MS);
  let last = { reason: "no time left to ask OpenClaw", retryable: false };
  for (let attempt = 1; attempt <= 2; attempt++) {
    const left = deadline - Date.now();
    if (left < DASHBOARD_MIN_ATTEMPT_MS) break;
    last = await run2(hostname, left);
    if ("url" in last) return last;
    console.error(`[access] openclaw dashboard failed (attempt ${attempt}): ${last.reason}`);
    if (!last.retryable || attempt === 2) break;
    await new Promise((r) => setTimeout(r, opts.retryWaitMs ?? DASHBOARD_RETRY_WAIT_MS));
  }
  return last;
}
async function handleAccess(req, res, pathname, opts = {}) {
  const vmId = readKey("vm_id");
  if (!vmId) {
    json(res, 500, { error: "Box has no vm_id" });
    return;
  }
  if (opts.only && !opts.only.has(pathname)) {
    json(res, 404, { error: "Not found" });
    return;
  }
  if (pathname === "/__cc/login" && req.method === "GET") {
    html(res, 200, loginPage(readKey("vm_hostname"), opts.steps));
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
    if (opts.requireWrite && payload.canWrite !== true) {
      json(res, 403, { error: opts.requireWrite });
      return;
    }
    if (opts.landing) {
      const landing = await opts.landing();
      if ("error" in landing) {
        json(res, 502, { error: landing.error });
        return;
      }
      const session2 = await issueSession(vmId, claims);
      json(res, 200, { next: landing.next, view: "direct", paired: true }, { "Set-Cookie": [sessionCookie(session2), ...payload.cookies] });
      return;
    }
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
      const bootstrap = await dashboardBootstrapUrl(hostname);
      if ("url" in bootstrap) {
        next = bootstrap.url;
        paired = true;
      } else {
        pairError = bootstrap.reason;
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

// src/gbrain-login.ts
var HELPER2 = "/usr/local/bin/cc-gbrain-login-link";
var HELPER_TIMEOUT_MS2 = 3e4;
var LINK_RE = /^https:\/\/[^/\s]+(\/admin\/auth\/[A-Za-z0-9_.~-]+)$/;
function parseLoginLink(stdout) {
  const line = stdout.trim().split("\n").pop()?.trim() ?? "";
  return LINK_RE.exec(line)?.[1] ?? null;
}
async function gbrainLoginPath(exec = defaultExec) {
  let stdout;
  try {
    ({ stdout } = await exec("sudo", [HELPER2], HELPER_TIMEOUT_MS2));
  } catch (err) {
    throw new Error(`could not get a GBrain login link: ${execFailureLine(err)}`, { cause: err });
  }
  const path = parseLoginLink(stdout);
  if (!path) throw new Error("GBrain returned no login link");
  return path;
}

// src/gbrain-gate.ts
import { createServer, request as httpRequest } from "http";
import { chmodSync, existsSync as existsSync5, mkdirSync as mkdirSync4, readFileSync as readFileSync11, renameSync as renameSync3, writeFileSync as writeFileSync6 } from "fs";
import { dirname as dirname4 } from "path";
import { networkInterfaces } from "os";
var GATE_PORT = 3131;
var HELPER3 = "/usr/local/bin/cc-gbrain-token";
var HELPER_TIMEOUT_MS3 = 25e3;
var UPSTREAM_TIMEOUT_MS = 10 * 6e4;
var VM_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
var PRIVATE_IP_RE = /^10\.(?:\d{1,3}\.){2}\d{1,3}$/;
var TOKEN_RE = /^[A-Za-z0-9_]{32,}$/;
function normalizeIp(a) {
  return (a ?? "").replace(/^::ffff:/i, "").trim();
}
function privateAddress() {
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) {
      if (a.family === "IPv4" && !a.internal && PRIVATE_IP_RE.test(a.address)) return a.address;
    }
  }
  return null;
}
function parseConnect(body) {
  if (!body) return "a JSON body is required";
  const { vmId, ip, scope } = body;
  if (typeof vmId !== "string" || !VM_ID_RE.test(vmId)) return "vmId is required";
  if (typeof ip !== "string" || !PRIVATE_IP_RE.test(ip)) return "ip must be a private 10.x address";
  if (scope !== "read" && scope !== "read_write") return "scope must be read or read_write";
  return { vmId, ip, scope };
}
function parseLock(body) {
  if (!body || typeof body.all !== "boolean" || !Array.isArray(body.vmIds)) return "all (boolean) and vmIds (array) are required";
  const vmIds = body.vmIds.filter((v) => typeof v === "string" && VM_ID_RE.test(v));
  if (vmIds.length !== body.vmIds.length) return "vmIds must be vm ids";
  return { all: body.all, vmIds: [...new Set(vmIds)].sort() };
}
function parseDisconnect(body) {
  const vmId = body?.vmId;
  if (typeof vmId !== "string" || !VM_ID_RE.test(vmId)) return "vmId is required";
  return { vmId };
}
var BrainGate = class {
  constructor(statePath2, exec = defaultExec, log = (l) => console.log(l)) {
    this.statePath = statePath2;
    this.exec = exec;
    this.log = log;
    this.entries = this.load();
  }
  entries;
  lockState = { all: false, vmIds: [] };
  load() {
    if (!existsSync5(this.statePath)) return [];
    try {
      const s = JSON.parse(readFileSync11(this.statePath, "utf-8"));
      const lock = parseLock(s.lock ?? null);
      if (typeof lock !== "string") this.lockState = lock;
      return Array.isArray(s.entries) ? s.entries.filter((e) => e && typeof e.token === "string" && typeof e.ip === "string") : [];
    } catch (err) {
      this.log(`[gbrain-gate] could not read ${this.statePath}: ${err.message}`);
      return [];
    }
  }
  save() {
    mkdirSync4(dirname4(this.statePath), { recursive: true });
    const tmp = `${this.statePath}.tmp`;
    writeFileSync6(tmp, JSON.stringify({ version: 1, entries: this.entries, lock: this.lockState }), { mode: 384 });
    chmodSync(tmp, 384);
    renameSync3(tmp, this.statePath);
  }
  /** What the firewall reads to reconcile. No tokens. */
  list() {
    return this.entries.map(({ vmId, ip, scope, at }) => ({ vmId, ip, scope, at }));
  }
  lock() {
    return { all: this.lockState.all, vmIds: [...this.lockState.vmIds] };
  }
  setLock(lock) {
    this.lockState = { all: lock.all, vmIds: [...lock.vmIds] };
    this.save();
    this.log(`[gbrain-gate] emergency stop: ${lock.all ? "every agent" : lock.vmIds.length ? lock.vmIds.join(", ") : "none"}`);
  }
  admit(sourceIp) {
    const ip = normalizeIp(sourceIp);
    const e = this.entries.find((x) => x.ip === ip);
    if (!e) return { refused: "unknown" };
    if (this.lockState.all || this.lockState.vmIds.includes(e.vmId)) return { refused: "stopped" };
    return { token: e.token };
  }
  async connect(input) {
    let token;
    try {
      const { stdout } = await this.exec("sudo", [HELPER3, "create", input.vmId, input.scope], HELPER_TIMEOUT_MS3);
      token = stdout.trim();
    } catch (err) {
      throw new Error(`could not create the agent's brain token: ${execFailureLine(err)}`, { cause: err });
    }
    if (!TOKEN_RE.test(token)) throw new Error("GBrain returned no usable token");
    const displaced = this.entries.filter((e) => e.ip === input.ip && e.vmId !== input.vmId);
    this.entries = this.entries.filter((e) => e.vmId !== input.vmId && e.ip !== input.ip);
    this.entries.push({ ...input, token, at: (/* @__PURE__ */ new Date()).toISOString() });
    this.save();
    for (const d of displaced) await this.revoke(d.vmId).catch((e) => this.log(`[gbrain-gate] ${e.message}`));
    this.log(`[gbrain-gate] ${input.vmId} at ${input.ip} may use the brain (${input.scope})`);
  }
  async disconnect(vmId) {
    const had = this.entries.some((e) => e.vmId === vmId);
    this.entries = this.entries.filter((e) => e.vmId !== vmId);
    this.save();
    await this.revoke(vmId);
    this.log(`[gbrain-gate] ${vmId} disconnected from the brain`);
    return had;
  }
  async revoke(vmId) {
    try {
      await this.exec("sudo", [HELPER3, "revoke", vmId], HELPER_TIMEOUT_MS3);
    } catch (err) {
      throw new Error(`could not revoke ${vmId}'s brain token: ${execFailureLine(err)}`, { cause: err });
    }
  }
};
function deny(res, status, message) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: message }));
}
function gateAllows(method, url) {
  const path = (url ?? "/").split("?")[0];
  return path === "/mcp" && (method === "POST" || method === "GET" || method === "DELETE");
}
function createBrainGate(opts) {
  const log = opts.log ?? ((l) => console.log(l));
  return createServer((req, res) => {
    if (!gateAllows(req.method, req.url)) {
      deny(res, 404, "Not found");
      req.resume();
      return;
    }
    const a = opts.gate.admit(req.socket.remoteAddress);
    if ("refused" in a) {
      log(`[gbrain-gate] refused ${normalizeIp(req.socket.remoteAddress)}: ${a.refused === "stopped" ? "under an emergency stop" : "not a connected agent"}`);
      deny(res, 403, a.refused === "stopped" ? "This agent is under an emergency stop." : "This agent is not connected to the brain.");
      req.resume();
      return;
    }
    const token = a.token;
    const headers = { ...req.headers, host: `${opts.target.host}:${opts.target.port}`, authorization: `Bearer ${token}` };
    delete headers["x-forwarded-for"];
    const upstream = httpRequest({ host: opts.target.host, port: opts.target.port, method: req.method, path: req.url, headers }, (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers);
      up.pipe(res);
    });
    upstream.setTimeout(UPSTREAM_TIMEOUT_MS, () => upstream.destroy(new Error("timeout")));
    upstream.on("error", (err) => {
      log(`[gbrain-gate] upstream failed: ${err.message}`);
      if (!res.headersSent) deny(res, 502, "The brain is not answering.");
      else res.end();
    });
    res.on("close", () => {
      if (!res.writableFinished) upstream.destroy();
    });
    req.pipe(upstream);
  });
}

// src/gbrain.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var BIND = process.env.AGENT_BIND ?? "127.0.0.1";
var KEYS_DIR2 = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
var STATE_DIR = process.env.STATE_DIR ?? "/opt/controlclaw/state";
var GBRAIN_PORT = parseInt(process.env.GBRAIN_PORT ?? "3130", 10);
if (process.env.CC_SERVICE !== "gbrain") {
  console.error("gbrain.js started without CC_SERVICE=gbrain; refusing (the lifecycle routes would act on the wrong unit)");
  process.exit(1);
}
try {
  setSaasPublicKey(readFileSync12(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8"));
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
  process.exit(1);
}
try {
  setOwnVmId(readFileSync12(`${KEYS_DIR2}/vm_id`, "utf-8").trim());
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
var gate = new BrainGate(`${STATE_DIR}/gbrain-gate.json`);
var BRAIN_ACCESS_ROUTES = /* @__PURE__ */ new Set(["/__cc/login", "/__cc/session", "/__cc/verify", "/__cc/logout"]);
var server = createServer2(async (req, res) => {
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
  if (url.pathname.startsWith("/__cc/")) {
    try {
      await handleAccess(req, res, url.pathname, {
        only: BRAIN_ACCESS_ROUTES,
        requireWrite: "Only owners and admins can open the brain.",
        steps: ["Signing you in to GBrain", "Loading the brain"],
        landing: async () => {
          try {
            return { next: await gbrainLoginPath() };
          } catch (err) {
            console.error(`[access] ${err.message}`);
            return { error: "The brain did not give a sign-in link. It may be starting; try Open again in a minute." };
          }
        }
      });
    } catch (err) {
      console.error(`[access] ${url.pathname} failed: ${err.message}`);
      if (!res.headersSent) sendJson(res, 500, { error: "The brain could not sign you in. Try Open again." });
      else res.end();
    }
    return;
  }
  if (url.pathname.startsWith("/gbrain/")) {
    if (!await verifyMitmRequest(req, "gbrain")) {
      sendJson(res, 401, { error: "brain connections must come from the org firewall" });
      return;
    }
    try {
      if (url.pathname === "/gbrain/connections" && req.method === "GET") {
        sendJson(res, 200, { ok: true, connections: gate.list(), lock: gate.lock() });
        return;
      }
      if (url.pathname === "/gbrain/connect" && req.method === "POST") {
        const input = parseConnect(await readJsonBody(req));
        if (typeof input === "string") return sendJson(res, 400, { ok: false, error: input });
        await gate.connect(input);
        sendJson(res, 200, { ok: true, applied: [] });
        return;
      }
      if (url.pathname === "/gbrain/lock" && req.method === "POST") {
        const input = parseLock(await readJsonBody(req));
        if (typeof input === "string") return sendJson(res, 400, { ok: false, error: input });
        gate.setLock(input);
        sendJson(res, 200, { ok: true, applied: [] });
        return;
      }
      if (url.pathname === "/gbrain/disconnect" && req.method === "POST") {
        const input = parseDisconnect(await readJsonBody(req));
        if (typeof input === "string") return sendJson(res, 400, { ok: false, error: input });
        const removed = await gate.disconnect(input.vmId);
        sendJson(res, 200, { ok: true, removed, applied: [] });
        return;
      }
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
      return;
    }
    sendJson(res, 404, { error: "Not found" });
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
function listenGate() {
  const ip = privateAddress();
  if (!ip) {
    console.warn("[gbrain-gate] no private address yet; trying again in 30 s");
    setTimeout(listenGate, 3e4).unref();
    return;
  }
  const g = createBrainGate({ gate, target: { host: "127.0.0.1", port: GBRAIN_PORT } });
  g.on("error", (err) => {
    console.error(`[gbrain-gate] could not listen on ${ip}:${GATE_PORT}: ${err.message}; trying again in 30 s`);
    setTimeout(listenGate, 3e4).unref();
  });
  g.listen(GATE_PORT, ip, () => console.log(`[gbrain-gate] listening on ${ip}:${GATE_PORT} (${gate.list().length} agent(s) connected)`));
}
listenGate();
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
  const base = saasBaseUrl(KEYS_DIR2);
  if (base) {
    new BrainActivity({
      gbrainUrl: `http://127.0.0.1:${GBRAIN_PORT}`,
      loginPath: () => gbrainLoginPath(),
      activityUrl: `${base}/api/vm-agent/activity`,
      getToken: makeBoxTokenSigner(KEYS_DIR2),
      reportPath: "/var/lib/gbrain-report/last-cycle.json",
      cursorPath: `${STATE_DIR}/brain-cycle.cursor`
    }).start();
  } else {
    console.warn("[brain-activity] no control plane URL in KEYS_DIR; Activity is not shipped");
  }
});
