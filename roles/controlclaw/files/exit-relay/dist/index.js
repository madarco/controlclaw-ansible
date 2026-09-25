// src/index.ts
import { readFileSync } from "fs";
import { createServer as createHttpServer } from "http";
import { createServer as createHttpsServer } from "https";

// src/config.ts
function required(env, name) {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
function num(env, name, fallback) {
  const raw = env[name];
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number`);
  return value;
}
function isLoopback(host) {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}
function loadConfig(env = process.env) {
  const cert = env.EXIT_RELAY_TLS_CERT ?? null;
  const key = env.EXIT_RELAY_TLS_KEY ?? null;
  if (Boolean(cert) !== Boolean(key)) throw new Error("EXIT_RELAY_TLS_CERT and EXIT_RELAY_TLS_KEY go together");
  const host = env.EXIT_RELAY_HOST ?? "0.0.0.0";
  if (!cert && !isLoopback(host) && env.EXIT_RELAY_ALLOW_PLAINTEXT !== "1") {
    throw new Error(`refusing to listen on ${host} without TLS: set EXIT_RELAY_TLS_CERT/_KEY, or EXIT_RELAY_ALLOW_PLAINTEXT=1 if something else terminates TLS`);
  }
  const controlPlaneTimeoutMs = num(env, "EXIT_RELAY_CONTROL_PLANE_TIMEOUT_MS", 1e4);
  const upstreamConnectTimeoutMs = num(env, "EXIT_RELAY_UPSTREAM_TIMEOUT_MS", 15e3);
  const slack = 5e3;
  const answerDeadlineMs = num(env, "EXIT_RELAY_ANSWER_DEADLINE_MS", controlPlaneTimeoutMs + upstreamConnectTimeoutMs + slack);
  if (answerDeadlineMs <= controlPlaneTimeoutMs + upstreamConnectTimeoutMs) {
    throw new Error(
      `EXIT_RELAY_ANSWER_DEADLINE_MS must be more than EXIT_RELAY_CONTROL_PLANE_TIMEOUT_MS + EXIT_RELAY_UPSTREAM_TIMEOUT_MS (${controlPlaneTimeoutMs} + ${upstreamConnectTimeoutMs}), or it fires on connections that were about to work`
    );
  }
  return {
    host,
    port: num(env, "EXIT_RELAY_PORT", 8443),
    tlsCertPath: cert,
    tlsKeyPath: key,
    healthHost: env.EXIT_RELAY_HEALTH_HOST ?? "127.0.0.1",
    healthPort: num(env, "EXIT_RELAY_HEALTH_PORT", 8080),
    tokenSecret: required(env, "EXIT_RELAY_TOKEN_SECRET"),
    upstreamHost: env.EXIT_RELAY_UPSTREAM_HOST ?? "proxy.apify.com",
    upstreamPort: num(env, "EXIT_RELAY_UPSTREAM_PORT", 8e3),
    upstreamGroups: env.EXIT_RELAY_UPSTREAM_GROUPS ?? "RESIDENTIAL",
    upstreamPassword: required(env, "EXIT_RELAY_UPSTREAM_PASSWORD"),
    controlPlaneUrl: required(env, "EXIT_RELAY_CONTROL_PLANE_URL").replace(/\/+$/, ""),
    meteringSecret: required(env, "EXIT_RELAY_METERING_SECRET"),
    relayId: env.EXIT_RELAY_ID ?? "relay-1",
    flushIntervalMs: num(env, "EXIT_RELAY_FLUSH_INTERVAL_MS", 2e4),
    balanceTtlMs: num(env, "EXIT_RELAY_BALANCE_TTL_MS", 6e4),
    maxConnectionsPerOrg: num(env, "EXIT_RELAY_MAX_CONNS_PER_ORG", 64),
    maxConnectionsTotal: num(env, "EXIT_RELAY_MAX_CONNS_TOTAL", 2e3),
    maxConnectsPerMinutePerOrg: num(env, "EXIT_RELAY_MAX_CONNECTS_PER_MIN", 600),
    idleTimeoutMs: num(env, "EXIT_RELAY_IDLE_TIMEOUT_MS", 12e4),
    controlPlaneTimeoutMs,
    upstreamConnectTimeoutMs,
    answerDeadlineMs
  };
}

// src/metering.ts
import { randomUUID } from "crypto";
var MAX_REPORTS_PER_CALL = 500;
var Ledger = class {
  opts;
  /** Bytes counted since the last flush, by org. */
  pending = /* @__PURE__ */ new Map();
  /** Reports built but not yet accepted by the control plane; retried with the same keys. */
  unsent = [];
  balances = /* @__PURE__ */ new Map();
  inflightRefresh = /* @__PURE__ */ new Map();
  constructor(options) {
    this.opts = {
      url: options.url,
      secret: options.secret,
      relayId: options.relayId,
      balanceTtlMs: options.balanceTtlMs,
      requestTimeoutMs: options.requestTimeoutMs ?? 1e4,
      maxPendingReports: options.maxPendingReports ?? 5e3,
      fetchImpl: options.fetchImpl ?? fetch,
      now: options.now ?? Date.now
    };
  }
  /** Count bytes and take them off the cached balance straight away (see the header comment). */
  record(organizationId, tokenId, bytes) {
    if (bytes <= 0) return;
    const entry = this.pending.get(organizationId);
    if (entry) {
      entry.bytes += bytes;
      entry.tokenId = tokenId;
    } else {
      this.pending.set(organizationId, { bytes, connections: 0, tokenId, since: this.opts.now() });
    }
    const cached = this.balances.get(organizationId);
    if (cached) cached.remainingBytes = Math.max(0, cached.remainingBytes - bytes);
  }
  /** One more connection served this period, for the ledger's own connection count. */
  countConnection(organizationId, tokenId) {
    const entry = this.pending.get(organizationId);
    if (entry) {
      entry.connections += 1;
      entry.tokenId = tokenId;
    } else {
      this.pending.set(organizationId, { bytes: 0, connections: 1, tokenId, since: this.opts.now() });
    }
  }
  /** What the relay believes is left, without asking. Null when it has never been told. */
  cachedRemaining(organizationId) {
    const cached = this.balances.get(organizationId);
    if (!cached) return null;
    if (this.opts.now() - cached.at > this.opts.balanceTtlMs) return null;
    return cached.remainingBytes;
  }
  /**
   * The cached balance ignoring its age, for a connection already being relayed. Staleness is a
   * reason to ask before admitting a new connection, never a reason to cut a live one: the number
   * here is the admitted balance minus what this org has moved since, and a flush that lands
   * mid-connection (a credit pack bought while the agent was running) raises it.
   */
  liveRemaining(organizationId) {
    return this.balances.get(organizationId)?.remainingBytes ?? null;
  }
  isRevoked(organizationId, tokenId) {
    return this.balances.get(organizationId)?.revoked.has(tokenId) ?? false;
  }
  /**
   * The balance, asking the control plane when the cached one is missing or stale. Concurrent
   * callers for the same org share one request, so a burst of new connections is one round trip.
   */
  async remaining(organizationId) {
    const cached = this.cachedRemaining(organizationId);
    if (cached !== null) return cached;
    const existing = this.inflightRefresh.get(organizationId);
    if (existing) return await existing;
    const request = this.send([], [organizationId]).then(() => this.cachedRemaining(organizationId));
    this.inflightRefresh.set(organizationId, request);
    try {
      return await request;
    } finally {
      this.inflightRefresh.delete(organizationId);
    }
  }
  /** Turn what has been counted into reports. Exposed for the flush path and for tests. */
  drain() {
    const now = new Date(this.opts.now());
    const reports = [];
    for (const [organizationId, entry] of this.pending) {
      if (entry.bytes <= 0 && entry.connections <= 0) continue;
      reports.push({
        key: randomUUID(),
        organizationId,
        tokenId: entry.tokenId,
        bytes: entry.bytes,
        connections: entry.connections,
        from: new Date(entry.since).toISOString(),
        to: now.toISOString()
      });
    }
    this.pending.clear();
    return reports;
  }
  /**
   * Ship what has been counted and take the balances back. `refresh` asks for organizations that
   * moved no bytes, which is how a first connection learns whether it may proceed.
   *
   * Reports the control plane did not accept are kept, with their keys, for the next attempt.
   */
  async flush(refresh = []) {
    const all = [...this.unsent, ...this.drain()];
    this.unsent = [];
    if (all.length === 0 && refresh.length === 0) return;
    const chunks = [];
    for (let i = 0; i < all.length; i += MAX_REPORTS_PER_CALL) chunks.push(all.slice(i, i + MAX_REPORTS_PER_CALL));
    if (chunks.length === 0) chunks.push([]);
    for (const [index, chunk] of chunks.entries()) {
      await this.send(chunk, index === 0 ? refresh : []);
    }
  }
  async send(reports, refresh) {
    let response;
    try {
      response = await this.opts.fetchImpl(`${this.opts.url}/api/exit-relay/usage`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${this.opts.secret}` },
        body: JSON.stringify({ relay: this.opts.relayId, reports, refresh }),
        signal: AbortSignal.timeout(this.opts.requestTimeoutMs)
      });
    } catch (error) {
      this.keep(reports);
      console.error("[exit-relay] usage report failed", { reports: reports.length, error: String(error) });
      return;
    }
    if (!response.ok) {
      if (response.status >= 500 || response.status === 429) this.keep(reports);
      console.error("[exit-relay] usage report refused", { status: response.status, reports: reports.length });
      return;
    }
    let body;
    try {
      body = await response.json();
    } catch (error) {
      console.error("[exit-relay] usage reply was not JSON", { error: String(error) });
      return;
    }
    const at = this.opts.now();
    for (const org of body.orgs ?? []) {
      if (!org?.organizationId || !Number.isFinite(org.remainingBytes)) continue;
      const sinceDrain = this.pending.get(org.organizationId)?.bytes ?? 0;
      this.balances.set(org.organizationId, {
        remainingBytes: Math.max(0, org.remainingBytes - sinceDrain),
        at,
        revoked: new Set(org.revokedTokenIds ?? [])
      });
    }
    this.forgetIdleOrgs(at);
  }
  /**
   * Drop organizations that have not been heard from for several balance lifetimes. A relay is
   * shared and long-lived, so an entry per organization that ever connected is unbounded growth;
   * the next connection asks again, which is what a missing entry already means.
   */
  forgetIdleOrgs(at) {
    const cutoff = at - this.opts.balanceTtlMs * 10;
    for (const [organizationId, cached] of this.balances) {
      if (cached.at < cutoff && !this.pending.has(organizationId)) this.balances.delete(organizationId);
    }
  }
  keep(reports) {
    this.unsent = [...this.unsent, ...reports].slice(-this.opts.maxPendingReports);
  }
  /** For the health endpoint: how much is waiting to be reported. */
  stats() {
    return { pendingOrgs: this.pending.size, unsentReports: this.unsent.length, knownOrgs: this.balances.size };
  }
};

// src/limits.ts
var Limiter = class {
  constructor(maxPerOrg, maxTotal, maxConnectsPerMinute, now = Date.now) {
    this.maxPerOrg = maxPerOrg;
    this.maxTotal = maxTotal;
    this.maxConnectsPerMinute = maxConnectsPerMinute;
    this.now = now;
  }
  open = /* @__PURE__ */ new Map();
  total = 0;
  /** Timestamps of recent CONNECTs, per org, trimmed to the last minute on every check. */
  recent = /* @__PURE__ */ new Map();
  /** Called once per CONNECT. Records the attempt only when it is allowed. */
  admit(organizationId) {
    if (this.total >= this.maxTotal) return { ok: false, reason: "total_connections" };
    if ((this.open.get(organizationId) ?? 0) >= this.maxPerOrg) return { ok: false, reason: "org_connections" };
    const at = this.now();
    const window = (this.recent.get(organizationId) ?? []).filter((t) => at - t < 6e4);
    if (window.length >= this.maxConnectsPerMinute) {
      this.recent.set(organizationId, window);
      return { ok: false, reason: "connect_rate" };
    }
    window.push(at);
    this.recent.set(organizationId, window);
    this.open.set(organizationId, (this.open.get(organizationId) ?? 0) + 1);
    this.total += 1;
    return { ok: true };
  }
  release(organizationId) {
    const count = this.open.get(organizationId) ?? 0;
    if (count <= 1) this.open.delete(organizationId);
    else this.open.set(organizationId, count - 1);
    if (this.total > 0) this.total -= 1;
  }
  /**
   * Forget organizations that have stopped connecting. A relay is shared and runs for months, so
   * an entry per organization that ever opened a tunnel would only ever grow; the rate window is
   * a minute, so anything older than that carries no information.
   */
  sweep() {
    const at = this.now();
    for (const [organizationId, window] of this.recent) {
      if (window.every((t) => at - t >= 6e4) && !this.open.has(organizationId)) this.recent.delete(organizationId);
    }
  }
  stats() {
    return { open: this.total, orgs: this.open.size };
  }
};

// src/upstream.ts
import { connect } from "net";
var UpstreamError = class extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
};
function upstreamUsername(groups, session, country) {
  return [`groups-${groups}`, country ? `country-${country.toUpperCase()}` : null, session ? `session-${session}` : null].filter(Boolean).join(",");
}
function connectRequest(target, options) {
  const authority = `${target.host}:${target.port}`;
  const auth = Buffer.from(`${upstreamUsername(options.groups, options.session, options.country)}:${options.password}`, "utf8").toString("base64");
  return [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`, `Proxy-Authorization: Basic ${auth}`, "Proxy-Connection: keep-alive", "", ""].join("\r\n");
}
function openUpstream(target, options) {
  const timeoutMs = options.connectTimeoutMs ?? 15e3;
  return new Promise((resolve, reject) => {
    const socket = connect({ host: options.host, port: options.port });
    let buffer = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => fail(new UpstreamError("the residential exit did not answer in time", null)), timeoutMs);
    function cleanup() {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
    }
    function fail(error) {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      reject(error);
    }
    function onError(error) {
      fail(new UpstreamError(`the residential exit refused the connection (${error.message})`, null));
    }
    function onClose() {
      fail(new UpstreamError("the residential exit closed the connection", null));
    }
    function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf("\r\n\r\n");
      if (end < 0) {
        if (buffer.length > 16384) fail(new UpstreamError("the residential exit sent a malformed reply", null));
        return;
      }
      const statusLine = buffer.subarray(0, buffer.indexOf("\r\n") < 0 ? end : buffer.indexOf("\r\n")).toString("latin1");
      const status = Number(/^HTTP\/1\.[01]\s+(\d{3})/.exec(statusLine)?.[1]);
      if (!Number.isFinite(status) || status < 200 || status > 299) {
        const where = options.country ? ` asking for an address in ${options.country}` : "";
        fail(
          new UpstreamError(
            `the residential exit answered ${Number.isFinite(status) ? status : "an unreadable status"}${where}`,
            Number.isFinite(status) ? status : null
          )
        );
        return;
      }
      settled = true;
      cleanup();
      resolve({ socket, head: buffer.subarray(end + 4) });
    }
    socket.on("error", onError);
    socket.on("close", onClose);
    socket.on("data", onData);
    socket.on("connect", () => socket.write(connectRequest(target, options)));
  });
}

// src/tokens.ts
import { createHmac, randomBytes, timingSafeEqual } from "crypto";
var PREFIX = "ccx1";
function mac(secret, body) {
  return createHmac("sha256", secret).update(body).digest();
}
function verifyToken(secret, token) {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== PREFIX) return null;
  const expected = mac(secret, `${parts[0]}.${parts[1]}`);
  let given;
  try {
    given = Buffer.from(parts[2], "base64url");
  } catch {
    return null;
  }
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (typeof payload?.o !== "string" || !payload.o || typeof payload?.i !== "string" || !payload.i) return null;
    return payload;
  } catch {
    return null;
  }
}
function parseProxyAuthorization(header) {
  if (!header) return null;
  const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header.trim());
  if (!match) return null;
  let decoded;
  try {
    decoded = Buffer.from(match[1], "base64").toString("utf8");
  } catch {
    return null;
  }
  const colon = decoded.indexOf(":");
  if (colon < 0) return null;
  return { username: decoded.slice(0, colon), password: decoded.slice(colon + 1) };
}
function sessionFromUsername(username) {
  for (const part of username.split(",")) {
    const m = /^session-([A-Za-z0-9_-]{1,40})$/.exec(part.trim());
    if (m) return m[1];
  }
  return null;
}
function countryFromUsername(username) {
  for (const part of username.split(",")) {
    const raw = part.trim();
    if (!raw.toLowerCase().startsWith("country-")) continue;
    const value = raw.slice("country-".length);
    if (/^[A-Za-z]{2}$/.test(value)) return { country: value.toUpperCase(), malformed: null };
    return { country: null, malformed: value.slice(0, 16) };
  }
  return { country: null, malformed: null };
}

// src/relay.ts
var DEFAULT_ANSWER_DEADLINE_MS = 2e4;
var BASIC_REALM = 'Proxy-Authenticate: Basic realm="controlclaw-exit"';
function looksLikeTls(head) {
  return head.length >= 3 && head[0] === 22 && head[1] === 3;
}
function refuse(socket, status, text, extraHeaders = []) {
  const body = `${text}
`;
  const headers = [
    `HTTP/1.1 ${status} ${text}`,
    ...extraHeaders,
    "Content-Type: text/plain; charset=utf-8",
    `Content-Length: ${Buffer.byteLength(body)}`,
    "Connection: close",
    "",
    body
  ].join("\r\n");
  socket.end(headers);
}
function parseAuthority(authority) {
  const match = /^(\[[0-9a-fA-F:]+\]|[^:]+):(\d{1,5})$/.exec(authority);
  if (!match) return null;
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host: match[1].replace(/^\[|\]$/g, ""), port };
}
var ExitRelay = class {
  deps;
  dial;
  cut = 0;
  constructor(deps) {
    this.deps = deps;
    this.dial = deps.dial ?? openUpstream;
  }
  /** Anything that is not a CONNECT. The relay is not an HTTP proxy and says so. */
  handleRequest = (_request, response) => {
    response.writeHead(405, { "content-type": "text/plain; charset=utf-8", connection: "close" });
    response.end("This exit accepts CONNECT for TLS only.\n");
  };
  handleConnect = (request, clientSocket, head) => {
    void this.serve(request, clientSocket, head).catch((error) => {
      console.error("[exit-relay] connection failed", { error: String(error) });
      clientSocket.destroy();
    });
  };
  async serve(request, clientSocket, head) {
    clientSocket.on("error", () => clientSocket.destroy());
    let answered = false;
    const deny = (status, text, reason, extra = {}) => {
      if (answered) return;
      answered = true;
      console.warn("[exit-relay] refused", {
        status,
        reason,
        ...extra.organizationId ? { organizationId: extra.organizationId } : {},
        ...extra.detail ? { detail: extra.detail } : {}
      });
      refuse(clientSocket, status, text, extra.headers ?? []);
    };
    const deadline = setTimeout(() => deny(503, "This exit is not answering right now", "answer_deadline"), this.deps.answerDeadlineMs ?? DEFAULT_ANSWER_DEADLINE_MS);
    deadline.unref();
    try {
      const target = parseAuthority(request.url ?? "");
      if (!target) return deny(400, "Bad CONNECT target", "bad_target");
      if (target.port === 80) {
        return deny(403, "This exit carries TLS only, not plain HTTP", "plain_http");
      }
      const credentials = parseProxyAuthorization(request.headers["proxy-authorization"]);
      const payload = credentials ? verifyToken(this.deps.tokenSecret, credentials.password) : null;
      if (!payload) {
        return deny(407, "Proxy authentication required", credentials ? "bad_token" : "no_token", { headers: [BASIC_REALM] });
      }
      const organizationId = payload.o;
      const tokenId = payload.i;
      if (this.deps.ledger.isRevoked(organizationId, tokenId)) {
        return deny(407, "This exit token has been replaced", "revoked_token", { organizationId, headers: [BASIC_REALM] });
      }
      const admitted = this.deps.limiter.admit(organizationId);
      if (!admitted.ok) {
        const status = admitted.reason === "total_connections" ? 503 : 429;
        return deny(status, admitted.reason === "connect_rate" ? "Too many connections a minute" : "Too many connections open", admitted.reason, { organizationId });
      }
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        this.deps.limiter.release(organizationId);
      };
      clientSocket.once("close", release);
      const remaining = await this.deps.ledger.remaining(organizationId);
      if (answered) return;
      if (remaining === null) {
        return deny(503, "This exit cannot check your balance right now", "no_balance", { organizationId });
      }
      if (remaining <= 0) {
        return deny(402, "Your residential exit balance is used up", "balance_empty", { organizationId });
      }
      const requested = countryFromUsername(credentials?.username ?? "");
      if (requested.malformed !== null) {
        return deny(400, "That exit country is not a two-letter country code", "bad_country", {
          organizationId,
          detail: requested.malformed
        });
      }
      let upstreamSocket;
      let upstreamHead;
      try {
        const opened = await this.dial(target, {
          host: this.deps.upstream.host,
          port: this.deps.upstream.port,
          groups: this.deps.upstream.groups,
          password: this.deps.upstream.password,
          session: sessionFromUsername(credentials?.username ?? ""),
          country: requested.country,
          connectTimeoutMs: this.deps.upstream.connectTimeoutMs
        });
        upstreamSocket = opened.socket;
        upstreamHead = opened.head;
      } catch (error) {
        const message = error instanceof UpstreamError ? error.message : "the residential exit is unavailable";
        return deny(502, message, "upstream_refused", { organizationId, detail: message });
      }
      if (answered || clientSocket.destroyed) {
        upstreamSocket.destroy();
        return;
      }
      answered = true;
      this.deps.ledger.countConnection(organizationId, tokenId);
      clientSocket.write("HTTP/1.1 200 Connection established\r\n\r\n");
      this.pipe({ clientSocket, upstreamSocket, head, upstreamHead, organizationId, tokenId, release });
    } finally {
      clearTimeout(deadline);
    }
  }
  pipe(args) {
    const { clientSocket, upstreamSocket, organizationId, tokenId } = args;
    let checkedTls = false;
    let pending = Buffer.alloc(0);
    const close = () => {
      clientSocket.destroy();
      upstreamSocket.destroy();
      args.release();
    };
    const charge = (bytes) => {
      this.deps.ledger.record(organizationId, tokenId, bytes);
      const left = this.deps.ledger.liveRemaining(organizationId);
      if (left !== null && left <= 0) {
        this.cut += 1;
        console.warn("[exit-relay] balance exhausted mid-connection", { organizationId });
        close();
      }
    };
    const fromClient = (chunk) => {
      let out = chunk;
      if (!checkedTls) {
        pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
        if (pending.length < 3) return;
        if (!looksLikeTls(pending)) {
          console.warn("[exit-relay] refused a tunnel that did not start with TLS", { organizationId });
          close();
          return;
        }
        checkedTls = true;
        out = pending;
        pending = Buffer.alloc(0);
      }
      charge(out.length);
      if (!upstreamSocket.write(out)) clientSocket.pause();
    };
    const fromUpstream = (chunk) => {
      charge(chunk.length);
      if (!clientSocket.write(chunk)) upstreamSocket.pause();
    };
    clientSocket.on("data", fromClient);
    upstreamSocket.on("data", fromUpstream);
    upstreamSocket.on("drain", () => clientSocket.resume());
    clientSocket.on("drain", () => upstreamSocket.resume());
    clientSocket.setTimeout(this.deps.idleTimeoutMs, close);
    upstreamSocket.setTimeout(this.deps.idleTimeoutMs, close);
    clientSocket.on("end", () => upstreamSocket.end());
    upstreamSocket.on("end", () => clientSocket.end());
    clientSocket.on("close", close);
    upstreamSocket.on("close", close);
    clientSocket.on("error", close);
    upstreamSocket.on("error", close);
    if (args.upstreamHead.length) fromUpstream(args.upstreamHead);
    if (args.head.length) fromClient(args.head);
  }
  stats() {
    return { cutForBalance: this.cut };
  }
};

// src/index.ts
var BUILD = {
  version: true ? "0.1.0" : "dev",
  commit: true ? "31ad498" : "unknown",
  at: true ? "2026-09-25T17:20:03+01:00" : "unknown"
};
function main() {
  const config = loadConfig();
  const ledger = new Ledger({
    url: config.controlPlaneUrl,
    secret: config.meteringSecret,
    relayId: config.relayId,
    balanceTtlMs: config.balanceTtlMs,
    requestTimeoutMs: config.controlPlaneTimeoutMs
  });
  const limiter = new Limiter(config.maxConnectionsPerOrg, config.maxConnectionsTotal, config.maxConnectsPerMinutePerOrg);
  const relay = new ExitRelay({
    ledger,
    limiter,
    tokenSecret: config.tokenSecret,
    upstream: {
      host: config.upstreamHost,
      port: config.upstreamPort,
      groups: config.upstreamGroups,
      password: config.upstreamPassword,
      connectTimeoutMs: config.upstreamConnectTimeoutMs
    },
    idleTimeoutMs: config.idleTimeoutMs,
    answerDeadlineMs: config.answerDeadlineMs
  });
  const server = config.tlsCertPath && config.tlsKeyPath ? createHttpsServer({ cert: readFileSync(config.tlsCertPath), key: readFileSync(config.tlsKeyPath) }) : createHttpServer();
  server.on("connect", relay.handleConnect);
  server.on("request", relay.handleRequest);
  server.on("clientError", (_error, socket) => socket.destroy());
  server.listen(config.port, config.host, () => {
    console.log("[exit-relay] listening", {
      address: `${config.host}:${config.port}`,
      tls: Boolean(config.tlsCertPath),
      upstream: `${config.upstreamHost}:${config.upstreamPort}`,
      groups: config.upstreamGroups,
      build: BUILD
    });
  });
  const health = createHttpServer((request, response) => {
    if (request.url !== "/health") {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        ok: true,
        build: BUILD,
        relay: config.relayId,
        uptimeSeconds: Math.round(process.uptime()),
        connections: limiter.stats(),
        ledger: ledger.stats(),
        relayStats: relay.stats()
      })
    );
  });
  health.listen(config.healthPort, config.healthHost);
  const timer = setInterval(() => {
    limiter.sweep();
    void ledger.flush();
  }, config.flushIntervalMs);
  timer.unref();
  let stopping = false;
  const stop = (signal) => {
    if (stopping) return;
    stopping = true;
    console.log("[exit-relay] stopping", { signal });
    clearInterval(timer);
    server.close();
    health.close();
    void ledger.flush().finally(() => process.exit(0));
    setTimeout(() => process.exit(0), 5e3).unref();
  };
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
}
main();
