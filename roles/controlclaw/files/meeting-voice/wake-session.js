// Meetings in wake mode on gpt-live (controlclaw docs/plans/gpt-live-and-wake-word.md, D6/D7).
// The agent listens on the box with cc-wake (Vosk) and keeps no gpt-live session open while
// nobody calls it. When an utterance seems to open with one of its names, a session is opened
// with no audio (an idle session is not billed), and closed again if what was said ends without
// a confirmed name. When the detector confirms the name, the last 10 s of meeting audio (the name
// and the request) are replayed into it, then live audio follows.
// The session closes after 20 s with no answer and no lookup running, after 5 minutes, or on
// "<name>, stop". Names heard while a session is open are ignored, so the agent's own voice
// coming back from someone's speaker cannot open a second one.
//
// If cc-wake cannot start, the meeting falls back to one session gated by the transcript
// (live.js with the wake word on), as before this mode existed.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { LiveBridge } from './live.js';
import { createWakeMatcher } from './wake.js';
const DETECTOR = fileURLToPath(new URL('./cc-wake.py', import.meta.url));
const RING_BYTES = 10 * 24000 * 2;
// Audio waiting for a session that is still connecting; beyond this, new audio is dropped, never
// the start of the request.
const MAX_QUEUE_BYTES = 30 * 24000 * 2;
// Timings (D7); tests shorten them through deps.timing. `confirm` is only a safety net: an early
// session closes when the detector says the utterance ended without a name.
const TIMING = { idle: 20000, maxSession: 5 * 60000, confirm: 15000, startGap: 5000, retry: 2500, tick: 1000 };
const MAX_SESSIONS = 40;
// Sessions opened early on a partial result and never confirmed: they cost a token mint, not money.
const OPENS_PER_SESSION = 6;
const REPLAY_CHUNK = 9600; // 200 ms

/** 24 kHz → 16 kHz, linear, carrying the last sample and the position across chunks. */
export function resampler() {
  let carry = null, pos = 0;
  return (pcm) => {
    const samples = carry === null ? [] : [carry];
    for (let i = 0; i + 1 < pcm.length; i += 2) samples.push(pcm.readInt16LE(i));
    const out = [];
    for (; pos + 1 < samples.length; pos += 1.5) {
      const i = Math.floor(pos), f = pos - i;
      out.push(samples[i] + (samples[i + 1] - samples[i]) * f);
    }
    if (samples.length) { pos -= samples.length - 1; carry = samples[samples.length - 1]; }
    const buf = Buffer.alloc(out.length * 2);
    out.forEach((v, i) => buf.writeInt16LE(Math.round(v), i * 2));
    return buf;
  };
}

export class WakeSessionBridge {
  constructor(req, deps) {
    this.req = req; this.deps = deps; this.config = req.providerConfig;
    this.names = createWakeMatcher(this.config.wake?.words).names;
    this.maxSessions = Math.min(MAX_SESSIONS, Number(this.config.wakeSessions) || 0);
    this.ring = []; this.ringBytes = 0; this.toDetector = resampler();
    this.session = null; this.opens = 0; this.sessions = 0; this.lastStart = 0;
    // Audio for the confirmed request (replay, then live), kept while a retry reconnects.
    this.queue = []; this.queueBytes = 0; this.holding = false;
    this.closed = false; this.ready = false;
    this.supportsToolResultContinuation = false;
    this.t = { ...TIMING, ...deps.timing };
  }
  metric(phase, extra = {}) { (this.deps.metric ?? (m => console.info(JSON.stringify(m))))({ event: 'cc.meeting.voice', family: 'live', mode: 'wake', phase, at: Date.now(), ...extra }); }
  async connect() {
    if (this.closed) throw new Error('Voice session closed');
    try { await this.startDetector(); }
    catch {
      if (this.closed) throw new Error('Voice session closed');
      // No local listening: one session for the meeting, gated by the transcript (PR 4 behaviour).
      this.metric('detector_unavailable');
      this.fallback = new LiveBridge(this.req, this.deps);
      return this.fallback.connect();
    }
    if (this.closed) { try { this.detector?.kill(); } catch { /* gone */ } throw new Error('Voice session closed'); }
    this.ready = true;
    this.timer = setInterval(() => this.tick(), this.t.tick); this.timer.unref?.();
    this.req.onReady?.();
  }
  startDetector() {
    return new Promise((resolve, reject) => {
      const child = this.detector = (this.deps.spawn ?? spawn)('/usr/bin/python3', [DETECTOR, ...this.names], { stdio: ['pipe', 'pipe', 'ignore'], env: { PATH: '/usr/bin:/bin', HOME: process.env.HOME ?? '' } });
      const timeout = setTimeout(() => { child.kill(); reject(new Error('Wake detector did not start')); }, 20000);
      let buffered = '', started = false;
      child.stdout.on('data', data => {
        buffered += data;
        if (buffered.length > 65536) { buffered = ''; return; }
        let nl;
        while ((nl = buffered.indexOf('\n')) >= 0) {
          const line = buffered.slice(0, nl); buffered = buffered.slice(nl + 1);
          let event; try { event = JSON.parse(line); } catch { continue; }
          if (event?.type === 'ready' && !started) { started = true; clearTimeout(timeout); resolve(); }
          else if (started) this.detected(event);
        }
      });
      child.stdin.on('error', () => {});
      child.on('error', () => { clearTimeout(timeout); reject(new Error('Wake detector failed')); });
      child.on('exit', () => {
        clearTimeout(timeout);
        if (!started) { reject(new Error('Wake detector exited')); return; }
        // Listening stopped mid-meeting: say so the way any voice failure is said.
        if (!this.closed) this.fail();
      });
    });
  }
  sendAudio(audio) {
    if (this.fallback) return this.fallback.sendAudio(audio);
    if (!this.ready || this.closed || !Buffer.isBuffer(audio) || audio.length % 2 || audio.length > 48000) return;
    this.ring.push(audio); this.ringBytes += audio.length;
    while (this.ringBytes - this.ring[0].length >= RING_BYTES) this.ringBytes -= this.ring.shift().length;
    const stdin = this.detector?.stdin;
    // A detector that falls behind skips audio rather than queueing it.
    if (stdin?.writable && stdin.writableLength < 64000) stdin.write(this.toDetector(audio));
    if (this.session?.confirmed || this.holding) { this.enqueue(audio); this.pump(); }
  }
  enqueue(audio) {
    if (this.queueBytes + audio.length > MAX_QUEUE_BYTES) return;
    this.queue.push(audio); this.queueBytes += audio.length;
  }
  detected(event) {
    if (this.closed || !event) return;
    if (event.type === 'partial') { if (!this.session && !this.holding) this.open(event.name, false); return; }
    // What was said is over and opened with no name: an early session is not needed.
    if (event.type === 'end') { if (this.session && !this.session.confirmed) this.endSession('unconfirmed'); return; }
    if (event.type !== 'wake') return;
    this.metric('wake_heard');
    if (this.session?.confirmed) {
      // A name while the agent is talking to someone is ignored, except "<name>, stop".
      if (event.stop) { this.metric('wake_stop'); this.endSession('stop'); }
      return;
    }
    if (event.stop) { if (this.session) this.endSession('stop'); return; }
    if (this.session) this.confirm();
    else if (!this.holding) this.open(event.name, true, true);
  }
  /** `immediate`: a confirmed name, which the client never holds back (the firewall still paces starts). */
  open(name, confirmed, immediate = false, retry = false) {
    const now = Date.now();
    if (this.sessions >= this.maxSessions || this.opens >= this.maxSessions * OPENS_PER_SESSION ||
        (!immediate && now - this.lastStart < this.t.startGap)) { this.metric('wake_skipped'); this.holding = false; return; }
    this.opens++; this.lastStart = now;
    const entry = { confirmed: false, openedAt: now, lastActivity: now, ready: false };
    const bridge = entry.bridge = new LiveBridge({
      ...this.req,
      providerConfig: { ...this.config, wake: { enabled: false, words: this.names }, woken: true },
      onReady: () => {},
      onAudio: (audio, meta) => { entry.lastActivity = Date.now(); this.req.onAudio(audio, meta); },
      onTranscript: (role, text, final) => { if (role === 'assistant') entry.lastActivity = Date.now(); this.req.onTranscript?.(role, text, final); },
      onToolCall: (call) => { entry.lastActivity = Date.now(); return this.req.onToolCall?.(call); },
      onClearAudio: () => this.req.onClearAudio?.(),
      onError: () => {},
      onClose: () => { if (this.session === entry) this.session = null; },
    }, this.deps);
    this.session = entry;
    this.metric('session_open', { early: !confirmed });
    bridge.connect().then(() => {
      entry.ready = true;
      if (this.session !== entry) { bridge.close(); return; }
      if (entry.confirmed) this.replay(entry);
    }).catch(() => {
      this.metric('session_failed');
      if (this.session !== entry) return;
      this.session = null;
      if (!entry.confirmed) { this.lastStart = 0; return; }
      // The previous session's socket may still be closing (the firewall allows one at a time):
      // a confirmed request gets one more try, with its audio kept meanwhile.
      this.sessions--;
      if (retry) { this.dropQueue(); return; }
      this.holding = true;
      const t = setTimeout(() => { if (!this.closed && !this.session && this.holding) this.open(name, true, true, true); }, this.t.retry); t.unref?.();
    });
    if (confirmed) this.confirm();
  }
  confirm() {
    const entry = this.session;
    if (!entry || entry.confirmed) return;
    if (this.sessions >= this.maxSessions) { this.metric('wake_skipped'); this.endSession('limit'); return; }
    this.sessions++;
    entry.confirmed = true; entry.lastActivity = Date.now(); entry.confirmedAt = Date.now();
    this.metric('session_confirmed');
    // The name and the request, already spoken: replay them first, then live audio. A retry keeps
    // what the failed attempt had gathered.
    if (!this.holding) { this.queue = this.ring.slice(); this.queueBytes = this.ringBytes; }
    this.holding = false;
    if (entry.ready) this.replay(entry);
  }
  replay(entry) { if (entry.confirmed && this.session === entry) this.pump(); }
  /** Replayed and live audio, in order, as fast as the socket takes it. */
  pump() {
    const entry = this.session;
    if (!entry?.ready || !entry.confirmed) return;
    clearTimeout(this.pumpTimer);
    while (this.queue.length && entry.bridge.canSend()) {
      let chunk = this.queue.shift();
      if (chunk.length > REPLAY_CHUNK) { this.queue.unshift(chunk.subarray(REPLAY_CHUNK)); chunk = chunk.subarray(0, REPLAY_CHUNK); }
      this.queueBytes -= chunk.length;
      entry.bridge.appendAudio(chunk);
    }
    if (this.queue.length) { this.pumpTimer = setTimeout(() => this.pump(), 20); this.pumpTimer.unref?.(); }
  }
  tick() {
    const entry = this.session; if (!entry) return;
    const now = Date.now();
    if (!entry.confirmed) { if (now - entry.openedAt > this.t.confirm) this.endSession('unconfirmed'); return; }
    if (now - entry.confirmedAt > this.t.maxSession) { this.endSession('limit'); return; }
    // A lookup still running keeps the session; so does anything the agent said in the last 20 s.
    if (!entry.bridge.jobs?.size && now - entry.lastActivity > this.t.idle) this.endSession('idle');
  }
  endSession(reason) {
    const entry = this.session; if (!entry) return;
    this.session = null; this.dropQueue();
    this.metric('session_closed', { reason });
    entry.bridge.close('completed');
  }
  dropQueue() { this.queue = []; this.queueBytes = 0; this.holding = false; clearTimeout(this.pumpTimer); }
  submitToolResult(callId, result) { (this.fallback ?? this.session?.bridge)?.submitToolResult(callId, result); }
  handleBargeIn() { this.fallback?.handleBargeIn(); }
  sendUserMessage() {}
  triggerGreeting() {}
  setMediaTimestamp() {}
  acknowledgeMark() {}
  isConnected() { return this.fallback ? this.fallback.isConnected() : this.ready && !this.closed; }
  fail() { if (this.closed) return; this.close('completed'); this.req.onError?.(new Error('Meeting voice stopped. Check speech credit, call limits and provider availability.')); }
  close(reason = 'completed') {
    if (this.fallback) return this.fallback.close(reason);
    if (this.closed) return; this.closed = true; this.ready = false;
    clearInterval(this.timer); clearTimeout(this.pumpTimer);
    if (this.session) { this.session.bridge.close('completed'); this.session = null; }
    try { this.detector?.kill(); } catch { /* already gone */ }
    this.req.onClearAudio?.(); this.req.onClose?.(reason);
  }
}
