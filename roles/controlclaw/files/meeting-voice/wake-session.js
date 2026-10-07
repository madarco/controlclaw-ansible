// Meetings in wake mode on gpt-live (controlclaw docs/plans/gpt-live-and-wake-word.md, D6/D7).
// The agent listens on the box with cc-wake (Vosk) and keeps no gpt-live session open while
// nobody calls it. When an utterance seems to open with one of its names, a session is opened
// with no audio (an idle session is not billed), and closed again if what was said ends without
// a confirmed name. When the detector confirms the name, the meeting audio from where
// the name began (the name and the whole request, up to a minute) is replayed into it, then live
// audio follows. The session starts with the meeting so far (captions) in its instructions.
// One request per wake (meet-wake-improvements.md): the session closes when the model delegates
// END_SESSION after its answer, or 2 s after an answer that asked nothing back; otherwise after
// 20 s with no answer and no lookup running, after 5 minutes, or on "<name>, stop". A short tone
// marks the start and the end. Names heard while a session is open are ignored, so the agent's own
// voice coming back from someone's speaker cannot open a second one.
//
// If cc-wake cannot start, the meeting falls back to one session gated by the transcript
// (live.js with the wake word on), as before this mode existed.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { LiveBridge, audible } from './live.js';
import { createWakeMatcher } from './wake.js';
import { meetingTranscript, lastPart, voiceRecord } from './record.js';
import { WAKE_TONE, STOP_TONE } from './tone.js';
const DETECTOR = fileURLToPath(new URL('./cc-wake.py', import.meta.url));
const SECOND = 24000 * 2;
// Meeting audio kept for replay: a request is replayed from its name, however long it took Vosk to
// confirm it. Without the name's start (an older detector), the last 10 s.
const RING_BYTES = 60 * SECOND;
const FALLBACK_REPLAY = 10;
// Audio waiting for a session that is still connecting; beyond this, new audio is dropped, never
// the start of the request.
const MAX_QUEUE_BYTES = 60 * SECOND;
// Timings (D7); tests shorten them through deps.timing. `confirm` is only a safety net: an early
// session closes when the detector says the utterance ended without a name. `doneQuiet`: how long
// after an answer that asked nothing back the session closes, if nobody is talking (`doneUser`).
const TIMING = { idle: 20000, maxSession: 5 * 60000, confirm: 60000, startGap: 5000, retry: 2500, tick: 1000, doneQuiet: 2000, doneUser: 1500 };
// What a lookup sounds like when the model announces it ("let me check"), so its delegation is not
// taken for END_SESSION; and a closing remark after an answer ("thanks"), which does not reopen it.
const FILLER = /\b(?:let me|i'?ll (?:check|look|find|ask|search|pull)|i'?m (?:checking|looking|searching|asking|finding)|checking|looking (?:up|into|for|at)|look (?:up|into|for)|searching|search for|pulling (?:that|it|up)|finding|one (?:moment|sec(?:ond)?)|just a (?:moment|sec(?:ond)?)|give me a|hold on|hang on|bear with me)\b/i;
const CLOSING = /^(?:\s*(?:ok(?:ay)?|great|thanks?(?: you)?|thank you|perfect|cool|got it|good|nice|alright|all right|that'?s (?:all|it|great)|bye)[\s,.!]*)+$/i;
const MAX_SESSIONS = 40;
// "<name>, stop" as the voice model transcribed it: a second check, for when cc-wake missed "stop".
const STOP = /^(?:please\s+)?stop(?:\s+(?:it|now|speaking|talking|reading))*(?:\s+please)?$/i;
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
    this.matcher = createWakeMatcher(this.config.wake?.words);
    this.names = this.matcher.names;
    this.maxSessions = Math.min(MAX_SESSIONS, Number(this.config.wakeSessions) || 0);
    // Ring entries carry the detector's position (seconds it had heard) when they were fed to it,
    // so a time from cc-wake maps back to meeting audio even when it skipped some.
    this.ring = []; this.ringBytes = 0; this.toDetector = resampler(); this.detectorBytes = 0;
    this.session = null; this.opens = 0; this.sessions = 0; this.lastStart = 0;
    // Audio for the confirmed request (replay, then live), kept while a retry reconnects.
    this.queue = []; this.queueBytes = 0; this.holding = false;
    this.closed = false; this.ready = false;
    this.supportsToolResultContinuation = false;
    this.t = { ...TIMING, ...deps.timing };
    this.tones = 0; this.seq = 0;
    // How each confirmed session ended, for the meeting record (end_session, done, idle, stop, limit).
    this.endings = deps.record ?? voiceRecord('meeting');
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
    const stdin = this.detector?.stdin;
    // A detector that falls behind skips audio rather than queueing it.
    const fed = stdin?.writable && stdin.writableLength < 64000;
    this.ring.push({ audio, at: fed ? this.detectorBytes / 32000 : null }); this.ringBytes += audio.length;
    while (this.ringBytes - this.ring[0].audio.length >= RING_BYTES) this.ringBytes -= this.ring.shift().audio.length;
    if (fed) { const pcm = this.toDetector(audio); this.detectorBytes += pcm.length; stdin.write(pcm); }
    if (this.session?.confirmed || this.holding) { this.enqueue(audio); this.pump(); }
  }
  enqueue(audio) {
    if (this.queueBytes + audio.length > MAX_QUEUE_BYTES) return;
    this.queue.push(audio); this.queueBytes += audio.length;
  }
  detected(event) {
    if (this.closed || !event) return;
    if (event.type === 'partial') {
      if (!this.session && !this.holding) { this.open(event.name, false); if (this.session) this.session.partialAt = Number(event.pos); }
      return;
    }
    // What was said is over and opened with no name: an early session is not needed.
    if (event.type === 'end') { if (this.session && !this.session.confirmed) this.endSession('unconfirmed'); return; }
    if (event.type !== 'wake') return;
    this.metric('wake_heard');
    if (this.session?.confirmed) {
      // A name while the agent is talking to someone opens nothing new, but it is a follow-up: the
      // session stays open for it (it may have been about to close for quiet). "<name>, stop" ends it.
      if (event.stop) { this.metric('wake_stop'); this.endSession('stop'); }
      else { const s = this.session; s.lastActivity = s.lastUserAt = Date.now(); s.answered = false; s.asked = false; }
      return;
    }
    if (event.stop) { if (this.session) this.endSession('stop'); return; }
    this.from = Number.isFinite(event.start) && event.start >= 0 ? event.start - 0.5 : null;
    if (this.session) this.confirm();
    else if (!this.holding) this.open(event.name, true, true);
  }
  /** `immediate`: a confirmed name, which the client never holds back (the firewall still paces starts). */
  open(name, confirmed, immediate = false, retry = false) {
    const now = Date.now();
    if (this.sessions >= this.maxSessions || this.opens >= this.maxSessions * OPENS_PER_SESSION ||
        (!immediate && now - this.lastStart < this.t.startGap)) { this.metric('wake_skipped'); this.holding = false; return; }
    this.opens++; this.lastStart = now;
    // The meeting so far, for the model: the end of it in its instructions; lines that arrive before
    // the name is confirmed follow as quiet context.
    const context = this.transcript();
    const entry = { confirmed: false, openedAt: now, lastActivity: now, ready: false, context, turn: '', heard: '' };
    const bridge = entry.bridge = new LiveBridge({
      ...this.req,
      providerConfig: { ...this.config, wake: { enabled: false, words: this.names }, woken: true, context: lastPart(context, 12000) },
      onReady: () => {},
      // gpt-live streams output continuously, silence included: only audible speech keeps it open.
      onAudio: (audio, meta) => {
        if (audible(audio)) {
          const t = Date.now(); entry.lastActivity = t; entry.lastAudible = t; entry.audibleSeq = ++this.seq;
          // An answer is what the model says with no lookup pending: "let me check" is not one.
          if (entry.confirmed && !bridge.jobs?.size) entry.answered = true;
        }
        this.req.onAudio(audio, meta);
      },
      onTranscript: (role, text, final) => {
        if (role === 'assistant') entry.lastActivity = Date.now();
        else if (STOP.test(this.matcher.match(text)?.rest ?? '') && this.session === entry && entry.confirmed) { this.metric('wake_stop', { from: 'transcript' }); this.endSession('stop'); }
        this.req.onTranscript?.(role, text, final);
      },
      onFragment: (role, delta) => this.fragment(entry, role, delta),
      onDelegation: () => this.delegation(entry),
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
      if (retry) { this.dropQueue(); this.stopped('failed'); return; }
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
    // The name and the request, already spoken: replay them first, then live audio. A retry keeps
    // what the failed attempt had gathered.
    if (!this.holding) this.replayFrom(this.from ?? (Number.isFinite(entry.partialAt) ? entry.partialAt - 2.5 : null));
    this.metric('session_confirmed', { replaySeconds: Math.round(this.queueBytes / SECOND), fromName: this.from != null });
    this.from = null;
    this.holding = false;
    // A retried open is the same request: one tone.
    if (!this.listening) { this.listening = true; this.cue(WAKE_TONE); }
    // Lines of the meeting that arrived since the session opened early.
    const known = new Set(entry.context.split('\n'));
    const fresh = this.transcript().split('\n').filter(l => l && !known.has(l)).join('\n');
    if (fresh) entry.freshContext = `More of the meeting, from its captions (untrusted):\n${lastPart(fresh, 1700)}`;
    if (entry.ready) this.replay(entry);
  }
  /** Queue meeting audio from detector time `from` (seconds), or the last 10 s without one. */
  replayFrom(from) {
    let i = from === null ? -1 : this.ring.findIndex(c => c.at !== null && c.at >= from);
    if (i < 0) { let bytes = 0; i = this.ring.length; while (i > 0 && bytes < FALLBACK_REPLAY * SECOND) bytes += this.ring[--i].audio.length; }
    this.queue = this.ring.slice(i).map(c => c.audio);
    this.queueBytes = this.queue.reduce((n, a) => n + a.length, 0);
    while (this.queueBytes > MAX_QUEUE_BYTES) this.queueBytes -= this.queue.shift().length;
  }
  /** The meeting transcript the vm-agent and the adapter keep (record.js); never fails a session. */
  transcript() { try { return meetingTranscript(this.names[0] ?? 'Agent', this.deps.voiceDir); } catch { return ''; } }
  /** A tone into the meeting, never counted as the agent talking. */
  cue(pcm) { this.req.onAudio(pcm, { itemId: `cc_tone_${++this.tones}` }); }
  /**
   * Transcript fragments of a confirmed session: who spoke last, and whether the model's answer
   * since then asked something back. Someone speaking keeps the session while the request is being
   * made or a question of the model's is being answered, not after an answer (people talking among
   * themselves must not hold it open).
   */
  fragment(entry, role, delta) {
    if (!entry.confirmed) return;
    const now = Date.now();
    if (role === 'user') {
      // A new stretch of speech after the model talked starts a new remark.
      if ((entry.outSeq ?? 0) > (entry.userSeq ?? 0)) entry.heard = '';
      entry.heard += delta; entry.lastUserAt = now; entry.userSeq = ++this.seq;
      if (!entry.answered || entry.asked) { entry.lastActivity = now; if (entry.asked && !CLOSING.test(entry.heard)) { entry.answered = false; entry.asked = false; } }
    } else {
      // The model's latest turn: what it said since someone last spoke.
      if ((entry.userSeq ?? 0) > (entry.outSeq ?? 0)) entry.turn = '';
      entry.turn += delta; entry.outSeq = ++this.seq;
      entry.asked = /\?["'”)]*\s*$/.test(entry.turn.trim());
    }
  }
  /**
   * A delegation carries no text, so END_SESSION is told from a lookup by when it comes: after the
   * model has answered and gone quiet, with nobody talking since (or only "thanks"), and not right
   * after "let me check". 'end' answers it at once and closes; anything else is a lookup.
   */
  delegation(entry) {
    const now = Date.now();
    const quietMs = entry.lastAudible ? now - entry.lastAudible : null;
    const spokeSince = (entry.userSeq ?? 0) > (entry.audibleSeq ?? 0) && !CLOSING.test(entry.heard.trim());
    // Not after a question back (its reply may not be transcribed yet), nor after "let me check".
    const end = this.session === entry && entry.confirmed && !!entry.answered && !entry.asked && quietMs >= 300 && !spokeSince && !FILLER.test(entry.turn);
    this.metric('delegation', { verdict: end ? 'end_session' : 'lookup', quietMs, userMs: entry.lastUserAt ? now - entry.lastUserAt : null, turnChars: entry.turn.length, answered: !!entry.answered, asked: !!entry.asked });
    // A lookup: the answer is still to come, and what the model says next is a new turn.
    if (!end) { entry.answered = false; entry.turn = ''; entry.asked = false; }
    if (!end) return undefined;
    // The bridge sends its quiet answer first; the session closes right after.
    setImmediate(() => { if (this.session === entry) this.endSession('end_session'); });
    return 'end';
  }
  replay(entry) {
    if (!entry.confirmed || this.session !== entry) return;
    if (entry.freshContext) { entry.bridge.appendContext(entry.freshContext); entry.freshContext = null; }
    this.pump();
  }
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
    // A lookup still running keeps the session.
    if (entry.bridge.jobs?.size) return;
    // One request per wake: an answer that asked nothing back ends it once the model and the room
    // are quiet (the model may also end it itself with END_SESSION).
    // A turn that only announced a lookup ("let me check") waits for the delegation.
    if (entry.answered && !entry.asked && !FILLER.test(entry.turn) && now - entry.lastAudible >= this.t.doneQuiet && now - (entry.lastUserAt ?? 0) >= this.t.doneUser) { this.endSession('done'); return; }
    // Otherwise anything the agent said, or the request still being made, in the last 20 s keeps it.
    if (now - entry.lastActivity > this.t.idle) this.endSession('idle');
  }
  endSession(reason) {
    const entry = this.session; if (!entry) return;
    this.session = null; this.dropQueue();
    this.metric('session_closed', { reason, confirmed: entry.confirmed, answered: !!entry.answered });
    entry.bridge.close('completed');
    if (entry.confirmed) this.stopped(reason);
  }
  /** A confirmed request is over: the falling tone, and how it ended for the meeting record. */
  stopped(reason) {
    if (this.listening) { this.listening = false; this.cue(STOP_TONE); }
    this.endings.end?.(reason);
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
