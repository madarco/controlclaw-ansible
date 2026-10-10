// What a voice session leaves for the vm-agent (controlclaw docs/plans/gpt-live-and-wake-word.md,
// D8/D11): its billed or connected seconds and, in meetings, what the agent said and heard. One JSON
// line each, in ~/.openclaw/cc-voice/<surface>.jsonl, on the agent box only. The vm-agent (same
// user) merges the lines into the meeting record or call history and empties the file when a
// meeting starts. Never credentials or audio.
import { appendFileSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
const MAX_BYTES = 8 * 1024 * 1024;
const DIR = () => join(process.env.HOME || homedir(), '.openclaw', 'cc-voice');
/**
 * Voice sessions the firewall allows in the current meeting, from its media lease (`wake_sessions`),
 * which the vm-agent writes to lease.json when the meeting starts and removes when it ends. 0 when
 * absent, stale or invalid: then the meeting keeps one session, as before wake mode.
 */
export function meetingWakeSessions(dir = DIR()) {
  try {
    const lease = JSON.parse(readFileSync(join(dir, 'lease.json'), 'utf8'));
    const n = lease?.wakeSessions, at = Date.parse(lease?.at);
    return Number.isInteger(n) && n > 1 && n <= 40 && Date.now() - at < 5 * 3600000 ? n : 0;
  } catch { return 0; }
}
/** The current meeting's lease as the vm-agent wrote it: when it started and the owner's direct chat, if there is one. */
export function meetingLease(dir = DIR()) {
  try { const lease = JSON.parse(readFileSync(join(dir, 'lease.json'), 'utf8')); return { at: typeof lease?.at === 'string' ? lease.at : '', owner: lease?.owner ?? null }; }
  catch { return { at: '', owner: null }; }
}
/** The tail of a JSON-lines file, parsed; at most `max` bytes. */
function tail(file, max = 1024 * 1024) {
  try {
    const size = statSync(file).size;
    const text = readFileSync(file).subarray(Math.max(0, size - max)).toString('utf8');
    return text.split('\n').slice(size > max ? 1 : 0).flatMap(l => { try { return [JSON.parse(l)]; } catch { return []; } });
  } catch { return []; }
}
const clock = at => { const d = new Date(at); return Number.isFinite(d.getTime()) ? d.toISOString().slice(11, 16) : '--:--'; };
/**
 * The meeting so far (meet-wake-improvements.md, 2), oldest first, one "[hh:mm] Speaker: text" line
 * each: the captions the vm-agent writes (captions.jsonl, final lines; captions-live.json, the
 * blocks Meet is still writing, so what someone is saying right now is there too), and the agent's
 * own lines from meeting.jsonl. Without captions (the host turned them off), what the agent heard
 * in its sessions stands in. `final` is false for a block still being written.
 */
export function meetingLines(name, dir = DIR()) {
  const caption = c => typeof c?.text === 'string' && c.text.trim() && typeof c.at === 'string';
  const who = c => typeof c.speaker === 'string' && c.speaker ? c.speaker.slice(0, 80) : 'Someone';
  const finals = tail(join(dir, 'captions.jsonl')).filter(caption).map(c => ({ at: c.at, speaker: who(c), text: c.text, final: true }));
  let live = [];
  try { const rows = JSON.parse(readFileSync(join(dir, 'captions-live.json'), 'utf8'))?.rows; if (Array.isArray(rows)) live = rows.slice(0, 50).filter(caption).map(c => ({ at: c.at, speaker: who(c), text: c.text.slice(-4000), final: false })); } catch { /* none yet */ }
  const voice = tail(join(dir, 'meeting.jsonl')).filter(l => l?.kind === 'line' && typeof l.text === 'string' && typeof l.at === 'string');
  const own = voice.filter(l => l.role === 'assistant').map(l => ({ at: l.at, speaker: name, text: l.text, final: true }));
  const heard = finals.length || live.length ? [] : voice.filter(l => l.role === 'user').map(l => ({ at: l.at, speaker: 'Someone', text: l.text, final: true }));
  return [...finals, ...live, ...own, ...heard].sort((a, b) => Date.parse(a.at) - Date.parse(b.at))
    .map(l => ({ line: `[${clock(l.at)}] ${l.speaker}: ${l.text.replace(/\s+/g, ' ').trim()}`, final: l.final }));
}
export const meetingTranscript = (name, dir = DIR()) => meetingLines(name, dir).map(l => l.line).join('\n');
/** At most `max` characters: the start and the end, with a marker between. */
export function clip(text, max) {
  if (text.length <= max) return text;
  const half = Math.floor((max - 40) / 2);
  return `${text.slice(0, half)}\n[… earlier part of the meeting left out …]\n${text.slice(-half)}`;
}
/** Only the end, cut at a line start. */
export function lastPart(text, max) {
  if (text.length <= max) return text;
  const cut = text.slice(-max); const nl = cut.indexOf('\n');
  return nl >= 0 ? cut.slice(nl + 1) : cut;
}
export function voiceRecord(surface, dir = DIR()) {
  const file = join(dir, `${surface === 'phone' ? 'phone' : 'meeting'}.jsonl`);
  const write = (entry) => {
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      try { if (statSync(file).size > MAX_BYTES) return; } catch { /* first line */ }
      appendFileSync(file, JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 });
    } catch { /* a full disk must not end the call */ }
  };
  return {
    /** A finished provider session: `seconds` billed (live) or connected (realtime). */
    usage(seconds, family, startedAt) { if (Number.isFinite(seconds) && seconds >= 0) write({ kind: 'usage', family, seconds: Math.round(seconds), startedAt: new Date(startedAt).toISOString() }); },
    /** A finished line of the conversation; phone history already has its own transcript. */
    /** How a woken meeting session ended: end_session (the model), done, idle, stop or limit. */
    end(reason) { if (surface !== 'phone' && /^[a-z_]{1,20}$/.test(reason)) write({ kind: 'session', reason }); },
    /** A reminder created for the owner, or a request left for them (actions.js). */
    action(kind, fields) { if (surface !== 'phone' && (kind === 'reminder' || kind === 'request')) write({ kind, ...fields }); },
    /** How many reminders this meeting has set (the log is emptied when a meeting starts). */
    reminders() { return tail(file).filter(l => l?.kind === 'reminder'); },
    line(role, text, startedAt) { if (surface !== 'phone' && typeof text === 'string' && text.trim()) write({ kind: 'line', role: role === 'assistant' ? 'assistant' : 'user', text: text.trim().slice(0, 4000), ...(Number.isFinite(startedAt) ? { at: new Date(startedAt).toISOString() } : {}) }); },
  };
}
