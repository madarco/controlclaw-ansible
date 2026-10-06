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
    line(role, text) { if (surface !== 'phone' && typeof text === 'string' && text.trim()) write({ kind: 'line', role: role === 'assistant' ? 'assistant' : 'user', text: text.trim().slice(0, 4000) }); },
  };
}
