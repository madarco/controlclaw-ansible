// What a conversation taught the agent, kept for the organization's brain (T-217).
//
// The vm-agent does the saving: when a conversation has been quiet for a while, or its session ended,
// it starts one agent run that writes a short summary page into the brain. This file only records
// what that run reads, and only while the owner's switch is on (`STATE`, written by the vm-agent):
//
// - agent_end: the user's message and the agent's answer of each finished turn the user started,
//   appended to one spool file per conversation. Heartbeats, cron, hooks (the save runs themselves)
//   and sub-agents are left out.
// - session_end (/new, /reset, an idle or daily reset, compaction): the conversation is marked done,
//   so it is saved without waiting for the quiet period. ControlClaw sets no reset policy, so most
//   conversations end by going quiet instead.
//
// The spool is in the vm-agent's state directory, which is inside the encrypted container on a
// secured box. Nothing here leaves the box.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const STATE = "/opt/controlclaw/state/brain-capture.json";
export const SPOOL = "/opt/controlclaw/state/brain-capture";
/** One conversation's file stops growing here: the oldest turns are dropped. */
export const MAX_FILE_BYTES = 48 * 1024;
const MAX_TEXT = 4000;
const END_REASONS = new Set(["new", "reset", "idle", "daily", "compaction"]);
const SKIP_KEY = /(^|:)(hook|cron|subagent|heartbeat|acp)(:|$)/;

let cached = { mtimeMs: -1, size: -1, enabled: false };

/** Whether the owner's switch is on. Read again only when the file changed. Never throws. */
export function captureEnabled(file = STATE) {
  try {
    const st = fs.statSync(file);
    if (st.mtimeMs !== cached.mtimeMs || st.size !== cached.size) {
      cached = { mtimeMs: st.mtimeMs, size: st.size, enabled: false };
      cached.enabled = JSON.parse(fs.readFileSync(file, "utf8"))?.enabled === true;
    }
    return cached.enabled;
  } catch {
    return false;
  }
}

/** A conversation the agent had with a person, not one of its own background runs. */
export function isConversation(sessionKey, trigger) {
  if (!sessionKey || SKIP_KEY.test(sessionKey)) return false;
  return trigger === undefined || trigger === "user";
}

/** The text of one message, without tool calls, tool results or images. */
export function messageText(m) {
  if (!m || typeof m !== "object") return "";
  const c = m.content;
  if (typeof c === "string") return c;
  if (!Array.isArray(c)) return "";
  return c
    .filter((p) => p && typeof p === "object" && p.type === "text" && typeof p.text === "string")
    .map((p) => p.text)
    .join("\n");
}

/** The finished turn: the last user message and the assistant text after it. Null when there is none. */
export function lastTurn(messages) {
  if (!Array.isArray(messages)) return null;
  let i = messages.length - 1;
  while (i >= 0 && messages[i]?.role !== "user") i--;
  if (i < 0) return null;
  const user = messageText(messages[i]).trim();
  const assistant = messages
    .slice(i + 1)
    .filter((m) => m?.role === "assistant")
    .map(messageText)
    .join("\n")
    .trim();
  if (!user || !assistant) return null;
  return { user: user.slice(0, MAX_TEXT), assistant: assistant.slice(0, MAX_TEXT) };
}

export function spoolFile(sessionKey, dir = SPOOL) {
  return path.join(dir, `${crypto.createHash("sha256").update(sessionKey).digest("hex").slice(0, 32)}.jsonl`);
}

function append(file, line) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  let lines = [];
  try {
    lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  } catch {}
  lines.push(JSON.stringify(line));
  // Keep the newest turns under the cap; the first line names the conversation.
  while (lines.length > 2 && Buffer.byteLength(lines.join("\n")) > MAX_FILE_BYTES) lines.splice(1, 1);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${lines.join("\n")}\n`, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** agent_end: record the turn. */
export function recordTurn(event, ctx, dir = SPOOL, enabled = captureEnabled) {
  try {
    if (!enabled() || !event?.success || !isConversation(ctx?.sessionKey, ctx?.trigger)) return false;
    const turn = lastTurn(event.messages);
    if (!turn) return false;
    const file = spoolFile(ctx.sessionKey, dir);
    if (!fs.existsSync(file)) append(file, { session: ctx.sessionKey, channel: ctx.channel ?? null });
    append(file, { at: new Date().toISOString(), ...turn });
    return true;
  } catch {
    return false;
  }
}

/** session_end: the conversation is over; the vm-agent saves it at its next look. */
export function markEnded(event, ctx, dir = SPOOL, enabled = captureEnabled) {
  try {
    const key = event?.sessionKey ?? ctx?.sessionKey;
    if (!enabled() || !END_REASONS.has(event?.reason) || !isConversation(key)) return false;
    const file = spoolFile(key, dir);
    if (!fs.existsSync(file)) return false;
    append(file, { ended: event.reason, at: new Date().toISOString() });
    return true;
  } catch {
    return false;
  }
}
