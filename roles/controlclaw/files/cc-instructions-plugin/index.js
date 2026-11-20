// ControlClaw's instructions to the agent, added to every run's system context (T-oc114).
//
// The vm-agent keeps them in /var/lib/controlclaw-instructions/AGENTS.md through the root helper
// cc-instructions: where the Google Drive folders are mounted and the owner's standing orders for
// meetings. Outside the workspace: the agent's file tools, the Files page, a template or a restore
// cannot change them there, and OpenClaw's doctor does not read them. The user's own AGENTS.md is left
// to the user.
//
// A hook rather than a context file: the Codex harness leaves out every context file named AGENTS.md
// (Codex reads the workspace's root one itself), and a file outside the workspace is not a context
// file at all. before_prompt_build runs for the embedded (Pi) and Codex harnesses, sub-agents and
// heartbeats; a plugin from outside OpenClaw's bundle needs hooks.allowConversationAccess for it.
//
// It also keeps what a conversation taught the agent for the organization's brain, while the owner's
// switch for this agent is on (brain-capture.js). agent_end needs the same grant.
import fs from "node:fs";
import { markEnded, recordTurn } from "./brain-capture.js";

const MAX_CHARS = 20_000;
export const FILE = "/var/lib/controlclaw-instructions/AGENTS.md";

let cached = { file: "", mtimeMs: -1, size: -1, text: "" };

/** The file's text, read again only when it changed. Empty when there is none. Never throws. */
// Only this path: not one the box user could name (through the gateway's environment, say).
export function readInstructions(file = FILE) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return "";
    if (file !== cached.file || st.mtimeMs !== cached.mtimeMs || st.size !== cached.size) {
      cached = { file, mtimeMs: st.mtimeMs, size: st.size, text: fs.readFileSync(file, "utf8").slice(0, MAX_CHARS).trim() };
    }
    return cached.text;
  } catch {
    return "";
  }
}

export function promptContext(text) {
  if (!text) return undefined;
  return { appendSystemContext: text };
}

export default {
  id: "cc-instructions",
  register(api) {
    api.on("before_prompt_build", () => promptContext(readInstructions()));
    api.on("agent_end", (event, ctx) => {
      recordTurn(event, ctx);
    });
    api.on("session_end", (event, ctx) => {
      markEnded(event, ctx);
    });
  },
};
