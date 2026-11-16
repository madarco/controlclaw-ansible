// What ControlClaw tells the agent about its own box, on every turn of every harness (T-oc114).
//
// The vm-agent writes ~/.openclaw/workspace/controlclaw/AGENTS.md: where the Google Drive folders
// are mounted (outside the workspace, so OpenClaw's doctor does not read them) and the owner's
// standing orders for meetings. The user's own AGENTS.md is left to the user.
//
// Not OpenClaw's bootstrap-extra-files hook: the Codex harness leaves out every context file named
// AGENTS.md, because Codex reads the workspace's root AGENTS.md itself (nativeProjectDocBasenames),
// and Codex never reads one in a subfolder, so the file would not reach a Codex turn. This hook adds
// it to the system context of the embedded (Pi), Codex and Copilot harnesses alike, sub-agents
// included.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const MAX_CHARS = 20_000;

export function contextFile(env = process.env) {
  return path.join(env.HOME || os.homedir(), ".openclaw", "workspace", "controlclaw", "AGENTS.md");
}

let cached = { mtimeMs: -1, size: -1, text: "" };

/** The file's text, read again only when it changed. Empty when there is none. Never throws. */
export function readContext(file = contextFile()) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return "";
    if (st.mtimeMs !== cached.mtimeMs || st.size !== cached.size) {
      cached = { mtimeMs: st.mtimeMs, size: st.size, text: fs.readFileSync(file, "utf8").slice(0, MAX_CHARS).trim() };
    }
    return cached.text;
  } catch {
    return "";
  }
}

export function promptContext(text) {
  if (!text) return undefined;
  return { appendSystemContext: `## ControlClaw (controlclaw/AGENTS.md)\n\nWritten by ControlClaw for this agent.\n\n${text}` };
}

export default {
  id: "cc-workspace-context",
  register(api) {
    api.on("before_prompt_build", () => promptContext(readContext()));
  },
};
