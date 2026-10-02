import { existsSync } from "node:fs";
export default {
  id: "cc-meeting-guard",
  register(api) {
    api.on("before_tool_call", event => {
      // The box page is the only supported inviter in this release. This hook reserves
      // automation, not a boundary against an agent with arbitrary shell/root access.
      if (event.toolName === "google_meet") return { block: true, blockReason: "Use the owner's enrolled Meetings page." };
      if (event.toolName === "browser" && (event.params.profile === "cc-meetings" || existsSync("/opt/controlclaw/state/meeting-browser-reserved"))) {
        return { block: true, blockReason: "The guest browser is reserved for the owner's meeting. Stop the meeting before browser automation." };
      }
    }, { priority: 1000 });
  },
};
