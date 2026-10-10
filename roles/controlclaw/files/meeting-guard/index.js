import { existsSync } from "node:fs";

// The agent's own Chrome (browser-stream.service), the one OpenClaw's default browser profile drives.
const CDP = "http://127.0.0.1:9222";
// OpenClaw gives a screenshot 20 seconds; the hold ends by itself a little after that.
const HOLD_MS = 30_000;
const SCREENCAST = { format: "jpeg", quality: 1, maxWidth: 16, maxHeight: 16, everyNthFrame: 60 };

/**
 * Keep every tab of the agent's Chrome drawing until the returned function is called.
 *
 * That Chrome has a window, and a tab that is not the one in front answers one
 * Page.captureScreenshot and then none, so OpenClaw's screenshot of it waits its 20 seconds out
 * ("timed out. The browser profile is external to OpenClaw...") and the tab stays stuck until
 * someone brings it to front. While any debugger session holds a screencast open on a tab, Chrome
 * keeps drawing it and every capture answers at once, whichever tab is in front. Nothing is read
 * from the pages: the frames are 16 pixels wide and are dropped.
 *
 * Never throws and never waits more than a second per step: a tool call must not fail on this.
 */
export async function keepTabsDrawn({ cdp = CDP, fetchImpl = fetch, connect = (url) => new WebSocket(url) } = {}) {
  const sockets = [];
  const release = () => { for (const ws of sockets.splice(0)) try { ws.close(); } catch {} };
  try {
    const targets = await (await fetchImpl(`${cdp}/json/list`, { signal: AbortSignal.timeout(1000) })).json();
    // Only the loopback debugger of that Chrome, and only its tabs.
    const pages = (Array.isArray(targets) ? targets : []).filter((t) => t?.type === "page" && /^ws:\/\/127\.0\.0\.1:\d+\/devtools\/page\//.test(t.webSocketDebuggerUrl ?? "")).slice(0, 30);
    await Promise.all(pages.map((t) => new Promise((resolve) => {
      const timer = setTimeout(resolve, 1000);
      const done = () => { clearTimeout(timer); resolve(); };
      const ws = connect(t.webSocketDebuggerUrl);
      sockets.push(ws);
      ws.addEventListener("open", () => ws.send(JSON.stringify({ id: 1, method: "Page.startScreencast", params: SCREENCAST })));
      ws.addEventListener("error", done);
      ws.addEventListener("close", done);
      ws.addEventListener("message", (event) => {
        let msg;
        try { msg = JSON.parse(String(event.data)); } catch { return; }
        if (msg.id === 1) done();
        // Chrome sends the next frame only once the last one is acknowledged.
        else if (msg.method === "Page.screencastFrame") ws.send(JSON.stringify({ id: 2, method: "Page.screencastFrameAck", params: { sessionId: msg.params?.sessionId } }));
      });
    })));
  } catch { /* Chrome is not there: the screenshot will say so itself */ }
  return release;
}

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

    // Screenshots of a tab that is not in front (see keepTabsDrawn): held while any screenshot
    // of the agent's own browser is running, and for HOLD_MS at most.
    let drawn = null, running = 0, timer = null;
    const end = () => {
      clearTimeout(timer);
      running = 0;
      const held = drawn;
      drawn = null;
      void held?.then((release) => release());
    };
    const ownScreenshot = (event) => event.toolName === "browser" && event.params?.action === "screenshot" && (!event.params.profile || event.params.profile === "openclaw");
    api.on("before_tool_call", async (event) => {
      if (!ownScreenshot(event)) return;
      running++;
      clearTimeout(timer);
      timer = setTimeout(end, HOLD_MS);
      timer.unref?.();
      await (drawn ??= keepTabsDrawn());
    });
    api.on("after_tool_call", (event) => {
      if (ownScreenshot(event) && --running <= 0) end();
    });
  },
};
