// OpenClaw gives a screenshot 20 seconds; a hold ends by itself a little after that.
const HOLD_MS = 30_000;
const SCREENCAST = { format: "jpeg", quality: 1, maxWidth: 16, maxHeight: 16, everyNthFrame: 60 };

/**
 * The debugger of the agent's own Chrome (browser-stream.service): what the role wrote into
 * OpenClaw's `openclaw` browser profile from `browser_cdp_port`, else BROWSER_CDP_PORT as the
 * vm-agent reads it, else 9222. Loopback only.
 */
export function ownCdpUrl(config, env = process.env) {
  const url = config?.browser?.profiles?.openclaw?.cdpUrl;
  if (typeof url === "string" && /^http:\/\/127\.0\.0\.1:\d+\/?$/.test(url)) return url.replace(/\/$/, "");
  return `http://127.0.0.1:${/^\d+$/.test(env.BROWSER_CDP_PORT ?? "") ? env.BROWSER_CDP_PORT : "9222"}`;
}

/**
 * Keep tabs of the agent's Chrome drawing until the returned function is called: the one tab
 * `targetId` names, or every tab when it names none Chrome knows.
 *
 * That Chrome has a window, and a tab that is not the one in front answers one
 * Page.captureScreenshot and then none, so OpenClaw's screenshot of it waits its 20 seconds out
 * ("timed out. The browser profile is external to OpenClaw...") and the tab stays stuck until
 * someone brings it to front. While any debugger session holds a screencast open on a tab, Chrome
 * keeps drawing it and every capture answers at once, whichever tab is in front. Nothing is read
 * from the pages: the frames are 16 pixels wide and are dropped.
 *
 * `targetId` is what the agent passed to the browser tool. When it is a Chrome target id, or the
 * start of exactly one, only that tab is held. A screenshot with no targetId, or with one of
 * OpenClaw's own names for a tab (`t2`, a label), goes to a tab this hook cannot tell, so all of
 * them are held, however many there are: a long-lived agent has dozens.
 *
 * Never throws and never waits more than a second per step: a tool call must not fail on this.
 */
export async function keepTabsDrawn({ cdp = ownCdpUrl(), targetId, fetchImpl = fetch, connect = (url) => new WebSocket(url) } = {}) {
  const sockets = [];
  const release = () => { for (const ws of sockets.splice(0)) try { ws.close(); } catch {} };
  try {
    const targets = await (await fetchImpl(`${cdp}/json/list`, { signal: AbortSignal.timeout(1000) })).json();
    // Only the loopback debugger of that Chrome, and only its tabs.
    let pages = (Array.isArray(targets) ? targets : []).filter((t) => t?.type === "page" && /^ws:\/\/127\.0\.0\.1:\d+\/devtools\/page\//.test(t.webSocketDebuggerUrl ?? ""));
    const wanted = typeof targetId === "string" ? targetId.trim().toLowerCase() : "";
    const named = wanted.length >= 4 ? pages.filter((t) => String(t.id ?? "").toLowerCase().startsWith(wanted)) : [];
    if (named.length === 1) pages = named;
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

/** The meeting's own Chrome (cc-meeting-browser.service): its profile name and its debugger port. */
const MEETING_PROFILE = "cc-meetings";
const MEETING_CDP_PORT = 9223;

/**
 * The browser profiles that reach the meeting's Chrome: `cc-meetings`, and any profile in OpenClaw's
 * config whose debugger is port 9223. Lower case: names are matched without regard to case.
 */
export function meetingProfiles(config) {
  const names = new Set([MEETING_PROFILE]);
  for (const [name, profile] of Object.entries(config?.browser?.profiles ?? {})) {
    const url = typeof profile?.cdpUrl === "string" ? profile.cdpUrl : "";
    if (profile?.cdpPort === MEETING_CDP_PORT || new RegExp(`:${MEETING_CDP_PORT}(?![0-9])`).test(url)) names.add(name.toLowerCase());
  }
  return names;
}

/**
 * True when a browser tool call would reach the meeting's Chrome. The tool takes no debugger URL of
 * its own: it reaches a browser by a profile name from the config (`profile`, or the default one
 * when it names none), and `importprofile` reads and writes profiles by name (`browser`,
 * `systemProfile`, `into`). The agent's own browser (port 9222, profile `openclaw`) stays usable
 * during a meeting: the meeting has had its own Chrome since meetings got one.
 */
export function reachesMeetingBrowser(params, config) {
  const meeting = meetingProfiles(config);
  const named = (v) => typeof v === "string" && meeting.has(v.trim().toLowerCase());
  const profile = typeof params?.profile === "string" && params.profile.trim() ? params.profile : config?.browser?.defaultProfile;
  if (named(profile)) return true;
  if (params?.action === "importprofile") return [params.browser, params.systemProfile, params.into].some((v) => named(v) || (typeof v === "string" && v.toLowerCase().includes(MEETING_PROFILE)));
  return false;
}

export default {
  id: "cc-meeting-guard",
  register(api) {
    api.on("before_tool_call", event => {
      // The box page is the only supported inviter in this release. This hook reserves
      // automation, not a boundary against an agent with arbitrary shell/root access.
      if (event.toolName === "google_meet") return { block: true, blockReason: "Use the owner's enrolled Meetings page." };
      if (event.toolName === "browser" && reachesMeetingBrowser(event.params, api.config)) {
        return { block: true, blockReason: "That browser is the meeting's own. Use your browser (the default profile) instead." };
      }
    }, { priority: 1000 });

    // Screenshots of a tab that is not in front (see keepTabsDrawn). One hold per screenshot,
    // kept by its toolCallId and ended by its own after_tool_call or after HOLD_MS, so an
    // after_tool_call that arrives late ends nothing but the hold it belongs to.
    //
    // before_tool_call fails closed: a handler that throws blocks the tool call, and OpenClaw
    // does not cut a slow handler short. Nothing here may throw or wait without a limit.
    // keepTabsDrawn catches everything and waits a second per step at most.
    const holds = new Map();
    let unnamed = 0;
    const end = (key) => {
      const hold = holds.get(key);
      if (!hold) return;
      holds.delete(key);
      clearTimeout(hold.timer);
      void hold.drawn.then((release) => release());
    };
    const ownScreenshot = (event) => event.toolName === "browser" && event.params?.action === "screenshot" && (!event.params.profile || event.params.profile === "openclaw");
    api.on("before_tool_call", async (event) => {
      if (!ownScreenshot(event)) return;
      // OpenClaw reports one call under two names (the tool and its wrapper); one hold serves both.
      const key = event.toolCallId || `unnamed:${++unnamed}`;
      if (holds.has(key)) return void (await holds.get(key).drawn);
      const timer = setTimeout(() => end(key), HOLD_MS);
      timer.unref?.();
      const drawn = keepTabsDrawn({ cdp: ownCdpUrl(api.config), targetId: event.params.targetId });
      holds.set(key, { timer, drawn });
      await drawn;
    });
    api.on("after_tool_call", (event) => {
      if (!ownScreenshot(event)) return;
      // Without an id, the oldest hold that has none.
      end(event.toolCallId || [...holds.keys()].find((k) => k.startsWith("unnamed:")));
    });
  },
};
