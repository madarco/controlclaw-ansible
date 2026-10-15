// The agent presents its own browser in a meeting (controlclaw docs/plans/meeting-present.md).
// Only when the owner turned presenting on and the meeting's lease says so (`present` in lease.json,
// written by the vm-agent from the firewall's media lease).
//
// The meeting Chrome (CDP 9223) starts with --auto-select-tab-capture-source-by-title=CC Stage
// (meeting-browser.sh), so Meet's share picker is answered with the stage tab without a human. The
// stage is one tab in the meeting Chrome titled "CC Stage" with a canvas. Twice a second the relay
// takes a screenshot of the agent browser's visible tab (CDP 9222: that page only, never the desktop
// or other windows) and draws it there. Then Share screen is clicked in the Meet tab through CDP (a
// mouse event, which counts as a user gesture), and the outcome is read from Meet itself: the voice is
// only told "presenting" once Meet says "You are presenting". Closing the stage tab stops it.
//
// Later modes (a URL, slides, a canvas) draw other frames into the same stage; nothing else changes.
// Nothing from the pages shown is logged.
import { createRequire } from 'node:module';
import { meetingLease } from './record.js';
const STAGE = 'CC Stage';
const FPS = 2;
const MAX_WIDTH = 1280;
const QUALITY = 60;
// How long Meet gets to say "You are presenting" after the click.
const CONFIRM_MS = 10000;
const SHARE = /\b(share screen|present now)\b/i;
// What Meet shows when the host does not let others share (wordings seen in Meet's help and UI).
const REFUSED = /\b(host (has )?(turned off|disabled|doesn('|’)t allow|does not allow|hasn('|’)t allowed)|can('|’)t (share|present)|cannot (share|present)|sharing is (turned off|disabled)|only the host can (share|present))\b/i;

const STAGE_HTML = `<!doctype html><meta charset=utf-8><title>${STAGE}</title><style>html,body{margin:0;height:100%;background:#111;color:#ddd;font:28px system-ui,sans-serif}canvas{width:100%;height:100%;object-fit:contain;display:block}#card{position:fixed;inset:0;display:none;align-items:center;justify-content:center}</style><canvas id=c></canvas><div id=card>Nothing to show</div><script>const c=document.getElementById('c'),x=c.getContext('2d'),card=document.getElementById('card');window.draw=b=>{const i=new Image();i.onload=()=>{card.style.display='none';if(c.width!==i.width||c.height!==i.height){c.width=i.width;c.height=i.height}x.drawImage(i,0,0)};i.src='data:image/jpeg;base64,'+b};window.card=t=>{card.textContent=t;card.style.display='flex';x.clearRect(0,0,c.width,c.height)}</script>`;

/** A minimal CDP client over the browser's page WebSocket. */
export function cdpClient(url, WebSocket) {
  const ws = new WebSocket(url, { maxPayload: 32 * 1024 * 1024 }); let id = 0; const wait = new Map();
  const ready = new Promise((resolve, reject) => { ws.on('open', resolve); ws.on('error', reject); });
  // A connection that fails before anyone awaits it must not become an unhandled rejection.
  ready.catch(() => {});
  ws.on('message', d => { let m; try { m = JSON.parse(d); } catch { return; } if (m.id && wait.has(m.id)) { wait.get(m.id)(m); wait.delete(m.id); } });
  ws.on('close', () => { for (const r of wait.values()) r({ error: { message: 'closed' } }); wait.clear(); });
  return {
    ready,
    // Every call answers within 5 s: Chrome does not answer a capture of a tab that is not in front.
    send: (method, params = {}) => new Promise(resolve => {
      if (ws.readyState !== 1) return resolve({ error: { message: 'closed' } });
      const i = ++id;
      const timer = setTimeout(() => { if (wait.delete(i)) resolve({ error: { message: 'timeout' } }); }, 5000); timer.unref?.();
      wait.set(i, m => { clearTimeout(timer); resolve(m); }); ws.send(JSON.stringify({ id: i, method, params }));
    }),
    close: () => { try { ws.close(); } catch { /* gone */ } },
  };
}
// How long a page asked for gets to load before it is shown anyway.
const PAGE_LOAD_MS = 8000;
const value = r => r?.result?.result?.value;
/** A tab with nothing to show: blank, empty, or Chrome's new-tab page. */
const blankUrl = url => !url || /^(about:blank|chrome:\/\/newtab|chrome-search:|data:,)/i.test(url);
/**
 * The page someone asked to see, as an https URL, or null. Plain checks only: https, no credentials,
 * a host name with a dot. "example.com" is taken as https://example.com.
 */
export function presentUrl(raw) {
  if (typeof raw !== 'string') return null;
  const text = raw.trim();
  if (!text || text.length > 2000 || /\s/.test(text)) return null;
  let url; try { url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname.includes('.')) return null;
  return url.href;
}

export function createPresenter(deps = {}) {
  const fetchJson = deps.json ?? (async (port, path, method = 'GET') => (await fetch(`http://127.0.0.1:${port}${path}`, { method, signal: AbortSignal.timeout(5000) })).json());
  const connect = deps.connect ?? (url => { const WebSocket = createRequire('/usr/lib/node_modules/openclaw/package.json')('ws'); return cdpClient(url, WebSocket); });
  const lease = deps.lease ?? (() => meetingLease(deps.dir));
  const sleep = deps.sleep ?? (ms => new Promise(r => setTimeout(r, ms)));
  const timers = deps.timers ?? { setInterval, clearInterval };
  const metric = deps.metric ?? (m => console.info(JSON.stringify({ event: 'cc.meeting.present', at: Date.now(), ...m })));
  let state = null; // { meetingId, meet, meetTarget, stage, stageTarget, source, sourceId, poll, watch, busy }

  const meetTab = async () => (await fetchJson(9223, '/json/list')).find(t => t.type === 'page' && /^https:\/\/meet\.google\.com\/[a-z]{3}-[a-z]{4}-[a-z]{3}/.test(t.url));
  /**
   * Meet's own words: presenting, refused, or neither. Presenting is Meet's own "Stop presenting"
   * control, matched whole; refused is a Meet dialog or notice. Never the page text or other labels:
   * the captions, the chat and participants' names are anyone's to choose.
   */
  const meetState = async meet => {
    const read = value(await meet.send('Runtime.evaluate', { expression: `JSON.stringify({ stop: [...document.querySelectorAll('button,[role=button]')].some(b => /^(cancel_presentation)?\\s*stop presenting$/i.test((b.getAttribute('aria-label') || b.textContent || '').trim())), notices: [...document.querySelectorAll('[role=dialog],[role=alertdialog],[role=alert]')].map(e => e.textContent).join(' ').slice(0, 5000) })` })) ?? '{}';
    let state; try { state = JSON.parse(read); } catch { state = {}; }
    return { presenting: state.stop === true, refused: REFUSED.test(state.notices ?? '') };
  };
  /** Stage tabs this process does not hold (a gateway restart left them): closed. True when there were any. */
  const closeOrphans = async () => {
    const orphans = (await fetchJson(9223, '/json/list').catch(() => [])).filter(t => t.type === 'page' && t.title === STAGE && t.id !== state?.stageTarget);
    for (const t of orphans) await fetchJson(9223, `/json/close/${t.id}`).catch(() => {});
    return orphans.length > 0;
  };
  // One start or stop at a time: a second request waits for the first and sees its result.
  let queue = Promise.resolve();
  const serial = fn => { const run = queue.then(fn, fn); queue = run.catch(() => {}); return run; };
  /** The share button's centre, or why there is none. */
  const shareButton = async meet => {
    const box = value(await meet.send('Runtime.evaluate', { expression: `(() => { const b = [...document.querySelectorAll('button,[role=button]')].find(b => ${SHARE}.test((b.getAttribute('aria-label') || '') + ' ' + b.textContent) && b.offsetParent); if (!b) return 'none'; if (b.disabled || b.getAttribute('aria-disabled') === 'true') return 'disabled'; const r = b.getBoundingClientRect(); return JSON.stringify([r.x + r.width / 2, r.y + r.height / 2]); })()` }));
    return box === 'none' || box === 'disabled' || !box ? { missing: box ?? 'none' } : { at: JSON.parse(box) };
  };
  /** The agent browser's visible tab (the one in front), or null. */
  const visibleSource = async () => {
    for (const t of (await fetchJson(9222, '/json/list')).filter(t => t.type === 'page')) {
      if (state?.sourceId === t.id && state.source) { if (value(await state.source.send('Runtime.evaluate', { expression: 'document.visibilityState' })) === 'visible') return { id: t.id, client: state.source, blank: blankUrl(t.url) }; continue; }
      const c = connect(t.webSocketDebuggerUrl);
      try { await c.ready; } catch { continue; }
      if (value(await c.send('Runtime.evaluate', { expression: 'document.visibilityState' })) === 'visible') return { id: t.id, client: c, blank: blankUrl(t.url) };
      c.close();
    }
    return null;
  };
  /**
   * Opens the page in the agent browser, in front: in the visible tab when that one is blank,
   * otherwise in a new tab. True once it loaded (or after a few seconds of trying).
   */
  const openPage = async url => {
    let tab;
    try {
      const front = await visibleSource();
      if (front?.blank) { tab = front; await front.client.send('Page.navigate', { url }); }
      else {
        if (front && front.client !== state?.source) front.client.close();
        const created = await fetchJson(9222, `/json/new?${encodeURIComponent(url)}`, 'PUT');
        await fetchJson(9222, `/json/activate/${created.id}`).catch(() => {});
        const c = connect(created.webSocketDebuggerUrl); await c.ready;
        tab = { id: created.id, client: c };
      }
    } catch { return false; }
    for (let waited = 0; waited < PAGE_LOAD_MS; waited += 500) {
      if (value(await tab.client.send('Runtime.evaluate', { expression: 'document.readyState' })) === 'complete') break;
      await sleep(500);
    }
    if (tab.client !== state?.source) tab.client.close();
    if (state) state.checkedAt = 0;
    return true;
  };
  const frame = async () => {
    if (!state || state.busy) return; state.busy = true;
    try {
      const now = Date.now();
      // Follow the tab in front: checked once a second.
      if (!state.source || now - (state.checkedAt ?? 0) >= 1000) {
        state.checkedAt = now;
        const found = await visibleSource();
        if (found?.id !== state.sourceId) { if (state.source && state.source !== found?.client) state.source.close(); state.source = found?.client ?? null; state.sourceId = found?.id ?? null; }
        state.blank = !!found?.blank;
      }
      // No tab, or a blank one (about:blank drew a white screen): the card, not an empty page.
      if (!state.source || state.blank) { await state.stage.send('Runtime.evaluate', { expression: 'card("Nothing to show")' }); return; }
      // The clip is in document coordinates: what the agent sees starts at the page's scroll position.
      const size = JSON.parse(value(await state.source.send('Runtime.evaluate', { expression: 'JSON.stringify([innerWidth, innerHeight, scrollX, scrollY])' })) ?? '[0,0,0,0]');
      if (!size[0] || !size[1]) return;
      const shot = await state.source.send('Page.captureScreenshot', { format: 'jpeg', quality: QUALITY, optimizeForSpeed: true, clip: { x: size[2] || 0, y: size[3] || 0, width: size[0], height: size[1], scale: Math.min(1, MAX_WIDTH / size[0]) } });
      if (shot.result?.data) await state.stage.send('Runtime.evaluate', { expression: `draw(${JSON.stringify(shot.result.data)})` });
    } catch { /* the next frame tries again */ }
    finally { if (state) state.busy = false; }
  };
  const teardown = async () => {
    const s = state; state = null; if (!s) return;
    timers.clearInterval(s.poll); timers.clearInterval(s.watch);
    // Closing the captured tab ends the presentation in Meet.
    try { await fetchJson(9223, `/json/close/${s.stageTarget}`); } catch { /* already gone */ }
    s.source?.close(); s.stage?.close(); s.meet?.close();
  };

  return {
    presenting: () => !!state,
    /** A voice session starts: a stage no one holds (a gateway restart) is closed. */
    reset() { return serial(async () => { if (!state) await closeOrphans(); }); },
    /**
     * Present the agent's browser. Resolves with the real outcome: 'presenting', 'already', 'refused'
     * (Meet would not let the agent present), 'not_started' (no "You are presenting" in time),
     * 'not_allowed' (the setting or the lease) or 'failed' (no Meet tab, the browsers not reachable).
     */
    start(opts = {}) { return serial(() => this.startNow(opts)); },
    stop() { return serial(() => this.stopNow()); },
    async startNow({ url } = {}) {
      const l = lease();
      if (l.present !== true || !l.meetingId) return 'not_allowed';
      const page = url === undefined ? null : presentUrl(url);
      if (url !== undefined && !page) return 'bad_url';
      // Already presenting: the page asked for is opened in front, and the presentation follows it.
      if (state) { if (!page) return 'already'; return (await openPage(page)) ? 'showing' : 'page_failed'; }
      if (page) { if (!(await openPage(page))) return 'page_failed'; }
      else {
        // Nothing open in the agent browser: nothing to share (it would be a white screen).
        let front; try { front = await visibleSource(); } catch { front = null; }
        front?.client.close();
        if (!front || front.blank) { metric({ phase: 'empty' }); return 'empty'; }
      }
      // A stage left by a gateway restart: closed first, so this process holds the only one.
      if (await closeOrphans()) await sleep(1500);
      let target;
      try { target = await meetTab(); } catch { return 'failed'; }
      if (!target) return 'failed';
      const meet = connect(target.webSocketDebuggerUrl);
      try { await meet.ready; } catch { return 'failed'; }
      if ((await meetState(meet)).presenting) { meet.close(); return 'already'; }
      const button = await shareButton(meet);
      if (button.missing) { const refused = (await meetState(meet)).refused || button.missing === 'disabled'; meet.close(); metric({ phase: 'refused', reason: button.missing }); return refused ? 'refused' : 'not_started'; }
      // The stage: a tab titled CC Stage, then the Meet tab back in front for the click.
      let stageTarget;
      try { stageTarget = await fetchJson(9223, '/json/new?about:blank', 'PUT'); } catch { meet.close(); return 'failed'; }
      const stage = connect(stageTarget.webSocketDebuggerUrl);
      try { await stage.ready; } catch { meet.close(); return 'failed'; }
      await stage.send('Page.navigate', { url: 'data:text/html;base64,' + Buffer.from(STAGE_HTML).toString('base64') });
      state = { meetingId: l.meetingId, meet, meetTarget: target.id, stage, stageTarget: stageTarget.id, source: null, sourceId: null, busy: false };
      await sleep(800);
      await frame();
      state.poll = timers.setInterval(() => void frame(), 1000 / FPS); state.poll.unref?.();
      try { await fetchJson(9223, `/json/activate/${target.id}`); } catch { /* the click may still land */ }
      const at = (await shareButton(meet)).at ?? button.at;
      for (const type of ['mousePressed', 'mouseReleased']) await meet.send('Input.dispatchMouseEvent', { type, x: at[0], y: at[1], button: 'left', clickCount: 1 });
      for (let waited = 0; waited < CONFIRM_MS; waited += 500) {
        await sleep(500);
        const s = await meetState(meet);
        if (s.presenting) break;
        if (s.refused) { await teardown(); metric({ phase: 'refused', reason: 'host' }); return 'refused'; }
      }
      if (!state || !(await meetState(meet)).presenting) { await teardown(); metric({ phase: 'not_started' }); return 'not_started'; }
      // While presenting: stop when the meeting or the setting goes, or when Meet stops it (the host, or another presenter).
      state.watch = timers.setInterval(async () => {
        if (!state || state.watching) return; state.watching = true;
        try {
          const now = lease();
          if (now.meetingId !== state.meetingId || now.present !== true || !(await meetState(state.meet)).presenting) { metric({ phase: 'ended' }); await teardown(); }
        } catch { await teardown(); }
        finally { if (state) state.watching = false; }
      }, 2000);
      state.watch.unref?.();
      metric({ phase: 'presenting' });
      return 'presenting';
    },
    /** Stop presenting: 'stopped', or 'not_presenting' when nothing was shown. */
    async stopNow() {
      // A stage left by a gateway restart counts: closing it stops that presentation.
      if (!state) return (await closeOrphans()) ? 'stopped' : 'not_presenting';
      const meet = connect((await meetTab().catch(() => null))?.webSocketDebuggerUrl ?? 'ws://127.0.0.1:1/none');
      await teardown();
      try { await meet.ready; for (let i = 0; i < 10 && (await meetState(meet)).presenting; i++) await sleep(500); } catch { /* the meeting is gone too */ }
      meet.close();
      metric({ phase: 'stopped' });
      return 'stopped';
    },
  };
}
/** One per gateway process: a presentation outlives the voice session that started it. */
export const meetingPresenter = createPresenter();

/** What the voice is told for each outcome: always the real one, never a guess. */
export const PRESENT_SAY = {
  presenting: 'Done: you are now presenting your browser to the meeting; everyone sees the page it shows. Say so in one short sentence.',
  already: 'You are already presenting your browser. Say so in a few words.',
  refused: 'Not done: Google Meet does not let you present in this meeting; the host may not let guests share their screen. Say that plainly.',
  not_started: 'Not done: presenting did not start (a technical failure); nothing is shared. Say so plainly.',
  not_allowed: "Not done: presenting is turned off for this agent. Say that the owner can turn it on in the agent's Meetings settings.",
  failed: 'Not done: presenting could not start (a technical failure); nothing is shared. Say so plainly.',
  stopped: 'Done: you stopped presenting. Say so in a few words.',
  not_presenting: 'You were not presenting. Say so in a few words.',
  empty: 'Not done: your browser has nothing open, so there is nothing to show. Say so, and ask which page or site they want to see.',
  showing: 'Done: the page they asked for is now open and shown in your presentation. Say so in a few words.',
  bad_url: 'Not done: that is not a web address you can open (only https sites). Say so and ask for the site again.',
  page_failed: 'Not done: the page could not be opened in your browser (a technical failure). Say so plainly.',
};
