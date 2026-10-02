const {chromium}=await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
import {execFileSync} from 'node:child_process';
import {runInNewContext} from 'node:vm';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
const browser=await chromium.launch({headless:true});
const fn=execFileSync('python3',[fileURLToPath(new URL('./export-meet-status.py',import.meta.url)),process.env.MEET_UPSTREAM || '/tmp/meet-upstream'],{encoding:'utf8'});
const source=runInNewContext(fn+`;meetStatusScript({allowMicrophone:false,autoJoin:true,captureCaptions:false,readOnly:false,guestName:'ControlClaw meeting assistant'})`,{});
for(const [name,html,permission,expected] of [
 ['refused admission',"<h1>You can't join this video call</h1>",'denied',{inCall:false,manualAction:{reason:'meet-admission-denied',message:'Google Meet refused guest admission.'}}],
 ['admission lobby','<h1>Please wait until a meeting host brings you into the call</h1><button aria-label="Leave call">Leave call</button>','prompt',{inCall:false,lobbyWaiting:true}],
 ['muted admitted call','<button aria-label="Leave call">Leave call</button><button aria-label="Turn on microphone">mic_off</button><button aria-label="Turn on camera">videocam_off</button>','prompt',{inCall:true,micMuted:true,cameraOff:true}],
 ['blocked devices admitted call','<button aria-label="Leave call">Leave call</button><button aria-label="Microphone problem. Show more info">mic</button><button aria-label="Camera problem. Show more info">videocam</button>','denied',{inCall:true,micMuted:true,cameraOff:true}],
 ['unverified devices are not called muted','<button aria-label="Leave call">Leave call</button>','prompt',{inCall:true,micMuted:undefined,cameraOff:undefined}],
]){
 const page=await browser.newPage();await page.setContent(html);await page.evaluate(permission=>Object.defineProperty(navigator,'permissions',{value:{query:async()=>({state:permission})}}),permission);
 const health=JSON.parse(await page.evaluate('('+source+')()'));
 for(const [k,v] of Object.entries(expected))assert.deepEqual(health[k],v,name+': '+k);
 console.log('PASS '+name);await page.close();
}
const captionSource=runInNewContext(fn+`;meetStatusScript({allowMicrophone:false,autoJoin:false,captureCaptions:true,captionSessionId:'regression',readOnly:false})`,{});
const page=await browser.newPage();
await page.route('https://meet.google.com/**',route=>route.fulfill({contentType:'text/html',body:'<button aria-label="Leave call">Leave call</button><div aria-live="polite">Your camera is off. Your microphone is muted.</div>'}));
await page.goto('https://meet.google.com/test');
await page.evaluate(()=>Object.defineProperty(navigator,'permissions',{value:{query:async()=>({state:'denied'})}}));
await page.evaluate(() => {
  const button=document.createElement('button');
  button.setAttribute('aria-label','Turn on captions');
  button.onclick=()=>button.setAttribute('aria-label','Turn off captions');
  document.body.append(button);
});
let health=JSON.parse(await page.evaluate('('+captionSource+')()'));
assert.equal(health.transcriptLines,0,'combined device announcement must not enter native captions');
assert.equal(await page.getByRole('button',{name:'Turn off captions',exact:true}).count(),1,'the bot enables its own captions');
for (const announcement of ['You have joined the call. There is one other person in the call. Your camera is off. Your microphone is off. Your hand is lowered.','arrow_downwardJump to bottom']) {
 await page.locator('[aria-live]').evaluate((el,text)=>el.innerText=text,announcement);
 health=JSON.parse(await page.evaluate('('+captionSource+')()'));
 assert.equal(health.transcriptLines,0,'Meet UI must not enter native captions: '+announcement);
}
await page.locator('[aria-live]').evaluate(el=>el.innerText='Alex\nAlex will check why the camera is off by Friday.');
health=JSON.parse(await page.evaluate('('+captionSource+')()'));
assert.equal(health.transcriptLines,1);
assert.equal(health.recentTranscript[0].text,'Alex will check why the camera is off by Friday.');
const initial=health.recentTranscript[0];
assert.ok(initial.source?.id,'session-scoped caption identity is available');
await page.locator('[aria-live]').evaluate(el=>el.innerText='Alex\nAlex will investigate why the camera is off by Friday.');
health=JSON.parse(await page.evaluate('('+captionSource+')()'));
const corrected=health.recentTranscript.at(-1);
assert.equal(corrected.source.id,initial.source.id,'a correction keeps the same caption identity');
assert.ok(Number(corrected.source.revision)>Number(initial.source.revision));
console.log('PASS native caption activation, UI filtering and revision identities');
await page.close();
await browser.close();
const recoveryFn=execFileSync('python3',[fileURLToPath(new URL('./export-meet-status.py',import.meta.url)),process.env.MEET_UPSTREAM || '/tmp/meet-upstream','recovery'],{encoding:'utf8'});
let recoveryParams;
const probe=runInNewContext(recoveryFn,{
 GOOGLE_MEET_PLATFORM_ADAPTER:{},
 resolveLocalMeetingBrowserRequest:async()=>()=>{},
 shouldCaptureCaptions:()=>true,
 recoverMeetingBrowserTab:async params=>{recoveryParams=params;return {found:false};},
});
await probe.run({id:'native-test-session',transport:'chrome',mode:'transcribe',url:'https://meet.google.com/abc-defg-hij',chrome:{}});
assert.equal(recoveryParams.meetingSessionId,'native-test-session','caption session identity survives both recovery layers');
console.log('PASS native recovery propagates caption session identity');
