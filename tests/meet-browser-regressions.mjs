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
let health=JSON.parse(await page.evaluate('('+captionSource+')()'));
assert.equal(health.transcriptLines,0,'combined device announcement must not enter native captions');
await page.locator('[aria-live]').evaluate(el=>el.innerText='Alex\nAlex will check why the camera is off by Friday.');
health=JSON.parse(await page.evaluate('('+captionSource+')()'));
assert.equal(health.transcriptLines,1);
assert.equal(health.recentTranscript[0].text,'Alex will check why the camera is off by Friday.');
console.log('PASS native captions discard device announcements and retain spoken actions');
await page.close();
await browser.close();
