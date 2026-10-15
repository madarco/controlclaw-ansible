import './fixtures/home.mjs';
import {execFileSync} from 'node:child_process';
import {runInNewContext} from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
const source=execFileSync('python3',[new URL('./export-meet-status.py',import.meta.url).pathname,process.env.MEET_UPSTREAM||'/tmp/meet-upstream','consult'],{encoding:'utf8'});
function fixture({closed=false,fail=false,voice,seen=[]}={}) {
 const events=[];
 const consult=runInNewContext(source,{
  normalizeAgentId:x=>x,resolveDefaultAgentId:()=> 'main',normalizeOptionalString:x=>x,
  resolveRealtimeVoiceAgentConsultToolsAllow:policy=>{assert.equal(policy,'safe-read-only');return ['read'];},
  tryBeginGatewayIndependentRootWorkAdmission:()=>{events.push('admit');return closed?null:{run:fn=>{events.push('run');return fn();},release:()=>events.push('release')};},
  consultRealtimeVoiceAgent:async args=>{seen.push(args);assert.equal(args.timeoutMs,15000);assert.deepEqual(args.toolsAllow,['read']);if(fail)throw Error('failed');return 'lemon shortbread';}
 });
 return {events,run:()=>consult({config:voice?{plugins:{entries:{'google-meet':{config:{realtime:{providers:{'cc-meeting-voice':voice}}}}}}}:{},runtime:{agent:{}},surface:{id:'meeting'},meetingSessionId:'test'})};
}
test('each persistent meeting consult acquires and releases independent work admission',async()=>{
 const f=fixture();assert.equal(await f.run(),'lemon shortbread');assert.deepEqual(f.events,['admit','run','release']);
 const failure=fixture({fail:true});await assert.rejects(failure.run(),/failed/);assert.deepEqual(failure.events,['admit','run','release']);
});
test('the meeting consult runs isolated on the model chosen for meetings, thinking low',async()=>{
 const seen=[];await fixture({seen,voice:{consultModel:'controlclaw/openai/gpt-5.4-mini'}}).run();
 assert.equal(seen[0].contextMode,'isolated');assert.equal(seen[0].provider,'controlclaw');assert.equal(seen[0].model,'openai/gpt-5.4-mini');assert.equal(seen[0].thinkLevel,'low');
 const main=[];await fixture({seen:main}).run();
 assert.equal(main[0].provider,undefined);assert.equal(main[0].model,undefined);assert.equal(main[0].thinkLevel,'low');
 const off=[];await fixture({seen:off,voice:{consultModel:'openai/gpt-6-luna',consultThinking:'off'}}).run();
 assert.equal(off[0].thinkLevel,'off');assert.equal(off[0].model,'gpt-6-luna');
 const bad=[];await fixture({seen:bad,voice:{consultModel:'nomodel',consultThinking:'high'}}).run();
 assert.equal(bad[0].model,undefined);assert.equal(bad[0].thinkLevel,'low');
});
test('a genuinely draining gateway rejects new meeting consults plainly',async()=>{
 const f=fixture({closed:true});await assert.rejects(f.run(),/restarting or temporarily unavailable/);assert.deepEqual(f.events,['admit']);
});
test('missing isolated participant capture fails closed instead of remapping bot output',async()=>{
 const text=execFileSync('python3',[new URL('./export-meet-status.py',import.meta.url).pathname,process.env.MEET_UPSTREAM||'/tmp/meet-upstream','backend'],{encoding:'utf8'});
 const commands=[];const ensure=runInNewContext(text,{PIPEWIRE_SINK_NAME:'openclaw_meeting_audio',PIPEWIRE_SOURCE_NAME:'cc_meeting_remote.monitor',assertCommandSucceeded:()=>{},pulseListContains:(text,name)=>text.includes(name)});
 await assert.rejects(ensure({backend:'pipewire-pulse',run:async args=>{commands.push(args);return {code:0,stdout:args.at(-1)==='sinks'?'0 openclaw_meeting_audio':'0 openclaw_meeting_audio.monitor'};}}),/Isolated meeting participant audio source is missing/);
 assert.equal(commands.some(x=>x.includes('module-remap-source')),false);
});
