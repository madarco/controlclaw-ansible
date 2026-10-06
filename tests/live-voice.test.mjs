import './fixtures/home.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {LiveBridge, liveModel} from '../roles/controlclaw/files/meeting-voice/live.js';
import {PhoneLiveBridge} from '../roles/controlclaw/files/meeting-voice/phone.js';
import * as codecs from './fixtures/phone-codecs.mjs';
function fixture(surface, Bridge = LiveBridge, wake){
 const audio=[],meta=[],sent=[],tools=[],transcripts=[],closed=[];
 const req={providerConfig:{provider:'gateway',model:'openai/gpt-live-1',surface,...(wake?{wake}:{})},onAudio:(b,m)=>{audio.push(b);meta.push(m);},onToolCall:t=>tools.push(t),onTranscript:(...x)=>transcripts.push(x),onClose:r=>closed.push(r),onClearAudio:()=>{}};
 const bridge=new Bridge(req,{codecs,metric:()=>{}});
 bridge.ws={readyState:1,bufferedAmount:0,send:s=>sent.push(JSON.parse(s)),terminate:()=>{}};bridge.ready=true;
 return {bridge,audio,meta,sent,tools,transcripts,closed,appends:()=>sent.filter(e=>e.type.endsWith('.append')&&e.type!=='session.input_audio.append')};
}
const said=(f,role,text)=>f.bridge.event({type:role==='user'?'session.input_transcript.delta':'session.output_transcript.delta',delta:text});
test('only gpt-live models of the provider, and a session start the firewall accepts',()=>{
 assert.equal(liveModel('gateway','openai/gpt-live-1'),true);assert.equal(liveModel('openai','gpt-live-1'),true);
 for(const [p,m] of [['gateway','gpt-live-1'],['codex','gpt-live-1'],['gateway','openai/gpt-realtime-2'],['gateway','openai/gpt-live-1;x']])assert.equal(liveModel(p,m),false);
 const f=fixture('meeting');const s=f.bridge.session();
 assert.deepEqual(Object.keys(s).sort(),['audio','delegation','instructions','model','store']);
 assert.equal(s.store,false);assert.deepEqual(s.delegation,{type:'client'});assert.deepEqual(s.audio.format,{type:'audio/pcm',rate:24000});
 assert.match(s.instructions,/Speak only when someone addresses you/);
 assert.match(fixture('phone').bridge.session().instructions,/no wake name is needed/);
});
test('a lookup is built from what was heard, answered aloud once, and survives the caller talking over it',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const f=fixture('phone');
 said(f,'user','Can you check my notes, which dessert do I like?');said(f,'assistant','Sure, checking your notes now.');
 f.bridge.event({type:'session.delegation.created',delegation:{id:'d1',type:'delegation',target:'client'}});
 assert.equal(f.tools.length,1);assert.equal(f.tools[0].name,'openclaw_agent_consult');assert.equal(f.tools[0].callId,'d1');
 assert.match(f.tools[0].args.question,/which dessert/);assert.match(f.tools[0].args.context,/checking your notes/);
 said(f,'user','Hmm, okay, take your time.');f.bridge.handleBargeIn();
 t.mock.timers.tick(8000);
 assert.deepEqual(f.appends().map(e=>[e.type,e.delegation_id]),[['session.thinking.append','d1']]);
 f.bridge.submitToolResult('d1',{text:'Lemon shortbread.'});f.bridge.submitToolResult('d1',{text:'again'});
 const spoken=f.appends().filter(e=>e.type==='session.commentary.append');
 assert.equal(spoken.length,1);assert.equal(spoken[0].delegation_id,'d1');assert.match(spoken[0].content,/Lemon shortbread/);
 f.bridge.close();
});
test('a lookup that never answers is reported failed after 30 s, never left open',t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const f=fixture('meeting',LiveBridge,{enabled:false,words:['ControlClaw']});f.bridge.event({type:'session.delegation.created',delegation:{id:'d1'}});
 t.mock.timers.tick(30000);
 const spoken=f.appends().filter(e=>e.type==='session.commentary.append');
 assert.equal(spoken.length,1);assert.match(spoken[0].content,/technical failure/);assert.equal(f.bridge.jobs.size,0);f.bridge.close();
});
test('lookups run one at a time; a second waits its turn, an overtaken answer is given quietly',()=>{
 const f=fixture('meeting',LiveBridge,{enabled:false,words:['ControlClaw']});
 f.bridge.event({type:'session.delegation.created',delegation:{id:'d1'}});f.bridge.event({type:'session.delegation.created',delegation:{id:'d2'}});
 assert.equal(f.tools.length,1);
 f.bridge.submitToolResult('d1',{text:'first'});
 const first=f.appends().find(e=>e.delegation_id==='d1');assert.equal(first.type,'session.thinking.append');
 assert.equal(f.tools.length,2);assert.equal(f.tools[1].callId,'d2');
 f.bridge.submitToolResult('d2',{text:'second'});
 assert.equal(f.appends().find(e=>e.delegation_id==='d2').type,'session.commentary.append');
 // d3 runs, d4 and d5 wait, d6 is told aloud to ask again, and d5 stays the newest.
 for(const id of ['d3','d4','d5','d6'])f.bridge.event({type:'session.delegation.created',delegation:{id}});
 assert.equal(f.tools.length,3);assert.deepEqual([...f.bridge.jobs.keys()],['d3','d4','d5']);
 const refused=f.appends().find(e=>e.delegation_id==='d6');assert.equal(refused.type,'session.commentary.append');assert.match(refused.content,/Too many lookups/);
 assert.equal(f.bridge.latestDelegation,'d5');f.bridge.close();
});
test('audio flows both ways, transcripts are reported per turn, and close asks for final usage',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const f=fixture('meeting',LiveBridge,{enabled:false,words:['ControlClaw']});f.bridge.sendAudio(Buffer.alloc(960));
 assert.equal(f.sent.at(-1).type,'session.input_audio.append');
 f.bridge.event({type:'session.output_audio.delta',delta:Buffer.alloc(480).toString('base64')});assert.equal(f.audio.length,1);
 said(f,'user','What is ');said(f,'user','seven times six?');t.mock.timers.tick(1200);
 assert.deepEqual(f.transcripts,[['user','What is seven times six?',true]]);
 f.bridge.event({type:'session.usage.updated',usage:{seconds:12}});f.bridge.close();
 assert.equal(f.sent.at(-1).type,'session.close');assert.deepEqual(f.closed,['completed']);
 f.bridge.event({type:'session.output_audio.delta',delta:Buffer.alloc(480).toString('base64')});assert.equal(f.audio.length,1);
});
test('phone: greeting once as spoken commentary, mu-law in and out, no realtime truncation on barge-in',()=>{
 const f=fixture('phone',PhoneLiveBridge);
 f.bridge.triggerGreeting();f.bridge.triggerGreeting();
 assert.equal(f.appends().filter(e=>e.type==='session.commentary.append').length,1);
 f.bridge.sendAudio(codecs.pcmToMulaw(Buffer.alloc(320)));assert.equal(f.sent.at(-1).type,'session.input_audio.append');
 // 8 kHz mu-law in, 24 kHz PCM16 out (the streaming resampler holds a few samples back).
 const pcm=Buffer.from(f.sent.at(-1).audio,'base64');assert.ok(pcm.length>800&&pcm.length<=960&&pcm.length%2===0,String(pcm.length));
 f.bridge.event({type:'session.output_audio.delta',delta:Buffer.alloc(4800).toString('base64')});assert.ok(f.audio.length>=1);
 const before=f.sent.length;f.bridge.handleBargeIn();assert.equal(f.sent.length,before);f.bridge.close();
});
test('timers start when a lookup arrives, a timed-out consult does not overlap the next, a repeated id is answered once',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const f=fixture('meeting');let finish;
 f.bridge.req.onToolCall=t2=>{f.tools.push(t2);return new Promise(r=>{finish=r;});};
 f.bridge.event({type:'session.delegation.created',delegation:{id:'d1'}});f.bridge.event({type:'session.delegation.created',delegation:{id:'d2'}});
 // d2 waits behind d1, but its own 30 s already run.
 t.mock.timers.tick(30000);
 assert.deepEqual(f.appends().filter(e=>e.type==='session.thinking.append'||e.type==='session.commentary.append').filter(e=>/technical failure/.test(e.content)).map(e=>e.delegation_id).sort(),['d1','d2']);
 assert.equal(f.tools.length,1,'d2 does not start while d1 is still running');
 finish();await Promise.resolve();await Promise.resolve();
 assert.equal(f.tools.length,1,'a timed-out waiting lookup is not started later');
 f.bridge.event({type:'session.delegation.created',delegation:{id:'d1'}});
 assert.equal(f.tools.length,1,'an answered id is not looked up again');f.bridge.close();
});
test('a late result after the consult promise settles is still delivered, and refused commands do not end the session',async()=>{
 const f=fixture('phone');
 f.bridge.event({type:'session.delegation.created',delegation:{id:'d1'}});await Promise.resolve();await Promise.resolve();
 f.bridge.submitToolResult('d1',{text:'Late but here.'});
 assert.match(f.appends().find(e=>e.delegation_id==='d1').content,/Late but here/);
 assert.ok(f.sent.every(e=>typeof e.event_id==='string'));
 f.bridge.event({type:'error',error:{code:'invalid_delegation',client_event_id:'cc_3'}});assert.equal(f.bridge.closed,false);
 f.bridge.event({type:'error',error:{code:'server_error'}});assert.equal(f.bridge.closed,true);
});
test('the same answer twice within a minute is passed quietly, not read out again',()=>{
 const f=fixture('phone');
 f.bridge.event({type:'session.delegation.created',delegation:{id:'d1'}});f.bridge.event({type:'session.delegation.created',delegation:{id:'d2'}});
 f.bridge.submitToolResult('d1',{text:'Lemon shortbread.'});f.bridge.submitToolResult('d2',{text:'Lemon shortbread.'});
 const d2=f.appends().find(e=>e.delegation_id==='d2');assert.equal(d2.type,'session.thinking.append');assert.match(d2.content,/Already given/);f.bridge.close();
});
test('output audio carries an item id, so the phone pacer marks playback; a pause starts a new item',t=>{
 const f=fixture('phone',PhoneLiveBridge);let clock=1_000_000;t.mock.method(Date,'now',()=>clock);
 const out=()=>f.bridge.event({type:'session.output_audio.delta',delta:Buffer.alloc(4800).toString('base64')});
 out();clock+=100;out();clock+=2000;out();
 const ids=f.meta.map(m=>m?.itemId);assert.ok(ids.every(Boolean));assert.equal(ids[0],ids[1]);assert.notEqual(ids[1],ids[2]);f.bridge.close();
});
test('wake word on: only what follows an addressed request is played; long answers and addressed lookups are not cut',t=>{
 let clock=1_000_000;t.mock.method(Date,'now',()=>clock);
 const f=fixture('meeting',LiveBridge,{enabled:true,words:['Jarvis','Maria Rossi']});
 assert.match(f.bridge.session().instructions,/Jarvis or Maria Rossi/);
 const loud=Buffer.alloc(480);for(let i=0;i<loud.length;i+=2)loud.writeInt16LE(i%4?3000:-3000,i);
 const out=(b=Buffer.alloc(480))=>f.bridge.event({type:'session.output_audio.delta',delta:b.toString('base64')});
 said(f,'user','I think the launch should move. ');out();assert.equal(f.audio.length,0,'nobody addressed it');
 said(f,'assistant','I could help with that.');assert.equal(f.bridge.said.length,0,'unplayed speech is not kept as context');
 clock+=1000;said(f,'user','Hey Jarvis, what is ');clock+=1500;said(f,'user','seven times six?');out();assert.equal(f.audio.length,1);
 // A long answer: audible output keeps the floor past the 15 s window.
 for(let i=0;i<20;i++){clock+=1000;out(loud);}assert.equal(f.audio.length,21);
 clock+=16000;out();assert.equal(f.audio.length,21,'quiet and past the window: muted');
 // A lookup nobody asked for by name is answered quietly and does not open the floor.
 f.bridge.event({type:'session.delegation.created',delegation:{id:'d1'}});f.bridge.submitToolResult('d1',{text:'42'});
 assert.equal(f.appends().find(e=>e.delegation_id==='d1').type,'session.thinking.append');out();assert.equal(f.audio.length,21);
 // An addressed one is answered aloud, even after a slow lookup.
 clock+=1000;said(f,'user','Maria Rossi, check the notes');f.bridge.event({type:'session.delegation.created',delegation:{id:'d2'}});
 clock+=25000;f.bridge.submitToolResult('d2',{text:'Lemon shortbread.'});
 assert.equal(f.appends().find(e=>e.delegation_id==='d2').type,'session.commentary.append');out();assert.equal(f.audio.length,22);
 f.bridge.close();
});
test('phone with wake words on still greets aloud',t=>{
 let clock=2_000_000;t.mock.method(Date,'now',()=>clock);
 const f=fixture('phone',LiveBridge,{enabled:true,words:['Jarvis']});f.bridge.triggerGreeting();
 f.bridge.event({type:'session.output_audio.delta',delta:Buffer.alloc(480).toString('base64')});assert.equal(f.audio.length,1);f.bridge.close();
});
test('phone: wake word off by default, on when the owner turns it on',()=>{
 assert.equal(fixture('phone').bridge.wakeRequired,false);
 assert.equal(fixture('phone',LiveBridge,{enabled:true,words:['Jarvis']}).bridge.wakeRequired,true);
 assert.equal(fixture('meeting').bridge.wakeRequired,true);
 assert.equal(fixture('meeting',LiveBridge,{enabled:false,words:['Jarvis']}).bridge.wakeRequired,false);
});
