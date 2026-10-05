import test from 'node:test';
import assert from 'node:assert/strict';
import {LiveBridge, liveModel} from '../roles/controlclaw/files/meeting-voice/live.js';
import {PhoneLiveBridge} from '../roles/controlclaw/files/meeting-voice/phone.js';
import * as codecs from './fixtures/phone-codecs.mjs';
function fixture(surface, Bridge = LiveBridge){
 const audio=[],sent=[],tools=[],transcripts=[],closed=[];
 const req={providerConfig:{provider:'gateway',model:'openai/gpt-live-1',surface},onAudio:b=>audio.push(b),onToolCall:t=>tools.push(t),onTranscript:(...x)=>transcripts.push(x),onClose:r=>closed.push(r),onClearAudio:()=>{}};
 const bridge=new Bridge(req,{codecs,metric:()=>{}});
 bridge.ws={readyState:1,bufferedAmount:0,send:s=>sent.push(JSON.parse(s)),terminate:()=>{}};bridge.ready=true;
 return {bridge,audio,sent,tools,transcripts,closed,appends:()=>sent.filter(e=>e.type.endsWith('.append')&&e.type!=='session.input_audio.append')};
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
 const f=fixture('meeting');f.bridge.event({type:'session.delegation.created',delegation:{id:'d1'}});
 t.mock.timers.tick(30000);
 const spoken=f.appends().filter(e=>e.type==='session.commentary.append');
 assert.equal(spoken.length,1);assert.match(spoken[0].content,/technical failure/);assert.equal(f.bridge.pending.size,0);f.bridge.close();
});
test('lookups run one at a time; a second waits its turn, an overtaken answer is given quietly',()=>{
 const f=fixture('meeting');
 f.bridge.event({type:'session.delegation.created',delegation:{id:'d1'}});f.bridge.event({type:'session.delegation.created',delegation:{id:'d2'}});
 assert.equal(f.tools.length,1);
 f.bridge.submitToolResult('d1',{text:'first'});
 const first=f.appends().find(e=>e.delegation_id==='d1');assert.equal(first.type,'session.thinking.append');
 assert.equal(f.tools.length,2);assert.equal(f.tools[1].callId,'d2');
 f.bridge.submitToolResult('d2',{text:'second'});
 assert.equal(f.appends().find(e=>e.delegation_id==='d2').type,'session.commentary.append');
 // d3 runs, d4 and d5 wait, d6 is told to ask again.
 for(const id of ['d3','d4','d5','d6'])f.bridge.event({type:'session.delegation.created',delegation:{id}});
 assert.equal(f.tools.length,3);assert.deepEqual(f.bridge.queue.map(q=>q.id),['d4','d5']);
 assert.match(f.appends().find(e=>e.delegation_id==='d6').content,/Too many lookups/);f.bridge.close();
});
test('audio flows both ways, transcripts are reported per turn, and close asks for final usage',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const f=fixture('meeting');f.bridge.sendAudio(Buffer.alloc(960));
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
