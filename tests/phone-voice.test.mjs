import './fixtures/home.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {PhoneVoiceBridge} from '../roles/controlclaw/files/meeting-voice/phone.js';
import * as codecs from './fixtures/phone-codecs.mjs';
function fixture(){
 const audio=[],sent=[],tools=[],closed=[],clears=[];let played=[];
 const bridge=new PhoneVoiceBridge({providerConfig:{provider:'gateway',model:'openai/gpt-realtime-1.5'},onAudio:(b,m)=>audio.push({b,m}),onToolCall:t=>tools.push(t),onClearAudio:()=>clears.push(true),onClose:r=>closed.push(r),getPlaybackState:()=>played},{codecs,metric:()=>{}});
 bridge.ws={readyState:1,bufferedAmount:0,send:s=>sent.push(JSON.parse(s)),terminate:()=>{}};bridge.ready=true;
 return {bridge,audio,sent,tools,closed,clears,playback:p=>{played=p;}};
}
test('stateful SDK codec preserves one minute duration with variable packet sizes and bounded quantization',()=>{
 const pcm=Buffer.alloc(8000*60*2);for(let i=0;i<pcm.length/2;i++)pcm.writeInt16LE(Math.round(10000*Math.sin(2*Math.PI*440*i/8000)),i*2);
 const up=codecs.createStreamingPcmResampler(8000,24000),down=codecs.createStreamingPcmResampler(24000,8000),frames=[];
 const mu=codecs.pcmToMulaw(pcm);for(let i=0;i<mu.length;i+=137)frames.push(down.process(up.process(codecs.mulawToPcm(mu.subarray(i,i+137)))));
 const result=Buffer.concat(frames);assert.ok(Math.abs(result.length-pcm.length)<200,`drift ${result.length-pcm.length}`);
 let peak=0;for(let i=0;i<result.length;i+=2)peak=Math.max(peak,Math.abs(result.readInt16LE(i)));assert.ok(peak>9000&&peak<12000,`peak ${peak}`);
});
test('phone greets once on readiness and accepts turns without wake words',()=>{
 const f=fixture();f.bridge.triggerGreeting('hello');f.bridge.triggerGreeting('hello');assert.equal(f.sent.filter(e=>e.type==='response-create').length,1);
 f.bridge.event({type:'response-created',responseId:'greeting'});f.bridge.event({type:'response-done',responseId:'greeting'});
 f.bridge.event({type:'input-transcription-completed',transcript:'What is two plus three?'});assert.equal(f.bridge.allowed,true);assert.equal(f.sent.filter(e=>e.type==='response-create').length,2);f.bridge.close();
});
test('phone echo does not interrupt, short answers are accepted after playback, stop clears and truncates only played audio',()=>{
 const f=fixture();f.bridge.triggerGreeting('hello');f.bridge.event({type:'response-created',responseId:'greeting'});f.bridge.rememberOutput('Five.');
 f.bridge.event({type:'input-transcription-completed',transcript:'Five.'});assert.equal(f.clears.length,0);
 f.bridge.event({type:'response-done',responseId:'greeting'});f.bridge.phonePlaybackUntil=Date.now()-1000;
 f.bridge.event({type:'input-transcription-completed',transcript:'Five.'});assert.equal(f.clears.length,1);f.bridge.event({type:'response-created',responseId:'reply'});
 f.playback([{itemId:'spoken',audioEndMs:320},{itemId:'queued',audioEndMs:0}]);
 const count=f.sent.filter(e=>e.type==='response-create').length;
 f.bridge.event({type:'input-transcription-completed',transcript:'Stop.'});assert.equal(f.sent.filter(e=>e.type==='response-create').length,count);
 assert.deepEqual(f.sent.filter(e=>e.type==='conversation-item-truncate').map(e=>[e.itemId,e.audioEndMs]),[['spoken',320],['queued',0]]);
 f.bridge.event({type:'audio-delta',responseId:'reply',delta:Buffer.alloc(960).toString('base64')});assert.equal(f.audio.length,0);f.bridge.close();
});
test('phone lookup survives the caller talking over it, provider failure is an error close for classic fallback',()=>{
 const f=fixture();f.bridge.event({type:'input-transcription-completed',transcript:'Look up the snack in memory.'});f.bridge.event({type:'response-created',responseId:'r'});
 f.bridge.event({type:'function-call-arguments-done',name:'ask_agent',callId:'c',arguments:JSON.stringify({question:'What is the snack?'})});assert.equal(f.tools[0].name,'openclaw_agent_consult');
 f.bridge.event({type:'response-done',responseId:'r'});
 // "Hmm, okay" while the main agent works: a new caller turn, which interrupts on phone.
 f.bridge.event({type:'input-transcription-completed',transcript:'Hmm, okay, take your time.'});f.bridge.event({type:'response-created',responseId:'r2'});
 assert.equal(f.bridge.calls.size,1);const creates=f.sent.filter(e=>e.type==='response-create').length;
 f.bridge.submitToolResult('c',{text:'lemon shortbread'});assert.equal(f.sent.filter(e=>e.type==='conversation-item-create').at(-1).item.callId,'c');
 f.bridge.event({type:'response-done',responseId:'r2'});assert.equal(f.sent.filter(e=>e.type==='response-create').length,creates+1);
 f.bridge.fail();assert.deepEqual(f.closed,['error']);
});
