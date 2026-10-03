import {execFileSync} from 'node:child_process';
import {runInNewContext} from 'node:vm';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';
const source=execFileSync('python3',[fileURLToPath(new URL('./export-meet-status.py',import.meta.url)),process.env.MEET_UPSTREAM||'/tmp/meet-upstream','output-queue'],{encoding:'utf8'});
const create=runInNewContext(source,{Buffer,Date});
test('normal generated reply can arrive faster than playback; interruption fences all queued audio',async()=>{
 let release;const writes=[];let clears=0;
 const queue=create({bytesPerMs:48,transport:{writeOutput:async b=>{writes.push(b);await new Promise(r=>release=r);},clearOutput:async()=>{clears++;}},onFailure:(_label,e)=>{throw e;}});
 for(let i=0;i<50;i++)assert.equal(queue.enqueue(Buffer.alloc(19200),true,i===0),true,'20 seconds fits the bounded playback queue');
 await new Promise(r=>setImmediate(r));assert.equal(writes.length,1);
 assert.equal(queue.enqueue(Buffer.alloc(1440000),true,false),false,'unbounded output is refused');
 queue.invalidate();queue.clear();release();await new Promise(r=>setImmediate(r));
 assert.equal(writes.length,1,'old queued audio must never resume');assert.ok(clears>0);
 assert.equal(queue.pending().pendingBytes,0);queue.stop();assert.equal(queue.enqueue(Buffer.alloc(2),true,true),false);
});
