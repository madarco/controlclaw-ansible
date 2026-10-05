import test from 'node:test';
import assert from 'node:assert/strict';
import {createWakeMatcher, nameList} from '../roles/controlclaw/files/meeting-voice/wake.js';
test('a request opens with a name, loosely spelled; a name mid-sentence or a look-alike does not count',()=>{
 const m=createWakeMatcher(['ControlClaw','Jarvis','Maria Rossi']);
 for(const [text,name,rest] of [['Control-claw, say hello.','ControlClaw','say hello'],['Hey Control Claw, say hello.','ControlClaw','say hello'],['ControlClone, ask the main agent.','ControlClaw','ask the main agent'],['Control Cloak, stop.','ControlClaw','stop'],['Sorry, ControlClaw, one more thing','ControlClaw','one more thing'],['okay so um ControlClaw help','ControlClaw','help'],['Hey Jarvis what time is it','Jarvis','what time is it'],['Maria Rossi please summarise','Maria Rossi','please summarise']])
  assert.deepEqual(m.match(text),{name,rest},text);
 for(const text of ['I asked ControlClaw yesterday','We need control over the claw machine','Travis, can you','the control panel is broken','Control, please stop','',null])
  assert.equal(m.match(text),null,String(text));
 assert.equal(m.strip('ControlClaw, stop.'),'stop');assert.equal(nameList(['A','B','C']),'A, B or C');
 assert.deepEqual(createWakeMatcher([]).names,['ControlClaw']);
});
