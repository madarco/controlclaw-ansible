import test from 'node:test';
import assert from 'node:assert/strict';
import { WAKE_TONE, STOP_TONE, chime, lead } from '../roles/controlclaw/files/meeting-voice/tone.js';

const samples = b => Array.from({ length: b.length / 2 }, (_, i) => b.readInt16LE(i * 2) / 32768);
const rms = (x, a, b) => Math.sqrt(x.slice(a, b).reduce((s, v) => s + v * v, 0) / Math.max(1, b - a));
/** Share of a stretch's energy at one frequency (Goertzel). */
function share(x, f, a, b) {
  const k = 2 * Math.cos(2 * Math.PI * f / 24000); let s1 = 0, s2 = 0, e = 0;
  for (let i = a; i < b; i++) { const s0 = x[i] + k * s1 - s2; s2 = s1; s1 = s0; e += x[i] * x[i]; }
  return (s1 * s1 + s2 * s2 - k * s1 * s2) / ((b - a) / 2) / e;
}

const LEAD = 7200; // 300 ms of low noise before each chime
test('the cues are short chimes, clearly louder than a quiet beep, ending in silence', () => {
  for (const [name, cue] of [['wake', WAKE_TONE], ['stop', STOP_TONE]]) {
    const x = samples(cue).slice(LEAD);
    const sounding = name === 'wake' ? x.length - 4000 : x.length; // the wake cue is followed by silence
    assert.ok(sounding / 24000 >= 0.4 && sounding / 24000 <= 0.5, `${name}: about 0.44 s`);
    const peak = Math.max(...x.map(Math.abs));
    assert.ok(peak > 0.54 && peak <= 0.57, `${name}: peaks near -5 dBFS`);
    assert.ok(20 * Math.log10(rms(x, 0, 2400)) > -16, `${name}: about 8 dB over the old -23 dBFS beep`);
    assert.ok(rms(x, sounding - 48, sounding) < peak / 100, `${name}: fades to silence (40 dB down at the end), no click`);
  }
  assert.ok(WAKE_TONE.subarray(-4000).every(b => b === 0), 'silence after the wake cue');
});

test('each chime starts after 300 ms of noise far under it, so Meet does not fade its first note in', () => {
  for (const [name, cue] of [['wake', WAKE_TONE], ['stop', STOP_TONE]]) {
    assert.deepEqual(cue.subarray(0, LEAD * 2), lead(), `${name}: the lead first`);
    const x = samples(cue);
    const db = 20 * Math.log10(rms(x, 480, LEAD)); // after its 20 ms fade-in
    assert.ok(db > -52 && db < -46, `${name}: lead at about -49 dBFS (${db.toFixed(1)})`);
    assert.ok(x.slice(0, LEAD).some(v => v !== 0), `${name}: not digital silence`);
    assert.ok(Math.abs(x[0]) < 0.001, `${name}: no click at the start`);
    for (const f of [784, 1047]) assert.ok(share(x, f, 480, LEAD) < 0.02, `${name}: no chime note in the lead`);
  }
  assert.deepEqual(lead(), lead(), 'the same lead every time');
});

test('harmonic-rich: the fundamental and its overtones, rising for wake and falling for stop, nothing a phone line would alias', () => {
  const x = samples(chime([784, 1047]));
  const first = [100, 2800], second = [3100, 5800];
  assert.ok(share(x, 784, ...first) > 0.3 && share(x, 1568, ...first) > 0.05 && share(x, 2352, ...first) > 0.005, 'G5 with its 2nd and 3rd harmonics');
  assert.ok(share(x, 1047, ...second) > share(x, 784, ...second), 'then C6');
  const y = samples(STOP_TONE).slice(LEAD);
  assert.ok(share(y, 1047, ...first) > share(y, 784, ...first), 'stop starts high');
  for (const f of [3600, 4200, 5000]) assert.ok(share(x, f, ...first) < 0.001, `no energy at ${f} Hz`);
});
