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
test('the cues ring for about 0.8 s at a high average level, peak -8 dBFS, ending in silence', () => {
  for (const [name, cue] of [['wake', WAKE_TONE], ['stop', STOP_TONE]]) {
    const x = samples(cue).slice(LEAD);
    const sounding = name === 'wake' ? x.length - 4000 : x.length; // the wake cue is followed by silence
    assert.ok(sounding / 24000 >= 0.75 && sounding / 24000 <= 0.85, `${name}: about 0.81 s`);
    const peak = Math.max(...x.map(Math.abs));
    assert.ok(peak > 0.39 && peak <= 0.399, `${name}: peaks at -8 dBFS, no clipping`);
    // The previous chime decayed within 90 ms and was heard as barely there: this one keeps ringing.
    const db = (a, b) => 20 * Math.log10(rms(x, a, b));
    assert.ok(db(0, 14400) > -18, `${name}: over -18 dBFS RMS across its first 600 ms (${db(0, 14400).toFixed(1)})`);
    assert.ok(db(9600, 12000) > db(0, 2400) - 9, `${name}: still within 9 dB of its start 400 ms later`);
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
    for (const f of [659, 784, 1047]) assert.ok(share(x, f, 480, LEAD) < 0.02, `${name}: no chime note in the lead`);
  }
  assert.deepEqual(lead(), lead(), 'the same lead every time');
});

test('three notes with their overtones, rising for wake and falling for stop, nothing a phone line would alias', () => {
  const x = samples(WAKE_TONE).slice(LEAD), y = samples(STOP_TONE).slice(LEAD);
  // Each note starts 130 ms after the last: E5, G5, C6 for wake.
  const first = [100, 3000], second = [3300, 6000], third = [6400, 9000];
  assert.ok(share(x, 659, ...first) > 0.3 && share(x, 1318, ...first) > 0.03, 'E5 with its 2nd harmonic first');
  assert.ok(share(x, 784, ...second) > share(x, 659, ...second) * 0.5, 'then G5');
  assert.ok(share(x, 1047, ...third) > 0.1, 'then C6');
  assert.ok(share(y, 1047, ...first) > share(y, 659, ...first), 'stop starts high');
  for (const f of [3600, 4200, 5000]) assert.ok(share(x, f, 100, 9000) < 0.002, `next to nothing at ${f} Hz`);
  assert.equal(chime([659]).length, Math.round(24000 * 0.55) * 2, 'a lone note rings 550 ms');
});
