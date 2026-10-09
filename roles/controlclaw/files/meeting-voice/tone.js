// Short cues that tell people the agent started or stopped listening (controlclaw
// docs/plans/meet-wake-improvements.md, 4). 24 kHz mono PCM16, made once.
//
// Two chime notes, like a soft marimba: a fundamental with a few harmonics, a quick attack and a
// decay. On a real Meet, 70 ms pure sine beeps at -20 dBFS arrived only as loud as speech, too short
// to be noticed, and noise suppression on the agent's microphone sometimes removed one note entirely
// (down to -56 dBFS; the vm-agent now opens that microphone without it, meeting-mic.ts). A harmonic,
// decaying sound is also what a noise filter is likelier to keep. The harmonics stay under 3.5 kHz, so the same cue
// goes through the phone's 8 kHz line unchanged.
const RATE = 24000;
const PARTIALS = [[1, 1], [2, 0.45], [3, 0.22]]; // multiple of the fundamental, amplitude
const NOTE_S = 0.32, STEP_S = 0.12, ATTACK_S = 0.004, DECAY_S = 0.09;
const PEAK = 0.56 * 32767; // about -5 dBFS at the attack, about -15 dBFS over its first 100 ms

export function chime(freqs) {
  const length = Math.round(RATE * (STEP_S * (freqs.length - 1) + NOTE_S));
  const mix = new Float64Array(length);
  freqs.forEach((f, n) => {
    const start = Math.round(RATE * STEP_S * n);
    for (let i = 0; start + i < length && i < RATE * NOTE_S; i++) {
      const t = i / RATE;
      const attack = Math.min(1, t / ATTACK_S);
      // Higher partials fade faster, as on a struck bar; the tail fades to silence by the end.
      const tail = Math.min(1, (NOTE_S - t) / 0.02);
      let v = 0;
      for (const [k, a] of PARTIALS) v += a * Math.exp(-t * k / DECAY_S) * Math.sin(2 * Math.PI * f * k * t);
      mix[start + i] += v * attack * tail;
    }
  });
  let peak = 0; for (const v of mix) peak = Math.max(peak, Math.abs(v));
  const out = Buffer.alloc(length * 2);
  mix.forEach((v, i) => out.writeInt16LE(Math.round(v / peak * PEAK), i * 2));
  return out;
}
const LEAD_S = 0.3, LEAD_DB = -49;
/**
 * 300 ms of very low noise (-49 dBFS, under a quiet room's own noise) before a cue. After a stretch of
 * digital silence, Meet fades in the first 100 ms or so of the next sound: the falling chime, which
 * follows the end of a session, reached people with its first note up to 10 dB down (T-meettone).
 * With this lead the meeting audio is already flowing when the chime starts.
 */
export function lead(seconds = LEAD_S) {
  const n = Math.round(RATE * seconds), out = Buffer.alloc(n * 2), level = 10 ** (LEAD_DB / 20) * 32767;
  let seed = 1, low = 0;
  for (let i = 0; i < n; i++) {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0; // the same noise every time
    low = low * 0.9 + (seed / 2147483648 - 1) * 0.1; // brown-ish: low-passed white noise
    // `low` has an RMS of about 0.13; a 20 ms fade-in.
    out.writeInt16LE(Math.round(low / 0.13 * level * Math.min(1, i / (RATE * 0.02))), i * 2);
  }
  return out;
}
const G5 = 784, C6 = 1047;
/**
 * Rising: the agent heard its name and is listening. A short silence follows, so an answer that
 * starts at once is queued after the chime instead of running into it.
 */
export const WAKE_TONE = Buffer.concat([lead(), chime([G5, C6]), Buffer.alloc(RATE / 6 * 2)]);
/** Falling: the agent stopped listening. */
export const STOP_TONE = Buffer.concat([lead(), chime([C6, G5])]);
