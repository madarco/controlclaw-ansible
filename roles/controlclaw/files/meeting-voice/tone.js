// Short cues that tell people the agent started or stopped listening (controlclaw
// docs/plans/meet-wake-improvements.md, 4). 24 kHz mono PCM16, made once.
//
// Three chime notes, like a vibraphone: a fundamental with a few harmonics, a soft attack and a
// long ring, the notes overlapping into a chord. On a real Meet, 70 ms pure sine beeps at -20 dBFS
// arrived only as loud as speech, too short to be noticed, and noise suppression on the agent's
// microphone sometimes removed one note entirely (down to -56 dBFS; the vm-agent now opens that
// microphone without it, meeting-mic.ts). The next chime, two notes that decayed within 90 ms, then
// reached people at its full level and was still heard as barely there (T-meettone, owner test
// 2026-10-09): the ear takes a sound that short for a quiet one. These notes ring for most of the
// chime's 0.8 s, and a soft limiter raises its average level while keeping the peak at -8 dBFS: about
// -14.5 LUFS over its first 600 ms, against -22 to -26 LUFS for the agent's speech in the meeting, so
// it is heard clearly over the speech without startling. The level reaches the meeting as made only
// because the vm-agent opens the agent's microphone without automatic gain (meeting-mic.ts).
// Harmonics stay under 3.4 kHz, so the same cue goes through the phone's 8 kHz line unchanged.
const RATE = 24000;
const PARTIALS = [[1, 1], [2, 0.5], [3, 0.25], [4, 0.1]]; // multiple of the fundamental, amplitude
const MAX_HZ = 3400;
const STEP_S = 0.13, RING_S = 0.55, ATTACK_S = 0.01, DECAY_S = 0.35, RELEASE_S = 0.08;
const PEAK = 10 ** (-8 / 20) * 32767; // -8 dBFS
const DRIVE = 2; // soft limiter: tanh(DRIVE x), about 3 dB more average level, no hard clipping

/** One note per frequency, each starting STEP_S after the last and ringing to the end of the chime. */
export function chime(freqs) {
  const length = Math.round(RATE * (STEP_S * (freqs.length - 1) + RING_S));
  const mix = new Float64Array(length);
  freqs.forEach((f, n) => {
    const start = Math.round(RATE * STEP_S * n);
    for (let i = 0; start + i < length; i++) {
      const t = i / RATE, left = (length - start - i) / RATE;
      const attack = Math.min(1, t / ATTACK_S);
      // A raised-cosine release over the last 80 ms: the chime ends in silence, without a click.
      const release = left >= RELEASE_S ? 1 : 0.5 - 0.5 * Math.cos(Math.PI * left / RELEASE_S);
      let v = 0;
      // Higher partials fade faster, as on a struck bar.
      for (const [k, a] of PARTIALS) if (f * k < MAX_HZ) v += a * Math.exp(-t * Math.sqrt(k) / DECAY_S) * Math.sin(2 * Math.PI * f * k * t);
      mix[start + i] += v * attack * release;
    }
  });
  let peak = 0; for (const v of mix) peak = Math.max(peak, Math.abs(v));
  const out = Buffer.alloc(length * 2);
  mix.forEach((v, i) => out.writeInt16LE(Math.round(Math.tanh(DRIVE * v / peak) / Math.tanh(DRIVE) * PEAK), i * 2));
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
const E5 = 659, G5 = 784, C6 = 1047;
/**
 * Rising: the agent heard its name and is listening. A short silence follows, so an answer that
 * starts at once is queued after the chime instead of running into it.
 */
export const WAKE_TONE = Buffer.concat([lead(), chime([E5, G5, C6]), Buffer.alloc(RATE / 6 * 2)]);
/** Falling: the agent stopped listening. */
export const STOP_TONE = Buffer.concat([lead(), chime([C6, G5, E5])]);
