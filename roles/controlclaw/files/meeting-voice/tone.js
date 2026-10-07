// Short tones that tell people the agent started or stopped listening (controlclaw
// docs/plans/meet-wake-improvements.md, 4). Two quiet notes, 24 kHz mono PCM16, made once.
const RATE = 24000;
const NOTE_MS = 70, FADE_MS = 8, GAP_MS = 20;
const LEVEL = 0.1 * 32767; // about -20 dBFS

export function tone(freqs) {
  const note = RATE * NOTE_MS / 1000, fade = RATE * FADE_MS / 1000, gap = RATE * GAP_MS / 1000;
  const out = Buffer.alloc((freqs.length * note + (freqs.length - 1) * gap) * 2);
  freqs.forEach((f, n) => {
    const at = n * (note + gap);
    for (let i = 0; i < note; i++) {
      const env = Math.min(1, i / fade, (note - 1 - i) / fade);
      out.writeInt16LE(Math.round(Math.sin(2 * Math.PI * f * i / RATE) * LEVEL * env), (at + i) * 2);
    }
  });
  return out;
}
/** Rising: the agent heard its name and is listening. */
export const WAKE_TONE = tone([660, 880]);
/** Falling: the agent stopped listening. */
export const STOP_TONE = tone([880, 660]);
