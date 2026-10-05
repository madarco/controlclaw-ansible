// Wake names (controlclaw docs/plans/gpt-live-and-wake-word.md, D5). A request is addressed to the
// agent when it opens with one of its names, optionally after a greeting ("hey", "ok") or a filler
// or two ("sorry, ControlClaw"). A name in the middle of a sentence does not count.
//
// Speech recognition spells names loosely ("Control Clone", "control-claw"), so a name matches when
// its letters are the same with spaces and punctuation ignored, within a small edit distance for
// longer names, or with the same consonants for names of six or more consonants.
export const DEFAULT_WAKE_WORDS = ['ControlClaw'];
const GREETINGS = new Set(['hey', 'hi', 'hello', 'ok', 'okay']);
const FILLERS = new Set(['so', 'um', 'uh', 'erm', 'sorry', 'excuse', 'me', 'and', 'oh', 'well', 'yes', 'yeah']);
const tokens = text => String(text ?? '').normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
const key = text => tokens(text).join('');
const consonants = k => k[0] + k.slice(1).replace(/[aeiouy]/g, '');
function distance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length];
}
function close(heard, name) {
  if (heard === name.key) return true;
  const d = distance(heard, name.key);
  if ((name.key.length >= 6 && d <= 1) || (name.key.length >= 10 && d <= 2)) return true;
  return name.consonants.length >= 6 && distance(consonants(heard), name.consonants) <= 1 && Math.abs(heard.length - name.key.length) <= 3;
}
export function createWakeMatcher(words = DEFAULT_WAKE_WORDS) {
  const names = (Array.isArray(words) && words.length ? words : DEFAULT_WAKE_WORDS)
    .map(word => ({ word: String(word), key: key(word), parts: tokens(word).length }))
    .filter(n => n.key.length >= 3)
    .map(n => ({ ...n, consonants: consonants(n.key) }));
  return {
    names: names.map(n => n.word),
    /** The name the text opens with, and what follows it; null when not addressed. */
    match(text) {
      const t = tokens(text);
      for (let start = 0; start <= Math.min(3, t.length - 1); start++) {
        // Only greetings and fillers may come before the name.
        if (start && !t.slice(0, start).every((w, i) => (i === 0 && GREETINGS.has(w)) || FILLERS.has(w) || GREETINGS.has(w))) break;
        for (const name of names)
          for (let span = 1; span <= name.parts + 2 && start + span <= t.length; span++)
            if (close(t.slice(start, start + span).join(''), name)) return { name: name.word, rest: t.slice(start + span).join(' ') };
      }
      return null;
    },
    /** The text without a leading name (for echo checks and the stop command). */
    strip(text) { const m = this.match(text); return m ? m.rest : String(text ?? ''); },
  };
}
/** "X" / "X or Y" / "X, Y or Z", for instructions and transcription prompts. */
export const nameList = names => names.length < 2 ? names.join('') : `${names.slice(0, -1).join(', ')} or ${names.at(-1)}`;
