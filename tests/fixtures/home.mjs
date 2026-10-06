// Voice bridges record usage under ~/.openclaw/cc-voice (record.js); keep tests out of the real home.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
process.env.HOME = mkdtempSync(join(tmpdir(), 'cc-voice-test-'));
