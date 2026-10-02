// These imports are part of the pinned OpenClaw 2026.9.7 runtime.
import { readFile, realpath } from 'node:fs/promises';
import { r as loadRecords } from '/usr/lib/node_modules/openclaw/dist/installed-plugin-index-record-reader-B9fPnhku.mjs';
import { r as isTrusted } from '/usr/lib/node_modules/openclaw/dist/official-external-install-records-CW-a1DbM.mjs';
const [version, digest] = process.argv.slice(2);
if (!version || !/^[a-f0-9]{128}$/.test(digest ?? '')) throw Error('Expected version and SHA-512 pin');
const record = (await loadRecords())['google-meet'];
let ok = Boolean(record && record.version === version && record.resolvedVersion === version &&
  record.integrity === 'sha512-' + Buffer.from(digest, 'hex').toString('base64') &&
  isTrusted({pluginId:'google-meet', packageName:'@openclaw/google-meet', record}));
let installPath;
if (ok) {
  installPath = await realpath(record.installPath);
  const pkg = JSON.parse(await readFile(installPath + '/package.json', 'utf8'));
  ok = pkg.name === '@openclaw/google-meet' && pkg.version === version;
}
process.stdout.write(JSON.stringify({ok, ...(ok ? {installPath} : {})}) + '\n');
