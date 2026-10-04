// Patch releases change bundle filenames and export aliases. Resolve the named functions
// from the root-owned installed runtime; ambiguous or missing exports fail closed.
import { readFile, realpath, readdir } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
async function runtimeFunction(prefix, name) {
  const dir = '/usr/lib/node_modules/openclaw/dist';
  const files = (await readdir(dir)).filter(f => f.startsWith(prefix + '-') && f.endsWith('.mjs'));
  if (files.length !== 1) throw Error('Expected one runtime module: ' + prefix);
  const source = await readFile(dir + '/' + files[0], 'utf8');
  const exports = source.match(/export \{([^}]+)\};?\s*$/)?.[1];
  const alias = exports?.split(',').map(s => s.trim().split(/\s+as\s+/)).find(([symbol]) => symbol === name)?.[1];
  if (!alias) throw Error('Missing runtime export: ' + name);
  const fn = (await import(pathToFileURL(dir + '/' + files[0]).href))[alias];
  if (typeof fn !== 'function') throw Error('Invalid runtime export: ' + name);
  return fn;
}
const loadRecords = await runtimeFunction('installed-plugin-index-record-reader', 'loadInstalledPluginIndexInstallRecords');
const isTrusted = await runtimeFunction('official-external-install-records', 'isTrustedOfficialPluginInstallRecord');
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
