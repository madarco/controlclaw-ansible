// Root-only, fixed local operations. Never prints private keys or accepts executable code.
const fs = require('node:fs');
const crypto = require('node:crypto');
const tls = require('node:tls');
const { execFileSync } = require('node:child_process');
const keys = '/opt/controlclaw/keys';
const read = (path) => fs.readFileSync(path, 'utf8');
const cmd = (args) => execFileSync(args[0], args.slice(1), { encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const write = (path, data, mode = 0o644, owned = false) => {
  // Service-owned key directories must not turn a predictable temporary name into a root write.
  const temporary = path + '.' + crypto.randomUUID();
  const fd = fs.openSync(temporary, 'wx', mode);
  try {
    fs.writeFileSync(fd, data);
    fs.fchmodSync(fd, mode);
    if (owned) { const uid = Number(cmd(['id', '-u', 'controlclaw'])); fs.fchownSync(fd, uid, uid); }
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, path);
};
const config = JSON.parse(read('/root/cc-pool-worker.json'));
function cert(hostname) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host: '127.0.0.1', port: 443, servername: hostname, rejectUnauthorized: true }, () => { resolve(sock.authorized); sock.end(); });
    sock.setTimeout(2000, () => { sock.destroy(); resolve(false); });
    sock.on('error', () => { sock.destroy(); resolve(false); });
  });
}
function publicFacts() {
  const result = { vmPublicKey: read(`${keys}/vm_public_key.pem`) };
  try { result.tangThumbprint = cmd(['/usr/local/bin/cc-secure', 'thumbprint']); } catch {}
  if (config.role === 'mitm' && fs.existsSync('/opt/controlclaw/mitm/ca/ca-cert.pem')) {
    const ca = read('/opt/controlclaw/mitm/ca/ca-cert.pem');
    result.ca = { cert: ca, signature: crypto.sign(null, Buffer.from(ca), read(`${keys}/vm_private_key.pem`)).toString('base64') };
  }
  return result;
}
function pair(peer) {
  if (!peer || !/^10\.0\.\d{1,3}\.\d{1,3}$/.test(peer.ip) || !/^[a-z0-9-]+$/.test(peer.id) || !/^[A-Za-z0-9_-]{43}$/.test(peer.tangThumbprint ?? '')) return;
  const pinPath = '/etc/controlclaw/pool-partner.json';
  if (fs.existsSync(pinPath)) {
    const pin = JSON.parse(read(pinPath));
    if (pin.id !== peer.id || pin.ip !== peer.ip || pin.vmPublicKey !== peer.vmPublicKey || pin.tangThumbprint !== peer.tangThumbprint) throw Error('peer changed');
  }
  write(pinPath, JSON.stringify(peer));
  write('/opt/controlclaw/state/tang-partners.json', JSON.stringify([{ ip: peer.ip, name: peer.name }]), 0o644, true);
  if (config.role === 'mitm') {
    write('/etc/controlclaw/pool-peer.json', JSON.stringify([{ private_ip: peer.ip, vm_id: peer.id, role: 'openclaw', public_key: peer.vmPublicKey }]));
  } else if (peer.ca) {
    if (!crypto.verify(null, Buffer.from(peer.ca.cert), peer.vmPublicKey, Buffer.from(peer.ca.signature, 'base64'))) throw Error('bad CA signature');
    const fingerprint = crypto.createHash('sha256').update(peer.ca.cert).digest('hex');
    if (!fs.existsSync(`${keys}/mitm_ca_fingerprint`)) {
      write(`${keys}/mitm_pinned_pubkey.pem`, peer.vmPublicKey, 0o644, true);
      write(`${keys}/mitm-ca.crt`, peer.ca.cert, 0o644, true);
      cmd(['/usr/local/bin/cc-install-ca']);
      write(`${keys}/mitm_ca_fingerprint`, fingerprint, 0o644, true);
    }
  }
  const bindings = cmd(['/usr/local/bin/cc-secure', 'list']).split('\n').filter(Boolean).map(JSON.parse);
  if (!bindings.some((b) => b.url === `http://${peer.ip}:3920` && b.thp === peer.tangThumbprint)) {
    cmd(['/usr/local/bin/cc-secure', 'bind', `http://${peer.ip}:3920`, peer.tangThumbprint]);
  }
}
async function healthy() {
  if (!fs.existsSync('/etc/controlclaw/pool-warmed')) return false;
  const partner = JSON.parse(read('/etc/controlclaw/pool-partner.json'));
  const bindings = cmd(['/usr/local/bin/cc-secure', 'list']).split('\n').filter(Boolean).map(JSON.parse);
  if (!bindings.some((b) => b.url === `http://${partner.ip}:3920` && b.thp === partner.tangThumbprint)) return false;
  cmd(['mountpoint', '-q', keys]);
  const units = config.role === 'mitm' ? ['controlclaw-mitm-agent', 'controlclaw-mitmproxy', 'controlclaw-connector', 'dnsmasq'] : ['openclaw', 'controlclaw-agent', 'browser-stream'];
  for (const unit of [...units, 'caddy', 'cc-secure', 'tangd.socket']) cmd(['systemctl', 'is-active', '--quiet', unit]);
  const response = await fetch('http://127.0.0.1:3100/health', { signal: AbortSignal.timeout(2000) });
  return response.ok && await cert(config.hostname);
}
function activate(vars) {
  if (vars.vm_id !== config.boxId || vars.vm_hostname !== config.hostname || !fs.existsSync('/etc/controlclaw/pool-unclaimed')) throw Error('identity mismatch');
  cmd(['mountpoint', '-q', keys]);
  if (!vars.saas_public_key.startsWith('-----BEGIN PUBLIC KEY-----\n') || crypto.createPublicKey(vars.saas_public_key).asymmetricKeyType !== 'ed25519') throw Error('bad SaaS public key');
  write('/etc/controlclaw/luks-recovery-pub.b64', vars.luks_recovery_pubkey);
  // Seal the SAME random passphrase. No key rotation, temporary recipient, or key export.
  cmd(['/usr/local/bin/cc-secure', 'reseal']);
  const files = { saas_public_key: 'saas_public_key.pem', vm_id: 'vm_id', vm_hostname: 'vm_hostname',
    vm_bootstrap_token: 'bootstrap_token', register_api_url: 'register_api_url', ready_api_url: 'ready_api_url',
    config_api_url: 'config_api_url', org_id: 'org_id', controlclaw_url: 'controlclaw_url' };
  for (const [name, file] of Object.entries(files)) if (vars[name]) write(`${keys}/${file}`, vars[name], name === 'vm_bootstrap_token' ? 0o600 : 0o644, true);
  if (config.role === 'openclaw') {
    const source = cmd(['/usr/local/bin/cc-doctor-trust']).trim();
    cmd(['ufw', 'allow', 'from', source, 'to', 'any', 'port', '22', 'proto', 'tcp']);
  }
  const base = config.url.split('/api/internal/ready-pool/poll')[0];
  write('/etc/controlclaw/disk.env', `VM_ID=${vars.vm_id}\nCONTROLCLAW_URL=${base}\n`);
  const pin = read('/etc/controlclaw/update.conf').replace(/^LUKS_RECOVERY_PUBKEY=.*$/m, `LUKS_RECOVERY_PUBKEY=${vars.luks_recovery_pubkey}`).replace(/^ORG_ID=.*$/m, `ORG_ID=${vars.org_id}`);
  write('/etc/controlclaw/update.conf', pin, 0o444);
  if (config.role === 'mitm') {
    fs.mkdirSync('/etc/systemd/system/controlclaw-mitm-agent.service.d', { recursive: true });
    write('/etc/systemd/system/controlclaw-mitm-agent.service.d/pool-claim.conf', `[Service]\nEnvironment=ORG_ID=${vars.org_id}\n`);
    // MITM_TENANT is log attribution only. Keep all runtime secrets and the running proxy.
  }
  // Store the alias for future reprovisioning before removing the unclaimed gate.
  write('/etc/controlclaw/handle-hostname', vars.handle_hostname);
  write(`${keys}/access_hostname`, vars.handle_hostname, 0o644, true);
  write('/etc/controlclaw/pool-activating', vars.vm_id);
  fs.unlinkSync('/etc/controlclaw/pool-unclaimed');
  cmd(['systemctl', 'daemon-reload']);
  cmd(['systemctl', 'restart', config.role === 'mitm' ? 'controlclaw-mitm-agent' : 'controlclaw-agent']);
  // Caddy obtains this certificate asynchronously; transport keeps using the neutral name.
  if (vars.handle_hostname !== config.hostname) {
    const path = '/etc/caddy/Caddyfile';
    const source = read(path);
    if (!source.includes(`\n${config.hostname} {`)) throw Error('Caddy primary hostname missing');
    write(path, source.replace(`\n${config.hostname} {`, `\n${config.hostname}, ${vars.handle_hostname} {`).replace(
      '# Pool handle Origin rewrite (installed at claim).',
      `# Pool handle Origin rewrite (installed at claim).\n            header_up Origin https://${config.hostname}`));
    cmd(['systemctl', 'reload', 'caddy']);
  }
}
(async () => {
  const action = process.argv[2];
  if (action === 'facts') console.log(JSON.stringify(publicFacts()));
  else if (action === 'peer') pair(JSON.parse(fs.readFileSync(0, 'utf8')));
  else if (action === 'health') process.exit(await healthy() ? 0 : 1);
  else if (action === 'activate') activate(JSON.parse(read('/root/cc-pool-claim.json')).vars);
  else throw Error('unsupported operation');
})().catch(() => { process.exit(1); });
