// Fixed local verification after claim. No remote commands or enrollment credential reuse.
const fs = require('node:fs');
const crypto = require('node:crypto');
const tls = require('node:tls');
const { execFileSync } = require('node:child_process');
const vars = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const api = vars.ready_api_url.replace('/api/vm-agent/ready', '/api/internal/ready-pool/complete');
const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function certificate() {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: '127.0.0.1', port: 443, servername: vars.vm_hostname,
      rejectUnauthorized: true }, () => { resolve(socket.authorized === true); socket.end(); });
    socket.setTimeout(3000, () => { socket.destroy(); resolve(false); });
    socket.on('error', () => { socket.destroy(); resolve(false); });
  });
}

(async () => {
  for (let i = 0; i < 240; i++) {
    try {
      const bindings = execFileSync('/usr/local/bin/cc-secure', ['list'], { timeout: 3000, encoding: 'utf8' })
        .trim().split('\n').filter(Boolean).map(JSON.parse);
      if (bindings.length && await certificate()) {
        const now = Math.floor(Date.now() / 1000);
        const unsigned = `${encode({ alg: 'EdDSA', typ: 'JWT' })}.${encode({ vmId: vars.vm_id, iat: now, exp: now + 60 })}`;
        const key = fs.readFileSync('/opt/controlclaw/keys/vm_private_key.pem');
        const token = `${unsigned}.${crypto.sign(null, Buffer.from(unsigned), key).toString('base64url')}`;
        const response = await fetch(api, { method: 'POST', signal: AbortSignal.timeout(5000),
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: JSON.stringify({ bindings, certificate: true }) });
        if (response.ok) return;
        // systemctl restart returns before asynchronous key registration finishes.
        // A signed report may race that first registration; retry within the bounded claim window.
        if ([403, 404].includes(response.status)) process.exit(1);
      }
    } catch { /* Never log keys, tokens, or claim variables. */ }
    await sleep(2000);
  }
  process.exit(1);
})();
