# System templates

The templates the console offers when an agent is created. Each folder is a template
(`apps/saas/docs/features/agent-templates.md`). `scripts/deploy-vm-agent.sh` copies this folder into
the vm-agent bundle, so an agent box has them at `/opt/controlclaw/agent/templates/`, and the
console reads their steps from `apps/saas/lib/templates/system.generated.json`. After changing a
template here, run `pnpm --filter @controlclaw/templates build:index`.

`example` and `example-failing` are for tests and dev pairs. The console offers them only outside
production.
