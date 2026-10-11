#!/bin/bash
# Schedules the morning brief with OpenClaw's own scheduler: 08:00 in the time zone the agent was
# created in (UTC when the console did not learn one).
set -euo pipefail
. "$CC_TEMPLATE_DIR/scripts/lib.sh"
jobs=$(cron_jobs) || { echo "OpenClaw did not answer"; exit 1; }
# Never a second job: if it is there already, paused or not, there is nothing to add.
found=0; echo "$jobs" | has_job morning-brief || found=$?
if [ "$found" = 0 ]; then exit 0; fi
# A list that cannot be read is not "no job": adding one now could make a second.
if [ "$found" != 1 ]; then echo "OpenClaw's list of scheduled jobs could not be read"; exit 1; fi
openclaw cron add --name morning-brief --cron "0 8 * * *" --tz "${CC_AGENT_TIMEZONE:-UTC}" --announce \
  --message "Morning brief: today's calendar, what in the inbox needs an answer, and what is still open from yesterday. Keep it short."
echo "scheduled for 08:00 ${CC_AGENT_TIMEZONE:-UTC}"
