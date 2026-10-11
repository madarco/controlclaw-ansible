#!/bin/bash
# The job is there, whatever its state: a person may have paused it or changed its time.
# If OpenClaw never answers, that is "could not check", not "no job": exit 124, which the runner
# reads as a check that did not run, so the job is not added a second time.
. "$CC_TEMPLATE_DIR/scripts/lib.sh"
jobs=$(cron_jobs) || { echo "OpenClaw did not answer"; exit 124; }
found=0; echo "$jobs" | has_job morning-brief || found=$?
if [ "$found" = 1 ]; then echo "no morning-brief job"; exit 1; fi
if [ "$found" != 0 ]; then echo "OpenClaw's list of scheduled jobs could not be read"; exit 124; fi
