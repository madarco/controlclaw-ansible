# OpenClaw's own list of scheduled jobs, paused ones included, as JSON. While OpenClaw restarts (it
# does in an agent's first minutes) the command fails; that is waited out, up to a minute and a half.
cron_jobs() {
  for attempt in 1 2 3 4 5 6 7 8 9; do
    if jobs=$(openclaw cron list --all --json 2>/dev/null); then echo "$jobs"; return 0; fi
    sleep 10
  done
  return 1
}

# Whether the list (on stdin) has a job with exactly this name. The name field is compared, not the
# text: a job whose message only mentions the name is not it. 0 yes, 1 no, 2 the list is unreadable.
has_job() {
  node -e '
    let text = "";
    process.stdin.on("data", (d) => (text += d)).on("end", () => {
      let list;
      try { list = JSON.parse(text); } catch { process.exit(2); }
      if (!Array.isArray(list)) list = list && Array.isArray(list.jobs) ? list.jobs : null;
      if (!list) process.exit(2);
      process.exit(list.some((job) => job && job.name === process.argv[1]) ? 0 : 1);
    });
  ' "$1"
}
