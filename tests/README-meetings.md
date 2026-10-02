# Meet runtime regression checks

Extract the pinned OpenClaw and Google Meet npm archives into `/tmp/meet-upstream/host/package` and `/tmp/meet-upstream/package`. Pins are in `roles/controlclaw/defaults/main.yml`.

Run `python3 -m unittest discover -s tests -v` and `ansible-playbook --syntax-check -i localhost, playbook.yml`.

With Playwright and Chromium installed, run `node tests/meet-browser-regressions.mjs`. `PLAYWRIGHT_MODULE` may point to an existing Playwright module and `MEET_UPSTREAM` overrides the archive directory. The test applies the integrity-checked patch to temporary copies, then executes its real status script against browser DOM fixtures. It covers admission-lobby detection, refusal, muted controls, enforced denied permissions, and unknown device states. It does not replace a live admitted-call soak.
