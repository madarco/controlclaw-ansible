# Meet runtime regression checks

Extract the pinned OpenClaw and Google Meet npm archives into `/tmp/meet-upstream/host/package` and `/tmp/meet-upstream/package`. Pins are in `roles/controlclaw/defaults/main.yml`.

Run `python3 -m unittest discover -s tests -v` and `ansible-playbook --syntax-check -i localhost, playbook.yml`.

With Playwright and Chromium installed, run `node tests/meet-browser-regressions.mjs`. `PLAYWRIGHT_MODULE` may point to an existing Playwright module and `MEET_UPSTREAM` overrides the archive directory. The test applies the integrity-checked patch to temporary copies, then executes its real status script against browser DOM fixtures. It covers admission-lobby detection, refusal, muted controls, enforced denied permissions, unknown device states, automatic participant-side caption activation, and caption filtering that removes device/join announcements while retaining spoken action items and native revision identities. It does not replace a live admitted-call soak.


Voice regressions use `MEET_UPSTREAM=/path/to/extracted node --test tests/meeting-{voice,consult,output-queue}.test.mjs`. The consult regression executes the patched native function, checks fresh admission and genuine drain handling, and rejects an absent isolated capture source. `CHROME_PATH=/usr/bin/google-chrome` may select an installed browser for DOM tests.

`live-meeting-voice.mjs` is an unattended diagnostic for a disposable, already approved dev pair. Copy it to the agent and run as `controlclaw` with `XDG_RUNTIME_DIR=/run/user/<uid>`, its Pulse socket and the firewall CA in `NODE_EXTRA_CA_CERTS`. Supply synthetic mono PCM16/24kHz files as positional arguments. A filename containing `long` is followed after 3.5 seconds by the next prompt, enabling interruption tests. Other prompts allow 22 seconds for a reply. The script uses the installed signed media grant, renews it, captures `cc_meeting_remote.monitor`, writes `openclaw_meeting_audio`, delegates through the patched native read-only consult, and closes its lease and audio processes.

Create `memory/meeting-demo.md` on the disposable agent with a public synthetic picnic snack before testing. The diagnostic warms the main-agent runtime with that fixture. It logs synthetic transcripts and answers deliberately; never run it with real participant audio or private fixtures. The product firewall activity remains metadata-only. This diagnostic does not establish admission, remote participant audibility, Meet RTP or live mode-switch continuity.
