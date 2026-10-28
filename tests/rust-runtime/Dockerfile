# For tests/rust-runtime.test.sh: Ubuntu 24.04 with ansible-core, a controlclaw user, and stand-ins
# for systemctl and journalctl (no systemd in a container).
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip sudo ca-certificates \
 && pip3 install --break-system-packages -q ansible-core \
 && useradd -m controlclaw && rm -rf /var/lib/apt/lists/*
RUN printf '#!/bin/sh\necho "systemctl $*" >> /tmp/systemctl.log\ncase "$*" in *"-p Result"*) echo start-limit-hit ;; esac\nexit 0\n' > /usr/local/bin/systemctl \
 && printf '#!/bin/sh\necho "the last line of the unit"\n' > /usr/local/bin/journalctl \
 && chmod +x /usr/local/bin/systemctl /usr/local/bin/journalctl
