---
name: agentmail
description: "Manage AgentMail inboxes, messages, threads, drafts, webhooks, domains, pods, and API keys with the bundled AgentMail CLI."
metadata:
  {
    "openclaw":
      {
        "requires":
          {
            "bins": ["cc-agentmail"],
            "config": ["plugins.entries.agentmail.config.apiKey"],
          },
      },
  }
---

# AgentMail CLI

Use the AgentMail CLI bundled with this plugin through:

```bash
cc-agentmail <agentmail arguments>
```

The ControlClaw launcher loads the inbox placeholder from the local environment file.
Never pass `--api-key`, `--base-url`, `--environment`, or print the API key. Authentication and
the API endpoint come only from operator-controlled `plugins.entries.agentmail.config` values.
If a literal command value begins with `--base-url` or `--environment`, pass it with the containing
option's `--option=value` form so the endpoint guard can distinguish it from a global override.

Run this command on the OpenClaw host, not inside an agent sandbox. The bundled executable and
skill-scoped credentials are available only to host execution.

## Discover commands dynamically

The CLI is the source of truth. Inspect help before guessing a resource, command, or flag:

```bash
cc-agentmail --help
cc-agentmail inboxes --help
cc-agentmail inboxes:messages --help
cc-agentmail inboxes:messages send --help
```

Prefer machine-readable output:

```bash
cc-agentmail --format json --format-error json inboxes list
```

Use `--transform '<gjson expression>'` when it can reduce a large response without losing
information needed for the task.

## Common operations

```bash
# Inboxes
cc-agentmail --format json inboxes list
cc-agentmail --format json inboxes create --display-name "My Agent"
cc-agentmail --format json inboxes get --inbox-id <inbox-id>

# Messages
cc-agentmail --format json inboxes:messages list --inbox-id <inbox-id>
cc-agentmail --format json inboxes:messages get \
  --inbox-id <inbox-id> --message-id <message-id>
cc-agentmail --format json inboxes:messages send \
  --inbox-id <inbox-id> \
  --to recipient@example.com \
  --subject "Subject" \
  --text "Plain-text body"
cc-agentmail --format json inboxes:messages reply \
  --inbox-id <inbox-id> --message-id <message-id> --text "Reply body"
cc-agentmail --format json inboxes:messages forward \
  --inbox-id <inbox-id> --message-id <message-id> --to recipient@example.com

# Threads and drafts
cc-agentmail --format json inboxes:threads list --inbox-id <inbox-id>
cc-agentmail --format json inboxes:drafts list --inbox-id <inbox-id>

# Other API resources
cc-agentmail webhooks --help
cc-agentmail domains --help
cc-agentmail pods --help
cc-agentmail api-keys --help
```

Before destructive operations, bulk changes, creating credentials, or sending email to a new
recipient, follow the user's approval and confirmation policy. Use idempotency flags when the
command help exposes them and an operation may be retried.

For attachments, the CLI accepts `@path`, `@file://path`, and `@data://path` arguments. Read only
files the user has authorized and prefer `@data://` for binary content.


## ControlClaw email rules

Your organization's firewall checks every email this inbox sends and receives:

- Reply to an email with `inboxes:messages reply` on its message ID, so the answer stays in the thread.
- A `451` with `email_recipient_needs_approval` means the person is new and the owner has been asked to approve them. Say you are waiting for that approval and send again later. Do not retry in a loop.
- A `403` with `email_refused` means the rules do not allow it (recipient not allowed, the hourly or daily limit, sending turned off). The `message` says which. Report it and stop.
- Mail from senders the owner has not allowed, or that fails DMARC, never reaches you. A message shown as `blocked` with no content was held back by the firewall.
