# Using seCreds with Claude Code

## Identify the agent

seCreds reads the agent's name from `SECREDS_AGENT`. Claude Code is also detected automatically (it sets `CLAUDECODE`), so
plain use needs nothing. List the names you use in `~/.secreds/config.json` (`secreds init --agents claude,codex`).

## Reasons and notes

Every `secreds run` needs `--reason "why"`, and the agent should finish with `secreds note RUN_ID "what happened"` (the run id is printed after the notice). Add `secreds note` to the allowed commands below so it does not prompt.

**Reference entries** hold no secret (for example, how keyless SSH to a host is set up). An agent reads one with `secreds info NAME`; `secreds run` refuses it. Add `secreds info` to the allowed commands as well.

## Permission rules

These rules in `~/.claude/settings.json` let the agent *use* credentials but keep it away from the Keychain, the data
folder and the management commands. Match the path to how you invoke `secreds` (`~/.local/bin/secreds` after `./install.sh`).

```json
{
  "permissions": {
    "allow": [
      "Bash(~/.local/bin/secreds run:*)",
      "Bash(~/.local/bin/secreds note:*)",
      "Bash(~/.local/bin/secreds info:*)",
      "Bash(~/.local/bin/secreds list)",
      "Bash(~/.local/bin/secreds audit:*)",
      "Bash(~/.local/bin/secreds notice)"
    ],
    "deny": [
      "Bash(security find-generic-password:*)",
      "Bash(security dump-keychain:*)",
      "Bash(security export:*)",
      "Bash(~/.local/bin/secreds add:*)",
      "Bash(~/.local/bin/secreds edit:*)",
      "Bash(~/.local/bin/secreds grant:*)",
      "Bash(~/.local/bin/secreds revoke:*)",
      "Bash(~/.local/bin/secreds restore:*)",
      "Bash(~/.local/bin/secreds delete:*)",
      "Bash(~/.local/bin/secreds end-grants:*)",
      "Bash(~/.local/bin/secreds export:*)",
      "Bash(~/.local/bin/secreds import:*)",
      "Bash(~/.local/bin/secreds import-keys:*)",
      "Bash(~/.local/bin/secreds import-env:*)",
      "Bash(~/.local/bin/secreds backup:*)",
      "Bash(~/.local/bin/secreds backups:*)",
      "Bash(~/.local/bin/secreds backup-info:*)",
      "Bash(~/.local/bin/secreds restore-backup:*)",
      "Bash(~/.local/bin/secreds update:*)",
      "Bash(~/.local/bin/secreds gui:*)",
      "Read(~/.secreds/**)",
      "Edit(~/.secreds/**)",
      "Bash(*/.secreds/venv/bin/python*)"
    ]
  }
}
```

These are guardrails for a cooperating agent, not a sandbox; see the README's security model.

Optionally allow the agent to *propose* credentials without a prompt each time:
`"Bash(~/.local/bin/secreds request:*)"` and `"Bash(~/.local/bin/secreds requests)"`.

## Adding a credential without pasting a secret

Tell the agent what you are about to use. It runs `secreds request NAME --kind login --address ... --folder ... --notes ...`
with only the non-secret details. Open the GUI's Home page: the request waits under "Waiting for your secret". Click
**Add the secret...**, review every field, type the secret and save. The agent never sees it.

## Two Claude profiles (for example personal and work)

If you run Claude Code with separate config directories, give each profile its own settings with the rules above, and set
a different name in the work profile's `settings.json`:

```json
{ "env": { "SECREDS_AGENT": "claude-work" } }
```

In `config.json` treat the two names as one agent for access, while the log keeps the real profile:

```json
{ "agents": ["claude", "claude-work"], "families": { "claude-work": "claude" } }
```

Remember that output from commands run in a work-account session belongs to that account's record. Keep credentials you
would not want your employer to see away from work sessions, or label them Personal and Work in the GUI and choose.

---

<sub>**seCreds** v0.6.0 · by [henderlabs](https://github.com/henderlabs) · [Send feedback](https://github.com/henderlabs/secreds/issues/new/choose)</sub>
