# seCreds

**Secrets for your AI agents, without handing them the keys.**

*seCreds is made by [henderlabs](https://github.com/henderlabs). Feedback is welcome: [open an issue](https://github.com/henderlabs/secreds/issues/new/choose) (never include a real secret).*

seCreds is a small local credential broker for AI coding agents such as Claude Code and Codex. Your passwords, API keys and tokens live in the macOS Keychain. An agent never gets to read them. It can only ask seCreds to run one command with a credential injected, and seCreds decides whether to allow that, asks for Touch ID when you want it to, masks the secret in the output, and writes every use to an audit log.

> **Status: alpha, macOS only.** It started as a personal tool. It is useful, tested, and honest about its limits (see [Security model](#security-model)), but it is not a sandbox and has not had an independent security review.

## What it looks like

*These screenshots use made-up demo data.*

**Home:** what is unlocked right now, anything that needs attention, and recent activity.

![Home page: unlocked credentials, attention list and recent activity](docs/screenshots/home.png)

**Credentials:** a folder tree on the left. Each card shows who can use the credential, whether it is locked, and what it is limited to.

![Credentials page: folder tree and a credential card with its lock state and pinned command](docs/screenshots/credentials.png)

**Activity:** every use, with the reason the agent gave, the command that ran, the result and the agent's own outcome note. Failures and refusals stand out.

![Activity page with two runs expanded, one of them a failed run](docs/screenshots/activity.png)

**Agents:** tick the AI tools you use (or add your own), group profiles that count as one agent, and see the exact notice every agent receives, plus a ready-to-paste instructions file for each tool.

![Agents page: agent list, profile groups, the notice agents see](docs/screenshots/agents.png)

**Backup:** set one backup password once, keep recovery files in two places, and run a scheduled plan to iCloud, a cloud drive, a folder or an S3 bucket. Restore and sync from the same page.

![Backup page: backup key status, backup plan, one-off backup, sync and restore](docs/screenshots/backup.png)

## Why

Agents need real credentials to do real work: a NAS API, an S3 bucket, a hypervisor. The usual options are bad: pasting secrets into chat (they end up in transcripts), keeping them in plain `.env` files (any process can read them), or giving the agent your whole password manager session. seCreds sits in the middle:

- the secret is typed **once**, by you, in a local GUI, and stored in the Keychain;
- agents use it through `secreds run NAME --reason "why" -- <command>`, which injects it as environment variables for that single process;
- you control **which agent** may use **which credential**, with **which commands**, for **how long**.

## Why not just give the agent your password manager?

Connecting an agent to a shared or team password manager is the easy route, and it quietly gives the agent a much bigger key than the job needs. seCreds gives agents a separate, purpose-built place for the handful of credentials they actually use:

- **A small, deliberate set.** Only what you put in seCreds exists for an agent. Your family's, your team's and your own personal vault items are never in reach, because they are not there.
- **Per-credential, per-agent access.** Each credential names the agents allowed to use it. Another agent, or the same agent on another credential, is refused.
- **A person approves.** Touch ID opens a time-limited window, and every use needs a written reason. Nothing is silently available.
- **Commands can be pinned.** You can restrict a credential to specific commands or scripts (pinned by hash), so a leaked or misused grant cannot be pointed at something else.
- **A trail you can read.** Every use records who, which credential, why, which command, from which folder, and what happened.
- **Nothing shared is exposed.** Other people's items never pass through an agent session, and revoking an agent's access never touches a shared vault.

**What it is not.** seCreds is a local, single-user tool for macOS. It complements a password manager and does not replace one, and it is not a team secrets platform. The agent still receives the secret as an environment variable for the one command it runs, so the protection comes from scoping, approval and audit rather than from the agent never seeing the value. It only governs agents that go through `secreds run`: an agent with other access to the machine can still reach whatever else is on it. Credentials set to "any command" are weaker than pinned ones, so pin commands wherever you can. See [Security model](#security-model) for the full list of limits.

## How a use works

1. You add a credential in the GUI (`secreds gui`). The value goes straight into the Keychain and is never shown again, except by **Reveal** or **Copy**, which need Touch ID.
2. An agent runs `secreds run NAME --reason "check the NAS volumes" -- python3 my_script.py`. The reason is required.
3. seCreds checks, in order: the caller's agent identity, the credential's allowed agents, revoked or expired, human-only, the allowed-commands list (with script hashes), and Touch ID approval (or an active approval window).
4. If everything passes it runs the command with the secret in its environment, masks the exact value in the output, and logs the use: the reason, the command (program and script, never its arguments), the folder, the script's SHA-256 fingerprint and the result.
5. When the task is done the agent adds a one-line outcome with `secreds note RUN_ID "what happened"`. The Activity page shows it next to the run, labelled as written by the agent.

## Features

- **Per-credential policy:** allowed agents, Touch ID or auto approval, an approval window (15 minutes to 24 hours; new credentials default to 30 minutes), expiry, revoke and restore.
- **Allowed-commands list with script pinning:** "this key may only be used with `python3 ~/scripts/audit.py`", and if that script changes it stops working until you re-pin it. Overly broad entries such as `bash -c` or `sudo` are rejected, and a script must be given by full path and exist when you allow it, so it can always be pinned.
- **Human-only credentials** that no agent can ever use (root passwords, admin logins). You can still reveal or copy them.
- **Reference entries:** a record with no secret, for access that needs none, such as keyless SSH from your Mac. It holds notes, an address and a folder. Agents read it with `secreds info NAME`. `secreds run` refuses it, and Reveal and Copy have nothing to show. It still appears in the inventory and in backups.
- **Credential types:** API key, login (username and password), S3 bucket (access key ID, secret key, bucket, endpoint, region), SSH key or passphrase, other. Logins and S3 credentials inject the right set of variables (`NAME_USERNAME`, `NAME_PASSWORD`, `AWS_*`, and so on), and an address or several hosts can be stored with each credential.
- **Credential requests:** an agent can *propose* a new credential with every non-secret detail filled in (`secreds request ...`). It shows on the Home page as "waiting for your secret"; you review it, type the secret and save. The agent never sees the secret.
- **Any AI tool:** pick the agents you use (Claude Code, Codex, Gemini CLI, Copilot, Cursor, Aider, ...) or add your own on the Agents page, which also gives you a ready-to-paste instructions file (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, ...) for each.
- **Settings and health check:** your name, update source, feedback link, and `secreds doctor` (Keychain, Touch ID, encryption, permissions, backups; never reads a secret).
- **Agent notice:** every use prints a short set of rules to the agent (never show the value, never use a stored password for sudo or SSH, and so on). It is fully editable.
- **Local GUI:** Home dashboard (what is unlocked, what needs attention), a credentials tree with folders, search, sort and filters, the notice editor, and an activity log. Listens on `127.0.0.1` only, behind a per-launch token, and opening it needs Touch ID.
- **Folders, Personal/Work labels, acknowledge-a-warning, duplicate.**
- **Backup and restore** of everything (secrets and settings) as one encrypted file, saved to a folder you choose or to iCloud Drive; it is also how you move to a second Mac.
- **Update check:** once a day it looks for a newer release on GitHub; installing one is always your decision (Touch ID).
- **Audit log** of every use, denial, approval, edit and reveal. It never contains a secret.

## Install

Requires macOS, Python 3.10 or newer, and a Mac with Touch ID (or a password fallback).

```bash
git clone https://github.com/henderlabs/secreds.git
cd secreds
./install.sh
```

The installer creates a private virtual environment in `~/.secreds/venv` and links `~/.local/bin/secreds`. It needs no `sudo` and changes nothing else. Make sure `~/.local/bin` is on your `PATH`.

Optional:

```bash
secreds init --owner "Your Name" --agents claude,codex     # how the notice addresses you, and which agents you use
secreds install-app                                       # builds ~/Applications/seCreds.app, a Dock-able launcher
```

## Quick start

```bash
secreds --version                # seCreds 0.6.5 by henderlabs; `secreds about` also shows where to send feedback
secreds gui                      # add a credential (Touch ID to open)
secreds list                     # names, settings and addresses: never secrets
SECREDS_AGENT=claude secreds run my-nas --reason "check free space on the NAS" -- python3 check_nas.py
secreds audit                    # who used what, and when
```

Inside a command the credential arrives as environment variables named after the credential (`my-nas` becomes `MY_NAS`, or `MY_NAS_USERNAME` and `MY_NAS_PASSWORD` for a login).

Agents identify themselves with `SECREDS_AGENT` (Claude Code is also detected automatically). See [docs/claude-code.md](docs/claude-code.md) for the permission rules that keep an agent away from the Keychain and the management commands, and for running two Claude profiles (for example personal and work) as one agent.

## Reasons and the audit trail

Every agent use needs `--reason` (10 to 200 characters). It is the agent's own statement of why it needs the credential, so it can be wrong; the command, folder, script fingerprint and exit code beside it are recorded by seCreds itself. The Activity page shows each use as a row you can open: reason, the agent's outcome note, the command that ran, folder, result, the Touch ID approval that covered it, the script fingerprint and the credential's configured address. Settings has an option to keep a copy of each script's text (small scripts, owner-only folder, off by default) so you can see exactly what ran, not just its hash.

## Reference entries

Some access needs no secret at all. Keyless SSH from your Mac is the usual example: the key lives in `~/.ssh` and `ssh-agent`, so there is nothing for seCreds to hold. A **reference entry** records that fact in one place, so an agent knows how a host is reached and does not ask for a password that does not exist.

```bash
secreds add lab-pve-ssh --kind ssh-key --reference --agents claude --folder Lab --address 192.0.2.101-106 \
  --notes "Keyless SSH with the Mac's agent: ssh st-pve101 ... st-pve106. No password."
secreds info lab-pve-ssh        # what an agent runs: prints the address and notes, never a secret
```

In the GUI, tick "No secret (reference only)" on the Add form. The card shows a "reference" tag instead of a lock, and there is no Reveal, Copy or Approve button. Agents can also propose one with `secreds request NAME --reference`. `secreds run` on a reference entry is refused and logged, and the message points to `secreds info`. Keyless SSH is full access to the host, so a reference entry still shows the "any command" warning on Home. Acknowledge it if that is intended.

## Optional: signed Keychain helper (macOS)

By default the Python that runs seCreds talks to the Keychain, so macOS grants and the Touch ID prompt belong to that shared Python. `tools/keychain-helper` builds a tiny native program, signed with your own Apple Development identity (a free Personal Team is enough), that does the Keychain reads and writes and the Touch ID prompt instead. Grants then belong to seCreds, survive rebuilds, and the prompt says "seCreds". seCreds uses it automatically when `~/.secreds/seCreds-kc.app` exists and falls back to the Python path if it is missing or fails.

```bash
tools/keychain-helper/build.sh                          # compile and sign (needs Xcode command line tools and a signing identity)
~/.secreds/seCreds-kc.app/Contents/MacOS/seCreds-kc trust NAME   # per existing credential: add the helper to its access list
```

`trust` only edits the item's access list; it never reads the secret. macOS may ask for your login password once per item. Personal Team certificates expire after about a year, so rebuild and re-sign then. The helper's `get` command refuses to run without a single-use, 30-second ticket that seCreds writes into its private data folder after the policy checks pass, so running the helper directly no longer hands out secrets. This raises the bar but is not a sandbox: code running as you that can also write into `~/.secreds` could forge a ticket, as before it could read the Keychain through the shared Python.

## Backup and restore

One encrypted file holds every secret and every setting (credential settings, folders, pending requests, the agent notice, `config.json`, the backup plan, and optionally the activity log). Backups are encrypted on your Mac before they leave it, so a cloud folder only ever holds ciphertext. Approval windows are not backed up: everything starts locked after a restore.

**The backup key (recommended).** You set **one backup password, once**. seCreds then keeps only a *public* key on the Mac, so it can make backups, including scheduled unattended ones, without ever knowing the password. A small **recovery file**, locked by your password, is what opens them (X25519 key agreement with AES-256-GCM; the recovery file uses scrypt). You need the password and the recovery file only on the day you restore. Keep the password in your password manager plus one offline copy, and keep the recovery file in two places.

```bash
secreds backup-key setup --icloud --to /Volumes/NAS/recovery   # once: choose a 16+ character password; saves the recovery file in each place
secreds backup-key status
secreds backup --icloud            # into iCloud Drive (a "seCreds Backups" folder), or:
secreds backup --to /Volumes/NAS/backups
secreds backup --plan              # run your saved plan: every destination, then prune old copies
secreds backups --icloud           # list the backups there
secreds backup-info FILE           # see what is inside (names only)
secreds restore-backup --icloud    # newest backup in iCloud Drive; add --dry-run to preview
secreds restore-backup FILE --mode overwrite --key /path/to/secreds-recovery-key-XXXX.json
```

The **Backup** page in the GUI does the same, with a folder chooser, a **backup plan** (main and second destination, optionally an S3 bucket, how many to keep, daily or weekly) and a restore test. Each backup is read back and verified, and creating or restoring one needs Touch ID (scheduled runs need none, since they only use the public key). Without a backup key, `secreds backup --passphrase` makes a one-off backup protected by a passphrase instead.

- **Password rules:** at least 16 characters for the backup key (four or five random words works well). Without the password and a recovery file a backup cannot be opened, and nobody can recover it.
- **Restore modes:** `merge` (default) never overwrites a credential that already exists on this Mac; `overwrite` lets the backup win, but a credential you revoked or made human-only stays restricted. Restoring never takes the update source or feedback link from a backup, and it validates each entry. Backups are encrypted but not signed, so only restore files you made.
- **A second Mac:** iCloud Keychain does not sync these items (see "Why not iCloud Keychain sync?"). Install seCreds on the new Mac, then `secreds restore-backup --icloud` with the recovery file. To catch a Mac up later, use **Backup → Sync from backup** or `secreds sync`: it compares by name, adds what is new, and only overwrites a credential that exists on both Macs if you tick it.

## Updates

```bash
secreds update                     # check (at most once a day) and report
secreds update --apply             # show the release notes, then install after Touch ID
secreds update --apply --tag vX.Y.Z   # install a specific version (also how you roll back)
secreds update --enable-daily      # a macOS LaunchAgent that checks once a day and notifies you
```

A check only **reads** the latest release; it never installs anything. Installing requires Touch ID and an explicit command, uses only the repository named by `update_repo` in `config.json` (default: this project; set it to `""` to turn update checks off), and refuses a download that is not the `secreds` package at the version the release claims. For a private repository, sign in with the GitHub CLI (`gh auth login`).

**Know the trade-off:** an update replaces the code that handles your secrets, so you are trusting whoever can publish releases to that repository. Read the release notes before installing, and keep the repository's account protected with two-factor authentication.

## Configuration

`~/.secreds/config.json` (or `$SECREDS_HOME/config.json`):

```json
{
  "owner": "Your Name",
  "agents": ["claude", "claude-work", "codex"],
  "families": { "claude-work": "claude" },
  "update_repo": "owner/secreds"
}
```

Everything here can also be changed on the Settings and Agents pages. `families` says that several profiles count as the same agent for access, while the log still records which one acted.

## Security model

**What seCreds protects against**

- Secrets at rest: stored in the Keychain, encrypted by macOS (turn on FileVault).
- An agent that is not on a credential's list, a revoked or expired credential, a command that is not on the allowed list, or a pinned script that was edited.
- Secrets leaking into transcripts, logs and files: values are masked in command output and never written to the audit log or settings files.
- Other websites or local pages talking to the GUI: loopback only, per-launch token, Host-header check, secret values reach the browser only through Reveal, which needs Touch ID (the dashboard shows a mask and the last few characters).
- Quiet loosening of policy: edits, restores, deletes, reveal, copy, export and re-pinning need Touch ID.

**What it does not protect against. Read this.**

- **Malicious code running as you while you are logged in.** The login Keychain is unlocked at that point, and the Touch ID check is made by seCreds, not by the operating system, so software that bypasses seCreds and asks the Keychain directly is not stopped.
- **A command that misuses the secret.** Once a command runs with a credential, it can do anything that credential allows. Masking only hides the exact value in output, and the allowed-commands list limits *which* commands run, not what an approved script does.
- **Identity.** The agent name is a setting the caller declares, not authentication. seCreds is guardrails, an audit trail and a kill switch for cooperating agents; it is **not a sandbox**.
- **Approval windows.** During a window, any command from that agent can use the credential without a new prompt.

The mitigations are the usual ones: FileVault, a strong login password, narrow service accounts, short windows, allowed-commands lists, and rotating anything you suspect. See [SECURITY.md](SECURITY.md).

**Why not iCloud Keychain sync?** Synced Keychain items need an app that carries an Apple developer entitlement, which needs a paid developer account. seCreds is a Python tool with an optional helper signed with a free development certificate (no such entitlement), so each Mac keeps its own Keychain. Use backups, or `secreds export` and `secreds import`, to move credentials.

## Roadmap

- A properly distributed, notarized app (Developer ID), which would allow hardware-enforced Touch ID (a Keychain access control) and iCloud sync without building the helper yourself.
- A "server edition" for Linux hosts (an encrypted store with a master passphrase, and passkey approval in the browser), so agents on other machines can share one broker. This needs a different design and is not built.
- A signed backup format, so a backup can be checked as coming from your Mac before it is restored.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[export]"
python -m unittest discover -s tests -v
```

The tests run on any OS: they replace the Keychain and Touch ID with in-memory stand-ins, use a temporary data folder, and cover the policy rules, the GUI server's access controls, the command line, folders, requests and export/import. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

---

<sub>**seCreds** v0.6.5 · by [henderlabs](https://github.com/henderlabs) · [Send feedback](https://github.com/henderlabs/secreds/issues/new/choose)</sub>
