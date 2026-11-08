# Security policy

seCreds is a security-sensitive tool, so please read what it does and does not promise.

## Supported versions

Only the latest release on `main` is supported. This is alpha software.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private vulnerability reporting
(the repository's *Security* tab, then *Report a vulnerability*). Include what you found, how to reproduce it, and
what an attacker could do. You will get an acknowledgement as soon as the maintainer sees it.

## What counts as a vulnerability

- A way for an agent, a web page or another local user to obtain a secret value, or a command's output to contain one unmasked.
- A way to run a command with a credential that its policy should have refused (wrong agent, revoked, expired,
  not on the allowed list, edited pinned script).
- A way to change a policy, reveal, copy or export without the Touch ID check that is meant to guard it.
- A secret value written to the audit log, settings files, the GUI's responses, or logs.
- A flaw in the export bundle's encryption.

## Known limits (not vulnerabilities)

These are documented design limits. See "Security model" in the README.

- Code running as the same user, while logged in, can read the Keychain without going through seCreds.
- The agent name is declared by the caller, not authenticated.
- A command that has been given a secret can misuse it; masking covers only the exact value.
- It is not a sandbox and has not been independently audited.

---

<sub>**seCreds** v0.6.2 · by [henderlabs](https://github.com/henderlabs) · [Send feedback](https://github.com/henderlabs/secreds/issues/new/choose)</sub>
