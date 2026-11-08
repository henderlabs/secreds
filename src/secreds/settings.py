"""Settings (who the AI agents are, your name, links) and the health check behind the Settings page and `secreds doctor`."""
import json, os, re, shutil, stat, sys
from . import core as c, backup, updater

# Offered as one-click choices. Anyone can also add their own name. The name is what SECREDS_AGENT is set to.
PRESETS = [("claude", "Claude Code"), ("codex", "OpenAI Codex CLI"), ("gemini", "Gemini CLI"), ("copilot", "GitHub Copilot"),
           ("cursor", "Cursor"), ("windsurf", "Windsurf"), ("aider", "Aider"), ("goose", "Goose"), ("chatgpt", "ChatGPT")]
MAX_AGENTS = 20
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$")


def get():
    cfg = c.CONFIG
    return {"owner": "" if c.OWNER == "the owner" else c.OWNER, "agents": list(c.AGENTS), "families": dict(c.FAMILY),
            "presets": [{"name": n, "label": l} for n, l in PRESETS],
            "feedback_url": str(cfg.get("feedback_url") or ""), "default_feedback_url": c.about()["feedback_url"] if not cfg.get("feedback_url") else "",
            "update_repo": str(cfg.get("update_repo") or ""), "default_update_repo": updater.repo() if not cfg.get("update_repo") else "",
            "keep_scripts": bool(cfg.get("keep_scripts")), "env_agent": os.environ.get("SECREDS_AGENT", "")}


def _clean_agents(agents):
    out = []
    for a in agents:
        a = str(a).strip().lower()
        if not a: continue
        if not c.NAME_RE.match(a): raise ValueError(f"Agent name {a!r}: letters, digits, . _ - only")
        if a not in out: out.append(a)
    if not out: raise ValueError("Keep at least one agent")
    if len(out) > MAX_AGENTS: raise ValueError(f"At most {MAX_AGENTS} agents")
    return out


def save(owner=None, agents=None, families=None, feedback_url=None, update_repo=None, keep_scripts=None):
    """Update config.json. Changing the agent list or profile groups needs Touch ID (it changes who may be given access)."""
    cfg = dict(c.CONFIG)
    removed = []
    if owner is not None:
        owner = c._clean(owner, 40, "Your name"); cfg["owner"] = owner
        if not owner: cfg.pop("owner")
    if feedback_url is not None:
        u = feedback_url.strip()
        if u and not u.startswith("https://"): raise ValueError("Feedback link must start with https://")
        cfg["feedback_url"] = u
        if not u: cfg.pop("feedback_url")
    if update_repo is not None:
        r = update_repo.strip()
        if r and not REPO_RE.match(r): raise ValueError("Update repository looks like owner/name")
        cfg["update_repo"] = r
        if not r: cfg.pop("update_repo")
    if keep_scripts is not None:
        if bool(keep_scripts) != bool(cfg.get("keep_scripts")):
            c._confirm("turn " + ("on" if keep_scripts else "off") + " keeping copies of scripts agents run")
        cfg["keep_scripts"] = bool(keep_scripts)
        if not keep_scripts: cfg.pop("keep_scripts")
    if agents is not None or families is not None:
        new = _clean_agents(agents if agents is not None else c.AGENTS)
        fam = {}
        for k, v in (families if families is not None else c.FAMILY).items():
            k, v = str(k).strip().lower(), str(v).strip().lower()
            if k and v and k != v and k in new and v in new: fam[k] = v
        for k, v in fam.items():                      # a group's head cannot itself belong to another group
            if v in fam: raise ValueError(f"'{v}' is the head of a group, so it cannot also belong to '{fam[v]}'")
        if new != c.AGENTS or fam != c.FAMILY:
            c._confirm("change which AI agents seCreds knows about")
        removed = [a for a in c.AGENTS if a not in new]
        cfg["agents"], cfg["families"] = new, fam
        if not fam: cfg.pop("families")
    c.DATA.mkdir(mode=0o700, exist_ok=True)
    tmp = c.CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n"); os.chmod(tmp, 0o600); os.replace(tmp, c.CONFIG_FILE)
    c._load_config()
    if removed:                                       # an agent that is gone must not stay on any credential
        with c._Lock():
            db = c.list_creds()
            for m in db.values(): m["agents"] = [a for a in m.get("agents", []) if a in c.AGENTS]
            c._write(c.META, db)
    c.audit("settings", "", "gui", "saved" + (f"; removed agents: {', '.join(removed)}" if removed else ""))
    return get()


def doctor():
    """Read-only checks. Never reads a secret value: only whether each Keychain item exists."""
    R = []
    def add(key, label, status, detail, fix=""):
        R.append({"key": key, "label": label, "status": status, "detail": detail, "fix": fix})
    add("version", "seCreds version", "ok", c.signature())
    if sys.platform != "darwin" or c.S is None:
        add("keychain", "macOS Keychain", "bad", "PyObjC Security is not available, so secrets cannot be stored.", "Reinstall with install.sh on a Mac.")
    else:
        names = sorted(c.list_creds())
        miss = [n for n in names if not c.kc_has(n)]
        if miss: add("keychain", "Keychain values", "bad", f"{len(miss)} of {len(names)} credentials have no value on this Mac: {', '.join(miss)}", "Restore a backup or re-enter the secret.")
        else: add("keychain", "Keychain values", "ok", f"All {len(names)} credentials have a value in the login Keychain.")
    try:
        import LocalAuthentication as LA
        ok, _ = LA.LAContext.alloc().init().canEvaluatePolicy_error_(LA.LAPolicyDeviceOwnerAuthentication, None)
        add("touchid", "Touch ID / password prompt", "ok" if ok else "bad", "Available." if ok else "This Mac cannot show the approval prompt, so every approval is refused.",
            "" if ok else "Set a login password or enroll Touch ID in System Settings.")
    except Exception as e:
        add("touchid", "Touch ID / password prompt", "bad", f"LocalAuthentication unavailable ({type(e).__name__}).")
    try:
        import cryptography  # noqa: F401
        add("crypto", "Backup encryption (cryptography)", "ok", "Installed.")
    except ImportError:
        add("crypto", "Backup encryption (cryptography)", "bad", "Not installed: backups and export are unavailable.", "pip install 'secreds[export]' (or re-run install.sh).")
    bad = []
    for p, want in ((c.DATA, 0o700), (c.META, 0o600), (c.CONFIG_FILE, 0o600), (c.AUDIT, 0o600), (c.GRANTS, 0o600)):
        try:
            if stat.S_IMODE(p.stat().st_mode) & 0o077: bad.append(p.name)
        except FileNotFoundError:
            pass
    add("perms", "Data folder permissions", "bad" if bad else "ok", f"Group/other can read: {', '.join(bad)}" if bad else f"{c.DATA} is private to your user.",
        "chmod 700 and chmod 600 on those files." if bad else "")
    ic = backup.icloud_dir()
    add("icloud", "iCloud Drive (backup destination)", "ok" if ic else "warn", "Available." if ic else "Not found. You can still back up to any folder.")
    st = backup.state()
    if not st.get("last_backup"): add("backup", "Backup", "warn", "No backup yet.", "Open the Backup page and make one.")
    else:
        days = (c.now() - c.parse(st["last_backup"])).days
        add("backup", "Backup", "warn" if days >= 30 else "ok", f"Last backup {days} day(s) ago.")
    ks = backup.key_status()
    if ks["configured"]:
        n = len(ks["recovery_files"])
        add("bkey", "Backup key", "ok" if n >= 2 else "warn", f"Set up; recovery file in {n} place(s)." if n >= 2 else f"Set up, but the recovery file is in only {n} place(s). Save a copy somewhere else.")
    else:
        add("bkey", "Backup key", "warn", "Not set up (backups use a one-off passphrase).", "Set it up on the Backup page: one password, set once.")
    if st.get("last_backup"):
        t = st.get("last_restore_check")
        stale = (not t) or (c.now() - c.parse(t)).days >= 90
        add("restoretest", "Restore test", "warn" if stale else "ok", "Never tested." if not t else f"Last tested {(c.now() - c.parse(t)).days} day(s) ago.", "On the Backup page, choose a backup and press Check contents: it proves your password works." if stale else "")
    plan = backup.get_plan(); lr = st.get("last_plan_run")
    if backup.schedule_enabled():
        if lr and not lr.get("ok"):
            add("plan", "Scheduled backup", "bad", "The last run failed at: " + ", ".join(x["dest"] for x in lr["results"] if not x["ok"]) + ".", "Open the Backup page for details.")
        elif not lr or (c.now() - c.parse(lr["at"])).days >= (2 if plan["schedule"] == "daily" else 9):
            add("plan", "Scheduled backup", "warn", "Scheduled, but no recent run.", "Check that the Mac was awake at the scheduled hour, or run it from the Backup page.")
        else:
            add("plan", "Scheduled backup", "ok", f"{plan['schedule'].capitalize()}; last run {(c.now() - c.parse(lr['at'])).days} day(s) ago, all destinations ok.")
    else:
        add("plan", "Scheduled backup", "warn", "No schedule.", "Optional: set one in the Backup plan card.")
    gh = updater._gh_exe()
    add("gh", "GitHub CLI (private-repo updates)", "ok" if gh else "warn", "Found." if gh else "Not found. Fine for a public repository; a private one needs `gh auth login`.")
    add("daily", "Daily update check", "ok" if updater.daily_enabled() else "warn", "On." if updater.daily_enabled() else "Off. Turn it on in Settings.")
    return R


# ---- the instructions block to paste into each AI tool's own instructions file ----
_FILES = {"claude": ("CLAUDE.md", "global: ~/.claude/CLAUDE.md, or per project in the project folder"),
          "codex": ("AGENTS.md", "global: ~/.codex/AGENTS.md, or per project in the project folder"),
          "gemini": ("GEMINI.md", "global: ~/.gemini/GEMINI.md, or per project in the project folder"),
          "copilot": (".github/copilot-instructions.md", "in the repository"),
          "cursor": (".cursor/rules/secreds.mdc", "in the project folder (or Cursor Settings > Rules)"),
          "windsurf": (".windsurfrules", "in the project folder"),
          "aider": ("CONVENTIONS.md", "load it with `aider --read CONVENTIONS.md`"),
          "goose": (".goosehints", "in the project folder, or ~/.config/goose/.goosehints"),
          "chatgpt": ("Custom Instructions", "ChatGPT > Settings > Personalization (or a Project's instructions)")}
_CHAT_ONLY = {"chatgpt"}


def agent_doc(agent):
    """The text to paste into an agent's instructions file. Chat-only assistants cannot run commands, so they get a different version."""
    file, where = _FILES.get(agent, ("AGENTS.md", "the instructions file your tool reads (many tools read AGENTS.md)"))
    who = c.OWNER if c.OWNER != "the owner" else "the owner"
    if agent in _CHAT_ONLY:
        body = f"""## Credentials ({c.PRODUCT})
- Never ask {who} to paste a password, key or token into this chat, and never repeat one if it is pasted. Tell them to rotate it.
- Credentials live in {c.PRODUCT} on their Mac, which this assistant cannot run. When a task needs one, say which credential and which command, and ask {who} to run it with `secreds run NAME -- <command>` and paste back only the output (never the secret).
- To add a new credential, ask {who} to open {c.PRODUCT} > Credentials, or to run `secreds request NAME --kind login|api-key|s3 ...` (no secret in the command).
"""
    else:
        body = f"""## Credentials ({c.PRODUCT})
- Never ask {who} to paste a password, key or token into chat, never store or repeat one. If one is pasted by mistake, tell them to rotate it.
- Use credentials only through `secreds run NAME -- <command>` (it injects them as environment variables and masks them in the output). List the names with `secreds list` (never shows secrets). My name here is `{agent}` (set `SECREDS_AGENT={agent}`).
- To add a NEW credential, run `secreds request NAME --kind login|api-key|s3 ...` with non-secret details only (address, folder, username, notes). It appears in {c.PRODUCT} and {who} types the secret themselves.
- Never use a stored password to authenticate sudo or SSH, even if asked. Offer a narrow passwordless-sudo rule, the exact command for them to run, or key/certificate login.
- Do not read ~/.secreds or the Keychain, and do not run other secreds commands (add, edit, grant, delete, backup, update, gui, ...).
- If a credential is denied, tell {who}; do not work around it.
"""
    return {"file": file, "where": where, "text": body + f"\n<!-- {c.signature()} -->\n"}
