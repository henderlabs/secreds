import re
import argparse, getpass, os, subprocess, sys, json, time
from . import core as c
from . import __version__, signature

def die(msg, code=1):
    print(f"secreds: {msg}", file=sys.stderr); sys.exit(code)

def cmd_import_keys(a):
    """Owner-run helper: import single-secret *.key files. Values never printed in full and never leave this process."""
    import re
    from pathlib import Path
    d = Path(a.dir).expanduser()
    picks = []
    for f in sorted(d.glob("*.key")):
        name = re.sub(r"[^A-Za-z0-9._-]", "-", f.stem)[:63]
        try: val = f.read_text().strip()
        except Exception as e: print(f"skip {f.name}: {e}"); continue
        if not val or "\n" in val:
            print(f"skip {f.name}: empty or multi-line (add it in the GUI instead)"); continue
        if name in c.list_creds(): print(f"skip {f.name}: '{name}' already in secreds"); continue
        tail = val[-4:] if len(val) >= 12 else ""
        if input(f"Import {f.name} as '{name}' (********{tail})? [y/N] ").strip().lower() == "y":
            picks.append((name, val, f.name))
    if not picks: print("nothing to import"); return
    if not c.touch_id(f"import {len(picks)} credential(s) into secreds"): die("Touch ID declined", 3)
    for name, val, fname in picks:
        c.save_cred(name, val, kind="api-key", notes=f"Imported from {d}/{fname}", agents=[], mode="ask",
                    window_minutes=c.DEFAULT_WINDOW, scope=a.scope, create=True)
        print(f"imported {name}  (no agents allowed yet: open the GUI to assign)")
    print("Originals were NOT touched. Delete them yourself once you've verified the imports.")

SECRET_RE = re.compile(r"(PASS|PASSWD|PASSWORD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE|CODE)", re.I)
PLAIN_RE = re.compile(r"(URL|HOST|ADDR|ADDRESS|USER|USERNAME|LOGIN|ID|PORT)$", re.I)
SUFFIX_RE = re.compile(r"_(PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|KEY|CODE)$", re.I)

def _parse_env(path):
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        k, v = line.split("=", 1); k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        elif " #" in v:
            v = v.split(" #", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
            out.append((k, v))
    return out

def _private_host(addr):
    h = re.sub(r"^[a-z]+://", "", addr or "").split("/")[0].split(":")[0]
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", h))

def cmd_import_env(a):
    """Owner-run helper: turn the secrets in a .env file into credentials. Secret values stay inside this process."""
    from pathlib import Path
    f = Path(a.file).expanduser()
    vars_ = _parse_env(f)
    env = dict(vars_)
    picks, used, skipped_names = [], set(), []
    for name, val in vars_:
        if not val or not SECRET_RE.search(name) or PLAIN_RE.search(name):
            continue
        m = SUFFIX_RE.search(name)
        base = name[:m.start()] if m else name
        user_var = next((base + sfx for sfx in ("_USER", "_USERNAME", "_LOGIN", "_ID") if env.get(base + sfx)), None)
        top = name.split("_")[0]
        addr_var = next((k for k, v in vars_ if v and k.startswith(top + "_") and re.search(r"(URL|HOST|ADDR|ADDRESS)$", k, re.I)), None)
        kind = "login" if user_var else "api-key"
        cname = (a.prefix + "-" if a.prefix else "") + base.lower().replace("_", "-").strip("-")
        if not user_var and m:
            cname += "-" + m.group(1).lower().replace("_", "-")
        cname = re.sub(r"[^A-Za-z0-9._-]", "-", cname)[:63]
        if cname in c.list_creds():
            print(f"skip {name}: '{cname}' already in seCreds"); continue
        user, addr = (env.get(user_var) if user_var else ""), (env.get(addr_var) if addr_var else "")
        tail = val[-4:] if len(val) >= 12 else ""
        detail = ", ".join(x for x in ((f"user {user}" if user else ""), (f"address {addr}" if addr else ""), f"********{tail}") if x)
        ans = input(f"Import {name} as {kind} '{cname}' ({detail})?\n  [y = yes, n = skip, or type a different name] ").strip()
        if ans.lower() in ("", "n", "no"):
            continue
        if ans.lower() not in ("y", "yes"):
            cname = ans
        if not c.NAME_RE.match(cname):
            print(f"skip {name}: '{cname}' is not a valid name (letters, digits, . _ - only)"); continue
        picks.append(dict(name=cname, value=val, kind=kind, user=user, addr=addr, vars=[name] + ([user_var] if user_var else []) + ([addr_var] if addr_var else [])))
        used.update(picks[-1]["vars"])
    if not picks:
        print("nothing to import"); return
    if not c.touch_id(f"import {len(picks)} credential(s) from {f.name} into secreds"):
        die("Touch ID declined", 3)
    for pk in picks:
        c.save_cred(pk["name"], pk["value"], kind=pk["kind"], notes=f"Imported from {f.name} ({', '.join(pk['vars'])})", agents=[], mode="ask",
                    window_minutes=c.DEFAULT_WINDOW, scope=a.scope, username=pk["user"], address=pk["addr"],
                    network="lan" if _private_host(pk["addr"]) else "", create=True)
        print(f"imported {pk['name']}  (no agents allowed yet: open the GUI to assign)")
    left = [k for k, _ in vars_ if k not in used]
    if left:
        print("Not imported (not secrets, or already used as an address or username): " + ", ".join(left[:20]) + (" ..." if len(left) > 20 else ""))
    print("The original file was NOT touched. Delete it yourself once you've verified the imports.")

def cmd_request(a):
    """Agent-safe: propose a credential (no secret). The owner completes it in the GUI."""
    agent = c.detect_agent()
    c.add_request(a.name, agent, kind=a.kind, username=a.username, address=a.address, network=a.network, scope=a.scope,
                  folder=a.folder, bucket=a.bucket, region=a.region, access_key_id=a.access_key_id, notes=a.notes,
                  agents=a.agents.split(",") if a.agents else None, allowed_commands=a.cmd, human_only=a.human_only, env_var=a.env, reference=a.reference)
    print(f"request recorded for '{a.name}'. It now waits on the seCreds Home page, where the owner " + ("confirms it (a reference entry has no secret)." if a.reference else "adds the secret."))

def cmd_requests(a):
    reqs = c.list_requests()
    if not reqs: print("(no requests waiting)"); return
    for n, r in sorted(reqs.items()):
        print(f"{n:24} {r['kind']:8} by {r['requested_by']:8} {r['requested_at'][:16]}  folder={r.get('folder') or '-'} addr={r.get('address') or '-'}")

def cmd_doctor(a):
    """Health check: Keychain, Touch ID, encryption, permissions, backups. Never reads a secret value."""
    from . import settings
    icon = {"ok": "ok  ", "warn": "warn", "bad": "BAD "}
    rs = settings.doctor()
    for r in rs:
        print(f"[{icon[r['status']]}] {r['label']}: {r['detail']}" + (f"  -> {r['fix']}" if r["fix"] else ""))
    sys.exit(1 if any(r["status"] == "bad" for r in rs) else 0)


def cmd_init(a):
    """Write a config.json: your name for the notice, the agents you use, and which profiles count as one agent."""
    c.DATA.mkdir(mode=0o700, exist_ok=True)
    if c.CONFIG_FILE.exists() and not a.force:
        die(f"{c.CONFIG_FILE} already exists (use --force to overwrite)")
    fam = dict(kv.split("=", 1) for kv in a.family if "=" in kv)
    c.CONFIG_FILE.write_text(json.dumps({"owner": a.owner, "agents": [x.strip() for x in a.agents.split(",") if x.strip()], "families": fam}, indent=2) + "\n")
    os.chmod(c.CONFIG_FILE, 0o600)
    c.use_home(c.DATA)
    print(f"wrote {c.CONFIG_FILE}\n  agents: {', '.join(c.AGENTS)}\n  profile groups: {c.FAMILY or 'none'}")

def cmd_install_app(a):
    """Build a double-clickable seCreds.app that opens the GUI (Touch ID first)."""
    import plistlib, shutil, stat
    from pathlib import Path
    exe = shutil.which("secreds") or sys.argv[0]
    app = Path(a.dest).expanduser() / "seCreds.app"
    (app / "Contents" / "MacOS").mkdir(parents=True, exist_ok=True); (app / "Contents" / "Resources").mkdir(parents=True, exist_ok=True)
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleName": "seCreds", "CFBundleDisplayName": "seCreds", "CFBundleIdentifier": "local.secreds.launcher",
                       "CFBundleExecutable": "secreds-launch", "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
                       "CFBundleIconFile": "seCreds", "LSUIElement": True,
                       "CFBundleShortVersionString": __version__, "NSHumanReadableCopyright": f"{signature()}"}, f)
    launcher = app / "Contents" / "MacOS" / "secreds-launch"
    launcher.write_text(f'#!/bin/bash\n# `secreds gui` asks for Touch ID itself, then opens (or reopens) the page.\nnohup "{Path(exe).resolve()}" gui >/dev/null 2>&1 &\n')
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    icon = Path(__file__).parent / "assets" / "seCreds.icns"
    if icon.exists():
        shutil.copy(icon, app / "Contents" / "Resources" / "seCreds.icns")
    print(f"built {app}\nDrag it to the Dock, or open it from Finder.")

def _passphrase(confirm=False):
    pw = getpass.getpass("Backup passphrase: ")
    if confirm and pw != getpass.getpass("Repeat it: "):
        die("The two passphrases differ")
    return pw


def _backup_folder(a):
    from . import backup
    if getattr(a, "icloud", False):
        d = backup.icloud_dir(create=True)
        if not d:
            die("iCloud Drive is not available on this Mac. Use a folder instead.")
        return d
    return getattr(a, "to", "") or None


def cmd_backup(a):
    """Write one encrypted backup file (secrets and settings) to a folder you choose, or to iCloud Drive."""
    from . import backup
    if a.plan or a.scheduled:
        try:
            r = backup.run_plan(agent="schedule" if a.scheduled else "cli", unattended=a.scheduled)
        except (ValueError, RuntimeError) as e:
            if a.scheduled:
                _notify("seCreds backup did not run: " + str(e)[:120])
            die(str(e))
        for x in r["results"]:
            print(("ok     " if x["ok"] else "FAILED ") + x["dest"] + ": " + x["note"])
        if not r["ok"]:
            if a.scheduled:
                _notify("seCreds backup: one or more destinations failed. Open seCreds > Backup.")
            sys.exit(1)
        return
    dest = _backup_folder(a)
    if not dest:
        die("Choose where to save it: --to FOLDER or --icloud (or --plan to use your backup plan)")
    use_key = backup.key_status()["configured"] and not a.passphrase
    try:
        r = backup.create_backup(dest, None if use_key else _passphrase(confirm=True), include_audit=not a.no_audit, agent="cli")
    except (ValueError, RuntimeError) as e:
        die(str(e))
    if use_key:
        print(f"Backed up {r['count']} credential(s) and your settings with the backup key (no password needed here).\n  {r['path']}")
        print("  Do a test restore soon: `secreds restore-backup FILE --dry-run` proves your password and recovery file work.")
    else:
        print(f"Backed up {r['count']} credential(s) and your settings, verified by reading the file back.\n  {r['path']}")
    if r["cloud"]:
        print("  It is in a cloud folder: give iCloud a minute to upload it. The file is encrypted before it leaves this Mac.")
    if r["missing"]:
        print(f"  Not backed up (no secret found in the Keychain): {', '.join(r['missing'])}")
    if not use_key:
        print("Keep the passphrase somewhere safe: without it the backup cannot be opened.")


def _notify(text):
    try:
        subprocess.run(["osascript", "-e", f'display notification {json.dumps(text)} with title "seCreds"'], capture_output=True, timeout=10)
    except Exception:
        pass


def cmd_backup_key(a):
    """Set up (or show) the backup key: one password, set once; the Mac can then back up without knowing it."""
    from . import backup
    if a.action == "status":
        st = backup.key_status()
        if not st["configured"]:
            print("The backup key is not set up. Run: secreds backup-key setup --icloud   (and a second --to FOLDER is much safer)"); return
        print(f"Backup key {st['key_id']} set up {st['created']}.")
        for f in st["recovery_files"]:
            print(f"  recovery file: {f}")
        return
    dests = list(a.to or [])
    if a.icloud:
        d = backup.icloud_dir(create=True)
        if not d:
            die("iCloud Drive is not available on this Mac. Use --to FOLDER instead.")
        dests.insert(0, d)
    print("Choose ONE backup password (16+ characters). Save it in your password manager AND keep an offline copy (printed).\n"
          "Do not store it in seCreds, an AI chat, email, or a note on this Mac, and not beside the backups.")
    pw = getpass.getpass("Backup password: ")
    if pw != getpass.getpass("Repeat it: "):
        die("The two passwords differ")
    try:
        r = backup.setup_key(pw, dests, replace=a.replace, agent="cli")
    except (ValueError, RuntimeError) as e:
        die(str(e))
    print(f"Backup key {r['key_id']} created. Recovery file saved (and checked against your password) in:")
    for f in r["files"]:
        print(f"  {f}")
    if len(r["files"]) < 2:
        print("Only ONE copy exists. Add a second place soon: it is useless to anyone without your password.")


def cmd_backups(a):
    from . import backup
    folder = _backup_folder(a) or a.dir or backup.state().get("last_backup_dir")
    if not folder:
        die("Give a folder (--in FOLDER) or use --icloud")
    found = backup.list_backups(folder)
    print(f"{len(found)} backup(s) in {folder}" if found else f"No backups found in {folder}")
    for f in found:
        print(f"  {f['modified'][:16]}  {f['bytes']:>9,} bytes  {f['name']}")


def cmd_backup_info(a):
    from . import backup
    try:
        i = backup.backup_info(a.file, getpass.getpass("Backup password / passphrase: "), key_file=a.key or None)
    except (ValueError, RuntimeError) as e:
        die(str(e))
    print(f"Created {i['created']} by seCreds {i['app_version']}: {i['count']} credential(s)")
    print("  " + ", ".join(i["names"])); print("  settings included: " + (", ".join(i["settings"]) or "none"))


def cmd_sync(a):
    """Bring this Mac up to date from the newest backup (new credentials are added; different ones only if you name them)."""
    from . import backup
    pw = getpass.getpass("Backup password / passphrase: ")
    try:
        pv = backup.sync_preview(pw, key_file=a.key or None)
        print(f"Newest backup: {pv['file']}")
        print(f"  new here ({len(pv['new'])}): {', '.join(pv['new']) or '-'}")
        print(f"  different from here ({len(pv['different'])}): {', '.join(pv['different']) or '-'}   (kept as they are unless you pass --take NAME)")
        print(f"  identical: {len(pv['same'])}")
        if a.dry_run or not (pv["new"] or a.take):
            return
        if not a.yes and input("Sync now? [y/N] ").strip().lower() != "y":
            print("Nothing was changed."); return
        r = backup.sync_apply(pw, path=pv["file"], take=a.take, key_file=a.key or None, agent="cli")
    except (ValueError, RuntimeError) as e:
        die(str(e))
    print(f"Synced: {r['restored']} credential(s) added or updated.")


def cmd_restore(a):
    """Restore from a backup. Default mode merge never overwrites anything already here."""
    from . import backup
    file = a.file
    if not file:
        if not a.icloud:
            die("Give the backup file, or use --icloud to take the newest one from iCloud Drive")
        found = backup.list_backups(_backup_folder(a))
        if not found:
            die("No backups found in iCloud Drive yet (they can take a minute to arrive on a new Mac)")
        file = found[0]["path"]
        print(f"Using the newest backup: {found[0]['name']}")
    pw = getpass.getpass("Backup password / passphrase: ")
    try:
        plan = backup.restore_backup(file, pw, mode=a.mode, dry_run=True, key_file=a.key or None)
        print(f"Would create {len(plan['create'])}, overwrite {len(plan['overwrite'])}, keep {len(plan['skip_existing'])} existing credential(s).")
        for label in ("create", "overwrite", "skip_existing"):
            if plan[label]:
                print(f"  {label.replace('_', ' ')}: {', '.join(plan[label])}")
        if a.dry_run:
            return
        if not a.yes and input("Restore now? [y/N] ").strip().lower() != "y":
            print("Nothing was changed."); return
        r = backup.restore_backup(file, pw, mode=a.mode, agent="cli", key_file=a.key or None)
    except (ValueError, RuntimeError) as e:
        die(str(e))
    print(f"Restored {r['restored']} credential(s) and the settings that were missing here.")


def cmd_update(a):
    """Check GitHub for a newer release once a day, and install one when you approve it."""
    from . import updater
    try:
        if a.enable_daily:
            updater.enable_daily(); print("Daily update check turned on (9:15 am). It only looks; it never installs anything by itself."); return
        if a.disable_daily:
            updater.disable_daily(); print("Daily update check turned off."); return
        if a.apply:
            st = updater.check(force=True)
            tag = a.tag or st.get("latest_tag")
            if not tag:
                die(st.get("error") or "No release was found")
            print(f"Installed: {updater.__version__}   Installing: {tag.lstrip('v')} from {updater.repo()}")
            if st.get("notes") and not a.tag:
                print("Release notes:\n  " + st["notes"].strip().replace("\n", "\n  ")[:1500])
            if not a.yes and input("Install it? [y/N] ").strip().lower() != "y":
                print("Nothing was changed."); return
            r = updater.apply(tag=a.tag, agent="cli")
            print(f"Updated {r['from']} -> {r['to']}. Reopen seCreds to use the new version.")
            return
        st = updater.check(force=a.now, quiet=a.quiet)
    except (updater.UpdateError, ValueError) as e:
        die(str(e))
    if a.quiet:
        return
    s = updater.status()
    print(f"seCreds {s['current']}  |  checking {s['repo'] or '(turned off)'}  |  daily check: {'on' if s['daily'] else 'off'}")
    if s["error"]:
        print(f"Could not check: {s['error']}")
    elif s["available"]:
        print(f"Update available: {s['latest_version']}. Install it with: secreds update --apply")
    else:
        print("You are up to date." if s["latest_tag"] else "No releases found. If the repository is private, sign in with `gh auth login`.")


def cmd_about(a):
    i = c.about()
    print(f"{i['signature']}\n  home:     {i['homepage']}\n  feedback: {i['feedback_url']}\n  data:     {c.DATA}")


def cmd_notice(a):
    print(c.notice(), end="")

def cmd_list(a):
    db, g = c.list_creds(), c.grants()
    if not db: print("(no credentials)"); return
    for n, m in sorted(db.items()):
        state = "REVOKED" if m["revoked"] else ("expired" if m["expires"] and c.parse(m["expires"]) < c.now() else "active")
        cmds = "REFERENCE (no secret)" if m.get("reference") else "human-only" if m.get("human_only") else (f"{len(m.get('allowed_commands', []))} pinned cmd(s)" if m.get("allowed_commands") else "ANY command" + (" (acknowledged)" if "any_command" in m.get("acks", []) else ""))
        print(f"{n:24} {state:8} {m['mode']:4} win={m['window_minutes']}m agents={','.join(m['agents']) or '-'} {cmds} folder={m.get('folder') or '-'} scope={m.get('scope') or '-'} addr={m.get('address') or '-'}{' (' + {'lan':'local network','remote':'remote','vpn':'vpn'}.get(m.get('network'), '') + ')' if m.get('network') else ''} "
              f"env={m['env_var']} last_used={m['last_used'] or 'never'} grants={list(g.get(n, {}))}")

def cmd_run(a):
    agent = c.detect_agent()
    cmd = a.command
    if not cmd: die("usage: secreds run NAME [NAME...] -- command args")
    env, secrets = dict(os.environ), []
    run_id = os.urandom(4).hex()
    try:
        one_s3 = sum(1 for n in a.names if c.get_meta(n).get("kind") == "s3") == 1   # AWS_* names only when unambiguous
        for n in a.names:
            v = c.authorize(n, agent, cmd, reason=a.reason, run_id=run_id); secrets.append(v); env.update(c.env_for(n, v, std=one_s3))
            if c.get_meta(n).get("access_key_id"): secrets.append(c.get_meta(n)["access_key_id"])
    except c.Denied as e:
        die(str(e), 3)
    env.pop("SECREDS_AGENT", None)
    sys.stderr.write(c.notice() + f" RUN_ID for secreds note: {run_id}\n"); sys.stderr.flush()
    t0 = time.time()
    try:
        p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as e:
        c.audit("finished", ",".join(a.names), agent, f"could not start: {e.strerror or type(e).__name__}", run=run_id, rc=127)
        die(f"could not start {cmd[0]}: {e.strerror or type(e).__name__}", 127)
    secrets = sorted(set(s for s in secrets if s), key=len, reverse=True)
    for raw in iter(lambda: p.stdout.readline(), b""):
        line = raw.decode(errors="replace")
        for s in secrets: line = line.replace(s, "***")
        sys.stdout.write(line); sys.stdout.flush()
    rc = p.wait(); secs = round(time.time() - t0, 1)
    c.audit("finished", ",".join(a.names), agent, f"exit {rc} after {secs}s", run=run_id, rc=rc, secs=secs)
    sys.exit(rc)

def cmd_note(a):
    """An agent adds a one-line outcome to a run it made (shown in the activity log, labelled as the agent's words)."""
    try:
        c.add_note(a.run_id, a.text, c.detect_agent())
    except ValueError as e:
        die(str(e), 3)
    print("noted")

def cmd_info(a):
    """Non-secret details of a reference entry (for example how keyless SSH to a host is set up)."""
    try:
        d = c.info(a.name, c.detect_agent())
    except c.Denied as e:
        die(str(e), 3)
    print(f"{d['name']}  (reference entry: no secret stored)")
    for k in ("kind", "folder", "scope", "network", "address", "username"):
        if d[k]: print(f"  {k}: {d[k]}")
    if d["notes"]: print("  notes:"); print("    " + d["notes"].replace("\n", "\n    "))

def cmd_add(a):
    v = None if a.reference else (os.environ.get("SECREDS_VALUE") or getpass.getpass(f"Value for {a.name} (hidden): "))
    c.save_cred(a.name, v, kind=a.kind, notes=a.notes, agents=a.agents.split(",") if a.agents else [],
                mode=a.mode, window_minutes=a.window, expires=a.expires, env_var=a.env, create=True,
                allowed_commands=a.cmd, human_only=a.human_only, username=a.username, address=a.address, network=a.network, scope=a.scope, access_key_id=a.access_key_id, bucket=a.bucket, region=a.region, folder=a.folder, reference=a.reference)
    print(f"stored {a.name}" + (" (reference entry, no secret)" if a.reference else ""))

def cmd_edit(a):
    m = c.get_meta(a.name)
    v = getpass.getpass("New value (blank = keep): ") if a.value else None
    c.save_cred(a.name, v, kind=a.kind or m["kind"], notes=m["notes"] if a.notes is None else a.notes,
                agents=a.agents.split(",") if a.agents is not None else m["agents"], mode=a.mode or m["mode"],
                window_minutes=m["window_minutes"] if a.window is None else a.window,
                expires=m["expires"] if a.expires is None else (a.expires or None), env_var=a.env or m["env_var"])
    print("updated")

def cmd_grant(a):
    c.get_meta(a.name)
    if not c.touch_id(f"grant {a.agent} access to '{a.name}' for {a.hours} h"): die("Touch ID declined", 3)
    c.add_grant(a.name, a.agent, int(a.hours * 60)); print("granted")

def cmd_audit(a):
    for e in c.read_audit(a.n):
        print(f"{e['t']}  {e['event']:14} {e['name']:20} {e['agent']:7} {e['detail']}")

def cmd_gui(a):
    from . import gui; gui.main()

def cmd_export(a):
    p1 = getpass.getpass("Passphrase for the bundle: ")
    if p1 != getpass.getpass("Repeat: "): die("passphrases differ")
    if not c.touch_id("export credentials to an encrypted bundle"): die("Touch ID declined", 3)
    c.export_bundle(a.path, p1); print(f"wrote {a.path}")

def cmd_import(a):
    done = c.import_bundle(a.path, getpass.getpass("Bundle passphrase: "), a.overwrite)
    print("imported:", ", ".join(done) or "(nothing new)")

def main():
    p = argparse.ArgumentParser(prog="secreds", description="Local credential broker for AI agents",
                                epilog=f"{signature()}  |  feedback: {c.about()['feedback_url']}")
    p.add_argument("--version", action="version", version=signature())
    s = p.add_subparsers(dest="cmd", required=True)
    s.add_parser("list").set_defaults(f=cmd_list)
    r = s.add_parser("run", help="run a command with credentials injected as env vars")
    r.add_argument("names", nargs="+")
    r.add_argument("--reason", default="", help="why you need the credential (required; goes in the audit trail)")
    r.set_defaults(f=cmd_run)
    nt = s.add_parser("note", help="add a one-line outcome to a run you made (for the activity log)")
    nt.add_argument("run_id"); nt.add_argument("text"); nt.set_defaults(f=cmd_note)
    ad = s.add_parser("add"); ad.add_argument("name"); ad.add_argument("--kind", default="api-key")
    ad.add_argument("--notes", default=""); ad.add_argument("--agents", default="claude"); ad.add_argument("--mode", default="ask")
    ad.add_argument("--window", type=int, default=c.DEFAULT_WINDOW); ad.add_argument("--expires"); ad.add_argument("--env")
    ad.add_argument("--cmd", action="append", default=[], help="allowed command (repeatable); empty = any command")
    ad.add_argument("--username", default=""); ad.add_argument("--address", default=""); ad.add_argument("--access-key-id", default=""); ad.add_argument("--folder", default=""); ad.add_argument("--bucket", default=""); ad.add_argument("--region", default=""); ad.add_argument("--scope", default="", choices=["", "personal", "work"]); ad.add_argument("--network", default="", choices=["", "lan", "remote", "vpn"]); ad.add_argument("--human-only", action="store_true"); ad.add_argument("--reference", action="store_true", help="no secret: a reference entry that only holds notes (for example how keyless SSH is set up)"); ad.set_defaults(f=cmd_add)
    e = s.add_parser("edit"); e.add_argument("name"); e.add_argument("--value", action="store_true")
    for k in ("kind", "notes", "agents", "mode", "expires", "env"): e.add_argument(f"--{k}")
    e.add_argument("--window", type=int); e.set_defaults(f=cmd_edit)
    for nm, flag in (("revoke", True), ("restore", False)):
        x = s.add_parser(nm); x.add_argument("name"); x.set_defaults(f=lambda a, fl=flag: (c.set_revoked(a.name, fl), print("ok")))
    d = s.add_parser("delete"); d.add_argument("name"); d.set_defaults(f=lambda a: (c.delete_cred(a.name), print("deleted")))
    g = s.add_parser("grant"); g.add_argument("name"); g.add_argument("agent", choices=c.AGENTS)
    g.add_argument("--hours", type=float, default=4); g.set_defaults(f=cmd_grant)
    s.add_parser("end-grants").set_defaults(f=lambda a: (c.clear_grants(), print("all time-window grants cleared")))
    au = s.add_parser("audit"); au.add_argument("-n", type=int, default=30); au.set_defaults(f=cmd_audit)
    s.add_parser("gui").set_defaults(f=cmd_gui)
    im2 = s.add_parser("import-keys", help="import single-secret *.key files from a folder (run by the owner)")
    im2.add_argument("dir", help="folder containing single-secret *.key files"); im2.add_argument("--scope", default="", choices=["", "personal", "work"], help="label every imported credential"); im2.set_defaults(f=cmd_import_keys)
    ie = s.add_parser("import-env", help="import the secrets in a .env file (run by the owner)")
    ie.add_argument("file"); ie.add_argument("--scope", default="", choices=["", "personal", "work"]); ie.add_argument("--prefix", default="")
    ie.set_defaults(f=cmd_import_env)
    rq = s.add_parser("request", help="propose a credential for the owner to complete (never takes a secret)")
    rq.add_argument("name"); rq.add_argument("--kind", default="api-key", choices=list(c.REQUEST_KINDS))
    for f in ("username", "address", "folder", "bucket", "region", "access-key-id", "notes", "agents", "env"):
        rq.add_argument("--" + f, default="")
    rq.add_argument("--network", default="", choices=["", "lan", "remote", "vpn"]); rq.add_argument("--scope", default="", choices=["", "personal", "work"])
    rq.add_argument("--cmd", action="append", default=[]); rq.add_argument("--human-only", action="store_true"); rq.add_argument("--reference", action="store_true", help="no secret: a reference entry that only holds notes"); rq.set_defaults(f=cmd_request)
    inf = s.add_parser("info", help="show the non-secret details of a reference entry (for example how keyless SSH is set up)")
    inf.add_argument("name"); inf.set_defaults(f=cmd_info)
    s.add_parser("requests", help="list credential requests waiting for the owner").set_defaults(f=cmd_requests)
    ini = s.add_parser("init", help="write config.json (your name, your agents, profile groups)")
    ini.add_argument("--owner", default="the owner"); ini.add_argument("--agents", default="claude,codex")
    ini.add_argument("--family", action="append", default=[], help="profile=agent, e.g. claude-work=claude (repeatable)")
    ini.add_argument("--force", action="store_true"); ini.set_defaults(f=cmd_init)
    s.add_parser("doctor", help="health check (Keychain, Touch ID, encryption, permissions, backups)").set_defaults(f=cmd_doctor)
    ia = s.add_parser("install-app", help="build seCreds.app (a double-clickable launcher for the GUI)")
    ia.add_argument("--dest", default="~/Applications");
    ia.set_defaults(f=cmd_install_app)
    bk = s.add_parser("backup", help="write one encrypted backup of everything to a folder you choose (or iCloud Drive)")
    bk.add_argument("--to", default="", help="folder to save into"); bk.add_argument("--icloud", action="store_true", help="save into iCloud Drive")
    bk.add_argument("--no-audit", action="store_true", help="leave the activity log out")
    bk.add_argument("--plan", action="store_true", help="run your backup plan now (all destinations, then prune)"); bk.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    bk.add_argument("--passphrase", action="store_true", help="use a one-off passphrase even though the backup key is set up"); bk.set_defaults(f=cmd_backup)
    bkk = s.add_parser("backup-key", help="set up the backup key (one password, set once) or show its status")
    bkk.add_argument("action", choices=["setup", "status"]); bkk.add_argument("--icloud", action="store_true", help="save a recovery file in iCloud Drive")
    bkk.add_argument("--to", action="append", help="also save a recovery file in this folder (repeat for more)"); bkk.add_argument("--replace", action="store_true"); bkk.set_defaults(f=cmd_backup_key)
    bl = s.add_parser("backups", help="list backup files in a folder (or iCloud Drive)")
    bl.add_argument("--in", dest="dir", default=""); bl.add_argument("--icloud", action="store_true"); bl.set_defaults(f=cmd_backups)
    bi = s.add_parser("backup-info", help="show what is inside a backup (names only)"); bi.add_argument("file"); bi.add_argument("--key", default="", help="recovery file (if not beside the backup)"); bi.set_defaults(f=cmd_backup_info)
    rs = s.add_parser("restore-backup", help="restore from a backup (merge by default: nothing here is overwritten)")
    rs.add_argument("file", nargs="?", default=""); rs.add_argument("--icloud", action="store_true", help="use the newest backup in iCloud Drive")
    rs.add_argument("--mode", default="merge", choices=["merge", "overwrite"]); rs.add_argument("--dry-run", action="store_true")
    rs.add_argument("--yes", action="store_true"); rs.add_argument("--key", default="", help="recovery file (if not beside the backup)"); rs.set_defaults(f=cmd_restore)
    sy = s.add_parser("sync", help="bring this Mac up to date from the newest backup (adds what is new)")
    sy.add_argument("--dry-run", action="store_true"); sy.add_argument("--yes", action="store_true")
    sy.add_argument("--take", action="append", default=[], help="also take the backup's version of this credential (repeat)")
    sy.add_argument("--key", default="", help="recovery file (if not beside the backup)"); sy.set_defaults(f=cmd_sync)
    up = s.add_parser("update", help="check GitHub for a newer release, or install one you approve")
    up.add_argument("--check", action="store_true"); up.add_argument("--now", action="store_true", help="ignore the once-a-day limit")
    up.add_argument("--apply", action="store_true"); up.add_argument("--tag", default="", help="install this release tag (also rolls back)")
    up.add_argument("--enable-daily", action="store_true"); up.add_argument("--disable-daily", action="store_true")
    up.add_argument("--quiet", action="store_true"); up.add_argument("--yes", action="store_true"); up.set_defaults(f=cmd_update)
    s.add_parser("about", help="show the version, who makes it, and where to send feedback").set_defaults(f=cmd_about)
    s.add_parser("notice", help="print the agent notice").set_defaults(f=cmd_notice)
    ex = s.add_parser("export"); ex.add_argument("path"); ex.set_defaults(f=cmd_export)
    im = s.add_parser("import"); im.add_argument("path"); im.add_argument("--overwrite", action="store_true"); im.set_defaults(f=cmd_import)
    argv = sys.argv[1:]
    rest = []
    if "--" in argv:
        i = argv.index("--"); argv, rest = argv[:i], argv[i + 1:]
    a = p.parse_args(argv); a.command = rest
    try: a.f(a)
    except (KeyError, ValueError, RuntimeError) as ex_: die(str(ex_))

if __name__ == "__main__":
    main()
