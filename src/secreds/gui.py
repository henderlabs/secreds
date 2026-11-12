"""Local GUI: loopback-only web server, random per-launch token. Secret values reach the browser only through Reveal (Touch ID); the dashboard shows a mask plus the last few characters."""
import json, secrets, threading, webbrowser
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from . import core as c
from . import backup, updater, settings
from . import __version__

TOKEN = secrets.token_urlsafe(24)
PORT_HOLDER = {}

def _backup_state():
    st = backup.state(); ic = backup.icloud_dir()
    return {"last_backup": st.get("last_backup"), "last_backup_dir": st.get("last_backup_dir"), "last_backup_file": st.get("last_backup_file"),
            "last_backup_count": st.get("last_backup_count"), "icloud": str(ic) if ic else "", "key": backup.key_status(), "plan": backup.get_plan(), "cloud_drives": backup.cloud_locations(), "schedule_on": backup.schedule_enabled(), "last_plan_run": st.get("last_plan_run"), "s3_creds": [{"name": n, "bucket": m.get("bucket", ""), "address": m.get("address", "")} for n, m in c.list_creds().items() if m.get("kind") == "s3"], "last_restore_check": st.get("last_restore_check"),
            "icloud_files": backup.list_backups(ic)[:5] if ic else []}


def _pick(kind):
    """Show the native macOS folder/file chooser and return the chosen path ('' if cancelled)."""
    import subprocess
    script = ('POSIX path of (choose folder with prompt "Choose where to save the backup")' if kind == "folder"
              else 'POSIX path of (choose file with prompt "Choose a seCreds backup file")')
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=600)
    return r.stdout.strip() if r.returncode == 0 else ""


def state():
    db, g = c.list_creds(), c.grants()
    out = []
    for n, m in sorted(db.items()):
        exp = bool(m["expires"] and c.parse(m["expires"]) < c.now())
        out.append(dict(m, name=n, in_keychain=True if m.get("reference") else c.kc_has(n), masked="" if m.get("reference") else c.masked(n), expired=exp, grants=g.get(n, {})))
    return {"creds": out, "agents": c.PICKABLE, "families": c.FAMILY, "audit": c.read_audit(100), "folders": c.list_folders(), "version": __version__, "about": c.about(), "backup": _backup_state(), "update": updater.status(), "settings": settings.get(), "agent_docs": {a: settings.agent_doc(a) for a in c.AGENTS}, "requests": [dict(r, name=n) for n, r in sorted(c.list_requests().items())], "notice": c.notice(), "notice_default": c.default_notice(), "notice_custom": c.notice_is_custom(), "notice_max": c.NOTICE_MAX}

def act(path, b):
    n = b.get("name", "")
    if path == "/api/save":
        mins = int(b.get("window_minutes") or 0)
        kw = dict(kind=b.get("kind") or "api-key", notes=b.get("notes", ""), agents=b.get("agents", []),
                  mode=b.get("mode", "ask"), window_minutes=mins, expires=b.get("expires") or None,
                  env_var=b.get("env_var") or None, username=b.get("username", ""), address=b.get("address", ""), network=b.get("network", ""), scope=b.get("scope", ""), folder=b.get("folder", ""), access_key_id=b.get("access_key_id", ""), bucket=b.get("bucket", ""), region=b.get("region", ""), human_only=bool(b.get("human_only")),
                  allowed_commands=[l for l in (b.get("allowed_commands") or "").splitlines()])
        c.save_cred(n, b.get("value") or None, create=bool(b.get("create")), reference=bool(b.get("reference")), **kw)
        if b.get("create") and b.get("fulfil_request"):
            c.complete_request(b["fulfil_request"])
    elif path == "/api/reveal": return {"value": c.reveal(n)}
    elif path == "/api/copy": return {"seconds": c.copy_value(n)}
    elif path == "/api/notice": c.set_notice(b.get("text", ""))
    elif path == "/api/notice-reset": c.reset_notice()
    elif path == "/api/pick": return {"path": _pick("folder" if b.get("kind") == "folder" else "file")}
    elif path == "/api/backup":
        dest = backup.icloud_dir(create=True) if b.get("icloud") else (b.get("dest") or "").strip()
        if not dest:
            raise ValueError("Choose where to save the backup (iCloud Drive is not available on this Mac, or no folder was given)")
        return backup.create_backup(dest, b.get("passphrase") or None, include_audit=bool(b.get("include_audit", True)), agent="gui")
    elif path == "/api/backup-plan-save": return {"plan": backup.save_plan(b.get("plan") or {}, agent="gui")}
    elif path == "/api/backup-plan-run": return backup.run_plan(agent="gui")
    elif path == "/api/backup-key-setup":
        dests = [backup.icloud_dir(create=True)] if b.get("icloud") and backup.icloud_dir() else []
        if (b.get("dest") or "").strip():
            dests.append(b["dest"].strip())
        if not b.get("ack_manager") or not b.get("ack_offline"):
            raise ValueError("Please confirm you saved the password in your password manager and made an offline copy")
        return backup.setup_key(b.get("password", ""), dests, replace=bool(b.get("replace")), agent="gui")
    elif path == "/api/sync-preview": return backup.sync_preview(b.get("password", ""), path=b.get("path") or None)
    elif path == "/api/sync-apply": return backup.sync_apply(b.get("password", ""), path=b.get("path") or None, take=b.get("take") or [], agent="gui")
    elif path == "/api/backup-key-copy":
        dest = backup.icloud_dir(create=True) if b.get("icloud") else (b.get("dest") or "").strip()
        if not dest:
            raise ValueError("Choose where to save the copy")
        return backup.copy_recovery(dest, agent="gui")
    elif path == "/api/restore-backup":
        return backup.restore_backup(b.get("path", ""), b.get("passphrase", ""), mode=b.get("mode", "merge"), dry_run=bool(b.get("dry_run")), agent="gui", key_file=(b.get("key_file") or "").strip() or None)
    elif path == "/api/settings-save": return {"settings": settings.save(**{k: b[k] for k in ("owner", "agents", "families", "feedback_url", "update_repo", "keep_scripts") if k in b})}
    elif path == "/api/script": return {"text": c.read_kept_script(b.get("sha256"))}
    elif path == "/api/doctor": return {"checks": settings.doctor()}
    elif path == "/api/update-check": return updater.check(force=True)
    elif path == "/api/update-apply": return updater.apply(tag=b.get("tag") or None, agent="gui")
    elif path == "/api/update-daily":
        updater.enable_daily() if b.get("on") else updater.disable_daily()
    elif path == "/api/request-dismiss": c.dismiss_request(n)
    elif path == "/api/folder-add": c.add_folder(b.get("path", ""))
    elif path == "/api/folder-rename": c.rename_folder(b.get("old", ""), b.get("new", ""))
    elif path == "/api/folder-delete": c.delete_folder(b.get("path", ""))
    elif path == "/api/move": c.set_folder(n, b.get("folder", ""))
    elif path == "/api/ack": c.set_ack(n, b.get("key", ""), bool(b.get("on")))
    elif path == "/api/repin": c.repin(n)
    elif path == "/api/revoke": c.set_revoked(n, True)
    elif path == "/api/restore": c.set_revoked(n, False)
    elif path == "/api/delete": c.delete_cred(n)
    elif path == "/api/end-grants": c.clear_grants(n or None)
    elif path == "/api/grant":
        if not c.touch_id(f"grant {b['agent']} access to '{n}' for {b['hours']} h"): raise ValueError("Touch ID declined")
        c.add_grant(n, b["agent"], int(float(b["hours"]) * 60))
    else: raise ValueError("unknown action")
    return {}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _touch(self):
        import time
        authed = self.headers.get("X-Token") == TOKEN or parse_qs(urlparse(self.path).query).get("t", [""])[0] == TOKEN
        if authed and not self.headers.get("X-Poll"):      # the page's own 15 s refresh, or a caller without the token, must not keep the server alive
            LAST["t"] = time.time()
    def _ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store"); self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self._touch()
        u = urlparse(self.path)
        if not self._ok(): return self._send(403, "{}")
        if u.path == "/favicon.svg":
            return self._send(200, FAVICON, "image/svg+xml")
        if u.path == "/":
            if parse_qs(u.query).get("t", [""])[0] != TOKEN: return self._send(403, "Open seCreds from its icon.", "text/plain")
            return self._send(200, PAGE.replace("__TOKEN__", TOKEN), "text/html; charset=utf-8")
        if u.path == "/api/state" and self.headers.get("X-Token") == TOKEN: return self._send(200, json.dumps(state()))
        if u.path == "/api/ping" and self.headers.get("X-Token") == TOKEN: return self._send(200, "{}")   # the page's "someone is using me" signal (_touch above)
        self._send(404, "{}")
    def do_POST(self):
        self._touch()
        if not self._ok() or self.headers.get("X-Token") != TOKEN: return self._send(403, "{}")
        try:
            b = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            out = act(urlparse(self.path).path, b) or {}; self._send(200, json.dumps(dict(out, ok=True)))
        except Exception as e:
            self._send(400, json.dumps({"error": str(e)}))

class Srv(ThreadingHTTPServer):
    def server_bind(self):  # skip HTTPServer's getfqdn() reverse-DNS lookup, which can hang on this network
        import socketserver
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

IDLE_MINUTES = 30
LAST = {"t": 0.0}
class _DataFile:
    """A path inside the data folder, looked up at use time (so tests and SECREDS_HOME work)."""
    def __init__(self, name): self.name = name
    def __getattr__(self, attr): return getattr(c.DATA / self.name, attr)
    def __fspath__(self): return str(c.DATA / self.name)
URLFILE = _DataFile("gui.url")

PIDFILE = _DataFile("gui.pid")
VERFILE = _DataFile("gui.ver")

def _code_version():
    """Changes whenever any seCreds source file changes, so an old server is never reused."""
    import hashlib
    pkg = Path(__file__).resolve().parent
    return hashlib.sha1("".join(f"{f.name}{f.stat().st_mtime_ns}" for f in sorted(pkg.glob("*.py"))).encode()).hexdigest()[:12]

def _stop_old():
    import os, signal, time
    try:
        pid = int(PIDFILE.read_text().strip())
        if pid != os.getpid():
            os.kill(pid, signal.SIGTERM)
    except Exception:
        pass
    for _ in range(30):                      # wait up to 3 s for it to let go
        if _running_url() is None: break
        time.sleep(0.1)
    for f in (URLFILE, PIDFILE, VERFILE):
        try: f.unlink()
        except FileNotFoundError: pass

def _running_url():
    """Return the URL of an already-running GUI of ours, or None."""
    import urllib.request
    try:
        url = URLFILE.read_text().strip()
        urllib.request.urlopen(url, timeout=2).close()
        return url
    except Exception:
        return None

def main():
    import os, time
    if not c.touch_id("open the credential manager"):
        c.audit("denied", "", "gui", "Touch ID declined: open GUI")
        print("secreds: Touch ID approval declined or unavailable"); return
    c.audit("gui-opened", "", "gui")
    ver = _code_version()
    url = _running_url()
    if url:
        try: same = VERFILE.read_text().strip() == ver
        except Exception: same = False
        if same:                 # already running the current code: just reopen it
            webbrowser.open(url); return
        _stop_old()              # stale server from before an update: replace it
    srv = Srv(("127.0.0.1", 0), H)
    url = f"http://127.0.0.1:{srv.server_address[1]}/?t={TOKEN}"
    fd = os.open(URLFILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f: f.write(url)
    for path, text in ((PIDFILE, str(os.getpid())), (VERFILE, ver)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f: f.write(text)
    LAST["t"] = time.time()
    def watchdog():  # stop the server after IDLE_MINUTES with no browser activity
        while True:
            time.sleep(30)
            if time.time() - LAST["t"] > IDLE_MINUTES * 60:
                srv.shutdown(); return
    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=lambda: updater.check(), daemon=True).start()      # at most once a day; only ever reads GitHub
    print("seCreds GUI:", url, f"\nCtrl-C to quit (auto-quits after {IDLE_MINUTES} idle minutes)."); webbrowser.open(url)
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        for f in (URLFILE, PIDFILE, VERFILE):
            try: f.unlink()
            except FileNotFoundError: pass

FAVICON = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='#2f6fed'/>"
           "<rect x='9' y='14' width='14' height='11' rx='2' fill='white'/>"
           "<path d='M12 14v-3a4 4 0 0 1 8 0v3' stroke='white' stroke-width='2.4' fill='none'/></svg>")

PAGE = r"""<!doctype html><html><head><meta charset=utf-8><title>seCreds</title><link rel=icon type="image/svg+xml" href="/favicon.svg"><meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#fff;--fg:#1c1c1e;--mut:#6b6b70;--line:#e3e3e6;--card:#f6f6f8;--acc:#2f6fed;--bad:#c62828;--ok:#1f8a4c}
@media(prefers-color-scheme:dark){:root{--bg:#161618;--fg:#f2f2f4;--mut:#9a9aa0;--line:#2c2c30;--card:#202024;--acc:#6b9bff;--bad:#ff6b6b;--ok:#4cc27f}}
body{margin:0;font:14px -apple-system,system-ui,sans-serif;background:var(--bg);color:var(--fg);min-height:100vh;display:flex;flex-direction:column}
.layout{flex:1 0 auto;width:100%;box-sizing:border-box}
footer.sig{margin-top:24px;border-top:1px solid var(--line);padding:14px 16px 18px;text-align:center;color:var(--mut);font-size:12px}
footer.sig a{color:var(--mut);text-decoration:underline}footer.sig a:hover{color:var(--acc)}footer.sig b{color:var(--fg);font-weight:600}
main{padding:16px 0 24px;min-width:0}
.layout{max-width:1240px;margin:0 auto;padding:0 16px;display:grid;grid-template-columns:272px minmax(0,1fr);gap:24px}
aside{position:sticky;top:57px;align-self:start;max-height:calc(100vh - 69px);overflow:auto;padding:16px 4px 16px 0}
.nav-item{display:flex;gap:7px;align-items:center;padding:6px 8px;border-radius:7px;cursor:pointer;border:1px solid transparent}
.nav-item:hover{background:var(--card)}.nav-item.on{background:var(--card);border-color:var(--acc)}
.dot{width:8px;height:8px;border-radius:50%;flex:none}
.grp{font-size:11px;text-transform:uppercase;color:var(--mut);margin:12px 8px 4px;letter-spacing:.05em}
@media(max-width:820px){.layout{grid-template-columns:1fr;gap:0}aside{position:static;max-height:none}}
header{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line)}
header .in{max-width:1240px;margin:0 auto;padding:10px 16px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
header a{color:var(--fg);text-decoration:none}header nav a{color:var(--mut);margin-right:12px}header nav a:hover,header a.brand:hover{color:var(--acc)}
a.brand{display:flex;align-items:center;gap:8px;font-weight:600;font-size:16px}
h2,#list,#form{scroll-margin-top:64px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px}.mut{color:var(--mut)}
.cgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,400px),1fr));gap:10px;align-items:start}.cgrid>.card{margin:0;min-width:0;overflow-wrap:anywhere}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:8px 0}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.sp{flex:1}
button{font:inherit;border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:7px;padding:5px 10px;cursor:pointer}
button.p{background:var(--acc);border-color:var(--acc);color:#fff}button.d{color:var(--bad)}
input,select,textarea{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:6px 8px;box-sizing:border-box}
label{display:block;margin:8px 0 3px;font-size:12px;color:var(--mut)}.g{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}
@media(max-width:640px){.g{grid-template-columns:1fr}}input[type=text],input[type=password],input[type=datetime-local],input[type=number],select,textarea{width:100%}
.lk{vertical-align:-3px}.tag{font-size:11px;border-radius:99px;padding:1px 8px;border:1px solid var(--line)}.bad{color:var(--bad)}.ok{color:var(--ok)}.warn{color:#d9902f}
table{width:100%;border-collapse:collapse;font-size:12px}td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line)}tr.clk{cursor:pointer}tr.clk:hover td{background:rgba(127,127,127,.08)}tr.det td{background:rgba(127,127,127,.06)}
#err{color:var(--bad);margin:8px 0;min-height:18px}
#err:not(:empty){position:sticky;top:58px;z-index:6;background:var(--bg);border:1px solid currentColor;border-radius:8px;padding:8px 12px;font-weight:600}
.page{display:none}.page.on{display:block}
.layout.nosb{grid-template-columns:minmax(0,1fr);max-width:1040px}.layout.nosb aside{display:none}
header nav a.on{color:var(--fg);font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:8px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer}.tile:hover{border-color:var(--acc)}
.tile span{color:var(--mut);font-size:12px}.tile b{display:block;font-size:26px;margin-top:2px}
.seg{display:inline-flex}.seg button{border-radius:0}.seg button:first-child{border-radius:7px 0 0 7px}.seg button:last-child{border-radius:0 7px 7px 0;border-left:0}
.seg button.on{background:var(--acc);border-color:var(--acc);color:#fff}
button.mini{padding:1px 8px;font-size:11px}
.badge{background:var(--acc);color:#fff;border-radius:99px;font-size:10px;padding:0 6px;margin-left:5px}
.chev{width:14px;display:inline-block;color:var(--mut);cursor:pointer;flex:none}.fname{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
.cnt{color:var(--mut);font-size:11px}.facts{display:none;gap:2px}.nav-item.folder:hover .facts{display:inline-flex}.nav-item.folder:hover .cnt{display:none}
.facts span{padding:0 3px;cursor:pointer;color:var(--mut)}.facts span:hover{color:var(--fg)}.nav-item.drop{outline:2px dashed var(--acc);background:var(--card)}tr.click{cursor:pointer}tr.click:hover td{background:var(--card)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:900px){.two{grid-template-columns:1fr}}
.att{margin:6px 0;padding-left:4px}
</style></head><body><header><div class=in>
<a class=brand href="#/home" title="Home"><svg width=22 height=22 viewBox="0 0 32 32"><rect width=32 height=32 rx=7 fill="#2f6fed"/><rect x=9 y=14 width=14 height=11 rx=2 fill="#fff"/><path d="M12 14v-3a4 4 0 0 1 8 0v3" stroke="#fff" stroke-width=2.4 fill="none"/></svg>seCreds</a>
<nav><a href="#/home" data-p=home>Home<span id=hbadge class=badge style="display:none"></span></a><a href="#/credentials" data-p=credentials>Credentials</a><a href="#/agents" data-p=agents>Agents</a><a href="#/activity" data-p=activity>Activity</a><a href="#/settings" data-p=settings>Settings</a><a href="#/backup" data-p=backup>Backup<span id=ubadge class=badge style="display:none" title="An update is available">!</span></a></nav>
<span class=sp style="flex:1"></span><button class=p onclick="addNew()">+ Add credential</button></div></header><div class=layout id=layout><aside id=side>
<input type=text id=q placeholder="Search…  (press / )" oninput="V.q=this.value;render()">
<label>Sort by</label><select id=sort onchange="setV('sort',this.value)"></select>
<label>Show</label><select id=flt onchange="setV('flt',this.value)"></select>
<div id=count class=mut style="margin:12px 8px 4px"></div>
<div class=row style="margin:10px 0 6px"><div class=seg><button id=tv-tree onclick="setTree(true)">Tree</button><button id=tv-flat onclick="setTree(false)">Flat</button></div><span class=sp></span><button class=mini onclick="newFolder('')" title="Create a folder (use Parent/Child to nest)">+ Folder</button></div>
<div class=nav-item id=nav_all onclick="showAll()" title="Drop a credential here to take it out of its folder"><b>All credentials</b></div>
<div id=navlist></div></aside><main>
<div id=err></div>
<section class=page id=p-home></section>
<section class=page id=p-credentials>
 <div class=row><h2 style="margin:0">Credentials</h2><span class=sp></span><div class=seg><button id=vw-cards onclick="setView('cards')">Cards</button><button id=vw-list onclick="setView('list')">List</button></div><button onclick="load()">Refresh</button></div>
 <div id=form></div><div id=list></div>
</section>
<section class=page id=p-agents>
 <h2 style="margin-top:0">Agents</h2>
 <div class=card><b>Your AI agents</b>
  <div class=mut style="margin:4px 0 8px">Tick the AI tools you use, or add your own. Only these can be given access to a credential. The name is what you set as <code>SECREDS_AGENT</code> for that tool (for example <code>export SECREDS_AGENT=gemini</code>). Changing this needs Touch ID. Unticking an agent removes it from every credential.</div>
  <div id=st-agents class=row style="gap:8px 14px"></div>
  <div class=row style="margin-top:10px"><input type=text id=st-custom placeholder="Add another AI, e.g. my-agent" style="max-width:240px" onkeydown="if(event.key=='Enter')stAdd()"><button onclick="stAdd()">Add</button></div>
  <div style="margin-top:12px"><b style="font-size:13px">Profiles that count as the same agent</b><div class=mut style="font-size:12px;margin:2px 0 6px">For example a second Claude profile you use for work: tell seCreds it is the same agent, so one approval covers both and the activity log still shows which profile acted.</div><div id=st-fam></div></div>
  <div class=row style="margin-top:10px"><button class=p onclick="stSaveAgents()">Save agents (Touch ID)</button><span id=st-amsg></span></div></div>
 <h3 style="margin:18px 0 4px">Notice to AI agents <span id=noticetag class=tag style="font-weight:400"></span> <button onclick="copyNotice(this)" style="margin-left:8px;font-size:12px">Copy notice</button></h3>
 <div class=mut>This is exactly what an agent sees each time it uses a credential.</div>
 <div class=card><pre id=notice style="white-space:pre-wrap;margin:0;font:12px ui-monospace,monospace"></pre></div>
 <div class=row style="margin:6px 0"><button onclick="editNotice()">Edit notice</button><button id=nreset onclick="resetNotice()">Reset to default (Touch ID)</button><span class=mut>Every line is yours to edit.</span></div><div id=noticeform></div>
 <div class=card><div class=row><b>Recommended instructions file</b><span class=sp></span><select id=ag-doc onchange="renderAgentDoc()"></select></div>
  <div class=mut style="margin:4px 0 8px" id=ag-docwhere></div>
  <pre id=ag-doctext style="white-space:pre-wrap;margin:0;font:12px ui-monospace,monospace"></pre>
  <div class=row style="margin-top:8px"><button onclick="copyAgentDoc(this)">Copy these instructions</button><span class=mut>Paste them into that file so the agent knows how to use seCreds. Cloud chat assistants cannot run commands; their version tells them to ask you instead.</span></div></div>
</section>
<section class=page id=p-activity>
 <h2 style="margin-top:0">Activity</h2>
 <div class=row><input type=text id=act-q placeholder="Search activity…" style="max-width:260px" oninput="A.q=this.value;renderActivity()" data-1p-ignore autocomplete=off>
  <select id=act-ev style="max-width:200px" onchange="A.ev=this.value;renderActivity()"></select><button onclick="actAll(true)">Expand all</button><button onclick="actAll(false)">Collapse all</button><span id=act-count class=mut></span></div>
 <div class=card style="padding:0;overflow:auto"><table id=audit></table></div>
</section>
<section class=page id=p-settings>
 <h2 style="margin-top:0">Settings</h2>
 <div class=card><b>About you</b>
  <div class=g><div><label>Your name (used in the agent notice)</label><input type=text id=st-owner maxlength=40 placeholder="the owner"></div></div>
  <div class=row style="margin-top:10px"><button class=p onclick="stSaveMisc()">Save</button><span id=st-omsg></span></div></div>
 <div class=card><b>Audit trail</b>
  <label style="display:block;color:var(--fg);margin-top:6px"><input type=checkbox id=st-keep onchange="stKeep(this.checked)"> Keep a copy of each script an agent runs</label>
  <div class=mut style="font-size:12px;margin-top:4px">The activity log always records a fingerprint (SHA-256) of the script, so you can match it later. With this on, the script text itself is also saved (small scripts only, owner-only folder) so you can see exactly what ran. Scripts normally get secrets from the environment, not their text, but check before turning it on if yours might hold one. Changing this asks for Touch ID.</div><div id=st-kmsg style="margin-top:6px"></div></div>
 <div class=card><b>Updates and feedback</b>
  <div class=g><div><label>Where updates come from (GitHub owner/name)</label><input type=text id=st-repo></div><div><label>Where the Send feedback link goes (https://)</label><input type=text id=st-fb></div></div>
  <div id=st-upinfo style="margin:10px 0 0"></div><div class=row style="margin-top:10px"><button class=p onclick="stSaveMisc()">Save</button><button onclick="upCheck()">Check for updates now</button><button class=p id=st-apply onclick="upApply()" style="display:none">Install the update (Touch ID)</button><button id=st-daily onclick="upDaily()"></button><span id=st-umsg></span></div>
  <div class=mut style="font-size:12px;margin-top:6px">A check only reads the latest release from GitHub; nothing is installed unless you press the button, and only from the repository named above. If an update misbehaves, <code>secreds update --apply --tag vX.Y.Z</code> installs an earlier version. Backups are made on the <a href="#/backup" style="color:var(--acc)">Backup</a> page.</div></div>
 <div class=card><div class=row><b>Health check</b><span class=sp></span><button onclick="runDoctor()">Run check</button></div>
  <div class=mut style="margin:4px 0 8px">Looks at the Keychain, Touch ID, backup encryption, file permissions, iCloud Drive, GitHub CLI and the daily check. It never reads a secret value.</div><div id=st-doc></div></div>
</section>
<section class=page id=p-backup>
 <h2 style="margin-top:0">Backup</h2>
 <div class=card id=bk-keycard><b>Backup password</b>
  <div id=kc-info style="margin:4px 0"></div>
  <div class=g><div><label>Save another copy of the recovery file to</label><select id=kc-loc onchange="kcLoc()"></select><div class=row id=kc-f style="margin-top:6px"><input type=text id=kc-dir placeholder="(a folder: NAS share, USB drive…)" style="flex:1"><button onclick="pickInto('kc-dir','folder')">Choose…</button></div></div>
   <div style="align-self:end"><div class=row><button onclick="kcCopy()">Save another copy</button><button class=d onclick="kcReplace()">Replace the backup key…</button></div></div></div>
  <div id=kc-msg style="margin-top:8px"></div></div>
 <div class=card id=bk-setup><b id=ks-title>Set up your backup password (once)</b><div id=ks-warn class=bad style="display:none;margin:4px 0"><b>You are replacing the backup key.</b> New backups will need the NEW password and recovery file. Backups made with the old key can only be opened with the OLD password and OLD recovery file, so keep both.</div>
  <div class=mut style="margin:4px 0 8px">Choose ONE backup password. seCreds keeps only a public key on this Mac, so it can make backups (manual now, scheduled later) without ever knowing the password. A small <b>recovery file</b>, locked by your password, is what restores them. You need the password only on the day you restore.</div>
  <div class=g><div><label>Backup password (16+ characters; four or five random words works well)</label><input type=password id=ks-pass></div><div><label>Repeat the password</label><input type=password id=ks-pass2></div>
   <div><label>Save the recovery file to</label><label style="display:block;color:var(--fg)"><input type=checkbox id=ks-ic checked> iCloud Drive (seCreds Backups folder)</label></div>
   <div><label>and also to a second place (recommended)</label><div class=row><input type=text id=ks-dir placeholder="(a USB drive, the NAS, another folder)" style="flex:1"><button onclick="pickInto('ks-dir','folder')">Choose…</button></div></div></div>
  <div class=mut style="margin:10px 0 4px"><b>Where to keep the password:</b> in your password manager (main copy) <u>and</u> one offline copy (printed or written, in a safe place). <b>Do not</b> store it in seCreds, an AI chat, an email, or a note or file on this Mac, and not next to the backups.</div>
  <label style="display:block;color:var(--fg)"><input type=checkbox id=ks-a1> I saved the password in my password manager</label>
  <label style="display:block;color:var(--fg)"><input type=checkbox id=ks-a2> I made an offline copy (printed or written down)</label>
  <div class=row style="margin-top:10px"><button class=p onclick="bkSetup()">Set up the backup key (Touch ID)</button></div><div id=ks-msg style="margin-top:8px"></div></div>
 <div class=card id=bk-plan><b>Backup plan</b><div id=pl-status class=mut style="margin:4px 0"></div>
  <div class=mut style="margin:4px 0 8px">Where backups go, how many to keep, and when. Each run makes one backup with your backup key and puts a copy in each place below. Scheduled runs need no password and no Touch ID.</div>
  <div class=g>
   <div><label>Main location</label><select id=pl-l1 onchange="plLoc()"></select>
    <div class=row id=pl-f1 style="margin-top:6px"><input type=text id=pl-d1 placeholder="(a folder: NAS share, USB drive, a cloud drive's folder)" style="flex:1"><button onclick="pickInto('pl-d1','folder')">Choose…</button></div></div>
   <div><label>Second location (a different place is much safer)</label><select id=pl-l2 onchange="plLoc()"></select>
    <div class=row id=pl-f2 style="margin-top:6px"><input type=text id=pl-d2 placeholder="(a folder: NAS share, USB drive, a cloud drive's folder)" style="flex:1"><button onclick="pickInto('pl-d2','folder')">Choose…</button></div>
    <div class=row id=pl-s3row style="margin-top:6px"><select id=pl-s3 style="flex:1"></select><input type=text id=pl-s3p placeholder="folder in the bucket" value="secreds-backups/" style="width:160px"></div></div>
   <div style="grid-column:1/-1" class=mut><span style="font-size:12px">Cloud drives (Google Drive, OneDrive…) show up in the lists above when they are installed and signed in on this Mac; seCreds writes into a folder called <i>seCreds Backups</i> inside them. If you choose a folder by hand for Google Drive, open <b>My Drive</b> first: its top level is read-only. A work OneDrive belongs to your employer: prefer a personal one. An S3 bucket is a credential of type <i>S3 bucket</i> (Credentials page): use a key that can only write, on a bucket with Object Lock. seCreds never deletes from S3.</span></div>
   <div><label>How many backups to keep in each folder / cloud drive</label><select id=pl-keep></select></div>
   <div><label>Schedule</label><div class=row><select id=pl-sch onchange="plSch()"><option value=off>Off (manual only)</option><option value=daily>Every day</option><option value=weekly>Every week</option></select><select id=pl-wd></select><select id=pl-hr></select></div>
    <label style="display:block;color:var(--fg);margin-top:8px"><input type=checkbox id=pl-audit checked> Include the activity log</label></div></div>
  <div class=row style="margin-top:10px"><button class=p onclick="plSave()">Save plan (Touch ID)</button><button onclick="plRun()">Back up now (Touch ID)</button></div><div id=pl-msg style="margin-top:8px"></div></div>
 <div class=card><b id=bk-title>One-off backup</b><div id=bk-keyinfo class=mut style="margin:4px 0"></div>
  <div class=mut style="margin:4px 0 8px">One encrypted file with every secret and every setting (folders, agents, the notice, your activity history). It is encrypted with a passphrase you choose before it leaves this Mac, so a cloud folder only ever holds ciphertext. It is also how you move seCreds to another Mac: iCloud Keychain does not sync these items.</div>
  <div class=g><div><label>Save it to</label><select id=bk-src onchange="bkSrc()"><option value=icloud id=bk-ic>iCloud Drive (an off-Mac copy)</option><option value=folder>A folder I choose</option></select><div id=bk-ic-note class=mut style="font-size:12px;margin-top:4px"></div></div>
   <div id=bk-pass-wrap><label>Passphrase (12+ characters; 16+ for a cloud folder)</label><input type=password id=bk-pass></div>
   <div id=bk-folder-wrap style="grid-column:1"><label>Folder</label><div class=row><input type=text id=bk-dir placeholder="(a folder, for example on a NAS or a USB drive)" style="flex:1"><button onclick="pickInto('bk-dir','folder')">Choose…</button></div></div>
   <div id=bk-pass2-wrap style="grid-column:2"><label>Repeat the passphrase</label><input type=password id=bk-pass2></div></div>
  <label style="display:block;color:var(--fg)"><input type=checkbox id=bk-audit checked> Include the activity log</label>
  <div class=row style="margin-top:10px"><button class=p onclick="bkRun()">Create backup (Touch ID)</button><button id=bk-usepass onclick="bkTogglePass()" style="display:none"></button><span id=bk-last class=mut></span></div><div id=bk-msg style="margin-top:8px"></div>
  <div class=mut style="font-size:12px;margin-top:6px">Keep the passphrase somewhere safe. Without it the backup cannot be opened, and nobody can recover it for you.</div></div>
 <div class=card id=bk-sync><b>Sync this Mac from the newest backup</b>
  <div class=mut style="margin:4px 0 8px">Two Macs do not share a vault: a credential added on one does not appear on the other. Press <b>Check</b> to compare this Mac with the newest backup (iCloud Drive or your backup folders). It lists names only. <b>Sync</b> adds what is new; credentials whose secret differs are kept as they are unless you tick them.</div>
  <div class=g><div><label>Backup password</label><input type=password id=sy-pass></div><div style="align-self:end"><div class=row><button onclick="syCheck()">Check what is new</button><button class=p id=sy-go onclick="syGo()" style="display:none">Sync now (Touch ID)</button></div></div></div>
  <div id=sy-out style="margin-top:8px"></div><div id=sy-msg style="margin-top:8px"></div></div>
 <div class=card><b>Restore from a backup</b>
  <div class=mut style="margin:4px 0 8px">Put your credentials and settings back, on this Mac or a new one. <b>Merge</b> never overwrites anything already here; <b>Overwrite</b> lets the backup win.</div>
  <div id=rs-recent></div>
  <div class=g><div style="grid-column:1/-1"><label>Recovery file (only if it is not in the same folder as the backup)</label><div class=row><input type=text id=rs-key placeholder="(optional)" style="flex:1"><button onclick="pickInto('rs-key','file')">Choose…</button></div></div><div style="grid-column:1/-1"><label>Backup file</label><div class=row><input type=text id=rs-path placeholder="(choose a .secreds file)" style="flex:1"><button onclick="pickInto('rs-path','file')">Choose…</button></div></div>
   <div><label>Password (or passphrase)</label><input type=password id=rs-pass></div><div><label>If a credential already exists here</label><select id=rs-mode><option value=merge>Merge: keep what is here</option><option value=overwrite>Overwrite: the backup wins</option></select></div></div>
  <div class=row style="margin-top:10px"><button onclick="rsCheck()">Check contents</button><button class=p onclick="rsRun()">Restore (Touch ID)</button></div><div id=rs-msg style="margin-top:8px"></div></div>
</section>
</main></div><footer class=sig id=sig>seCreds</footer><script>
const T="__TOKEN__";const KINDS=[['api-key','API key'],['login','Login (username + password)'],['s3','S3 bucket (access key + secret key)'],['ssh-key','SSH key / passphrase'],['other','Other secret']];const WINS=[[0,'Nothing: ask every time'],[15,'15 minutes'],[30,'30 minutes'],[60,'1 hour'],[120,'2 hours'],[240,'4 hours'],[480,'8 hours'],[720,'12 hours'],[1440,'24 hours']];let S={creds:[],agents:[],audit:[]};
const $=id=>document.getElementById(id);const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let REQ=null,FORM_DIRTY=false;
function dropForm(){const f=$('form');if(f.innerHTML&&FORM_DIRTY&&!confirm('Discard your unsaved changes?'))return false;f.innerHTML='';FORM_DIRTY=false;return true}
document.addEventListener('input',e=>{if(e.target.closest&&e.target.closest('#form'))FORM_DIRTY=true});
document.addEventListener('change',e=>{if(e.target.closest&&e.target.closest('#form'))FORM_DIRTY=true});

const PAGES=['home','credentials','agents','settings','activity','backup'];
function pageName(){const h=(location.hash||'').replace(/^#\/?/,'').replace(/^notice$/,'agents');return PAGES.includes(h)?h:'home'}
function route(){const p=pageName();document.querySelectorAll('.page').forEach(e=>e.classList.toggle('on',e.id=='p-'+p));
 document.querySelectorAll('header nav a').forEach(a=>a.classList.toggle('on',a.dataset.p==p));$('layout').classList.toggle('nosb',p!='credentials');window.scrollTo(0,0)}
function go(p){if(pageName()==p)route();else location.hash='#/'+p}
function openCred(n){if(!dropForm())return;V.sel=n;V.fsel=null;go('credentials');render()}
function addNew(){if(!dropForm())return;V.sel=null;go('credentials');render();openForm();goto('form')}
function goFilter(f){if(!dropForm())return;V.flt=f;V.sel=null;V.fsel=null;V.q='';$('flt').value=f;$('q').value='';go('credentials');render()}
function goto(id){const e=$(id);if(e)e.scrollIntoView({behavior:'smooth',block:'start'})}
async function api(p,b,poll){let r;try{r=await fetch(p,{method:b?'POST':'GET',headers:Object.assign({'X-Token':T,'Content-Type':'application/json'},poll?{'X-Poll':'1'}:{}),body:b?JSON.stringify(b):undefined})}catch(e){$('err').style.color='var(--bad)';$('err').textContent='secreds has stopped (it quits after 30 idle minutes). Open it again from the seCreds icon.';throw 0}
 if(r.status===403){$('err').style.color='var(--bad)';$('err').textContent='This page is out of date (seCreds was updated or restarted). Close this tab and open seCreds again from its icon.';throw 0}
 const j=await r.json();if(!r.ok||j.error){$('err').textContent=j.error||'failed';throw 0}$('err').textContent='';return j}
async function load(poll){S=await api('/api/state',null,poll);render()}
function fmt(t){return t?new Date(t).toLocaleString():'never'}
const V={q:'',sort:'name',flt:'all',sel:null,view:'cards',fsel:null,tree:true,collapsed:new Set()},A={q:'',ev:''};
try{const sv=JSON.parse(localStorage.getItem('secreds_view')||'{}');V.sort=sv.sort||'name';V.view=sv.view||'cards';V.tree=sv.tree!==false;V.collapsed=new Set(JSON.parse(localStorage.getItem('secreds_collapsed')||'[]'))}catch(e){}   // only the sort order is remembered; filters always start at Everything
const SORT_OPTS=[['name','Name A–Z'],['name-desc','Name Z–A'],['used','Last used (newest)'],['used-asc','Least recently used'],['new','Recently added'],['old','Oldest added'],['type','Type'],['scope','Personal / Work'],['status','Status (problems first)']];
const FLT_OPTS=[['all','Everything'],['unlocked','Unlocked now'],['locked','Locked (Touch ID needed)'],['active','Active only'],['attention','Revoked or expired'],['human','Human-only'],['any','Unrestricted (any command)'],['pinned','Pinned commands'],['never','Never used'],['personal','Personal'],['work','Work']];
function initSide(){$('sort').innerHTML=SORT_OPTS.map(o=>`<option value=${o[0]}>${o[1]}</option>`).join('');$('flt').innerHTML=FLT_OPTS.map(o=>`<option value=${o[0]}>${o[1]}</option>`).join('');
 $('sort').value=V.sort;$('flt').value=V.flt;$('q').setAttribute('data-1p-ignore','');$('q').setAttribute('autocomplete','off')}
function persist(){try{localStorage.setItem('secreds_view',JSON.stringify({sort:V.sort,view:V.view,tree:V.tree}));localStorage.setItem('secreds_collapsed',JSON.stringify([...V.collapsed]))}catch(e){}}
function setV(k,v){V[k]=v;persist();render()}
function pick(n){if(!dropForm())return;V.sel=n;render();window.scrollTo({top:0,behavior:'smooth'})}
function showAll(){if(!dropForm())return;V.sel=null;V.fsel=null;render();window.scrollTo({top:0,behavior:'smooth'})}
function setTree(t){V.tree=t;persist();render()}
function setView(v){if(!dropForm())return;V.view=v;V.sel=null;setV('view',v)}
function remain(t){const mn=Math.max(1,Math.ceil((new Date(t)-Date.now())/60000));return mn>=60?`${Math.floor(mn/60)} h ${mn%60} min left`:`${mn} min left`}
const LKC=c=>`<svg class=lk viewBox="0 0 16 16" width=15 height=15 style="color:${c}" aria-hidden=true><rect x=3 y=7 width=10 height=7.5 rx=1.6 fill=currentColor /><path d="M5.2 7V5.2a2.8 2.8 0 0 1 5.6 0V7" fill=none stroke=currentColor stroke-width=1.7 stroke-linecap=round /></svg>`;
const LKO=c=>`<svg class=lk viewBox="0 0 16 16" width=15 height=15 style="color:${c}" aria-hidden=true><rect x=3 y=7.6 width=10 height=6.9 rx=1.6 fill=none stroke=currentColor stroke-width=1.6 /><path d="M5.2 7.6V5.2a2.8 2.8 0 0 1 5.5-.8" fill=none stroke=currentColor stroke-width=1.7 stroke-linecap=round /></svg>`;
function lockInfo(m){
 if(m.reference)return{state:'reference',cls:'',glyph:'<span class=lk style="color:var(--mut);font-weight:700">ⓘ</span>',text:'reference · no secret'};
 if(m.human_only)return{state:'human',cls:'',glyph:LKC('var(--acc)'),text:'human-only'};
 if(m.revoked)return{state:'revoked',cls:'bad',glyph:'⛔',text:'revoked'};
 if(m.expired)return{state:'expired',cls:'bad',glyph:'⛔',text:'expired'};
 if(m.mode=='auto')return{state:'auto',cls:'warn',glyph:LKO('#d9902f'),text:'auto: no Touch ID needed'};
 const g=Object.entries(m.grants||{}).filter(([a,t])=>new Date(t)>new Date());
 if(g.length)return{state:'open',cls:'ok',glyph:LKO('var(--ok)'),text:'unlocked · '+g.map(([a,t])=>`${a}, ${remain(t)}`).join(' · ')};
 return{state:'locked',cls:'',glyph:LKC('var(--mut)'),text:'locked · Touch ID needed'}}
function acked(m,k){return (m.acks||[]).includes(k)}
function status(m){return m.revoked?'revoked':m.expired?'expired':'active'}
function matches(m){const q=V.q.trim().toLowerCase();
 if(q&&![m.name,m.kind,m.scope,m.bucket,m.folder,m.notes,m.username,m.env_var,m.address,(m.agents||[]).join(' ')].some(x=>String(x||'').toLowerCase().includes(q)))return false;
 const ac=m.allowed_commands||[];
 switch(V.flt){case 'unlocked':return lockInfo(m).state=='open';case 'locked':return lockInfo(m).state=='locked';case 'active':return status(m)=='active';case 'attention':return status(m)!='active';case 'human':return !!m.human_only;
  case 'any':return !m.human_only&&!ac.length;case 'pinned':return ac.length>0;case 'never':return !m.last_used;case 'personal':return m.scope=='personal';case 'work':return m.scope=='work';
  default:if((S.agents||[]).includes(V.flt))return (m.agents||[]).includes(V.flt)}return true}
function ordered(l){const t=x=>x?Date.parse(x):0,n=(a,b)=>a.name.localeCompare(b.name,undefined,{sensitivity:'base',numeric:true}),rank={revoked:0,expired:1,active:2};
 const f={'name':n,'name-desc':(a,b)=>n(b,a),'used':(a,b)=>t(b.last_used)-t(a.last_used)||n(a,b),'used-asc':(a,b)=>t(a.last_used)-t(b.last_used)||n(a,b),
  'new':(a,b)=>t(b.created)-t(a.created)||n(a,b),'old':(a,b)=>t(a.created)-t(b.created)||n(a,b),'type':(a,b)=>a.kind.localeCompare(b.kind)||n(a,b),'scope':(a,b)=>(a.scope||'~').localeCompare(b.scope||'~')||n(a,b),
  'status':(a,b)=>rank[status(a)]-rank[status(b)]||n(a,b)}[V.sort]||n;return l.slice().sort(f)}
function renderFlat(list){const key=m=>V.sort=='type'?m.kind:V.sort=='scope'?(m.scope||'not set'):V.sort=='status'?status(m):null;let last,html='';
 list.forEach(m=>{const k=key(m);if(k!==null&&k!==last){html+=`<div class=grp>${esc(k)}</div>`;last=k}
  const col=m.revoked||m.expired?'var(--bad)':'var(--ok)',ac=(m.allowed_commands||[]).length;
  html+=`<div class="nav-item ${V.sel===m.name?'on':''}" onclick="pick('${esc(m.name)}')" title="${esc(m.name)}"><span class=dot style="background:${col}"></span><span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.name)}</span><span title="${esc(lockInfo(m).text)}">${lockInfo(m).glyph}</span>${m.human_only?'<span class=tag>human</span>':ac?'':`<span class="tag ${acked(m,'any_command')?'':'bad'}">any</span>`}</div>`});
 $('navlist').innerHTML=html||'<p class=mut style="margin:8px">Nothing matches.</p>';
 }
function folderSet(){const s=new Set(S.folders||[]);S.creds.forEach(m=>{if(m.folder)s.add(m.folder)});[...s].forEach(f=>{const g=f.split('/');for(let i=1;i<g.length;i++)s.add(g.slice(0,i).join('/'))});return s}
const byName=(a,b)=>a.localeCompare(b,undefined,{sensitivity:'base',numeric:true});
function credInner(m){const col=m.revoked||m.expired?'var(--bad)':'var(--ok)',ac=(m.allowed_commands||[]).length;
 return `<span class=dot style="background:${col}"></span><span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.name)}</span><span title="${esc(lockInfo(m).text)}">${lockInfo(m).glyph}</span>${m.human_only?'<span class=tag>human</span>':ac?'':`<span class="tag ${acked(m,'any_command')?'':'bad'}">any</span>`}`}
function renderTree(list){
 const filtering=!!V.q.trim()||V.flt!='all',folders=[...folderSet()].sort(byName),byF={};
 list.forEach(m=>{(byF[m.folder||'']=byF[m.folder||'']||[]).push(m)});
 const inF=(m,f)=>(m.folder||'')===f||(m.folder||'').startsWith(f+'/');
 const kids=p=>folders.filter(f=>p===''?!f.includes('/'):(f.startsWith(p+'/')&&!f.slice(p.length+1).includes('/')));
 const visible=p=>!filtering||list.some(m=>inF(m,p));
 const walk=(p,d)=>{let h='';
  kids(p).filter(visible).forEach(f=>{const open=filtering||!V.collapsed.has(f),leaf=f.split('/').pop(),n=list.filter(m=>inF(m,f)).length;
   h+=`<div class="nav-item folder ${V.fsel===f&&!V.sel?'on':''}" data-kind=folder data-v="${esc(f)}" style="padding-left:${8+d*16}px"><span class=chev data-act=toggle data-v="${esc(f)}">${open?'▾':'▸'}</span><span>📁</span><span class=fname>${esc(leaf)}</span><span class=cnt>${n}</span><span class=facts><span data-act=sub data-v="${esc(f)}" title="New folder inside">＋</span><span data-act=ren data-v="${esc(f)}" title="Rename">✎</span><span data-act=del data-v="${esc(f)}" title="Delete folder (contents move up)">🗑</span></span></div>`;
   if(open)h+=walk(f,d+1)});
  const own=(byF[p]||[]);if(p===''&&own.length&&folders.length)h+='<div class=grp>Not in a folder</div>';
  own.forEach(m=>{h+=`<div class="nav-item ${V.sel===m.name?'on':''}" data-kind=cred data-v="${esc(m.name)}" draggable=true style="padding-left:${8+d*16}px" title="${esc(m.name)}">${credInner(m)}</div>`});return h};
 $('navlist').innerHTML=walk('',0)||'<p class=mut style="margin:8px">Nothing matches.</p>'}
function renderSide(list){
 if(V.tree)renderTree(list);else renderFlat(list);
 $('tv-tree').className=V.tree?'on':'';$('tv-flat').className=V.tree?'':'on';
 $('nav_all').className='nav-item'+(V.sel||V.fsel?'':' on');$('count').textContent=`${list.length} of ${S.creds.length} shown`}
async function moveCred(n,f){await api('/api/move',{name:n,folder:f});flash(`Moved ${n} to ${f||'no folder'}.`);load()}
async function newFolder(parent){const nm=prompt(parent?`New folder inside "${parent}":`:'New folder name (use Parent/Child to nest):','');if(!nm||!nm.trim())return;await api('/api/folder-add',{path:(parent?parent+'/':'')+nm.trim()});if(parent){V.collapsed.delete(parent);persist()}load()}
async function renameFolder(f){const leaf=f.split('/').pop(),par=f.includes('/')?f.slice(0,f.lastIndexOf('/')):'';const nm=prompt('Rename folder:',leaf);if(!nm||nm.trim()==leaf)return;
 const nf=(par?par+'/':'')+nm.trim();await api('/api/folder-rename',{old:f,new:nf});if(V.fsel&&(V.fsel==f||V.fsel.startsWith(f+'/')))V.fsel=nf+V.fsel.slice(f.length);load()}
async function deleteFolder(f){if(!confirm(`Delete the folder "${f}"? Everything inside moves up one level. No credential is deleted.`))return;await api('/api/folder-delete',{path:f});if(V.fsel&&(V.fsel==f||V.fsel.startsWith(f+'/')))V.fsel=null;load()}
function folderAct(act,f){if(act=='toggle'){V.collapsed.has(f)?V.collapsed.delete(f):V.collapsed.add(f);persist();render()}else if(act=='sub')newFolder(f);else if(act=='ren')renameFolder(f);else if(act=='del')deleteFolder(f)}
function pickFolder(f){if(!dropForm())return;V.fsel=V.fsel===f?null:f;V.sel=null;render();window.scrollTo({top:0,behavior:'smooth'})}
function fulfilRequest(n){const r=(S.requests||[]).find(x=>x.name===n);if(!r)return;V.sel=null;V.fsel=null;go('credentials');render();
 openForm(Object.assign({notes:'',mode:'ask',window_minutes:30,expires:'',env_var:''},r,{allowed_commands:(r.allowed_commands||[]).map(c=>({cmd:c}))}),null,true,r);goto('form')}
async function dismissRequest(n){if(!confirm(`Dismiss the request for "${n}"?`))return;await api('/api/request-dismiss',{name:n});load()}
function renderAgentDoc(){const d=S.agent_docs||{},sel=$('ag-doc'),names=Object.keys(d);if(!names.length)return;
 if([...sel.options].map(o=>o.value).join()!=names.join()){const cur=sel.value;sel.innerHTML=names.map(n=>`<option value="${esc(n)}">${esc(n)}</option>`).join('');sel.value=names.includes(cur)?cur:names[0]}
 const x=d[sel.value];$('ag-docwhere').innerHTML=`Put this in <b>${esc(x.file)}</b> — ${esc(x.where)}`;$('ag-doctext').textContent=x.text}
function copyAgentDoc(b){navigator.clipboard.writeText($('ag-doctext').textContent).then(()=>{const t=b.textContent;b.textContent='Copied';setTimeout(()=>b.textContent=t,1500)})}
let ST=null;
function renderSettings(){const t=S.settings;if(!t)return;if(!ST||ST.stamp!==JSON.stringify(t))ST={stamp:JSON.stringify(t),agents:[...t.agents],fam:Object.assign({},t.families)};
 const known=[...new Set([...t.presets.map(p=>p.name),...ST.agents])],lab=Object.fromEntries(t.presets.map(p=>[p.name,p.label]));
 $('st-agents').innerHTML=known.map(n=>`<label style="color:var(--fg);display:flex;gap:6px;align-items:center"><input type=checkbox ${ST.agents.includes(n)?'checked':''} onchange="stTick('${esc(n)}',this.checked)">${esc(lab[n]||n)}${lab[n]?` <span class=mut>(${esc(n)})</span>`:''}</label>`).join('');
 $('st-fam').innerHTML=ST.agents.length>1?ST.agents.map(a=>`<div class=row style="margin:3px 0"><code>${esc(a)}</code><span class=mut>counts as</span><select onchange="stFam('${esc(a)}',this.value)"><option value="">its own agent</option>${ST.agents.filter(x=>x!=a&&!ST.fam[x]).map(x=>`<option value="${esc(x)}" ${ST.fam[a]==x?'selected':''}>${esc(x)}</option>`).join('')}</select></div>`).join(''):'<span class=mut>Add a second agent to group profiles.</span>';
 if(document.activeElement!==$('st-owner'))$('st-owner').value=t.owner;if(document.activeElement!==$('st-repo')){$('st-repo').value=t.update_repo;$('st-repo').placeholder=t.default_update_repo||''}
 if(document.activeElement!==$('st-fb')){$('st-fb').value=t.feedback_url;$('st-fb').placeholder=t.default_feedback_url||''}
 $('st-keep').checked=!!t.keep_scripts;
 $('st-daily').textContent=(S.update||{}).daily?'Turn off the daily check':'Check daily'}
function stTick(n,on){ST.agents=on?[...ST.agents,n]:ST.agents.filter(x=>x!=n);if(!on){delete ST.fam[n];for(const k in ST.fam)if(ST.fam[k]==n)delete ST.fam[k]}renderSettings()}
function stAdd(){const v=$('st-custom').value.trim().toLowerCase();if(!v)return;if(!/^[a-z0-9][a-z0-9._-]{0,62}$/.test(v)){msg('st-amsg','Use letters, digits, . _ - only.',1);return}if(!ST.agents.includes(v))ST.agents.push(v);$('st-custom').value='';renderSettings()}
function stFam(a,h){if(h)ST.fam[a]=h;else delete ST.fam[a];renderSettings()}
async function stSaveAgents(){try{await api('/api/settings-save',{agents:ST.agents,families:ST.fam});ST=null;await load();msg('st-amsg','Saved.')}catch(e){msg('st-amsg',e.message,1)}}
async function stKeep(on){try{await api('/api/settings-save',{keep_scripts:on});await load();msg('st-kmsg','Saved.')}catch(e){await load();msg('st-kmsg',e.message,1)}}
async function stSaveMisc(){try{await api('/api/settings-save',{owner:$('st-owner').value,update_repo:$('st-repo').value,feedback_url:$('st-fb').value});await load();msg('st-omsg','Saved.');msg('st-umsg','Saved.')}catch(e){msg('st-omsg',e.message,1);msg('st-umsg',e.message,1)}}
async function runDoctor(){const r=await api('/api/doctor',{});$('st-doc').innerHTML=r.checks.map(k=>`<div class=row style="margin:4px 0"><span>${{ok:'✅',warn:'⚠️',bad:'⛔'}[k.status]}</span><b>${esc(k.label)}</b><span class=mut>${esc(k.detail)}</span>${k.fix?`<span class=mut style="font-size:12px">→ ${esc(k.fix)}</span>`:''}</div>`).join('')}
function msg(id,text,bad){const e=$(id);e.style.color=bad?'var(--bad)':'var(--ok)';e.textContent=text}
async function bkSetup(){const p=$('ks-pass').value;if(p!==$('ks-pass2').value){msg('ks-msg','The two passwords differ',1);return}
 let r;try{r=await api('/api/backup-key-setup',{password:p,icloud:$('ks-ic').checked,dest:$('ks-dir').value,ack_manager:$('ks-a1').checked,ack_offline:$('ks-a2').checked,replace:REPL})}catch(e){msg('ks-msg','Not set up: '+($('err').textContent||'see the message at the top'),1);return}
 REPL=false;$('ks-pass').value=$('ks-pass2').value='';msg('ks-msg',`Backup key ${r.key_id} created. Recovery file saved and checked against your password in ${r.files.length} place${r.files.length==1?'':'s'}.`);load()}
let PLINIT=false,PLFILLED=false;
function plInit(){if(PLINIT)return;PLINIT=true;$('pl-keep').innerHTML=[[0,'Keep all of them'],[2,'2'],[3,'3'],[5,'5'],[7,'7'],[10,'10'],[14,'14'],[20,'20'],[30,'30'],[60,'60'],[90,'90'],[180,'180']].map(a=>`<option value=${a[0]}>${a[1]}</option>`).join('');
 $('pl-wd').innerHTML=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'].map((d,i)=>`<option value=${i}>${d}</option>`).join('');
 $('pl-hr').innerHTML=Array.from({length:24},(_,h)=>`<option value=${h}>${String(h).padStart(2,'0')}:00</option>`).join('')}
function plSch(){const v=$('pl-sch').value;$('pl-wd').style.display=v=='weekly'?'':'none';$('pl-hr').style.display=v=='off'?'none':''}
function plOpts(second){const B=S.backup||{};let h=second?'<option value="none">None</option>':'';h+=(B.cloud_drives||[]).map((c,i)=>`<option value="cloud:${i}">${esc(c.name)}</option>`).join('');
 h+='<option value="folder">A folder I choose…</option>';if(second)h+='<option value="s3">An S3 bucket</option>';return h}
function plLoc(){for(const n of [1,2]){const v=$('pl-l'+n).value;$('pl-f'+n).style.display=v=='folder'?'':'none'}$('pl-s3row').style.display=$('pl-l2').value=='s3'?'':'none'}
function plSetLoc(n,d){const B=S.backup||{},cd=B.cloud_drives||[];if(!d){$('pl-l'+n).value=n==2?'none':(cd[0]?'cloud:0':'folder');return}
 if(d.type=='icloud'){const i=cd.findIndex(c=>c.kind=='icloud');$('pl-l'+n).value=i>=0?'cloud:'+i:'folder';return}
 if(d.type=='s3'){$('pl-l2').value='s3';$('pl-s3').value=d.credential;$('pl-s3p').value=d.prefix;return}
 const i=cd.findIndex(c=>c.path==d.path);if(i>=0)$('pl-l'+n).value='cloud:'+i;else{$('pl-l'+n).value='folder';$('pl-d'+n).value=d.path}}
function plFill(){const B=S.backup||{},P=B.plan||{};plInit();const d=P.destinations||[];
 $('pl-l1').innerHTML=plOpts(false);$('pl-l2').innerHTML=plOpts(true);
 $('pl-s3').innerHTML=(B.s3_creds||[]).length?(B.s3_creds||[]).map(x=>`<option value="${esc(x.name)}">${esc(x.name)} (${esc(x.bucket)})</option>`).join(''):'<option value="">(add an S3 bucket credential first)</option>';
 plSetLoc(1,d[0]);plSetLoc(2,d[1]);
 $('pl-keep').value=P.keep;$('pl-sch').value=B.schedule_on?P.schedule:'off';$('pl-wd').value=P.weekday;$('pl-hr').value=P.hour;$('pl-audit').checked=!!P.include_audit;plSch();plLoc()}
function plStatus(){const B=S.backup||{},L=B.last_plan_run;$('pl-status').innerHTML=!L?'No plan run yet.':(L.ok?'<span class=ok>Last run '+fmt(L.at)+': all places ok.</span>':'<span class=bad>Last run '+fmt(L.at)+': something failed.</span>')+'<ul style="margin:4px 0 0 18px">'+L.results.map(x=>`<li class="${x.ok?'':'bad'}">${esc(x.dest)}: ${esc(x.note)}</li>`).join('')+'</ul>'}
function plOne(n){const B=S.backup||{},v=$('pl-l'+n).value;if(v=='none')return null;
 if(v.startsWith('cloud:')){const c=(B.cloud_drives||[])[+v.slice(6)];return c.kind=='icloud'?{type:'icloud'}:{type:'folder',path:c.path}}
 if(v=='s3')return {type:'s3',credential:$('pl-s3').value,prefix:$('pl-s3p').value};
 const p=$('pl-d'+n).value.trim();return p?{type:'folder',path:p}:null}
function plRead(){const d=[plOne(1),plOne(2)].filter(Boolean);
 return {destinations:d,keep:+$('pl-keep').value,schedule:$('pl-sch').value,hour:+$('pl-hr').value,weekday:+$('pl-wd').value,include_audit:$('pl-audit').checked}}
async function plSave(){try{await api('/api/backup-plan-save',{plan:plRead()});msg('pl-msg','Plan saved.'+($('pl-sch').value!='off'?' The schedule is on.':' No schedule.'));PLINIT=true;await load();plFill()}catch(e){msg('pl-msg','Not saved: '+($('err').textContent||'see the message at the top'),1);$('err').scrollIntoView({block:'nearest'})}}
async function plRun(){try{msg('pl-msg','Backing up…');const r=await api('/api/backup-plan-run',{});msg('pl-msg',(r.ok?'Done: ':'Finished with problems: ')+r.results.map(x=>x.dest+(x.ok?' ok':' FAILED ('+x.note+')')).join('; ')+'. File: '+r.file,!r.ok);load()}catch(e){msg('pl-msg','Backup did not run: '+($('err').textContent||'see the message at the top'),1)}}
let REPL=false,SYNC=null;
async function syCheck(){try{msg('sy-msg','Checking…');const r=await api('/api/sync-preview',{password:$('sy-pass').value});SYNC=r;msg('sy-msg','');
 $('sy-out').innerHTML=`<div class=mut>Newest backup: <code>${esc(r.file.split('/').pop())}</code></div><div style="margin-top:6px"><b>New here (${r.new.length}):</b> ${r.new.map(esc).join(', ')||'nothing'}</div><div style="margin-top:6px"><b>Different from here (${r.different.length}):</b> ${r.different.length?r.different.map(n=>`<label style="display:inline-block;margin-right:12px;color:var(--fg)"><input type=checkbox class=sy-take value="${esc(n)}"> ${esc(n)}</label>`).join(''):'nothing'}${r.different.length?'<div class=mut style="font-size:12px">Ticked ones take the backup\'s secret and replace the one on this Mac.</div>':''}</div><div class=mut style="margin-top:6px">Identical: ${r.same.length}</div>`;
 $('sy-go').style.display=(r.new.length||r.different.length)?'':'none'}catch(e){msg('sy-msg','Could not check: '+($('err').textContent||'see the message at the top'),1)}}
async function syGo(){const take=[...document.querySelectorAll('.sy-take:checked')].map(x=>x.value);try{const r=await api('/api/sync-apply',{password:$('sy-pass').value,path:SYNC&&SYNC.file,take});$('sy-pass').value='';$('sy-out').innerHTML='';$('sy-go').style.display='none';msg('sy-msg',`Synced: ${r.restored} credential${r.restored==1?'':'s'} added or updated.`);load()}catch(e){msg('sy-msg','Not synced: '+($('err').textContent||'see the message at the top'),1)}}
function plName(f){const d=f.replace(/\/[^\/]*$/,''),cd=((S.backup||{}).cloud_drives||[]).find(c=>c.path==d);return cd?cd.name+' › seCreds Backups':d.replace(/^\/Users\/[^\/]+/,'~')}
function kcFill(){const have=new Set((((S.backup||{}).key||{}).recovery_files||[]).map(f=>f.replace(/\/[^\/]*$/,'')));const cd=(S.backup||{}).cloud_drives||[];
 $('kc-loc').innerHTML=cd.map((c,i)=>have.has(c.path)?'':`<option value="cloud:${i}">${esc(c.name)}</option>`).join('')+'<option value="folder">A folder I choose…</option>';kcLoc()}
function kcLoc(){$('kc-f').style.display=$('kc-loc').value=='folder'?'':'none'}
async function kcCopy(){const B=S.backup||{},v=$('kc-loc').value;let body;if(v.startsWith('cloud:')){const c=(B.cloud_drives||[])[+v.slice(6)];body=c.kind=='icloud'?{icloud:true}:{dest:c.path}}else body={dest:$('kc-dir').value.trim()};
 try{const r=await api('/api/backup-key-copy',body);msg('kc-msg','Saved. The recovery file is now in '+r.places+' places.');await load();kcFill()}catch(e){msg('kc-msg','Not saved: '+($('err').textContent||'see the message at the top'),1)}}
function kcReplace(){if(!confirm('Replace the backup password and key? Older backups will still need the OLD password and OLD recovery file. Continue?'))return;REPL=true;renderBackup();$('bk-setup').scrollIntoView({behavior:'smooth'})}
let BKPASS=false;function bkTogglePass(){BKPASS=!BKPASS;renderBackup()}
function bkSrc(){$('bk-folder-wrap').style.display=$('bk-src').value=='folder'?'':'none'}
async function pickInto(id,kind){const r=await api('/api/pick',{kind});if(r.path)$(id).value=r.path}
function renderBackup(){const B=S.backup||{},U=S.update||{};
 if(!B.icloud){$('bk-ic').disabled=true;if($('bk-src').value=='icloud')$('bk-src').value='folder'}else $('bk-ic').disabled=false;
 $('bk-ic-note').textContent=B.icloud?'Goes to iCloud Drive, in a folder called seCreds Backups. iCloud may take a minute to upload it.':'iCloud Drive is not available on this Mac.';bkSrc();
 const K=B.key||{};$('bk-setup').style.display=(!K.configured||REPL)?'':'none';$('bk-keycard').style.display=K.configured?'':'none';$('ks-title').textContent=REPL?'Replace the backup password':'Set up your backup password (once)';$('ks-warn').style.display=REPL?'':'none';
 if(K.configured){const n=(K.recovery_files||[]).length;$('kc-info').innerHTML=`<span class=ok>The backup password is set.</span> Key <code>${esc(K.key_id)}</code>, created ${fmt(K.created)}. The Mac does not know the password: only you do. Recovery file in <b>${n}</b> place${n==1?'':'s'}:<ul style="margin:4px 0 0 18px">${(K.recovery_files||[]).map(f=>'<li title="'+esc(f)+'">'+esc(plName(f))+'</li>').join('')}</ul>${n<2?'<span class=bad>Save a copy in a second place.</span>':''}`}
 $('bk-keyinfo').innerHTML=K.configured?`Using your <b>backup key</b> (${esc(K.key_id)}): no password to type here. Recovery file in <b>${(K.recovery_files||[]).length}</b> place${(K.recovery_files||[]).length==1?'':'s'}${(K.recovery_files||[]).length<2?' <span class=bad>(save a copy in a second place)</span>':''}.${B.last_backup&&!B.last_restore_check?' <span class=bad>You have not tested a restore yet: choose a backup below, enter your password and press Check contents.</span>':''}`:'';
 $('bk-plan').style.display=K.configured?'':'none';if(K.configured&&!PLFILLED){PLFILLED=true;plFill();kcFill()}plStatus();$('bk-pass-wrap').style.display=$('bk-pass2-wrap').style.display=(!K.configured||BKPASS)?'':'none';$('bk-usepass').style.display=K.configured?'':'none';$('bk-usepass').textContent=BKPASS?'Use the backup key instead':'Use a one-off passphrase instead';$('bk-title').textContent=K.configured?'One-off backup':'Back up everything';
 $('bk-last').textContent=B.last_backup?`Last backup: ${fmt(B.last_backup)} · ${B.last_backup_count} credential${B.last_backup_count==1?'':'s'} · ${B.last_backup_file||''}`:'No backup has been made yet.';
 $('rs-recent').innerHTML=(B.icloud_files||[]).length?`<div class=mut style="margin-bottom:4px">Backups in iCloud Drive (click one to use it):</div>`+B.icloud_files.map(f=>`<div class="nav-item" onclick="$('rs-path').value=this.dataset.p" data-p="${esc(f.path)}"><span style="flex:1">${esc(f.name)}</span><span class=mut>${fmt(f.modified)}</span></div>`).join(''):'';
 $('ubadge').style.display=U.available?'':'none';
 $('st-upinfo').innerHTML=`seCreds <b>${esc(U.current||'')}</b> · checks <code>${esc(U.repo||'(turned off)')}</code> · last checked ${U.last_checked?fmt(new Date(U.last_checked*1000).toISOString()):'never'}<br>`+
  (U.error?`<span class=bad>Could not check: ${esc(U.error)}</span>`:U.available?`<b class=ok>Update available: ${esc(U.latest_version)}</b><pre style="white-space:pre-wrap;font:12px ui-monospace,monospace;margin:6px 0">${esc((U.notes||'').slice(0,1200)||'(no release notes)')}</pre>`:(U.latest_tag?'You are up to date.':'No releases found. If the repository is private, sign in with `gh auth login`.'))+
  (U.previous_version?`<div class=mut style="font-size:12px">Previous version: ${esc(U.previous_version)}</div>`:'');
 $('st-apply').style.display=U.available?'':'none';$('st-daily').textContent=U.daily?'Turn off the daily check':'Check once a day';}
async function bkRun(){const K=(S.backup||{}).key||{},usePass=!K.configured||BKPASS,p1=usePass?$('bk-pass').value:'';if(usePass&&p1!==$('bk-pass2').value){msg('bk-msg','The two passphrases differ',1);return}
 let r;try{r=await api('/api/backup',{icloud:$('bk-src').value=='icloud',dest:$('bk-dir').value,passphrase:p1,include_audit:$('bk-audit').checked})}catch(e){msg('bk-msg','Backup did not run: '+($('err').textContent||'see the message at the top'),1);return}
 $('bk-pass').value=$('bk-pass2').value='';if(r.method=='key')$('rs-path').value=r.path;msg('bk-msg',`Backed up ${r.count} credential${r.count==1?'':'s'} and your settings`+(r.method=='key'?' with the backup key. Now test it: scroll to Restore (the file is filled in), enter your backup password and press Check contents. ':', verified by reading the file back. ')+`${r.path}${r.missing&&r.missing.length?' Not backed up (no secret in the Keychain): '+r.missing.join(', '):''}`);load()}
async function rsCheck(){const r=await api('/api/restore-backup',{path:$('rs-path').value,passphrase:$('rs-pass').value,key_file:$('rs-key').value,mode:$('rs-mode').value,dry_run:true});
 msg('rs-msg',`This would create ${r.create.length}, overwrite ${r.overwrite.length} and keep ${r.skip_existing.length} existing credential(s).`+(r.create.length?' New: '+r.create.join(', ')+'.':'')+(r.overwrite.length?' Overwritten: '+r.overwrite.join(', ')+'.':''))}
async function rsRun(){if(!confirm('Restore from this backup now? ('+($('rs-mode').value=='overwrite'?'credentials that exist here will be overwritten by the backup':'nothing that exists here will be overwritten')+')'))return;
 const r=await api('/api/restore-backup',{path:$('rs-path').value,passphrase:$('rs-pass').value,key_file:$('rs-key').value,mode:$('rs-mode').value});$('rs-pass').value='';
 msg('rs-msg',`Restored ${r.restored} credential${r.restored==1?'':'s'} and the settings that were missing here.`);load()}
function umsg(t,bad){msg('st-umsg',t,bad)}
async function upCheck(){umsg('Checking GitHub…');try{await api('/api/update-check',{});await load();const U=S.update||{};umsg(U.error?'Could not check: '+U.error:U.available?'Update available: '+U.latest_version:(U.latest_tag?'You are up to date.':'No releases found. If the repository is private, sign in with `gh auth login`.'),!!U.error)}catch(e){umsg(e.message,1)}}
async function upApply(){const U=S.update||{};
 const r=await api('/api/update-apply',{});umsg(`Updated ${r.from} → ${r.to}. Quit and reopen seCreds from its icon to use the new version.`);load()}
async function upDaily(){await api('/api/update-daily',{on:!(S.update||{}).daily});await load();umsg((S.update||{}).daily?'The daily check is on (9:15 am). It only looks.':'The daily check is off.')}
function addInFolder(){if(!dropForm())return;V.sel=null;go('credentials');render();openForm({name:'',kind:'api-key',notes:'',agents:['claude'],mode:'ask',window_minutes:30,expires:'',env_var:'',folder:V.fsel||''},null,true);goto('form')}
function famOf(a){const f=Object.entries(S.families||{}).filter(([k,v])=>v==a).map(([k])=>k);return f.length?' (also covers '+f.join(', ')+')':''}
function folderOptions(sel){return '<option value="">(no folder)</option>'+[...folderSet()].sort(byName).map(f=>`<option value="${esc(f)}" ${f==sel?'selected':''}>${'\u2003'.repeat(f.split('/').length-1)}📁 ${esc(f.split('/').pop())}</option>`).join('')}
(function(){const nl=$('navlist'),sd=$('side');let dragName=null;
 nl.addEventListener('click',e=>{const a=e.target.closest('[data-act]');if(a){e.stopPropagation();folderAct(a.dataset.act,a.dataset.v);return}
  const it=e.target.closest('[data-kind]');if(!it)return;if(it.dataset.kind=='cred')pick(it.dataset.v);else pickFolder(it.dataset.v)});
 sd.addEventListener('dragstart',e=>{const it=e.target.closest('[data-kind=cred]');if(it){dragName=it.dataset.v;e.dataTransfer.setData('text/plain',dragName);e.dataTransfer.effectAllowed='move'}});
 sd.addEventListener('dragover',e=>{const t=e.target.closest('[data-kind=folder],#nav_all');if(t&&dragName){e.preventDefault();document.querySelectorAll('.drop').forEach(x=>x.classList.remove('drop'));t.classList.add('drop')}});
 sd.addEventListener('drop',e=>{const t=e.target.closest('[data-kind=folder],#nav_all');if(!t||!dragName)return;e.preventDefault();t.classList.remove('drop');const f=t.id=='nav_all'?'':t.dataset.v,n=dragName;dragName=null;moveCred(n,f)});
 sd.addEventListener('dragend',()=>{dragName=null;document.querySelectorAll('.drop').forEach(x=>x.classList.remove('drop'))})})();
function refreshAgentFilters(){const sel=$('flt'),all=FLT_OPTS.concat((S.agents||[]).map(a=>[a,'Usable by '+a])),have=[...sel.options].map(o=>o.value).join();
 if(have!=all.map(o=>o[0]).join()){const cur=sel.value;sel.innerHTML=all.map(o=>`<option value="${esc(o[0])}">${esc(o[1])}</option>`).join('');sel.value=cur||'all'}}
function renderSig(){const a=S.about;if(!a)return;$('sig').innerHTML=`<b>${esc(a.product)}</b> v${esc(a.version)} · by ${esc(a.maker)} · <a href="${esc(a.feedback_url)}" target=_blank rel=noopener>Send feedback</a> · <a href="${esc(a.homepage)}" target=_blank rel=noopener>GitHub</a>`}
function render(){refreshAgentFilters();renderSig();
 $('notice').textContent=S.notice;$('noticetag').textContent=S.notice_custom?'customized':'default';$('nreset').style.display=S.notice_custom?'':'none';
 const card=m=>{const st=m.revoked?'<span class="tag bad">revoked</span>':m.expired?'<span class="tag bad">expired</span>':'<span class="tag ok">active</span>';
  const g=Object.entries(m.grants).map(([a,t])=>`${a} until ${new Date(t).toLocaleTimeString()}`).join(', ');
  return `<div class=card><div class=row><b>${esc(m.name)}</b>${st}<span class="tag ${lockInfo(m).cls}" title="Who can use it right now">${lockInfo(m).glyph} ${esc(lockInfo(m).text)}</span>${m.reference?'':`<span class=tag>${m.mode==='ask'?'Touch ID':'auto'}</span>`}<span class=tag>${esc(m.kind)}</span>${m.folder?`<span class=tag>📁 ${esc(m.folder)}</span>`:''}${m.scope?`<span class=tag>${m.scope=='work'?'💼 work':'🏠 personal'}</span>`:''}${m.human_only?'<span class="tag ok">human-only</span>':((m.allowed_commands||[]).length?`<span class="tag ok">${m.allowed_commands.length} pinned command${m.allowed_commands.length>1?'s':''}</span>`:`${acked(m,'any_command')?`<span class=tag title="You marked this as intended">any command · acknowledged</span><button class=mini onclick="ack('${esc(m.name)}','any_command',false)">Undo</button>`:`<span class="tag bad">any command</span><button class=mini onclick="ack('${esc(m.name)}','any_command',true)" title="This is intended: stop flagging it">Acknowledge</button>`}`)}</div><div class=row style="margin-top:8px">
  <button onclick="edit('${esc(m.name)}')">Edit</button><button onclick="dup('${esc(m.name)}')" title="New credential with the same settings">Duplicate</button>
  ${m.revoked?`<button onclick="post('/api/restore','${esc(m.name)}')">Restore</button>`:`<button class=d onclick="post('/api/revoke','${esc(m.name)}')">Revoke</button>`}
  <button class=d onclick="del('${esc(m.name)}')">Delete</button></div>
  <div class=mut>${m.address?`<b>${m.kind=='s3'?'Endpoint':'Address'}:</b> ${esc(m.address)}${m.network?' ('+({lan:'local network',remote:'remote',vpn:'through VPN'}[m.network]||'')+')':''} · `:''}Agents: ${m.agents.join(', ')||'none'} · ${m.reference?`user ${esc(m.username||'(none)')}`:m.kind=='login'?`user ${esc(m.username||'(none)')} · env ${esc(m.env_var)}_USERNAME / _PASSWORD`:m.kind=='s3'?`bucket <b>${esc(m.bucket||'(none)')}</b>${m.username?' · user '+esc(m.username):''} · key ID ····${esc((m.access_key_id||'').slice(-4))} · env ${esc(m.env_var)}_ACCESS_KEY_ID / _SECRET_ACCESS_KEY (+ AWS_* when used alone)`:`env var ${esc(m.env_var)}${m.username?' + '+esc(m.env_var)+'_ID (app ID '+esc(m.username)+')':''}`} · last used ${fmt(m.last_used)} · expires ${m.expires?fmt(m.expires):'never'}${m.in_keychain?'':' · <span class=bad>value missing on this Mac</span>'}</div>
  ${m.reference?'<div class=row style="margin-top:6px"><span class=mut>Reference entry: no secret is stored. Agents can read the notes with <code>secreds info</code>.</span></div>':`<div class=row style="margin-top:6px"><span class=mut>Value:</span><code id="v_${esc(m.name)}" style="font:13px ui-monospace,monospace">${esc(m.masked||'(missing on this Mac)')}</code>
   <button onclick="reveal('${esc(m.name)}')">Reveal (Touch ID)</button><button onclick="copyVal('${esc(m.name)}')">Copy (Touch ID)</button></div>`}
  ${m.notes?`<div class=mut>${esc(m.notes)}</div>`:''}
  <div class=row style="margin-top:8px">${m.reference?'<span class=mut>Nothing to approve: there is no secret to release.</span>':m.human_only?'<span class=mut>No agent can use this credential.</span>':S.agents.map(a=>`<button onclick="grant('${esc(m.name)}','${a}')">Approve ${a} for…</button>`).join('')}${(m.allowed_commands||[]).length?`<button onclick="post('/api/repin','${esc(m.name)}')">Re-pin scripts (Touch ID)</button>`:''}
  ${g?`<span class=mut>Approved: ${esc(g)}</span><button onclick="endGrants('${esc(m.name)}')">Lock now</button>`:''}</div></div>`};
 const list=ordered(S.creds.filter(matches));if(V.sel&&!S.creds.some(c=>c.name===V.sel))V.sel=null;
 const inF2=(m,f)=>(m.folder||'')===f||(m.folder||'').startsWith(f+'/'),base=V.fsel?list.filter(m=>inF2(m,V.fsel)):list;
 const shown=V.sel?S.creds.filter(c=>c.name===V.sel):base;
 const stName={reference:'reference',open:'unlocked',locked:'locked',auto:'auto',human:'human-only',revoked:'revoked',expired:'expired'};
 const table=l=>`<div class=card style="padding:0;overflow:auto"><table><tr><th>Name<th>Type<th>Lock<th>Address<th>Agents<th>Commands<th>Last used</tr>${l.map(m=>{const i=lockInfo(m),ac=(m.allowed_commands||[]).length;
  return `<tr class=click onclick="pick('${esc(m.name)}')"><td><b>${esc(m.name)}</b><td>${esc(m.kind)}<td class="${i.cls}">${i.glyph} ${stName[i.state]}<td>${esc(m.address||'')}<td>${esc((m.agents||[]).join(', ')||'none')}<td>${m.human_only?'human-only':ac?ac+' pinned':`<span class="${acked(m,'any_command')?'':'bad'}">any${acked(m,'any_command')?' (ack)':''}</span>`}<td>${m.last_used?fmt(m.last_used):'never'}</tr>`}).join('')}</table></div>`;
 $('vw-cards').className=V.view=='cards'?'on':'';$('vw-list').className=V.view=='list'?'on':'';
 const fhead=V.fsel&&!V.sel?`<div class=row style="margin:8px 0 4px"><b>📁 ${esc(V.fsel.split('/').join(' / '))}</b><span class=mut>${base.length} credential${base.length==1?'':'s'} (including subfolders)</span><span class=sp></span><button class=mini onclick="addInFolder()">+ Credential here</button><button class=mini onclick="newFolder(V.fsel)">+ Subfolder</button><button class=mini onclick="renameFolder(V.fsel)">Rename</button><button class="mini d" onclick="deleteFolder(V.fsel)">Delete folder</button></div>`:'';
 $('list').innerHTML=(V.sel?'<div class=mut style="margin:8px 0 4px"><a href="#" onclick="pick(null);return false" style="color:var(--acc)">← Back</a></div>':fhead||`<div class=mut style="margin:8px 0 4px">${list.length} of ${S.creds.length} credential${S.creds.length==1?'':'s'}</div>`)
  +(V.sel?shown.map(card).join(''):!base.length?`<p class=mut>${S.creds.length?(V.fsel?'This folder is empty. Drag credentials onto it in the sidebar, or use + Credential here.':'No credentials match your search or filter.'):'No credentials yet.'}</p>`:V.view=='list'?table(base):'<div class=cgrid>'+base.map(card).join('')+'</div>');
 renderSide(list);renderHome();renderActivity();renderBackup();renderSettings();renderAgentDoc()}
function renderHome(){
 const cs=S.creds,L=cs.map(lockInfo),open=cs.filter((m,i)=>L[i].state=='open'),locked=cs.filter((m,i)=>L[i].state=='locked');
 const link=n=>`<a href="#" onclick="openCred('${esc(n)}');return false" style="color:var(--acc)">${esc(n)}</a>`,names=f=>cs.filter(f).map(m=>link(m.name)).join(', ');
 const noCmd=m=>!m.human_only&&!m.revoked&&!m.expired&&!(m.allowed_commands||[]).length;
 const att=[];
 const rv=cs.filter(m=>m.revoked||m.expired);if(rv.length)att.push(['bad','⛔',`${rv.length} revoked or expired: ${names(m=>m.revoked||m.expired)}`]);
 const mi=cs.filter(m=>!m.in_keychain);if(mi.length)att.push(['bad','⚠️',`Value missing on this Mac: ${names(m=>!m.in_keychain)}`]);
 const au=cs.filter(m=>m.mode=='auto'&&!m.human_only&&!m.revoked&&!acked(m,'auto')),an=cs.filter(m=>noCmd(m)&&!acked(m,'any_command'));
 const ackRow=(m,k,glyph,text)=>att.push(['warn',glyph,`${link(m.name)} ${text} <button class=mini onclick="ack('${esc(m.name)}','${k}',true)" title="This is intended: stop flagging it">Acknowledge</button>`]);
 au.forEach(m=>ackRow(m,'auto',LKO('#d9902f'),'needs no Touch ID (auto approval)'));an.forEach(m=>ackRow(m,'any_command','⚠️','can run any command'));
 const ex=cs.filter(m=>m.expires&&!m.expired&&Date.parse(m.expires)-Date.now()<14*864e5);if(ex.length)att.push(['warn','⏳',`Expiring within 14 days: ${names(m=>m.expires&&!m.expired&&Date.parse(m.expires)-Date.now()<14*864e5)}`]);
 const ackd=cs.flatMap(m=>[['any_command',noCmd(m)],['auto',m.mode=='auto'&&!m.human_only&&!m.revoked]].filter(([k,on])=>on&&acked(m,k)).map(([k])=>[m,k]));
 const rq=S.requests||[];$('hbadge').style.display=rq.length?'':'none';$('hbadge').textContent=rq.length;
 const reqCard=rq.length?`<div class=card style="border-color:var(--acc)"><b>Waiting for your secret (${rq.length})</b><div class=mut style="margin:4px 0 8px">An agent proposed these. Nothing is saved until you add the secret yourself, so review every field first.</div>${rq.map(r=>`<div class=row style="margin:6px 0"><b>${esc(r.name)}</b><span class=tag>${esc(r.kind)}</span><span class=mut>requested by ${esc(r.requested_by)} · ${fmt(r.requested_at)}${r.folder?' · 📁 '+esc(r.folder):''}</span><span class=sp></span><button class=p onclick="fulfilRequest('${esc(r.name)}')">Add the secret…</button><button onclick="dismissRequest('${esc(r.name)}')">Dismiss</button></div>${r.notes?`<div class=mut style="margin:0 0 6px 4px">${esc(r.notes)}</div>`:''}`).join('')}</div>`:'';
 const bk=S.backup||{};
 if(!bk.last_backup)att.push(['warn','💾','No backup yet. <a href="#/backup" style="color:var(--acc)">Make one</a>: a copy of everything, encrypted, in iCloud Drive or a folder you choose.']);
 else{const days=Math.floor((Date.now()-Date.parse(bk.last_backup))/864e5);if(days>=30)att.push(['warn','💾',`The last backup was ${days} days ago. <a href="#/backup" style="color:var(--acc)">Make a new one</a>.`])}
 const up=S.update||{},updCard=up.available?`<div class=card style="border-color:var(--acc)"><div class=row><b>Update available</b><span class=mut>seCreds ${esc(up.latest_version)} (you have ${esc(up.current)})</span><span class=sp></span><a href="#/backup" style="color:var(--acc)">Review and update →</a></div></div>`:'';
 const tile=(label,n,cls,f)=>`<div class=tile onclick="${f?`goFilter('${f}')`:`go('credentials')`}"><span>${label}</span><b class="${cls||''}">${n}</b></div>`;
 const unl=open.map(m=>Object.entries(m.grants||{}).filter(([a,t])=>new Date(t)>new Date()).map(([a,t])=>`<div class=row style="margin:6px 0">${LKO('var(--ok)')} ${link(m.name)}<span class=mut>${esc(a)} · ${remain(t)}</span><span class=sp></span><button onclick="endGrants('${esc(m.name)}')">Lock now</button></div>`).join('')).join('');
 const runsUsed=new Set(S.audit.filter(e=>e.event=='used'&&e.run).map(e=>e.run)),runsNoted=new Set(S.audit.filter(e=>e.event=='note'&&e.run).map(e=>e.run));
 const noNote=[...runsUsed].filter(r=>!runsNoted.has(r)).length,noteLine=runsUsed.size?`<div class=mut style="font-size:12px;margin-top:6px">${noNote?`${noNote} of the last ${runsUsed.size} agent runs have no outcome note.`:`Every one of the last ${runsUsed.size} agent runs has an outcome note.`} <a href="#/activity" style="color:var(--acc)">Review</a></div>`:'';
 const recent=S.audit.filter(e=>!((e.event=='finished'||e.event=='note')&&e.run&&runsUsed.has(e.run))).slice(0,6).map(e=>`<tr><td>${fmt(e.t)}<td class="${e.event=='denied'?'bad':''}">${esc(e.event)}<td>${esc(e.name)}<td>${esc(e.agent)}</tr>`).join('');
 $('p-home').innerHTML=`<h2 style="margin-top:0">Home</h2><div class=mut>Credentials for your AI agents. Values live in this Mac's Keychain and are never shown here.</div>
 <div class=tiles>${tile('Credentials',cs.length,'')}${tile('Unlocked now',open.length,open.length?'ok':'','unlocked')}${tile('Locked',locked.length,'','locked')}${tile('Needs attention',att.length,att.some(a=>a[0]=='bad')?'bad':att.length?'warn':'ok')}</div>
 ${updCard}${reqCard}
 ${cs.length?'':'<div class=card><b>No credentials yet.</b><div class=mut style="margin:6px 0">Add your first one to get started.</div><button class=p onclick="addNew()">+ Add credential</button></div>'}
 <div class=two><div class=card><b>Unlocked now</b>${unl||'<div class=mut style="margin:8px 0">Nothing is unlocked. Every credential needs Touch ID.</div>'}
   ${open.length?'<div style="margin-top:8px"><button onclick="endGrants(\'\')">Lock everything now</button></div>':''}</div>
  <div class=card><b>Needs attention</b>${att.length?att.map(a=>`<div class=att><span class="${a[0]}">${a[1]}</span> ${a[2]}</div>`).join(''):'<div class=mut style="margin:8px 0">✅ Nothing needs attention.</div>'}${ackd.length?`<details style="margin-top:10px"><summary class=mut style="font-size:12px;cursor:pointer">Acknowledged as intended (${ackd.length})</summary><table style="margin-top:6px"><tr><th>Credential<th>Acknowledged as<th></tr>${ackd.map(([m,k])=>`<tr><td>${link(m.name)}<td>${k=='auto'?'No Touch ID (auto approval)':'Any command'}<td style="text-align:right"><button class=mini onclick="ack('${esc(m.name)}','${k}',false)">Undo</button></tr>`).join('')}</table></details>`:''}</div></div>
 <div class=card><div class=row><b>Recent activity</b><span class=sp></span><a href="#/activity" style="color:var(--acc)">View all activity →</a></div>
  ${recent?`<table style="margin-top:6px"><tr><th>Time<th>Event<th>Credential<th>Agent</tr>${recent}</table>${noteLine}`:'<div class=mut style="margin:8px 0">No activity yet.</div>'}</div>`}
let OPEN={},ALLOPEN=false;
const SCRIPTS={};
async function viewScript(h){try{SCRIPTS[h]=(await api('/api/script',{sha256:h})).text}catch(e){SCRIPTS[h]='('+(e.message||'could not load')+')'}renderActivity()}
function hideScript(h){delete SCRIPTS[h];renderActivity()}
function actToggle(k){OPEN[k]=!(ALLOPEN?OPEN[k]!==false:!!OPEN[k]);renderActivity()}
function actAll(on){ALLOPEN=on;OPEN={};renderActivity()}
function pathHtml(cmd){ // program dimmed, folder dimmed, file name bold; wraps at slashes, never mid-word
 const m=String(cmd).match(/^(\S+) (\/\S+)$/);if(!m)return esc(cmd);
 const i=m[2].lastIndexOf('/'),dir=m[2].slice(0,i+1),file=m[2].slice(i+1);
 return `${esc(m[1])} <span class=mut>${esc(dir).replace(/\//g,'/<wbr>')}</span><b>${esc(file)}</b>`}
function renderActivity(){
 // "finished" (result) and "note" (agent's outcome) lines are folded into the "used" line that shares their run id
 const fin={},note={};S.audit.forEach(e=>{if(!e.run)return;if(e.event=='finished')fin[e.run+'|'+e.name]=e;if(e.event=='note')(note[e.run]=note[e.run]||[]).push(e)});
 const usedRuns=new Set(S.audit.filter(e=>e.event=='used'&&e.run).map(e=>e.run));
 const base=S.audit.filter(e=>!((e.event=='finished'||e.event=='note')&&e.run&&usedRuns.has(e.run)));
 const evs=[...new Set(base.map(e=>e.event))].sort(),q=A.q.trim().toLowerCase();
 const sel=$('act-ev');if(sel.options.length!==evs.length+1){sel.innerHTML='<option value="">All events</option>'+evs.map(e=>`<option>${esc(e)}</option>`).join('');sel.value=A.ev}
 const notesOf=e=>(note[e.run]||[]).map(n=>n.detail).join(' · ');
 const rows=base.filter(e=>(!A.ev||e.event==A.ev)&&(!q||[e.name,e.agent,e.detail,e.event,e.reason,e.cmd,e.cwd,e.sha256,notesOf(e)].some(x=>String(x||'').toLowerCase().includes(q))));
 $('act-count').textContent=`${rows.length} of the latest ${base.length}`;
 const approval=e=>{ // the Touch ID approval that covered this use, if it is still in the loaded log
  const ap=S.audit.find(x=>x.event=='approved'&&x.name==e.name&&x.agent==e.agent&&x.t<=e.t);if(!ap)return '';
  const mins=+((ap.detail||'').match(/window (\d+)/)||[])[1]||0,age=(new Date(e.t)-new Date(ap.t))/60000;
  if(mins&&age>mins)return '';
  const secs=Math.round(age*60),later=secs<5?'':secs<120?` · ${secs} s later`:` · ${Math.round(age)} min later`;
  return `Touch ID approved at ${fmt(ap.t).replace(/^.*, /,'')}`+(mins?`, ${mins}-minute window`:' (this use only)')+later};
 const detail=e=>{const f=e.run?(fin[e.run+'|'+e.name]||fin[e.run+'|'+String(e.name).split(',')[0]]):null,ns=note[e.run]||[];
  if(!(e.reason||e.cmd||e.cwd))return null;
  const failed=f&&f.rc!==0,res=f?`exit ${f.rc} after ${f.secs}s`+(failed?' (failed)':' (succeeded)'):(e.event=='used'?'(no result recorded)':'');
  const kv=[['Why (as stated by the agent)',esc(e.reason||'')],
   ['Outcome (written by the agent)',ns.length?ns.map(n=>esc(n.detail)).join('<br>'):(e.event=='used'?'<span class=mut>(none added)</span>':'')],
   ['Command that ran',e.cmd?pathHtml(e.cmd):''],['Folder',esc(e.cwd||'')],
   ['Credential\'s address (where it should go)',e.addr?esc(e.addr)+' <span class=mut>(from the credential; the log cannot confirm where the command actually sent it)</span>':''],
   ['Result',e.event=='used'?`<span class="${failed?'bad':''}">${esc(res)}</span>`:''],
   ['Approval',esc(e.event=='used'?approval(e):'')],
   ['Script fingerprint',e.sha256?`<code>${esc(e.sha256.slice(0,16))}…</code> · ${e.size} bytes · ${e.kept?(SCRIPTS[e.sha256]!==undefined?`<a href="#" onclick="event.stopPropagation();hideScript('${e.sha256}');return false">hide script</a>`:`<a href="#" onclick="event.stopPropagation();viewScript('${e.sha256}');return false">view script (copy kept)</a>`):'text not kept'}`:''],
   ['Script text',e.sha256&&e.kept&&SCRIPTS[e.sha256]!==undefined?`<pre style="white-space:pre-wrap;margin:0;padding:8px;border:1px solid var(--line,#8884);border-radius:6px;max-height:320px;overflow:auto;font-size:12px">${esc(SCRIPTS[e.sha256])}</pre>`:''],
   ['Run id',esc(e.run||'')]].filter(x=>x[1]);
  return kv.length?kv:null};
 $('audit').innerHTML='<tr><th><th>Time<th>Event<th>Credential<th>Agent<th>Detail</tr>'+rows.map(e=>{
  const d=detail(e),key=e.t+'|'+e.event+'|'+e.name+'|'+(e.run||''),open=ALLOPEN?OPEN[key]!==false:!!OPEN[key];
  const failedRow=e.event=='used'&&e.run&&fin[e.run+'|'+e.name]&&fin[e.run+'|'+e.name].rc!==0;
  const main=`<tr ${d?`class=clk onclick="actToggle('${esc(key)}')"`:''}><td style="width:18px;color:var(--mut)">${d?(open?'▾':'▸'):''}<td>${fmt(e.t)}<td class="${e.event=='denied'||failedRow?'bad':''}">${esc(e.event)}${failedRow?' (failed)':''}<td>${esc(e.name)}<td>${esc(e.agent)}<td>${esc(e.detail)}</tr>`;
  const more=d&&open?`<tr class=det><td><td colspan=5><div style="display:grid;grid-template-columns:200px 1fr;gap:4px 12px;font-size:13px;padding:4px 0;overflow-wrap:anywhere">${d.map(x=>`<div class=mut>${esc(x[0])}</div><div>${x[1]}</div>`).join('')}</div></tr>`:'';
  return main+more}).join('')}
function openForm(m,dupOf,isNew,req){REQ=req||null;FORM_DIRTY=false;const n=!m||!!dupOf||!!isNew;m=m||{name:'',kind:'api-key',notes:'',agents:['claude'],mode:'ask',window_minutes:30,expires:'',env_var:''};
 $('form').innerHTML=`<div class=card><b>${req?'Requested by '+esc(req.requested_by)+' · review every field, then '+(req.reference?'save it (a reference entry has no secret)':'enter the secret'):dupOf?'Duplicate of '+esc(dupOf)+': set a new name, value and address':n?'Add credential':'Edit '+esc(m.name)}</b><div class=g>
 <div><label>Name</label><input type=text id=f_name value="${esc(m.name)}" ${n?'':'disabled'} placeholder="(letters, numbers, - _ . only)"></div>
 <div><label>Type</label><select id=f_kind onchange="kindChanged()">${KINDS.concat(KINDS.some(k=>k[0]==m.kind)?[]:[[m.kind,m.kind]]).map(k=>`<option value="${esc(k[0])}" ${k[0]==m.kind?'selected':''}>${esc(k[1])}</option>`).join('')}</select></div>
 <div id=f_user_wrap><label id=f_ulabel>Username (not a secret)</label><input type=text id=f_user value="${esc(m.username||'')}" placeholder="(account name)"></div>
 <div id=f_val_wrap><label id=f_vlabel data-new="${n?1:0}"></label><input type=password id=f_value></div>
 <div id=f_s3_wrap style="display:none"><label>Access key ID (the identifier, not the secret key)</label><input type=text id=f_akid value="${esc(m.access_key_id||'')}" placeholder="(access key ID)"></div>
 <div id=f_bucket_wrap style="display:none"><label>Bucket</label><input type=text id=f_bucket value="${esc(m.bucket||'')}" placeholder="(bucket name)"></div>
 <div id=f_region_wrap style="display:none"><label>Region (optional)</label><input type=text id=f_region value="${esc(m.region||'')}" placeholder="(worked out from the endpoint if blank)"></div>
 <div><label>Env var injected for the command</label><input type=text id=f_env value="${esc(m.env_var)}" placeholder="(optional: made from the name)"></div>
 <div><label id=f_alabel>Address (optional)</label><input type=text id=f_addr value="${esc(m.address||'')}" placeholder="(IP or hostname; for several hosts, separate with commas)"></div>
 <div><label>Folder</label><select id=f_folder>${folderOptions(m.folder||'')}</select></div>
 <div><label>Belongs to</label><select id=f_scope>${[['','(not set)'],['personal','Personal'],['work','Work']].map(o=>`<option value="${o[0]}" ${o[0]==(m.scope||'')?'selected':''}>${o[1]}</option>`).join('')}</select></div>
 <div><label>Where it lives</label><select id=f_net>${[['','(not specified)'],['lan','Local network'],['remote','Remote (internet)'],['vpn','Through VPN']].map(o=>`<option value="${o[0]}" ${o[0]==(m.network||'')?'selected':''}>${o[1]}</option>`).join('')}</select></div>
 <div><label>Approval</label><select id=f_mode><option value=ask ${m.mode=='ask'?'selected':''}>Ask with Touch ID</option><option value=auto ${m.mode=='auto'?'selected':''}>Auto (no prompt)</option></select></div>
 <div><label>After approving with Touch ID, stay approved for</label><select id=f_win>${WINS.concat(WINS.some(w=>w[0]==m.window_minutes)?[]:[[m.window_minutes,m.window_minutes+' min (custom)']]).map(w=>`<option value=${w[0]} ${w[0]==m.window_minutes?'selected':''}>${w[1]}</option>`).join('')}</select></div>
 <div><label>Expires (optional)</label><input type=datetime-local id=f_exp value="${m.expires?m.expires.slice(0,16):''}"></div>
 <div><label>Reference entry</label><label style="display:block;color:var(--fg)"><input type=checkbox id=f_ref ${m.reference?'checked':''} ${(n||m.reference)?'':'disabled'} onchange="refChanged()"> No secret (reference only): holds notes, such as how keyless SSH to a host is set up</label></div>
 <div><label>Human-only</label><label style="display:block;color:var(--fg)"><input type=checkbox id=f_ho ${m.human_only?'checked':''} onchange="document.querySelectorAll('.f_ag').forEach(x=>x.disabled=this.checked)"> No agent may ever use this (logins, root/sudo passwords)</label></div>
 <div><label>Allowed agents</label>${S.agents.map(a=>`<label style="display:inline-block;margin-right:12px;color:var(--fg)"><input type=checkbox class=f_ag value=${a} ${m.agents.some(x=>x==a||(S.families||{})[x]==a)?'checked':''}> ${a}${famOf(a)}</label>`).join('')}</div></div>
 <label>Allowed commands, one per line (blank = ANY command; scripts named here are pinned by hash)</label><textarea id=f_cmds rows=3 placeholder="(optional: leave blank to allow any command)">${esc((m.allowed_commands||[]).map(e=>e.cmd).join('\n'))}</textarea>
 <label>Notes</label><textarea id=f_notes rows=2 placeholder="(optional)">${esc(m.notes)}</textarea>
 <div class=row style="margin-top:10px"><button class=p onclick="save(${n})">Save</button><button onclick="dropForm()">Cancel</button></div></div>`;
 document.querySelectorAll('#form input,#form textarea').forEach(e=>{e.setAttribute('data-1p-ignore','');e.setAttribute('data-lpignore','true');e.setAttribute('data-form-type','other');e.setAttribute('autocomplete',e.type=='password'?'new-password':'off')});kindChanged();refChanged();if(n)$('f_name').focus()}
function refChanged(){const r=$('f_ref').checked;$('f_val_wrap').style.display=r?'none':'';if(r)$('f_value').value=''}
function kindChanged(){const k=$('f_kind').value,lg=k=='login',s3=k=='s3';
 $('f_user_wrap').style.display=(lg||s3||k=='api-key')?'':'none';['f_s3_wrap','f_bucket_wrap','f_region_wrap'].forEach(i=>$(i).style.display=s3?'':'none');
 $('f_ulabel').textContent=s3?'User / account name (optional, not a secret)':k=='api-key'?'App ID / client ID (optional, not a secret)':'Username (not a secret)';$('f_alabel').textContent=s3?'Endpoint (host name)':'Address (optional)';
 const nw=$('f_vlabel').dataset.new=='1';$('f_vlabel').textContent=(lg?'Password':s3?'Secret access key':'Value')+(nw?' (hidden)':' (hidden; leave blank to keep)')}
function edit(n){openForm(S.creds.find(c=>c.name===n))}
function dup(n){const m=S.creds.find(c=>c.name===n);openForm(Object.assign({},m,{name:'',env_var:'',address:'',revoked:false}),n);goto('form')}
async function save(create){const exp=$('f_exp').value;await api('/api/save',{create,name:$('f_name').value.trim().replace(/\s+/g,'-'),username:$('f_user').value,address:$('f_addr').value,folder:$('f_folder').value,fulfil_request:REQ?REQ.name:'',access_key_id:$('f_akid').value,bucket:$('f_bucket').value,region:$('f_region').value,scope:$('f_scope').value,network:$('f_net').value,kind:$('f_kind').value,value:$('f_value').value,reference:$('f_ref').checked,env_var:$('f_env').value,
 mode:$('f_mode').value,window_minutes:$('f_win').value,expires:exp?new Date(exp).toISOString():'',notes:$('f_notes').value,human_only:$('f_ho').checked,allowed_commands:$('f_cmds').value,agents:$('f_ho').checked?[]:[...document.querySelectorAll('.f_ag:checked')].map(x=>x.value)});
 REQ=null;$('form').innerHTML='';load()}
async function post(p,name){await api(p,{name});load()}
async function ack(n,k,on){await api('/api/ack',{name:n,key:k,on});load()}
async function del(n){if(confirm('Delete '+n+' and its Keychain value? This cannot be undone.')){await post('/api/delete',n)}}
async function endGrants(n){await api('/api/end-grants',{name:n});load()}
async function reveal(n){const r=await api('/api/reveal',{name:n});const el=$('v_'+n);const m=S.creds.find(c=>c.name===n).masked;
 el.textContent=r.value;let t=15;const b=document.createElement('button');b.textContent='Copy';b.onclick=()=>navigator.clipboard.writeText(r.value);el.after(b);
 const iv=setInterval(()=>{if(--t<=0){clearInterval(iv);el.textContent=m;b.remove()}},1000)}
async function copyVal(n){const r=await api('/api/copy',{name:n});flash('Copied '+n+'. The clipboard clears itself in '+r.seconds+' seconds.')}
function editNotice(){$('noticeform').innerHTML=`<div class=card><b>Edit the notice shown to AI agents</b><label>Plain text, up to ${S.notice_max} characters. Saved with Touch ID. Nothing here is locked, including the core rules.</label>
 <textarea id=nx rows=16 style="font:12px ui-monospace,monospace" data-1p-ignore autocomplete=off>${esc(S.notice)}</textarea>
 <div class=row style="margin-top:8px"><button class=p onclick="saveNotice()">Save (Touch ID)</button><button onclick="$('nx').value=S.notice_default">Load default text</button><button onclick="$('noticeform').innerHTML=''">Cancel</button></div></div>`;goto('noticeform')}
async function saveNotice(){await api('/api/notice',{text:$('nx').value});$('noticeform').innerHTML='';load();flash('Notice updated.')}
async function resetNotice(){await api('/api/notice-reset',{});$('noticeform').innerHTML='';load();flash('Notice reset to the default.')}
function copyNotice(b){navigator.clipboard.writeText(S.notice).then(()=>{const t=b.textContent;b.textContent='Copied';setTimeout(()=>b.textContent=t,1500)})}
function flash(t){const e=$('err');e.style.color='var(--ok)';e.textContent=t;setTimeout(()=>{e.textContent='';e.style.color=''},6000)}
async function grant(n,a){const h=prompt('Approve '+a+' to use '+n+' without prompting, for how many hours?','4');if(!h)return;await api('/api/grant',{name:n,agent:a,hours:h});load()}
initSide();document.querySelectorAll('#p-backup input').forEach(e=>{e.setAttribute('data-1p-ignore','');e.setAttribute('autocomplete',e.type=='password'?'new-password':'off')});route();window.addEventListener('hashchange',route);document.addEventListener('keydown',e=>{if(e.key=='/'&&!/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)){e.preventDefault();go('credentials');setTimeout(()=>$('q').focus(),0)}});
load();setInterval(()=>{if(!$('form').innerHTML)load(true)},15000)
// Moving between pages, opening rows and typing in forms never reach the server, so tell it when a person is really here.
// Only genuine input counts (not the page's own refresh), at most every 30 s, so an unattended tab still times out.
let lastInput=0;['pointerdown','keydown','wheel','scroll','touchstart','mousemove','hashchange'].forEach(ev=>addEventListener(ev,()=>{lastInput=Date.now()},{passive:true,capture:true}));
setInterval(()=>{if(Date.now()-lastInput<30000)fetch('/api/ping',{headers:{'X-Token':T}}).catch(()=>{})},30000)
</script></body></html>"""
