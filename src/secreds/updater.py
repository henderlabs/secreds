"""A daily check for a newer release on GitHub, and an update you approve yourself.

Nothing here installs anything on its own. A check only READS the latest release. Installing needs Touch ID and an explicit
request, comes only from the repository named in config.json ("update_repo"; set it to "" to turn update checks off), and is
refused unless the downloaded package really is secreds at the version the release claims.
"""
import json
import os, re, shutil, subprocess, sys, tarfile, tempfile, time, urllib.error, urllib.request
from pathlib import Path

from . import REPO, __version__
from . import core as c

DEFAULT_REPO = REPO
CHECK_EVERY = 24 * 3600
LABEL = "com.secreds.update-check"
MAX_BYTES = 25 * 1024 * 1024


class UpdateError(Exception):
    pass


def repo():
    return str(c.CONFIG.get("update_repo", DEFAULT_REPO) or "").strip()


def _state_file():
    return c.DATA / "update.json"


def load_state():
    return c._read(_state_file(), {})


def _save_state(st):
    c._write(_state_file(), st)


def _now():
    return time.time()


def parse_version(tag):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", (tag or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def is_newer(candidate, current=__version__):
    a, b = parse_version(candidate), parse_version(current)
    return bool(a and b and a > b)


# ---- network (small functions so tests can replace them) ----
def _gh_exe():
    """Find gh even when the app was started from the Dock/Finder, which has a minimal PATH (no Homebrew)."""
    found = shutil.which("gh")
    if found:
        return found
    for cand in ("/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"):
        if os.access(cand, os.X_OK):
            return cand
    return None


def _gh(args):
    """Use the GitHub CLI if it is installed and signed in: this is what makes a private repository work."""
    exe = _gh_exe()
    if not exe:
        return None
    r = subprocess.run([exe, "api", *args], capture_output=True, timeout=60)
    return r.stdout if r.returncode == 0 else None


def _http(url):
    req = urllib.request.Request(url, headers={"User-Agent": "secreds-updater", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise UpdateError("The download is larger than expected; refusing it")
    return data


def _fetch(path):
    data = _gh([path])
    if data is not None:
        return data
    try:
        return _http(f"https://api.github.com/{path}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise UpdateError(f"GitHub answered HTTP {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise UpdateError(f"Could not reach GitHub ({type(e).__name__})")


def latest_release(r):
    data = _fetch(f"repos/{r}/releases/latest")
    if data is None:
        return None
    try:
        return json.loads(data)
    except ValueError:
        raise UpdateError("GitHub sent something unexpected")


def download_tarball(r, tag, dest):
    data = _fetch(f"repos/{r}/tarball/{tag}")
    if not data or len(data) > MAX_BYTES:
        raise UpdateError("Could not download that release")
    Path(dest).write_bytes(data)


# ---- checking ----
def check(force=False, quiet=False):
    """Look for a newer release at most once a day. Never raises: problems are recorded in the returned state."""
    st = load_state(); now = _now()
    if not force and st.get("last_checked") and now - st["last_checked"] < CHECK_EVERY:
        return st
    r = repo()
    st.update(repo=r, last_checked=now, error="")
    if not r:
        st.update(error="Update checks are turned off (update_repo is empty)", available=False)
        _save_state(st); return st
    try:
        rel = latest_release(r)
    except UpdateError as e:
        st.update(error=str(e)); _save_state(st); return st
    if rel is None:
        st.update(latest_tag="", latest_version="", available=False, notes="")
    else:
        tag = str(rel.get("tag_name", ""))
        st.update(latest_tag=tag, latest_version=tag.lstrip("v"), available=is_newer(tag), notes=str(rel.get("body") or "")[:4000],
                  published=rel.get("published_at"), url=rel.get("html_url"))
    _save_state(st)
    if quiet and st.get("available") and st.get("notified") != st.get("latest_tag"):
        notify(f"seCreds {st['latest_version']} is available. Open seCreds to review and update.")
        st["notified"] = st["latest_tag"]; _save_state(st)
    return st


def notify(text):
    try:
        subprocess.run(["osascript", "-e", f'display notification {json.dumps(text)} with title "seCreds"'], capture_output=True, timeout=10)
    except Exception:
        pass


def status():
    st = load_state()
    return {"current": __version__, "repo": repo(), "last_checked": st.get("last_checked"), "latest_tag": st.get("latest_tag", ""),
            "latest_version": st.get("latest_version", ""), "available": bool(st.get("available")), "notes": st.get("notes", ""),
            "error": st.get("error", ""), "previous_version": st.get("previous_version", ""), "daily": daily_enabled()}


# ---- installing an update ----
def validate_tarball(path, tag):
    """The package must really be secreds, and its own version must match the release tag."""
    try:
        with tarfile.open(path, "r:gz") as t:
            names = t.getnames()
            if any(n.startswith("/") or ".." in Path(n).parts for n in names):
                raise UpdateError("The download contains unsafe file paths; refusing it")
            def read(suffix):
                m = next((x for x in t.getmembers() if x.isfile() and x.name.count("/") == (1 if suffix == "pyproject.toml" else 3) and x.name.endswith("/" + suffix)), None)
                return t.extractfile(m).read().decode() if m else ""
            pyproject, init = read("pyproject.toml"), read("src/secreds/__init__.py")
    except (tarfile.TarError, OSError):
        raise UpdateError("The download is not a valid release archive")
    if not re.search(r'^name\s*=\s*"secreds"\s*$', pyproject, re.M):
        raise UpdateError("That archive is not the secreds package; refusing it")
    m = re.search(r'__version__\s*=\s*"([^"]+)"', init)
    if not m or m.group(1) != tag.lstrip("v"):
        raise UpdateError("The package's own version does not match the release tag; refusing it")
    return m.group(1)


def apply(tag=None, agent="cli"):
    """Download a release, check it, and install it into this environment. Needs Touch ID."""
    st = check(force=True)
    tag = tag or st.get("latest_tag")
    if not tag:
        raise UpdateError(st.get("error") or "No release was found to install")
    if not parse_version(tag):
        raise UpdateError("That does not look like a release tag (use v1.2.3)")
    if tag.lstrip("v") == __version__:
        raise UpdateError(f"Already on {__version__}")
    r = repo()
    if not r:
        raise UpdateError("Update checks are turned off (update_repo is empty)")
    c._confirm(f"update seCreds from {__version__} to {tag.lstrip('v')}")
    with tempfile.TemporaryDirectory() as td:
        tgz = Path(td) / "release.tar.gz"
        download_tarball(r, tag, tgz)
        version = validate_tarball(tgz, tag)
        p = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", f"{tgz}[export]"], capture_output=True, text=True)
        if p.returncode:
            raise UpdateError("The install failed: " + (p.stderr.strip().splitlines() or ["unknown error"])[-1][:200])
    prev = __version__
    st = load_state(); st.update(previous_version=prev, installed_version=version, updated_at=_now(), available=False)
    _save_state(st)
    c.audit("updated", "", agent, f"{prev} -> {version}")
    return {"from": prev, "to": version}


# ---- the once-a-day check (a macOS LaunchAgent) ----
def plist_path():
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def plist_dict(exe, hour=9, minute=15):
    return {"Label": LABEL, "ProgramArguments": [str(exe), "update", "--check", "--quiet"],
            "StartCalendarInterval": {"Hour": hour, "Minute": minute}, "RunAtLoad": False,
            "EnvironmentVariables": {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "SECREDS_HOME": str(c.DATA)},
            "StandardOutPath": str(c.DATA / "update-check.log"), "StandardErrorPath": str(c.DATA / "update-check.log")}


def _launchctl(*args):
    return subprocess.run(["launchctl", *args], capture_output=True, text=True)


def daily_enabled():
    return plist_path().exists()


def enable_daily(exe=None):
    import os, plistlib
    exe = exe or shutil.which("secreds") or sys.argv[0]
    p = plist_path(); p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as f:
        plistlib.dump(plist_dict(Path(exe).resolve()), f)
    _launchctl("bootout", f"gui/{os.getuid()}", str(p))
    r = _launchctl("bootstrap", f"gui/{os.getuid()}", str(p))
    if r.returncode:
        raise UpdateError("macOS refused to start the daily check: " + (r.stderr.strip()[:150] or "unknown"))
    c.audit("update-check-enabled", "", "cli", "daily")


def disable_daily():
    import os
    p = plist_path()
    if p.exists():
        _launchctl("bootout", f"gui/{os.getuid()}", str(p)); p.unlink()
    c.audit("update-check-disabled", "", "cli", "")
