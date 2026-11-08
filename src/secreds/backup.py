"""Complete, encrypted backups: every secret plus every setting, restorable on this Mac or a new one.

A backup is ONE file. Two ways to protect it: a one-off passphrase (scrypt + AES-256-GCM, format 2), or the backup key
(format 3): you set one password once; the Mac keeps only a public key and can write backups without ever knowing the
password, while the private key lives in a recovery file locked by that password (X25519 + HKDF + AES-256-GCM). It contains the secrets, the
credential settings, folders, pending requests, the agent notice, config.json and the audit log. It is not tied to this
Mac's Keychain, so it is also how you move seCreds to a second Mac (iCloud Keychain does not sync these items).
"""
import base64, datetime, json, os
from pathlib import Path

from . import __version__, signature
from . import core as c

FORMAT, VERSION = "secreds-backup", 2
KDF_N = 2 ** 17                  # scrypt cost for new backups; the file records its own value
MAX_KDF_N = 2 ** 20              # refuse absurd values from a hostile file
MIN_PASSPHRASE = 12
MIN_PASSPHRASE_CLOUD = 16        # a file in the cloud can be attacked offline if the account is ever compromised, so be stricter
ICLOUD_ROOT = Path.home() / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
ICLOUD_FOLDER = "seCreds Backups"
BACKUP_GLOB = "secreds-backup-*.secreds"
SETTINGS = ("folders.json", "requests.json", "config.json", "notice.txt", "audit.log", "backup-key.json", "backup-plan.json")
AAD = b"secreds-backup-v2"
AAD3 = b"secreds-backup-v3"
AADK = b"secreds-recovery-key-v1"
RECOVERY_GLOB = "secreds-recovery-key*.json"
MIN_KEY_PASSWORD = 16


def _crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError:
        raise RuntimeError("Backups need the 'cryptography' package (pip install cryptography)")
    return AESGCM, Scrypt


def is_cloud_path(path):
    """True for iCloud Drive and the other cloud-synced folders macOS exposes."""
    s = str(Path(path).expanduser())
    return "/Library/Mobile Documents/" in s or "/Library/CloudStorage/" in s


def icloud_dir(create=False):
    """The folder seCreds uses inside iCloud Drive, or None if iCloud Drive is not available on this Mac."""
    if not ICLOUD_ROOT.is_dir():
        return None
    d = ICLOUD_ROOT / ICLOUD_FOLDER
    if create:
        d.mkdir(exist_ok=True)
    return d


def cloud_locations():
    """Cloud drives on this Mac that can hold a backup folder: iCloud Drive plus Google Drive, OneDrive, Dropbox... that are
    mounted under ~/Library/CloudStorage. Only places this user can write to are offered (Google Drive's root is read-only:
    files go inside 'My Drive')."""
    out = []
    ic = icloud_dir()
    if ic:
        out.append({"name": "iCloud Drive", "path": str(ic), "kind": "icloud"})
    root = Path.home() / "Library" / "CloudStorage"
    if root.is_dir():
        for d in sorted(root.iterdir()):
            if not d.is_dir() or d.name.startswith("."):
                continue
            base = d / "My Drive" if d.name.startswith("GoogleDrive") and (d / "My Drive").is_dir() else d
            if os.access(base, os.W_OK):
                label = d.name.split("-", 1)
                nice = {"GoogleDrive": "Google Drive", "OneDrive": "OneDrive", "Dropbox": "Dropbox", "Box": "Box"}.get(label[0], label[0])
                out.append({"name": f"{nice} ({label[1]})" if len(label) > 1 else nice, "path": str(base / ICLOUD_FOLDER), "kind": "folder"})
    return out


def list_backups(folder):
    """Backup files in a folder, newest first (names and dates only; nothing is opened)."""
    d = Path(folder).expanduser()
    if not d.is_dir():
        return []
    files = sorted(d.glob(BACKUP_GLOB), key=lambda f: f.stat().st_mtime, reverse=True)
    return [{"path": str(f), "name": f.name, "bytes": f.stat().st_size, "modified": c.iso(__import__("datetime").datetime.fromtimestamp(f.stat().st_mtime).astimezone())} for f in files]


def check_passphrase(p, cloud=False):
    need = MIN_PASSPHRASE_CLOUD if cloud else MIN_PASSPHRASE
    if len(p or "") < need:
        raise ValueError(f"Use a passphrase of at least {need} characters" + (" (longer for a cloud folder: four or five random words works well)" if cloud else ""))
    if len(set(p)) < 5:
        raise ValueError("That passphrase is too repetitive")


def _b64(b):
    return base64.b64encode(b).decode()


def _derive(passphrase, salt, n, r, p):
    _, Scrypt = _crypto()
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode())


def _seal(payload, passphrase):
    AESGCM, _ = _crypto()
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(passphrase, salt, KDF_N, 8, 1)
    ct = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), AAD)
    return {"format": FORMAT, "version": VERSION, "generator": signature(), "kdf": {"name": "scrypt", "n": KDF_N, "r": 8, "p": 1},
            "salt": _b64(salt), "nonce": _b64(nonce), "ct": _b64(ct)}


def _kdf_params(k):
    n, r, p = int(k["n"]), int(k["r"]), int(k["p"])
    if k.get("name") != "scrypt" or n > MAX_KDF_N or n < 2 ** 14 or n & (n - 1) or not (1 <= r <= 16) or not (1 <= p <= 4):
        raise ValueError
    return n, r, p


def _load_blob(path):
    try:
        blob = json.loads(Path(path).expanduser().read_text())
        if blob.get("format") != FORMAT or blob.get("version") not in (2, 3):
            raise ValueError
        return blob
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("This is not a seCreds backup file (or it is damaged)")


def _open(path, passphrase, key_file=None):
    blob = _load_blob(path)
    if blob["version"] == 3:
        return _open_v3(path, blob, passphrase, key_file)
    AESGCM, _ = _crypto()
    try:
        n, r, p = _kdf_params(blob["kdf"])
        salt, nonce, ct = (base64.b64decode(blob[x]) for x in ("salt", "nonce", "ct"))
    except (ValueError, KeyError, TypeError):
        raise ValueError("This is not a seCreds backup file (or it is damaged)")
    try:
        plain = AESGCM(_derive(passphrase, salt, n, r, p)).decrypt(nonce, ct, AAD)
    except Exception:
        raise ValueError("Wrong passphrase, or the file is damaged")
    return json.loads(plain)


# ---- the backup key: one password, set once ----
def _x():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        raise RuntimeError("Backups need the 'cryptography' package (pip install cryptography)")
    return hashes, serialization, X25519PrivateKey, X25519PublicKey, HKDF


def _raw_pub(pub):
    _, ser, *_ = _x()
    return pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def _key_id(pub_raw):
    import hashlib
    return hashlib.sha256(pub_raw).hexdigest()[:12]


def _wrap_key(shared, eph_raw, recipient_raw):
    hashes, _, _, _, HKDF = _x()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=AAD3 + eph_raw + recipient_raw).derive(shared)


def _keyfile():
    return c.DATA / "backup-key.json"


def key_status():
    """Whether the backup key is set up, and where its recovery files were saved (never any key material)."""
    k = c._read(_keyfile(), {})
    if not k.get("public"):
        return {"configured": False}
    files = [f for f in state().get("recovery_files", []) if Path(f).exists()]
    return {"configured": True, "key_id": k.get("key_id"), "created": k.get("created"), "recovery_files": files}


def _write_new(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def unlock_recovery(path, password):
    """Open a recovery file with its password. Returns (private key bytes, public key bytes, key id)."""
    AESGCM, _ = _crypto()
    try:
        blob = json.loads(Path(path).expanduser().read_text())
        if blob.get("format") != "secreds-recovery-key" or blob.get("version") != 1:
            raise ValueError
        n, r, p = _kdf_params(blob["kdf"])
        salt, nonce, ct, pub = (base64.b64decode(blob[x]) for x in ("salt", "nonce", "ct", "public"))
        kid = str(blob["key_id"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("This is not a seCreds recovery file (or it is damaged)")
    try:
        priv = AESGCM(_derive(password, salt, n, r, p)).decrypt(nonce, ct, AADK + kid.encode())
    except Exception:
        raise ValueError("Wrong password, or the recovery file is damaged")
    return priv, pub, kid


def setup_key(password, dests, replace=False, agent="cli"):
    """Create the backup key pair. The Mac keeps the public half; the private half goes, locked by `password`, into a
    recovery file written to every folder in `dests` and proven to open before anything is saved. Needs Touch ID."""
    if len(password or "") < MIN_KEY_PASSWORD:
        raise ValueError(f"Use a password of at least {MIN_KEY_PASSWORD} characters (four or five random words works well)")
    if len(set(password)) < 6:
        raise ValueError("That password is too repetitive")
    dests = [Path(d).expanduser() for d in (dests or [])]
    if not dests:
        raise ValueError("Choose at least one place to save the recovery file (two different places is much safer)")
    if key_status()["configured"] and not replace:
        raise ValueError("A backup key is already set up. Replacing it means older key backups need the OLD recovery file and password.")
    AESGCM, _ = _crypto(); _, ser, X25519PrivateKey, _, _ = _x()
    c._confirm("set up the backup key")
    priv = X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    pub = _raw_pub(priv.public_key()); kid = _key_id(pub)
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_derive(password, salt, KDF_N, 8, 1)).encrypt(nonce, raw_priv, AADK + kid.encode())
    text = json.dumps({"format": "secreds-recovery-key", "version": 1, "generator": signature(), "key_id": kid, "public": _b64(pub),
                       "kdf": {"name": "scrypt", "n": KDF_N, "r": 8, "p": 1}, "salt": _b64(salt), "nonce": _b64(nonce), "ct": _b64(ct)})
    written = []
    try:
        for d in dests:
            d.mkdir(parents=True, exist_ok=True)
            path = d / f"secreds-recovery-key-{kid}.json"
            _write_new(path, text); written.append(path)
            got, got_pub, _ = unlock_recovery(path, password)             # prove each copy opens with this password
            if got != raw_priv or got_pub != pub:
                raise RuntimeError("A recovery file did not verify after writing")
    except Exception:
        for w in written:
            w.unlink(missing_ok=True)
        raise
    c._write(_keyfile(), {"format": "secreds-backup-key", "version": 1, "public": _b64(pub), "key_id": kid, "created": c.iso(c.now())})
    os.chmod(_keyfile(), 0o600)
    _save_state(recovery_files=[str(w) for w in written])
    c.audit("backup-key-setup", "", agent, f"key {kid}, recovery file saved in {len(written)} place(s)")
    return {"key_id": kid, "files": [str(w) for w in written]}


def copy_recovery(dest, agent="gui"):
    """Save another copy of the recovery file (already locked by your password, so no password is needed) into `dest`."""
    import hashlib
    st = key_status()
    if not st["configured"] or not st["recovery_files"]:
        raise ValueError("There is no recovery file on record to copy (set up the backup key first)")
    src = Path(st["recovery_files"][0]); dest = Path(dest).expanduser()
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / src.name
    if target.exists():
        raise ValueError("That place already has this recovery file")
    data = src.read_bytes()
    _write_new(target, data.decode())
    if hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(data).digest():
        target.unlink(missing_ok=True)
        raise RuntimeError("The copy did not match the original, so it was removed")
    _save_state(recovery_files=[str(f) for f in st["recovery_files"]] + [str(target)])
    c.audit("backup-key-recovery-copied", "", agent, f"now in {len(st['recovery_files']) + 1} place(s)")
    return {"path": str(target), "places": len(st["recovery_files"]) + 1}


def _seal_v3(payload):
    AESGCM, _ = _crypto(); _, _, X25519PrivateKey, X25519PublicKey, _ = _x()
    k = c._read(_keyfile(), {})
    if not k.get("public"):
        raise ValueError("The backup key is not set up yet. Set it up first, or give a one-off passphrase.")
    recip = base64.b64decode(k["public"])
    eph = X25519PrivateKey.generate(); eph_raw = _raw_pub(eph.public_key())
    key = _wrap_key(eph.exchange(X25519PublicKey.from_public_bytes(recip)), eph_raw, recip)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), AAD3 + k["key_id"].encode())
    return {"format": FORMAT, "version": 3, "generator": signature(), "key_id": k["key_id"], "eph": _b64(eph_raw), "nonce": _b64(nonce), "ct": _b64(ct)}


def _find_recovery(path, key_id):
    """The recovery file for this key: next to the backup, or in the iCloud folder."""
    for d in (Path(path).expanduser().parent, icloud_dir()):
        if d and Path(d).is_dir():
            for f in sorted(Path(d).glob(RECOVERY_GLOB)):
                try:
                    if json.loads(f.read_text()).get("key_id") == key_id:
                        return f
                except (OSError, ValueError, AttributeError):
                    pass
    return None


def _open_v3(path, blob, password, key_file):
    AESGCM, _ = _crypto(); _, _, X25519PrivateKey, X25519PublicKey, _ = _x()
    try:
        eph_raw, nonce, ct = (base64.b64decode(blob[x]) for x in ("eph", "nonce", "ct")); kid = str(blob["key_id"])
    except (KeyError, ValueError, TypeError):
        raise ValueError("This is not a seCreds backup file (or it is damaged)")
    rf = Path(key_file).expanduser() if key_file else _find_recovery(path, kid)
    if not rf or not rf.exists():
        raise ValueError(f"This backup needs its recovery file (secreds-recovery-key-{kid}.json). Choose it, or put it in the same folder as the backup.")
    priv_raw, pub_raw, rid = unlock_recovery(rf, password)
    if rid != kid:
        raise ValueError("That recovery file belongs to a different backup key")
    key = _wrap_key(X25519PrivateKey.from_private_bytes(priv_raw).exchange(X25519PublicKey.from_public_bytes(eph_raw)), eph_raw, pub_raw)
    try:
        plain = AESGCM(key).decrypt(nonce, ct, AAD3 + kid.encode())
    except Exception:
        raise ValueError("The backup could not be decrypted (damaged file?)")
    return json.loads(plain)


def _state_file():
    return c.DATA / "state.json"


def state():
    return c._read(_state_file(), {})


def _save_state(**kw):
    st = state(); st.update(kw)
    c._write(_state_file(), st)


def _collect(include_audit):
    db = c.list_creds()
    secrets, missing = {}, []
    for name in db:
        if db[name].get("reference"):          # nothing stored in the Keychain for reference entries
            continue
        try:
            secrets[name] = c.kc_get(name)
        except KeyError:
            missing.append(name)
    files = {"meta.json": json.dumps(db)}
    for f in SETTINGS:
        p = c.DATA / f
        if p.exists() and not (f == "audit.log" and not include_audit):
            files[f] = p.read_text()
    payload = {"created": c.iso(c.now()), "app_version": __version__, "files": files, "secrets": secrets}
    return payload, missing


def create_backup(dest, passphrase=None, include_audit=True, agent="cli", confirm=True):
    """Write one encrypted backup file into `dest` (any folder you choose). Needs Touch ID. With no passphrase the backup key
    is used (no password needed on this Mac). Returns a summary."""
    dest = Path(dest).expanduser()
    use_key = not passphrase
    if use_key and not key_status()["configured"]:
        raise ValueError("Set up the backup key first (Backup page), or give a one-off passphrase")
    if not use_key:
        check_passphrase(passphrase, cloud=is_cloud_path(dest))
    if confirm:
        c._confirm("create an encrypted backup of every credential")
    dest.mkdir(parents=True, exist_ok=True)
    payload, missing = _collect(include_audit)
    stamp = f"{c.now():%Y%m%d-%H%M%S}"
    path, n = dest / f"secreds-backup-{stamp}.secreds", 1
    while path.exists():                                              # two backups in the same second must not collide
        n += 1; path = dest / f"secreds-backup-{stamp}-{n}.secreds"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(_seal_v3(payload) if use_key else _seal(payload, passphrase), f)
    if use_key:
        try:                                                        # the Mac cannot decrypt a key backup: check what it can
            blob = _load_blob(path)
            assert blob["version"] == 3 and blob["key_id"] == key_status()["key_id"] and len(base64.b64decode(blob["ct"])) > 16
        except Exception:
            path.unlink(missing_ok=True)
            raise RuntimeError("The backup did not check out after writing, so it was deleted. Nothing was backed up.")
    else:
        back = _open(path, passphrase)                               # prove the file can be read back before trusting it
        if sorted(back["secrets"]) != sorted(payload["secrets"]) or any(back["secrets"][k] != v for k, v in payload["secrets"].items()):
            path.unlink()
            raise RuntimeError("The backup did not verify after writing, so it was deleted. Nothing was backed up.")
    _save_state(last_backup=c.iso(c.now()), last_backup_file=path.name, last_backup_dir=str(dest), last_backup_count=len(payload["secrets"]))
    c.audit("backup-created", "", agent, f"{len(payload['secrets'])} credentials, {'backup key' if use_key else 'passphrase'}, to a folder named {dest.name}")
    return {"path": str(path), "count": len(payload["secrets"]), "missing": missing, "bytes": path.stat().st_size, "verified": not use_key, "method": "key" if use_key else "passphrase", "cloud": is_cloud_path(dest)}


def backup_info(path, passphrase, key_file=None):
    """What is inside a backup (names and settings only, never a secret)."""
    b = _open(path, passphrase, key_file)
    _save_state(last_restore_check=c.iso(c.now()))
    meta = json.loads(b["files"]["meta.json"])
    return {"created": b.get("created"), "app_version": b.get("app_version"), "count": len(meta), "names": sorted(meta),
            "has_secrets": sorted(b["secrets"]), "settings": sorted(f for f in b["files"] if f != "meta.json")}


def restore_backup(path, passphrase, mode="merge", dry_run=False, agent="cli", key_file=None, also=None):
    """Restore from a backup. merge (default) never overwrites what is already here; overwrite lets the backup win."""
    if mode not in ("merge", "overwrite"):
        raise ValueError("mode must be merge or overwrite")
    b = _open(path, passphrase, key_file)
    _save_state(last_restore_check=c.iso(c.now()))              # it opened: the password and recovery file work
    meta = json.loads(b["files"]["meta.json"]); secrets = b["secrets"]
    local = c.list_creds()
    create = [n for n in meta if n not in local]
    clash = [n for n in meta if n in local]
    also = [n for n in (also or []) if n in clash]               # merge, but take the backup's version of these names
    overwrite = clash if mode == "overwrite" else also
    skip = [] if mode == "overwrite" else [n for n in clash if n not in also]
    different = []
    for n in clash:                                               # names only: which shared credentials hold a different secret
        if meta[n].get("reference") or local[n].get("reference"):
            continue
        try:
            if n in secrets and c.kc_get(n) != secrets[n]:
                different.append(n)
        except KeyError:
            different.append(n)
    no_secret = [n for n in create + overwrite if n not in secrets and not meta[n].get("reference")]
    plan = {"create": sorted(create), "overwrite": sorted(overwrite), "skip_existing": sorted(skip), "no_secret_in_backup": sorted(no_secret), "different": sorted(different)}
    if dry_run:
        return plan
    c._confirm(f"restore {len(create) + len(overwrite)} credentials from a backup")
    for n in create + overwrite:                      # secrets first: if the Keychain refuses, no settings are written
        if n in secrets:
            c.kc_set(n, secrets[n])
    with c._Lock():
        db = c.list_creds()
        for n in create + overwrite:
            db[n] = meta[n]
        c._write(c.META, db)
    files = b["files"]
    if "folders.json" in files:
        c._write(c.FOLDERS, sorted(set(json.loads(files["folders.json"])) | set(c._read(c.FOLDERS, []))))
    if "requests.json" in files:
        mine = c._read(c.REQUESTS, {}); theirs = json.loads(files["requests.json"]); db = c.list_creds()
        for k, v in theirs.items():
            if k not in mine and k not in db:
                mine[k] = v
        c._write(c.REQUESTS, mine)
    for f, target in (("config.json", c.CONFIG_FILE), ("notice.txt", c.NOTICE_FILE)):
        if f in files and (mode == "overwrite" or not target.exists()):
            target.write_text(files[f]); os.chmod(target, 0o600)
    if "backup-key.json" in files and (mode == "overwrite" or not _keyfile().exists()):
        k = json.loads(files["backup-key.json"])               # the PUBLIC half only: lets this Mac back up with the same key
        c._write(_keyfile(), k); os.chmod(_keyfile(), 0o600)
        found = []
        for d in {Path(path).expanduser().parent, icloud_dir()}:
            if d and Path(d).is_dir():
                for f in Path(d).glob(RECOVERY_GLOB):
                    try:
                        if json.loads(f.read_text()).get("key_id") == k.get("key_id"):
                            found.append(str(f))
                    except (OSError, ValueError, AttributeError):
                        pass
        _save_state(recovery_files=sorted(found))
    if "backup-plan.json" in files and (mode == "overwrite" or not _plan_file().exists()):
        c._write(_plan_file(), json.loads(files["backup-plan.json"])); os.chmod(_plan_file(), 0o600)   # saved, but the schedule stays OFF until you save the plan here
    if "audit.log" in files and not c.AUDIT.exists():
        c.AUDIT.write_text(files["audit.log"]); os.chmod(c.AUDIT, 0o600)
    for n in create + overwrite:
        if meta[n].get("folder"):
            c.ensure_folders(meta[n]["folder"])
    c.use_home(c.DATA)                                # pick up a restored config.json
    c.audit("backup-restored", "", agent, f"{len(create)} created, {len(overwrite)} overwritten, {len(skip)} kept as they were")
    return dict(plan, restored=len(create) + len(overwrite))



# ---------- the backup plan: where, how many to keep, and when ----------
PLAN_LABEL = "com.secreds.backup"
DEFAULT_PLAN = {"destinations": [], "keep": 10, "schedule": "off", "hour": 2, "weekday": 0, "include_audit": True}
S3_PREFIX_RE = __import__("re").compile(r"^[A-Za-z0-9._/-]{0,128}$")


def _plan_file():
    return c.DATA / "backup-plan.json"


def get_plan():
    p = dict(DEFAULT_PLAN); p.update(c._read(_plan_file(), {}))
    return p


def _clean_plan(plan):
    db = c.list_creds(); out = dict(DEFAULT_PLAN)
    dests = []
    for d in (plan.get("destinations") or [])[:6]:
        t = d.get("type")
        if t == "icloud":
            dests.append({"type": "icloud"})
        elif t == "folder":
            path = str(d.get("path") or "").strip()
            if not path or len(path) > 1024 or "\n" in path or "\x00" in path:
                raise ValueError("Give a folder for the folder destination")
            dests.append({"type": "folder", "path": path})
        elif t == "s3":
            name = str(d.get("credential") or ""); m = db.get(name)
            if not m or m.get("kind") != "s3" or not m.get("bucket"):
                raise ValueError(f"'{name}' is not an S3 credential with a bucket")
            prefix = str(d.get("prefix") if d.get("prefix") is not None else "secreds-backups/")
            if not S3_PREFIX_RE.match(prefix) or prefix.startswith("/") or ".." in prefix:
                raise ValueError("The S3 folder name may use letters, digits and . _ - / only")
            dests.append({"type": "s3", "credential": name, "prefix": prefix})
        else:
            raise ValueError("Unknown destination type")
    out["destinations"] = dests
    try:
        keep = int(plan.get("keep", 10)); hour = int(plan.get("hour", 2)); wd = int(plan.get("weekday", 0))
    except (TypeError, ValueError):
        raise ValueError("Numbers only for how many to keep, the hour and the weekday")
    if keep != 0 and not (2 <= keep <= 999):
        raise ValueError("Keep between 2 and 999 backups (0 keeps all of them)")
    if not (0 <= hour <= 23 and 0 <= wd <= 6):
        raise ValueError("That hour or weekday is out of range")
    sch = plan.get("schedule", "off")
    if sch not in ("off", "daily", "weekly"):
        raise ValueError("The schedule must be off, daily or weekly")
    out.update(keep=keep, hour=hour, weekday=wd, schedule=sch, include_audit=bool(plan.get("include_audit", True)))
    if sch != "off":
        if not dests:
            raise ValueError("Choose at least one place to back up to before turning on a schedule")
        if not key_status()["configured"]:
            raise ValueError("Scheduled backups need the backup key (set it up first)")
    return out


def schedule_enabled():
    return (Path.home() / "Library" / "LaunchAgents" / f"{PLAN_LABEL}.plist").exists()


def _apply_schedule(plan):
    import plistlib, shutil, subprocess, sys
    p = Path.home() / "Library" / "LaunchAgents" / f"{PLAN_LABEL}.plist"
    uid = os.getuid()
    def lc(*a): return subprocess.run(["launchctl", *a], capture_output=True, text=True)
    if plan["schedule"] == "off":
        if p.exists():
            lc("bootout", f"gui/{uid}", str(p)); p.unlink()
        return
    exe = Path(shutil.which("secreds") or sys.argv[0]).resolve()
    when = {"Hour": plan["hour"], "Minute": 0}
    if plan["schedule"] == "weekly":
        when["Weekday"] = plan["weekday"]
    d = {"Label": PLAN_LABEL, "ProgramArguments": [str(exe), "backup", "--scheduled"], "StartCalendarInterval": when, "RunAtLoad": False,
         "EnvironmentVariables": {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "SECREDS_HOME": str(c.DATA)},
         "StandardOutPath": str(c.DATA / "backup-schedule.log"), "StandardErrorPath": str(c.DATA / "backup-schedule.log")}
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as f:
        plistlib.dump(d, f)
    lc("bootout", f"gui/{uid}", str(p))
    r = lc("bootstrap", f"gui/{uid}", str(p))
    if r.returncode:
        raise RuntimeError("macOS refused to start the schedule: " + (r.stderr.strip()[:150] or "unknown"))


def save_plan(plan, agent="gui"):
    """Save the backup plan (destinations, how many to keep, schedule). Needs Touch ID, since it decides where secrets go."""
    clean = _clean_plan(plan)
    c._confirm("change the backup plan")
    c._write(_plan_file(), clean); os.chmod(_plan_file(), 0o600)
    _apply_schedule(clean)
    c.audit("backup-plan-saved", "", agent, f"{len(clean['destinations'])} destination(s), keep {clean['keep']}, schedule {clean['schedule']}")
    return clean


def _s3_conn(name):
    m = c.get_meta(name)
    ep = re_sub_scheme(m.get("address", ""))
    if not ep or not m.get("access_key_id") or not m.get("bucket"):
        raise ValueError(f"S3 credential '{name}' needs an endpoint, access key ID and bucket")
    return {"host": ep, "region": m.get("region") or c._region_from(m.get("address", "")) or "us-east-1", "bucket": m["bucket"],
            "access": m["access_key_id"], "secret": c.kc_get(name)}


def re_sub_scheme(addr):
    return __import__("re").sub(r"^[a-z]+://", "", (addr or "").strip()).strip("/")


def _s3_call(conn, method, key, body=b""):
    """One AWS Signature V4 request (path style) with the standard library only. Returns (status, headers)."""
    import hashlib, hmac, urllib.error, urllib.parse, urllib.request
    now = datetime.datetime.now(datetime.timezone.utc); amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    uri = "/" + conn["bucket"] + "/" + urllib.parse.quote(key, safe="/-_.~")
    h = {"host": conn["host"], "x-amz-content-sha256": hashlib.sha256(body).hexdigest(), "x-amz-date": amz}
    if method == "PUT":
        h["content-md5"] = base64.b64encode(hashlib.md5(body).digest()).decode()
    signed = ";".join(sorted(h)); canon_h = "".join(f"{k}:{h[k]}\n" for k in sorted(h))
    canon = "\n".join([method, uri, "", canon_h, signed, h["x-amz-content-sha256"]])
    scope = f"{day}/{conn['region']}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = ("AWS4" + conn["secret"]).encode()
    for part in (day, conn["region"], "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    h["authorization"] = f"AWS4-HMAC-SHA256 Credential={conn['access']}/{scope}, SignedHeaders={signed}, Signature={sig}"
    req = urllib.request.Request(f"https://{conn['host']}{uri}", data=body if method == "PUT" else None, method=method,
                                 headers={k2: v for k2, v in h.items() if k2 != "host"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


def _s3_put(conn, key, data):
    st, _ = _s3_call(conn, "PUT", key, data)
    if st not in (200, 201):
        raise RuntimeError(f"The S3 service refused the upload (HTTP {st}). Check the bucket, key permissions and endpoint.")
    st, hd = _s3_call(conn, "HEAD", key)
    if st != 200 or int(hd.get("Content-Length", -1)) != len(data):
        raise RuntimeError("The upload could not be confirmed (the stored size does not match).")


def prune(folder, keep):
    """Delete the oldest backup files beyond `keep` (0 = keep all). Never touches recovery files or other files."""
    if not keep:
        return 0
    old = list_backups(folder)[keep:]
    for f in old:
        Path(f["path"]).unlink(missing_ok=True)
    return len(old)


def _local_dir(d):
    if d["type"] == "icloud":
        x = icloud_dir(create=True)
        if not x:
            raise RuntimeError("iCloud Drive is not available on this Mac")
        return x
    return Path(d["path"]).expanduser()


def run_plan(agent="gui", unattended=False):
    """Make one backup with the backup key and put it in every destination of the plan, then prune old copies.
    `unattended` (the scheduled job) skips Touch ID: the file can only be opened with your password, so it is safe to write."""
    import shutil, tempfile
    plan = get_plan(); dests = plan["destinations"]
    if not dests:
        raise ValueError("The backup plan has no destinations yet")
    if not key_status()["configured"]:
        raise ValueError("Backups from the plan need the backup key (set it up first)")
    results, tmp = [], None
    local = [d for d in dests if d["type"] in ("icloud", "folder")]
    try:
        if local:
            first = _local_dir(local[0])
        else:
            tmp = Path(tempfile.mkdtemp(prefix="secreds-")); first = tmp
        r = create_backup(first, None, include_audit=plan["include_audit"], agent=agent, confirm=not unattended)
        src = Path(r["path"]); data = src.read_bytes()
        for d in dests:
            label = {"icloud": "iCloud Drive", "folder": d.get("path", ""), "s3": f"S3 {d.get('credential', '')}"}[d["type"]]
            try:
                if d["type"] == "s3":
                    _s3_put(_s3_conn(d["credential"]), d["prefix"] + src.name, data)
                    results.append({"dest": label, "ok": True, "note": "uploaded and size confirmed (old copies are not deleted from S3: use the bucket's lifecycle rules)"})
                else:
                    folder = _local_dir(d)
                    if folder != first:
                        folder.mkdir(parents=True, exist_ok=True)
                        target = folder / src.name
                        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, "wb") as f:
                            f.write(data)
                        if target.stat().st_size != len(data):
                            raise RuntimeError("the copy is the wrong size")
                    n = prune(folder, plan["keep"])
                    results.append({"dest": label, "ok": True, "note": f"saved; removed {n} older backup(s)" if n else "saved"})
            except Exception as e:
                results.append({"dest": label, "ok": False, "note": str(e)[:200]})
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    ok = all(x["ok"] for x in results)
    _save_state(last_plan_run={"at": c.iso(c.now()), "ok": ok, "results": results, "file": src.name, "by": agent},
                last_backup_dir=str(first) if not tmp else "")
    c.audit("backup-plan-run", "", agent, f"{sum(x['ok'] for x in results)}/{len(results)} destinations ok" + ("" if ok else "; FAILED: " + "; ".join(x["dest"] for x in results if not x["ok"])))
    return {"ok": ok, "results": results, "file": src.name, "count": r["count"]}



# ---------- sync: bring this Mac up to date from the newest backup ----------
def newest_backup():
    """The newest backup file in any place this Mac knows: the plan's folders, iCloud Drive, the last backup folder."""
    dirs = []
    for d in get_plan()["destinations"]:
        if d["type"] in ("icloud", "folder"):
            try:
                dirs.append(_local_dir(d))
            except Exception:
                pass
    ic = icloud_dir()
    if ic:
        dirs.append(ic)
    if state().get("last_backup_dir"):
        dirs.append(Path(state()["last_backup_dir"]))
    best = None
    for d in dirs:
        for f in list_backups(d):
            if not best or f["modified"] > best["modified"]:
                best = f
    return best


def sync_preview(password, path=None, key_file=None):
    """What a sync would do, by name only: new here, different from here, identical. Nothing is changed."""
    path = path or (newest_backup() or {}).get("path")
    if not path:
        raise ValueError("No backup found in iCloud Drive or your backup folders yet")
    plan = restore_backup(path, password, mode="merge", dry_run=True, key_file=key_file)
    return {"file": path, "new": plan["create"], "different": plan["different"],
            "same": sorted(set(plan["skip_existing"]) - set(plan["different"]))}


def sync_apply(password, path=None, take=None, key_file=None, agent="gui"):
    """Add what is new from the newest backup, and take the backup's version of the names in `take`. Needs Touch ID."""
    path = path or (newest_backup() or {}).get("path")
    if not path:
        raise ValueError("No backup found in iCloud Drive or your backup folders yet")
    return restore_backup(path, password, mode="merge", agent=agent, key_file=key_file, also=take or [])
