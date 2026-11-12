"""Regression tests for the 0.6.5 code-review fixes."""
import base64, json, os, stat, sys, tempfile, threading, unittest, pathlib
from helpers import CoreCase, SECRET
from secreds import core as c
from secreds.mask import Masker


def run_mask(secrets, chunks):
    m = Masker(secrets); out = b""
    for ch in chunks:
        out += m.feed(ch)
    return out + m.flush()


class MaskTests(unittest.TestCase):
    def test_plain_and_split_across_chunks(self):
        s = "tok-ABCDEF123456"
        self.assertEqual(run_mask([s], [f"a {s} b".encode()]), b"a *** b")
        data = f"x {s} y".encode()
        for cut in range(1, len(data)):
            self.assertEqual(run_mask([s], [data[:cut], data[cut:]]), b"x *** y", cut)

    def test_multiline_secret(self):
        key = "-----BEGIN KEY-----\nAAAAAAAAAAAAAAAA\nBBBBBBBBBBBBBBBB\n-----END KEY-----"
        out = run_mask([key], [(f"before\n{key}\nafter\n").encode()])
        self.assertNotIn(b"AAAAAAAA", out); self.assertNotIn(b"BBBBBBBB", out)
        self.assertIn(b"before", out); self.assertIn(b"after", out)

    def test_encoded_forms(self):
        s = "p@ss/w0rd+value=1"
        forms = [base64.b64encode(s.encode()), base64.urlsafe_b64encode(s.encode()), json.dumps(s)[1:-1].encode(),
                 b"p%40ss%2Fw0rd%2Bvalue%3D1", base64.b64encode(f"user:{s}".encode())]
        for form in forms[:4]:
            self.assertNotIn(form, run_mask([s], [b"hdr " + form + b" end"]), form)
        # a Basic-auth header is base64("user:secret"); the run command adds that pair for login credentials
        self.assertNotIn(forms[4], run_mask([s, f"user:{s}"], [b"Authorization: Basic " + forms[4]]))

    def test_unrelated_output_passes_and_tail_is_flushed(self):
        self.assertEqual(run_mask(["secret-value-9"], [b"hello world\n", b"sec"]), b"hello world\nsec")

    def test_short_values_do_not_shred_output(self):
        self.assertEqual(run_mask(["ab"], [b"abab cab"]), b"abab cab")


class FixTests(CoreCase):
    def test_parse_handles_z_and_naive(self):
        self.assertIsNotNone(c.parse("2030-01-01T00:00:00Z").tzinfo)
        self.assertIsNotNone(c.parse("2030-01-01").tzinfo)
        self.assertTrue(c.parse("2030-01-01") > c.now())

    def test_naive_expires_is_normalised_and_does_not_crash(self):
        rec = self.add(expires="2030-01-01")
        self.assertTrue(rec["expires"].endswith(("+00:00",)) or "+" in rec["expires"] or "-" in rec["expires"][10:])
        c.authorize("svc", "claude", ["true"], reason="a long enough reason")      # no TypeError
        with self.assertRaises(ValueError):
            self.add("bad", expires="not a date")

    def test_old_naive_expiry_in_meta_still_works(self):
        self.add()
        db = c.list_creds(); db["svc"]["expires"] = "2020-01-01T00:00:00"; c._write(c.META, db)
        with self.assertRaises(c.Denied):
            c.authorize("svc", "claude", ["true"], reason="a long enough reason")

    def test_allowlist_requires_existing_absolute_script(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("print(1)")
        try:
            c.cmd_tokens(f"python3 {f.name}", validate=True)
            with self.assertRaises(ValueError):
                c.cmd_tokens("python3 ./deploy.py", validate=True)
            with self.assertRaises(ValueError):
                c.cmd_tokens("python3 /nonexistent/dir/deploy.py", validate=True)
            c.cmd_tokens("aws s3 ls --region us-east-1 s3://bucket/key", validate=True)      # flags, URLs, plain words are fine
            rec = self.add("pinned", allowed_commands=[f"python3 {f.name}"])
            self.assertTrue(rec["allowed_commands"][0]["pins"])
        finally:
            os.unlink(f.name)

    def test_read_audit_tail_limit_and_bad_lines(self):
        for i in range(30):
            c.audit("e", f"n{i}")
        with open(c.AUDIT, "a") as fh:
            fh.write("{broken line\n")
        c.audit("last", "z")
        got = c.read_audit(5)
        self.assertEqual([e["event"] for e in got][:2], ["last", "e"])
        self.assertEqual(len(got), 5)
        self.assertEqual(len(c.read_audit(500)), 31)           # the damaged line is skipped, not fatal

    def test_audit_rotates(self):
        old = c.AUDIT_MAX_BYTES; c.AUDIT_MAX_BYTES = 200
        try:
            for i in range(20):
                c.audit("e", f"n{i}")
        finally:
            c.AUDIT_MAX_BYTES = old
        self.assertTrue((self.home / "audit.log.1").exists())

    def test_delete_keeps_credential_when_keychain_refuses(self):
        self.add()
        def boom(n): raise RuntimeError("Keychain delete failed (-1)")
        c.kc_delete = boom
        with self.assertRaises(RuntimeError):
            c.delete_cred("svc")
        self.assertIn("svc", c.list_creds())
        c.kc_delete = lambda n: self.store.pop(n, None)
        c.delete_cred("svc")
        self.assertNotIn("svc", c.list_creds())

    def test_touch_id_is_not_asked_while_holding_the_lock(self):
        self.add()
        held = []
        def probe(reason, timeout=0):
            import fcntl
            f = open(self.home / ".lock", "w")
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB); held.append(False)
            except OSError:
                held.append(True)
            finally:
                f.close()
            return True
        c.touch_id = probe
        c.save_cred("svc", None, kind="api-key", agents=["claude"], mode="auto", window_minutes=30)
        self.assertEqual(held, [False])

    def test_masked_uses_stored_hint_and_does_not_read_the_keychain(self):
        self.add(value="abcdefghijklmnop")
        self.assertEqual(c.masked("svc"), "********mnop")
        reads = []
        c.kc_get = lambda n: reads.append(n) or "x"
        self.assertEqual(c.masked("svc"), "********mnop")
        self.assertEqual(reads, [])
        db = c.list_creds(); db["svc"].pop("hint"); c._write(c.META, db)       # an entry from before the hint existed
        c.kc_get = self._kc_get
        self.assertEqual(c.masked("svc"), "********mnop")
        self.assertEqual(c.list_creds()["svc"]["hint"], "mnop")

    def test_ticket_is_private_and_names_the_credential(self):
        tid = c._issue_ticket("svc")
        p = self.home / "tickets" / tid
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(json.loads(p.read_text())["name"], "svc")
        self.assertEqual(len(tid), 64)

    def test_sanitize_meta_keeps_local_restrictions(self):
        self.add(agents=["claude"])
        c.set_revoked("svc", True)
        local = c.list_creds()["svc"]
        backup = dict(local, revoked=False, agents=["claude", "codex"], mode="auto")
        clean, notes = c.sanitize_meta(backup, local)
        self.assertTrue(clean["revoked"])
        self.assertTrue(any("agents" in n for n in notes))

    def test_sanitize_meta_rejects_damaged_entries(self):
        self.add()
        good = c.list_creds()["svc"]
        for bad in (dict(good, env_var="bad name"), dict(good, mode="open"), dict(good, allowed_commands=["bash -c x"]),
                    dict(good, allowed_commands=[{"cmd": "sudo ls"}]), "text"):
            with self.assertRaises(ValueError):
                c.sanitize_meta(bad)


if __name__ == "__main__":
    unittest.main()
