"""Reference entries: a record with no secret (for example how keyless SSH to a host is set up)."""
import json, threading, unittest, urllib.request
from helpers import CoreCase, SECRET, c
from secreds import backup, gui
from test_cli_and_gui import run_cli

NOTE = "SSH via the st-pve aliases and the Mac's agent. No password."


class ReferenceCoreTests(CoreCase):
    def ref(self, name="lab-ssh", **kw):
        kw.setdefault("agents", ["claude"]); kw.setdefault("kind", "ssh-key"); kw.setdefault("notes", NOTE)
        return c.save_cred(name, None, create=True, reference=True, **kw)

    def test_a_reference_entry_needs_no_value_and_writes_nothing_to_the_keychain(self):
        rec = self.ref()
        self.assertTrue(rec["reference"]); self.assertEqual(self.store, {})

    def test_a_normal_entry_still_needs_a_value(self):
        with self.assertRaises(ValueError): c.save_cred("x", None, create=True, kind="api-key")

    def test_a_reference_entry_refuses_a_value(self):
        with self.assertRaises(ValueError): c.save_cred("x", "oops", create=True, reference=True, kind="other")
        self.assertEqual(self.store, {})

    def test_running_it_is_refused_and_points_to_info(self):
        self.ref()
        with self.assertRaises(c.Denied) as cm: c.authorize("lab-ssh", "claude", ["ssh"], reason="try to use a reference entry")
        self.assertIn("secreds info lab-ssh", str(cm.exception))
        self.assertIn("reference entry", self.audit_text())

    def test_info_returns_the_non_secret_details_to_an_allowed_agent(self):
        self.ref(address="192.168.111.101-106", folder="Lab", scope="personal", network="lan")
        d = c.info("lab-ssh", "claude")
        self.assertEqual(d["notes"], NOTE); self.assertEqual(d["address"], "192.168.111.101-106"); self.assertEqual(d["folder"], "Lab")
        self.assertIn('"event": "info"', self.audit_text())

    def test_info_is_refused_for_other_agents_revoked_entries_and_real_credentials(self):
        self.ref(); self.add("real", agents=["claude"])
        with self.assertRaises(c.Denied): c.info("lab-ssh", "codex")          # not on the list
        with self.assertRaises(c.Denied): c.info("lab-ssh", "")               # unknown caller
        with self.assertRaises(c.Denied): c.info("real", "claude")            # holds a secret: info never applies
        with self.assertRaises(c.Denied): c.info("missing", "claude")
        c.set_revoked("lab-ssh", True)
        with self.assertRaises(c.Denied): c.info("lab-ssh", "claude")

    def test_reveal_and_copy_have_nothing_to_show(self):
        self.ref()
        with self.assertRaises(ValueError): c.reveal("lab-ssh")
        with self.assertRaises(ValueError): c.copy_value("lab-ssh")

    def test_a_credential_that_holds_a_secret_cannot_be_turned_into_a_reference_by_accident(self):
        self.add("real")
        with self.assertRaises(ValueError): c.save_cred("real", None, reference=True, kind="api-key")
        self.assertEqual(self.store["real"], SECRET)                          # the secret is untouched

    def test_a_reference_entry_becomes_a_real_credential_only_with_a_value(self):
        self.ref()
        with self.assertRaises(ValueError): c.save_cred("lab-ssh", None, reference=False, kind="api-key")
        c.save_cred("lab-ssh", "now-a-secret", reference=False, kind="api-key")
        self.assertEqual(self.store["lab-ssh"], "now-a-secret"); self.assertFalse(c.get_meta("lab-ssh")["reference"])

    def test_editing_notes_keeps_it_a_reference_entry(self):
        self.ref()
        c.save_cred("lab-ssh", None, kind="ssh-key", notes="changed", agents=["claude"])
        m = c.get_meta("lab-ssh"); self.assertTrue(m["reference"]); self.assertEqual(m["notes"], "changed")

    def test_deleting_a_reference_entry_works(self):
        self.ref(); c.delete_cred("lab-ssh"); self.assertNotIn("lab-ssh", c.list_creds())


@unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"), "cryptography not installed")
class ReferenceTransferTests(CoreCase):
    def test_export_import_roundtrip_keeps_a_reference_entry_without_a_value(self):
        c.save_cred("lab-ssh", None, create=True, reference=True, kind="ssh-key", notes=NOTE, agents=["claude"])
        self.add("real")
        bundle = self.home / "bundle.json"
        c.export_bundle(bundle, "correct horse battery")
        c.delete_cred("lab-ssh"); c.delete_cred("real")
        self.assertEqual(sorted(c.import_bundle(bundle, "correct horse battery")), ["lab-ssh", "real"])
        self.assertTrue(c.get_meta("lab-ssh")["reference"]); self.assertNotIn("lab-ssh", self.store); self.assertEqual(self.store["real"], SECRET)

    def test_backup_carries_the_reference_entry_and_does_not_report_a_missing_secret(self):
        kdf, backup.KDF_N = backup.KDF_N, 2 ** 14
        try:
            c.save_cred("lab-ssh", None, create=True, reference=True, kind="ssh-key", notes=NOTE, agents=["claude"])
            self.add("real")
            r = backup.create_backup(self.home / "bk", "correct horse battery staple")
            c.delete_cred("lab-ssh"); c.delete_cred("real")
            plan = backup.restore_backup(r["path"], "correct horse battery staple", dry_run=True)
            self.assertEqual(plan["create"], ["lab-ssh", "real"]); self.assertEqual(plan["no_secret_in_backup"], [])
            backup.restore_backup(r["path"], "correct horse battery staple")
            self.assertTrue(c.get_meta("lab-ssh")["reference"]); self.assertNotIn("lab-ssh", self.store)
        finally:
            backup.KDF_N = kdf


class ReferenceCliTests(CoreCase):
    def test_add_reference_does_not_prompt_and_info_prints_the_notes(self):
        code, out, _ = run_cli("add", "lab-ssh", "--kind", "ssh-key", "--reference", "--agents", "claude", "--notes", NOTE, "--address", "192.168.111.101-106")
        self.assertEqual(code, 0); self.assertIn("reference entry", out); self.assertEqual(self.store, {})
        code, out, _ = run_cli("info", "lab-ssh", env={"SECREDS_AGENT": "claude"})
        self.assertEqual(code, 0); self.assertIn(NOTE, out); self.assertIn("192.168.111.101-106", out); self.assertIn("no secret stored", out)

    def test_run_on_a_reference_entry_fails_with_a_pointer_to_info(self):
        c.save_cred("lab-ssh", None, create=True, reference=True, kind="ssh-key", agents=["claude"])
        code, out, err = run_cli("run", "lab-ssh", "--reason", "check refusal of a reference entry", "--", "echo", "hi", env={"SECREDS_AGENT": "claude"})
        self.assertNotEqual(code, 0); self.assertNotIn("hi", out); self.assertIn("secreds info lab-ssh", err + out)

    def test_info_on_a_real_credential_is_refused(self):
        self.add("real")
        code, _, err = run_cli("info", "real", env={"SECREDS_AGENT": "claude"})
        self.assertNotEqual(code, 0); self.assertNotIn(SECRET, err)

    def test_list_marks_reference_entries(self):
        c.save_cred("lab-ssh", None, create=True, reference=True, kind="ssh-key", agents=["claude"])
        code, out, _ = run_cli("list"); self.assertIn("REFERENCE", out)

    def test_an_agent_can_request_a_reference_entry(self):
        code, out, _ = run_cli("request", "vultr-ssh", "--kind", "ssh-key", "--reference", "--notes", NOTE, env={"SECREDS_AGENT": "claude"})
        self.assertEqual(code, 0); self.assertTrue(c.list_requests()["vultr-ssh"]["reference"])


class ReferenceGuiTests(CoreCase):
    def setUp(self):
        super().setUp()
        c.save_cred("lab-ssh", None, create=True, reference=True, kind="ssh-key", notes=NOTE, agents=["claude"])
        self.srv = gui.Srv(("127.0.0.1", 0), gui.H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close(); super().tearDown()

    def call(self, path, body=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"X-Token": gui.TOKEN, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r: return json.loads(r.read().decode() or "{}")

    def test_state_shows_it_as_present_with_nothing_masked(self):
        m = [x for x in self.call("/api/state")["creds"] if x["name"] == "lab-ssh"][0]
        self.assertTrue(m["reference"]); self.assertTrue(m["in_keychain"]); self.assertEqual(m["masked"], "")

    def test_the_save_endpoint_creates_a_reference_entry_without_a_value(self):
        self.call("/api/save", {"create": True, "name": "other-ssh", "kind": "ssh-key", "reference": True, "agents": ["claude"], "value": ""})
        self.assertTrue(c.get_meta("other-ssh")["reference"]); self.assertNotIn("other-ssh", self.store)

    def test_the_page_has_the_reference_checkbox_and_hides_reveal_for_reference_entries(self):
        with urllib.request.urlopen(urllib.request.Request(self.base + "/?t=" + gui.TOKEN), timeout=5) as r: page = r.read().decode()
        self.assertIn("f_ref", page); self.assertIn("Reference entry: no secret is stored", page)


if __name__ == "__main__":
    unittest.main()
