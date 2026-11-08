import os, pathlib, unittest
from helpers import CoreCase, SECRET, c


def authz(name, agent, argv=None, reason="checking the lab state for a test", run_id=""):
    return c.authorize(name, agent, argv, reason=reason, run_id=run_id)


class PolicyTests(CoreCase):
    def test_allowed_agent_gets_the_value(self):
        self.add()
        self.assertEqual(authz("svc", "claude", ["echo"]), SECRET)

    def test_denials(self):
        self.add()
        with self.assertRaises(c.Denied): authz("svc", "codex", ["x"])          # not on the list
        with self.assertRaises(c.Denied): authz("svc", "", ["x"])               # caller unknown
        with self.assertRaises(c.Denied): authz("missing", "claude", ["x"])     # no such credential
        c.set_revoked("svc", True)
        with self.assertRaises(c.Denied): authz("svc", "claude", ["x"])         # revoked
        self.assertIn('"event": "denied"', self.audit_text())

    def test_expired_credential_is_denied(self):
        self.add(expires="2000-01-01T00:00:00+00:00")
        with self.assertRaises(c.Denied): authz("svc", "claude", ["x"])

    def test_human_only_is_never_released_to_an_agent(self):
        self.add(human_only=True, agents=["claude"])
        self.assertEqual(c.get_meta("svc")["agents"], [])        # agent list is cleared
        with self.assertRaises(c.Denied): authz("svc", "claude", ["x"])
        # defence in depth: even if the stored agent list were tampered with, the human-only flag still blocks agents
        db = c.list_creds(); db["svc"]["agents"] = ["claude"]; c._write(c.META, db)
        with self.assertRaises(c.Denied): authz("svc", "claude", ["x"])

    def test_ask_mode_needs_touch_id_and_the_window_is_shared(self):
        self.write_config(agents=["claude", "claude-work"], families={"claude-work": "claude"})
        self.add(mode="ask", window_minutes=60)
        authz("svc", "claude", ["x"])
        self.assertEqual(len(self.prompts), 1)
        authz("svc", "claude-work", ["x"])                # same family: no second prompt
        self.assertEqual(len(self.prompts), 1)
        self.assertIn('"agent": "claude-work"', self.audit_text())   # the log keeps the real profile

    def test_declined_touch_id_denies(self):
        self.add(mode="ask")
        self.touch = False
        with self.assertRaises(c.Denied): authz("svc", "claude", ["x"])

    def test_edits_need_touch_id(self):
        self.add()
        self.touch = False
        with self.assertRaises(ValueError): c.save_cred("svc", notes="x")
        with self.assertRaises(ValueError): c.delete_cred("svc")
        self.touch = True
        c.save_cred("svc", notes="x")
        self.assertEqual(c.get_meta("svc")["notes"], "x")

    def test_unknown_agents_names_are_rejected_by_config(self):
        self.write_config(agents=["bad name!", "claude"])
        self.assertEqual(c.AGENTS, ["claude"])

    def test_secret_is_never_written_to_meta_or_audit(self):
        self.add(); authz("svc", "claude", ["x"]); c.set_revoked("svc", True)
        for p in self.home.iterdir():
            if p.is_file():
                self.assertNotIn(SECRET, p.read_text(errors="ignore"), p.name)

    def test_acknowledgement_clears_when_the_situation_changes(self):
        self.add()
        c.set_ack("svc", "any_command", True)
        self.assertEqual(c.get_meta("svc")["acks"], ["any_command"])
        c.save_cred("svc", address="10.0.0.1")                 # unrelated edit keeps it
        self.assertEqual(c.get_meta("svc")["acks"], ["any_command"])
        c.save_cred("svc", allowed_commands=["python3 /bin/echo"])   # now limited: nothing left to acknowledge
        self.assertEqual(c.get_meta("svc")["acks"], [])
        with self.assertRaises(ValueError): c.set_ack("svc", "bogus", True)


class AllowlistTests(CoreCase):
    def test_exact_command_and_pinned_script(self):
        script = self.home / "audit.py"; script.write_text("print('v1')")
        self.add(allowed_commands=[f"python3 {script}"])
        authz("svc", "claude", ["python3", str(script)])
        authz("svc", "claude", ["python3", str(script), "--flag"])
        for argv in (["curl", "http://x"], ["sh", "-c", f"python3 {script}"], None):
            with self.assertRaises(c.Denied): authz("svc", "claude", argv)

    def test_editing_a_pinned_script_blocks_it_until_repinned(self):
        script = self.home / "audit.py"; script.write_text("print('v1')")
        self.add(allowed_commands=[f"python3 {script}"])
        script.write_text("print('tampered')")
        with self.assertRaises(c.Denied): authz("svc", "claude", ["python3", str(script)])
        self.touch = False
        with self.assertRaises(ValueError): c.repin("svc")      # re-pinning needs Touch ID
        self.touch = True
        c.repin("svc")
        authz("svc", "claude", ["python3", str(script)])

    def test_overly_broad_entries_are_rejected_before_anything_is_stored(self):
        for bad in ("bash", "bash -c 'x'", "python3 -c 'x'", "sudo ls"):
            with self.assertRaises(ValueError):
                c.save_cred("bad", SECRET, create=True, allowed_commands=[bad])
        self.assertNotIn("bad", self.store)                     # nothing leaked into the Keychain


class ReasonTests(CoreCase):
    def test_reason_is_required_and_audited(self):
        self.add()
        for bad in ("", "   ", "short"):
            with self.assertRaises(c.Denied) as cm:
                c.authorize("svc", "claude", ["echo"], reason=bad)
            self.assertIn("reason is required", str(cm.exception))
        self.assertEqual(c.read_audit(1)[0]["event"], "denied")
        c.authorize("svc", "claude", ["echo", "x"], reason="  check   pve101 running VMs  ", run_id="ab12cd34")
        e = [x for x in c.read_audit(10) if x["event"] == "used"][0]
        self.assertEqual(e["reason"], "check pve101 running VMs")      # whitespace tidied
        self.assertEqual(e["detail"], e["reason"])                      # the Detail column shows it
        self.assertEqual(e["cmd"], "echo (1 args)")
        self.assertEqual(e["run"], "ab12cd34")
        self.assertEqual(e["cwd"], os.getcwd())

    def test_reason_is_capped(self):
        self.add()
        c.authorize("svc", "claude", ["echo"], reason="x" * 500)
        self.assertEqual(len([x for x in c.read_audit(5) if x["event"] == "used"][0]["reason"]), c.REASON_MAX)

    def test_command_summary_never_includes_arguments(self):
        tok = "tok_SECRET_arg_123"
        for argv in (["curl", "-H", "Authorization: " + tok, "http://x"], ["sh", "-c", "echo " + tok], ["python3", "-c", tok]):
            self.assertNotIn(tok, c.cmd_summary(argv))
        self.assertTrue(c.cmd_summary(["sh", "-c", "echo hi"]).startswith("sh -c (inline script"))
        script = self.home / "s.py"
        script.write_text("print(1)")
        self.assertEqual(c.cmd_summary(["python3", str(script), "--flag", tok]), "python3 " + os.path.abspath(str(script)))

    def test_denial_keeps_the_reason_for_the_trail(self):
        self.add()
        with self.assertRaises(c.Denied):
            c.authorize("svc", "codex", ["x"], reason="trying something odd here")
        e = c.read_audit(1)[0]
        self.assertEqual((e["event"], e["reason"]), ("denied", "trying something odd here"))


if __name__ == "__main__":
    unittest.main()


class FingerprintAndNoteTests(CoreCase):
    def _script(self, text="print('hi')\n"):
        p = self.home / "job.py"; p.write_text(text); return p

    def test_fingerprint_is_logged_but_text_is_not_kept_by_default(self):
        import hashlib
        self.add(); s = self._script("print('TOP_SECRET_TEXT')\n")
        c.authorize("svc", "claude", ["python3", str(s)], reason="run the job script now")
        e = [x for x in c.read_audit(5) if x["event"] == "used"][0]
        self.assertEqual(e["sha256"], hashlib.sha256(s.read_bytes()).hexdigest())
        self.assertEqual(e["size"], s.stat().st_size)
        self.assertNotIn("kept", e)
        self.assertFalse((self.home / "scripts").exists())
        self.assertNotIn("TOP_SECRET_TEXT", json.dumps(c.read_audit(10)))

    def test_copy_kept_only_when_setting_on_and_owner_only(self):
        self.add(); s = self._script()
        c.CONFIG["keep_scripts"] = True
        try:
            c.authorize("svc", "claude", ["python3", str(s)], reason="run the job script now")
        finally:
            c.CONFIG.pop("keep_scripts", None)
        e = [x for x in c.read_audit(5) if x["event"] == "used"][0]
        f = self.home / "scripts" / (e["sha256"] + ".txt")
        self.assertTrue(e["kept"]); self.assertEqual(f.read_text(), "print('hi')\n")
        self.assertEqual(oct(f.stat().st_mode & 0o777), "0o600")

    def test_inline_script_is_hashed_not_stored(self):
        self.add()
        c.authorize("svc", "claude", ["sh", "-c", "echo hello"], reason="a quick inline command")
        e = [x for x in c.read_audit(5) if x["event"] == "used"][0]
        self.assertEqual(len(e["sha256"]), 64); self.assertNotIn("hello", json.dumps(e))

    def test_note_attaches_to_own_run_only(self):
        self.add()
        c.authorize("svc", "claude", ["echo"], reason="check something harmless", run_id="r1r1r1r1")
        c.add_note("r1r1r1r1", "  updated   the thing to v2  ", "claude")
        n = [x for x in c.read_audit(5) if x["event"] == "note"][0]
        self.assertEqual((n["detail"], n["run"], n["name"], n["agent"]), ("updated the thing to v2", "r1r1r1r1", "svc", "claude"))
        with self.assertRaises(ValueError): c.add_note("nope", "x", "claude")                 # no such run
        with self.assertRaises(ValueError): c.add_note("r1r1r1r1", "x", "")                   # not an agent
        with self.assertRaises(ValueError): c.add_note("r1r1r1r1", "   ", "claude")           # empty
        c.CONFIG["agents"] = c.AGENTS  # codex is a different agent: cannot annotate claude's run
        with self.assertRaises(ValueError): c.add_note("r1r1r1r1", "hijack", "codex")


import json  # noqa: E402  (used above)


class AddressInLogTests(CoreCase):
    def test_used_entry_carries_the_credentials_configured_address(self):
        self.add(address="10.0.0.1")
        c.authorize("svc", "claude", ["echo"], reason="check the address is logged")
        self.assertEqual([x for x in c.read_audit(5) if x["event"] == "used"][0]["addr"], "10.0.0.1")
        self.add(name="noaddr")
        c.authorize("noaddr", "claude", ["echo"], reason="no address configured here")
        self.assertNotIn("addr", [x for x in c.read_audit(5) if x["event"] == "used" and x["name"] == "noaddr"][0])


class DefaultWindowTests(CoreCase):
    def test_new_credentials_default_to_a_30_minute_window(self):
        self.assertEqual(c.DEFAULT_WINDOW, 30)
        c.save_cred("fresh", "v", kind="api-key", agents=["claude"], create=True)
        self.assertEqual(c.get_meta("fresh")["window_minutes"], 30)
