import contextlib, io, json, os, pathlib, re, shutil, subprocess, sys, threading, unittest, urllib.error, urllib.request
from helpers import CoreCase, SECRET, c
from secreds import cli, gui


def run_cli(*argv, env=None):
    old_argv, old_env = sys.argv, dict(os.environ)
    sys.argv = ["secreds", *argv]
    os.environ.pop("SECREDS_AGENT", None); os.environ.pop("CLAUDECODE", None); os.environ.update(env or {})
    out, err, code = io.StringIO(), io.StringIO(), 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try: cli.main()
            except SystemExit as e: code = e.code or 0
    finally:
        sys.argv = old_argv; os.environ.clear(); os.environ.update(old_env)
    return code, out.getvalue(), err.getvalue()


class CliTests(CoreCase):
    def test_run_injects_the_value_and_masks_it_in_output(self):
        self.add()
        code, out, err = run_cli("run", "svc", "--reason", "run the unit test command", "--", sys.executable, "-c", "import os; print('got', os.environ['SVC'])", env={"SECREDS_AGENT": "claude"})
        self.assertEqual(code, 0); self.assertIn("got ***", out); self.assertNotIn(SECRET, out + err)
        self.assertIn("NOTICE TO AI AGENTS", err)               # the agent notice is shown on every use

    def test_run_records_reason_command_and_result(self):
        self.add()
        code, _, _ = run_cli("run", "svc", "--reason", "prove the audit trail records it", "--", sys.executable, "-c", "raise SystemExit(5)", env={"SECREDS_AGENT": "claude"})
        self.assertEqual(code, 5)
        ev = {e["event"]: e for e in c.read_audit(10) if e["event"] in ("used", "finished")}
        self.assertEqual(ev["used"]["reason"], "prove the audit trail records it")
        self.assertIn("inline script", ev["used"]["cmd"])
        self.assertEqual(ev["used"]["run"], ev["finished"]["run"])       # the two lines share a run id
        self.assertEqual((ev["finished"]["rc"], ev["finished"]["name"]), (5, "svc"))

    def test_note_command_and_run_id_is_shown(self):
        self.add()
        code, _, err = run_cli("run", "svc", "--reason", "produce a run id to annotate", "--", "true", env={"SECREDS_AGENT": "claude"})
        rid = re.search(r"RUN_ID for secreds note: (\w+)", err).group(1)
        self.assertEqual(run_cli("note", rid, "did the thing", env={"SECREDS_AGENT": "claude"})[0], 0)
        self.assertEqual(run_cli("note", "badbadba", "x", env={"SECREDS_AGENT": "claude"})[0], 3)
        self.assertEqual(run_cli("note", rid, "no identity")[0], 3)

    def test_run_refuses_unknown_callers_and_other_agents(self):
        self.add()
        self.assertEqual(run_cli("run", "svc", "--reason", "a perfectly fine reason", "--", "true")[0], 3)   # no agent identity
        self.assertEqual(run_cli("run", "svc", "--", "true", env={"SECREDS_AGENT": "claude"})[0], 3)   # allowed agent but no reason
        self.assertEqual(run_cli("run", "svc", "--reason", "a perfectly fine reason", "--", "true", env={"SECREDS_AGENT": "codex"})[0], 3)   # not allowed

    def test_request_and_list_commands(self):
        code, out, _ = run_cli("request", "new-one", "--kind", "login", "--address", "10.0.0.5", env={"SECREDS_AGENT": "claude"})
        self.assertEqual(code, 0); self.assertIn("new-one", run_cli("requests")[1])
        self.add("svc"); self.assertIn("svc", run_cli("list")[1])

    def test_init_writes_config(self):
        code, out, _ = run_cli("init", "--owner", "Alex", "--agents", "claude,claude-work,codex", "--family", "claude-work=claude")
        self.assertEqual(code, 0); self.assertEqual(c.FAMILY, {"claude-work": "claude"}); self.assertEqual(c.PICKABLE, ["claude", "codex"])
        self.assertEqual(run_cli("init")[0], 1)                  # refuses to overwrite without --force


class GuiServerTests(CoreCase):
    def setUp(self):
        super().setUp()
        self.add("shown", folder="F")
        self.srv = gui.Srv(("127.0.0.1", 0), gui.H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close(); super().tearDown()

    def get(self, path, headers=None):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r: return r.status, r.read().decode()
        except urllib.error.HTTPError as e: return e.code, ""

    def test_idle_timer_counts_real_activity_but_not_the_pages_own_refresh(self):
        tok = {"X-Token": gui.TOKEN}
        gui.LAST["t"] = 1.0
        self.get("/api/state", {**tok, "X-Poll": "1"})                 # the page's 15 s refresh: not activity
        self.assertEqual(gui.LAST["t"], 1.0)
        self.assertEqual(self.get("/api/ping", tok)[0], 200)           # real input reported by the page: activity
        self.assertGreater(gui.LAST["t"], 1.0)
        gui.LAST["t"] = 1.0
        self.assertEqual(self.get("/api/ping")[0], 404)                          # no token: no ping...
        self.assertEqual(self.get("/api/ping", {"X-Token": "wrong"})[0], 404)
        self.assertEqual(gui.LAST["t"], 1.0)                                     # ...and no effect on the idle timer

    def test_page_sends_the_activity_heartbeat(self):
        self.assertIn("/api/ping", gui.PAGE)
        self.assertIn("pointerdown", gui.PAGE)

    def test_page_and_api_need_the_session_token(self):
        self.assertEqual(self.get("/")[0], 403)
        self.assertEqual(self.get(f"/?t={gui.TOKEN}")[0], 200)
        self.assertIn(self.get("/api/state")[0], (403, 404))
        self.assertEqual(self.get("/api/state", {"X-Token": gui.TOKEN})[0], 200)

    def test_other_host_names_are_refused(self):
        self.assertEqual(self.get("/api/state", {"X-Token": gui.TOKEN, "Host": "evil.example"})[0], 403)

    def test_state_never_contains_a_secret_value(self):
        status, body = self.get("/api/state", {"X-Token": gui.TOKEN})
        data = json.loads(body)
        self.assertNotIn(SECRET, body)
        self.assertEqual(data["creds"][0]["name"], "shown"); self.assertTrue(data["creds"][0]["masked"].startswith("********"))

    def test_post_without_token_is_refused(self):
        req = urllib.request.Request(self.base + "/api/delete", data=b'{"name":"shown"}', method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm: urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 403); self.assertIn("shown", c.list_creds())

    def test_page_script_is_valid_javascript(self):
        node = shutil.which("node")
        if not node: self.skipTest("node not installed")
        js = re.findall(r"<script>(.*?)</script>", gui.PAGE.replace("__TOKEN__", "t"), re.S)[0]
        p = self.home / "page.js"; p.write_text(js)
        r = subprocess.run([node, "--check", str(p)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class TransferTests(CoreCase):
    @unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"), "cryptography not installed")
    def test_export_import_roundtrip_with_wrong_passphrase_failing(self):
        self.add("a", kind="login", username="u", address="10.0.0.1", folder="F")
        bundle = self.home / "bundle.json"
        c.export_bundle(bundle, "correct horse battery")
        self.assertNotIn(SECRET, bundle.read_text())            # the bundle is encrypted
        with self.assertRaises(Exception): c.import_bundle(bundle, "wrong passphrase")
        c.delete_cred("a")
        self.assertEqual(c.import_bundle(bundle, "correct horse battery"), ["a"])
        self.assertEqual(c.kc_get("a"), SECRET); self.assertEqual(c.get_meta("a")["folder"], "F")


if __name__ == "__main__":
    unittest.main()


class BackupUpdateCliTests(CoreCase):
    def setUp(self):
        super().setUp()
        from secreds import backup
        self.backup = backup; self._kdf, backup.KDF_N = backup.KDF_N, 2 ** 14
        import getpass; self._gp = getpass.getpass
        self.passes = []
        getpass.getpass = lambda prompt="": self.passes.pop(0)
        self.add("alpha", kind="login", username="u", value="alpha-secret-AAAA-1111")

    def tearDown(self):
        import getpass; getpass.getpass = self._gp; self.backup.KDF_N = self._kdf; super().tearDown()

    def test_backup_to_a_folder_then_restore_on_a_new_home(self):
        dest = self.home / "somewhere"
        self.passes = ["correct horse battery staple"] * 2
        code, out, _ = run_cli("backup", "--to", str(dest))
        self.assertEqual(code, 0); self.assertIn("verified", out); self.assertNotIn("alpha-secret", out)
        file = next(dest.glob("secreds-backup-*.secreds"))
        self.passes = ["correct horse battery staple"]; code, out, _ = run_cli("backups", "--in", str(dest)); self.assertIn(file.name, out)
        import pathlib, tempfile
        self.store.clear(); c.use_home(pathlib.Path(tempfile.mkdtemp()))
        self.passes = ["correct horse battery staple"]; code, out, _ = run_cli("restore-backup", str(file), "--dry-run")
        self.assertEqual(code, 0); self.assertIn("Would create 1", out); self.assertNotIn("alpha", self.store)
        self.passes = ["correct horse battery staple"]; code, out, _ = run_cli("restore-backup", str(file), "--yes")
        self.assertEqual(code, 0); self.assertEqual(self.store["alpha"], "alpha-secret-AAAA-1111")

    def test_backup_needs_a_destination_and_matching_passphrases(self):
        self.assertEqual(run_cli("backup")[0], 1)
        self.passes = ["correct horse battery staple", "something else entirely"]
        self.assertEqual(run_cli("backup", "--to", str(self.home / "d"))[0], 1)

    def test_wrong_passphrase_exits_with_an_error(self):
        self.passes = ["correct horse battery staple"] * 2; run_cli("backup", "--to", str(self.home / "d"))
        file = next((self.home / "d").glob("*.secreds"))
        self.passes = ["wrong passphrase"]; code, out, err = run_cli("restore-backup", str(file), "--dry-run")
        self.assertEqual(code, 1); self.assertIn("Wrong passphrase", err)

    def test_update_command_reports_without_installing(self):
        from secreds import updater
        saved = updater.latest_release
        updater.latest_release = lambda repo: {"tag_name": "v9.9.9", "body": "notes"}
        try:
            code, out, _ = run_cli("update", "--now")
        finally:
            updater.latest_release = saved
        self.assertEqual(code, 0); self.assertIn("Update available: 9.9.9", out)


class GuiBackupUpdateTests(CoreCase):
    PASS = "correct horse battery staple"

    def setUp(self):
        super().setUp()
        from secreds import backup, updater
        self.backup, self.updater = backup, updater
        self._kdf, backup.KDF_N = backup.KDF_N, 2 ** 14
        self._gui_saved = (gui._pick, updater.latest_release, updater.notify)
        gui._pick = lambda kind: str(self.home / "picked")
        updater.latest_release = lambda repo: {"tag_name": "v9.9.9", "body": "notes"}
        self.add("alpha", value="alpha-secret-AAAA-1111")
        self.srv = gui.Srv(("127.0.0.1", 0), gui.H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        gui._pick, self.updater.latest_release, self.updater.notify = self._gui_saved
        self.backup.KDF_N = self._kdf; self.srv.shutdown(); self.srv.server_close(); super().tearDown()

    def post(self, path, body, token=True):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **({"X-Token": gui.TOKEN} if token else {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r: return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")

    def test_new_endpoints_need_the_session_token(self):
        for path in ("/api/backup", "/api/restore-backup", "/api/update-apply", "/api/update-check", "/api/update-daily", "/api/pick"):
            self.assertEqual(self.post(path, {}, token=False)[0], 403, path)

    def test_state_reports_backup_and_update_status_without_secrets(self):
        status, body = (lambda r: (r.status, r.read().decode()))(urllib.request.urlopen(urllib.request.Request(self.base + "/api/state", headers={"X-Token": gui.TOKEN})))
        data = json.loads(body)
        self.assertIn("backup", data); self.assertIn("update", data); self.assertEqual(data["update"]["current"], data["version"])
        self.assertNotIn("alpha-secret-AAAA-1111", body)

    def test_backup_and_restore_check_through_the_gui(self):
        dest = str(self.home / "dest")
        code, r = self.post("/api/backup", {"dest": dest, "passphrase": self.PASS, "include_audit": True})
        self.assertEqual((code, r["count"], r["verified"]), (200, 1, True))
        self.assertNotIn("alpha-secret", json.dumps(r))
        code, plan = self.post("/api/restore-backup", {"path": r["path"], "passphrase": self.PASS, "mode": "merge", "dry_run": True})
        self.assertEqual((code, plan["skip_existing"]), (200, ["alpha"]))
        code, err = self.post("/api/restore-backup", {"path": r["path"], "passphrase": "wrong wrong wrong wrong", "dry_run": True})
        self.assertEqual(code, 400); self.assertIn("Wrong passphrase", err["error"])
        code, err = self.post("/api/backup", {"dest": dest, "passphrase": "short"})
        self.assertEqual(code, 400); self.assertIn("at least", err["error"])
        code, err = self.post("/api/backup", {"passphrase": self.PASS})
        self.assertEqual(code, 400)                                                           # no destination chosen

    def test_picker_returns_the_chosen_path(self):
        self.assertEqual(self.post("/api/pick", {"kind": "folder"})[1]["path"], str(self.home / "picked"))

    def test_update_check_reads_and_apply_is_gated(self):
        code, st = self.post("/api/update-check", {}); self.assertEqual((code, st["available"], st["latest_tag"]), (200, True, "v9.9.9"))
        self.touch = False
        code, err = self.post("/api/update-apply", {}); self.assertEqual(code, 400)           # declined Touch ID: nothing installed
        self.assertIn("Touch ID", err["error"])


