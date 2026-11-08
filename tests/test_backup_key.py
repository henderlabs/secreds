import json, pathlib, unittest
from helpers import CoreCase, c
from secreds import backup

PW = "river lantern copper meadow quiet"


@unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"), "cryptography not installed")
class BackupKeyTests(CoreCase):
    def setUp(self):
        super().setUp()
        self._kdf, backup.KDF_N = backup.KDF_N, 2 ** 14
        self.add("alpha", kind="login", username="u", value="alpha-secret-AAAA-1111")
        self.dest = self.home / "backups"; self.rec = self.home / "recovery"; self.rec2 = self.home / "usb"

    def tearDown(self):
        backup.KDF_N = self._kdf
        super().tearDown()

    def test_setup_rules(self):
        for bad in ("short", "a" * 20, ""):
            with self.assertRaises(ValueError): backup.setup_key(bad, [self.rec])
        with self.assertRaises(ValueError): backup.setup_key(PW, [])
        self.assertFalse(backup.key_status()["configured"])

    def test_backup_without_setup_needs_a_passphrase(self):
        with self.assertRaises(ValueError): backup.create_backup(self.dest)

    def test_setup_writes_verified_recovery_files_and_mac_keeps_no_private_key(self):
        r = backup.setup_key(PW, [self.rec, self.rec2])
        self.assertEqual(len(r["files"]), 2)
        for f in r["files"]:
            backup.unlock_recovery(f, PW)
            with self.assertRaises(ValueError): backup.unlock_recovery(f, "wrong wrong wrong wrong")
        st = backup.key_status(); self.assertTrue(st["configured"]); self.assertEqual(len(st["recovery_files"]), 2)
        keyfile = json.loads((c.DATA / "backup-key.json").read_text())
        self.assertEqual(set(keyfile), {"format", "version", "public", "key_id", "created"})   # public half only
        with self.assertRaises(ValueError): backup.setup_key(PW, [self.rec])                   # no silent replace

    def test_key_backup_needs_no_password_and_restores_with_it(self):
        backup.setup_key(PW, [self.dest])                       # recovery file next to the backups
        r = backup.create_backup(self.dest)
        self.assertEqual(r["method"], "key"); self.assertEqual(r["count"], 1)
        text = pathlib.Path(r["path"]).read_text()
        self.assertNotIn("alpha-secret", text); self.assertNotIn(PW, text)
        info = backup.backup_info(r["path"], PW)                # recovery file found beside the backup
        self.assertEqual(info["names"], ["alpha"])
        self.assertIn("last_restore_check", backup.state())
        with self.assertRaises(ValueError): backup.backup_info(r["path"], "wrong wrong wrong wrong")
        plan = backup.restore_backup(r["path"], PW, dry_run=True)
        self.assertEqual(plan["skip_existing"], ["alpha"])

    def test_recovery_file_elsewhere_and_missing(self):
        backup.setup_key(PW, [self.rec])
        r = backup.create_backup(self.dest)
        with self.assertRaises(ValueError) as e: backup.backup_info(r["path"], PW)
        self.assertIn("recovery file", str(e.exception))
        rf = next(self.rec.glob("secreds-recovery-key*.json"))
        self.assertEqual(backup.backup_info(r["path"], PW, key_file=rf)["count"], 1)

    def test_copy_recovery_file_to_a_second_place_needs_no_password(self):
        backup.setup_key(PW, [self.rec])
        r = backup.copy_recovery(self.rec2)
        self.assertEqual(r["places"], 2); self.assertEqual(len(backup.key_status()["recovery_files"]), 2)
        copy = next(self.rec2.glob("secreds-recovery-key*.json")); backup.unlock_recovery(copy, PW)
        with self.assertRaises(ValueError): backup.copy_recovery(self.rec2)          # already there

    def test_replacing_the_key_keeps_old_backups_openable_with_the_old_files(self):
        backup.setup_key(PW, [self.rec])
        old = backup.create_backup(self.dest); old_rf = next(self.rec.glob("secreds-recovery-key*.json"))
        PW2 = "second password with many words"
        backup.setup_key(PW2, [self.rec2], replace=True)
        self.assertEqual(backup.backup_info(old["path"], PW, key_file=old_rf)["count"], 1)
        new = backup.create_backup(self.dest)
        self.assertEqual(backup.backup_info(new["path"], PW2, key_file=next(self.rec2.glob("secreds-recovery-key*.json")))["count"], 1)
        with self.assertRaises(ValueError): backup.backup_info(new["path"], PW, key_file=old_rf)

    def test_old_passphrase_backups_still_work(self):
        r = backup.create_backup(self.dest, "correct horse battery staple")
        self.assertEqual(r["method"], "passphrase"); self.assertTrue(r["verified"])
        self.assertEqual(backup.backup_info(r["path"], "correct horse battery staple")["count"], 1)

    def test_gui_setup_needs_both_confirmations_then_backs_up_without_a_password(self):
        from secreds import gui
        base = {"password": PW, "dest": str(self.rec), "icloud": False}
        for missing in ({}, {"ack_manager": True}, {"ack_offline": True}):
            with self.assertRaises(ValueError): gui.act("/api/backup-key-setup", dict(base, **missing))
        self.assertFalse(gui.state()["backup"]["key"]["configured"])
        gui.act("/api/backup-key-setup", dict(base, ack_manager=True, ack_offline=True))
        self.assertTrue(gui.state()["backup"]["key"]["configured"])
        r = gui.act("/api/backup", {"dest": str(self.dest), "passphrase": ""})
        self.assertEqual(r["method"], "key")
        rf = next(self.rec.glob("secreds-recovery-key*.json"))
        out = gui.act("/api/restore-backup", {"path": r["path"], "passphrase": PW, "key_file": str(rf), "dry_run": True})
        self.assertEqual(out["skip_existing"], ["alpha"])


@unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"), "cryptography not installed")
class BackupPlanTests(CoreCase):
    def setUp(self):
        super().setUp()
        self._kdf, backup.KDF_N = backup.KDF_N, 2 ** 14
        self._sched, backup._apply_schedule = backup._apply_schedule, lambda plan: None      # never touch launchd in tests
        self.add("alpha", kind="login", username="u", value="alpha-secret-AAAA-1111")
        self.a = self.home / "a"; self.b = self.home / "b"
        backup.setup_key(PW, [self.a])

    def tearDown(self):
        backup.KDF_N = self._kdf; backup._apply_schedule = self._sched
        super().tearDown()

    def plan(self, **kw):
        p = {"destinations": [{"type": "folder", "path": str(self.a)}, {"type": "folder", "path": str(self.b)}], "keep": 2, "schedule": "off"}
        p.update(kw); return p

    def test_plan_validation(self):
        for bad in ({"keep": 1}, {"keep": "x"}, {"schedule": "hourly"}, {"hour": 30}, {"destinations": [{"type": "s3", "credential": "alpha"}]},
                    {"destinations": [{"type": "folder", "path": ""}]}, {"schedule": "daily", "destinations": []}):
            with self.assertRaises(ValueError, msg=str(bad)): backup.save_plan(self.plan(**bad))
        self.assertEqual(backup.save_plan(self.plan(keep=0))["keep"], 0)

    def test_cloud_drives_are_detected_and_google_drive_uses_my_drive(self):
        import os
        from unittest import mock
        fake = self.home / "fakehome"; cs = fake / "Library" / "CloudStorage"
        (cs / "GoogleDrive-me@example.com" / "My Drive").mkdir(parents=True)
        (cs / "OneDrive-Personal").mkdir(); (cs / ".hidden").mkdir()
        with mock.patch.dict(os.environ, {"HOME": str(fake)}):
            found = {x["name"]: x["path"] for x in backup.cloud_locations() if x["kind"] == "folder"}
        self.assertEqual(found["Google Drive (me@example.com)"], str(cs / "GoogleDrive-me@example.com" / "My Drive" / "seCreds Backups"))
        self.assertEqual(found["OneDrive (Personal)"], str(cs / "OneDrive-Personal" / "seCreds Backups"))
        self.assertEqual(len(found), 2)

    def test_schedule_needs_the_key(self):
        (c.DATA / "backup-key.json").unlink()
        with self.assertRaises(ValueError): backup.save_plan(self.plan(schedule="daily"))

    def test_run_writes_every_place_and_prunes_but_never_the_recovery_file(self):
        backup.save_plan(self.plan(keep=2))
        import time
        for i in range(4):
            r = backup.run_plan(); self.assertTrue(r["ok"]); time.sleep(1.1)
        for d in (self.a, self.b):
            self.assertEqual(len(backup.list_backups(d)), 2)
        self.assertEqual(len(list(self.a.glob("secreds-recovery-key*.json"))), 1)
        self.assertTrue(backup.state()["last_plan_run"]["ok"])

    def test_unattended_run_skips_touch_id_and_manual_run_asks(self):
        backup.save_plan(self.plan())
        asked = []
        orig, c._confirm = c._confirm, lambda action: asked.append(action)
        try:
            backup.run_plan(unattended=True); self.assertEqual(asked, [])
            backup.run_plan(); self.assertEqual(len(asked), 1)
        finally:
            c._confirm = orig

    def test_one_failing_place_is_reported_and_the_others_still_get_the_backup(self):
        blocked = self.home / "file-not-folder"; blocked.write_text("x")
        backup.save_plan(self.plan(destinations=[{"type": "folder", "path": str(self.a)}, {"type": "folder", "path": str(blocked / "sub")}]))
        r = backup.run_plan()
        self.assertFalse(r["ok"]); self.assertTrue(r["results"][0]["ok"]); self.assertFalse(r["results"][1]["ok"])
        self.assertEqual(len(backup.list_backups(self.a)), 1)

    def test_s3_destination_uploads_the_ciphertext_only(self):
        self.add("bucket", kind="s3", access_key_id="K1", bucket="bk-bucket", address="s3.example.com", value="s3-secret-ZZZZ-9999")
        got = {}
        orig = (backup._s3_put, backup._s3_conn)
        backup._s3_conn = lambda name: {"host": "h", "bucket": "bk"}
        backup._s3_put = lambda conn, key, data: got.update(key=key, data=data)
        try:
            backup.save_plan(self.plan(destinations=[{"type": "s3", "credential": "bucket", "prefix": "vault/"}]))
            r = backup.run_plan(unattended=True)
        finally:
            backup._s3_put, backup._s3_conn = orig
        self.assertTrue(r["ok"]); self.assertTrue(got["key"].startswith("vault/secreds-backup-"))
        for secret in (b"alpha-secret", b"s3-secret", PW.encode()): self.assertNotIn(secret, got["data"])


@unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"), "cryptography not installed")
class SyncTests(CoreCase):
    def setUp(self):
        super().setUp()
        self._kdf, backup.KDF_N = backup.KDF_N, 2 ** 14
        self._sched, backup._apply_schedule = backup._apply_schedule, lambda plan: None
        self.add("alpha", kind="login", username="u", value="alpha-secret-AAAA-1111")
        self.add("beta", kind="login", username="u", value="beta-secret-BBBB-2222")
        self.box = self.home / "box"
        backup.setup_key(PW, [self.box])
        backup.save_plan({"destinations": [{"type": "folder", "path": str(self.box)}], "keep": 5, "schedule": "off"})
        self.r = backup.create_backup(self.box)

    def tearDown(self):
        backup.KDF_N = self._kdf; backup._apply_schedule = self._sched
        super().tearDown()

    def test_newest_backup_is_found_in_the_plan_folders(self):
        self.assertEqual(backup.newest_backup()["path"], self.r["path"])

    def test_preview_lists_new_and_different_by_name_only_and_changes_nothing(self):
        c.delete_cred("beta")                                   # "new here": exists in the backup, not on this Mac
        c.kc_set("alpha", "changed-on-this-mac-9999")          # "different": exists on both with another secret
        pv = backup.sync_preview(PW)
        self.assertEqual(pv["new"], ["beta"]); self.assertEqual(pv["different"], ["alpha"]); self.assertEqual(pv["same"], [])
        self.assertNotIn("secret", json.dumps(pv)); self.assertNotIn("9999", json.dumps(pv))
        self.assertEqual(c.kc_get("alpha"), "changed-on-this-mac-9999")
        self.assertNotIn("beta", c.list_creds())

    def test_apply_adds_new_keeps_different_unless_taken(self):
        c.delete_cred("beta"); c.kc_set("alpha", "changed-on-this-mac-9999")
        r = backup.sync_apply(PW)
        self.assertEqual(r["create"], ["beta"]); self.assertEqual(c.kc_get("beta"), "beta-secret-BBBB-2222")
        self.assertEqual(c.kc_get("alpha"), "changed-on-this-mac-9999")                 # not overwritten
        backup.sync_apply(PW, take=["alpha"])
        self.assertEqual(c.kc_get("alpha"), "alpha-secret-AAAA-1111")                   # now taken from the backup

    def test_wrong_password_and_no_backup(self):
        with self.assertRaises(ValueError): backup.sync_preview("wrong wrong wrong wrong")

    def test_restore_carries_the_public_key_and_plan_to_a_fresh_mac(self):
        (c.DATA / "backup-key.json").unlink(); (c.DATA / "backup-plan.json").unlink()
        c.delete_cred("alpha"); c.delete_cred("beta")
        self.assertFalse(backup.key_status()["configured"])
        backup.restore_backup(self.r["path"], PW)
        st = backup.key_status()
        self.assertTrue(st["configured"]); self.assertEqual(len(st["recovery_files"]), 1)          # recovery file found beside the backup
        self.assertEqual(backup.get_plan()["destinations"][0]["path"], str(self.box))
        self.assertEqual(backup.create_backup(self.box)["method"], "key")                        # this Mac can now back up with the same key


if __name__ == "__main__":
    unittest.main()
