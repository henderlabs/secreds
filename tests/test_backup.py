import json, os, pathlib, stat, tempfile, unittest
from helpers import CoreCase, SECRET, c
from secreds import backup

PASS = "correct horse battery staple"


@unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"), "cryptography not installed")
class BackupTests(CoreCase):
    def setUp(self):
        super().setUp()
        self._kdf, backup.KDF_N = backup.KDF_N, 2 ** 14          # fast key derivation for tests only
        self.add("alpha", kind="login", username="u", address="10.0.0.1", folder="Lab/NAS", value="alpha-secret-AAAA-1111")
        self.add("beta", kind="s3", access_key_id="K1", bucket="b-bucket", value="beta-secret-BBBB-2222")
        c.set_notice("my custom agent notice")
        self.dest = self.home / "elsewhere" / "backups"

    def tearDown(self):
        backup.KDF_N = self._kdf
        super().tearDown()

    def make(self, **kw):
        return backup.create_backup(self.dest, PASS, **kw)

    def test_passphrase_rules(self):
        for bad in ("short", "aaaaaaaaaaaaaaaa", ""):
            with self.assertRaises(ValueError): backup.check_passphrase(bad)
        backup.check_passphrase(PASS)

    def test_backup_is_one_private_encrypted_verified_file_in_a_folder_you_choose(self):
        r = self.make()
        p = pathlib.Path(r["path"])
        self.assertEqual(p.parent, self.dest); self.assertEqual(r["count"], 2); self.assertTrue(r["verified"])
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        text = p.read_text()
        for secret in ("alpha-secret-AAAA-1111", "beta-secret-BBBB-2222", "my custom agent notice", "10.0.0.1"):
            self.assertNotIn(secret, text)                          # settings AND secrets are encrypted
        self.assertIn("backup-created", self.audit_text()); self.assertNotIn("alpha-secret", self.audit_text())
        self.assertEqual(backup.state()["last_backup_count"], 2)

    def test_a_cloud_folder_needs_a_longer_passphrase(self):
        cloud = self.home / "Library" / "Mobile Documents" / "com~apple~CloudDocs" / "seCreds Backups"
        self.assertTrue(backup.is_cloud_path(cloud)); self.assertFalse(backup.is_cloud_path(self.dest))
        with self.assertRaises(ValueError): backup.create_backup(cloud, "fifteen-chars-x")          # 15 characters: fine locally, too short for iCloud
        r = backup.create_backup(cloud, "a considerably longer passphrase phrase")
        self.assertTrue(r["cloud"]); self.assertEqual(pathlib.Path(r["path"]).parent, cloud)

    def test_two_backups_in_the_same_second_do_not_collide(self):
        a, b = self.make()["path"], self.make()["path"]
        self.assertNotEqual(a, b); self.assertTrue(pathlib.Path(a).exists() and pathlib.Path(b).exists())

    def test_listing_backups_newest_first_without_opening_them(self):
        a = self.make()["path"]; os.utime(a, (1_000_000, 1_000_000)); b = self.make()["path"]
        (self.dest / "notes.txt").write_text("ignored")
        names = [x["name"] for x in backup.list_backups(self.dest)]
        self.assertEqual(names, [pathlib.Path(b).name, pathlib.Path(a).name]); self.assertEqual(backup.list_backups(self.home / "nope"), [])

    def test_icloud_folder_is_offered_only_when_icloud_drive_exists(self):
        old = backup.ICLOUD_ROOT
        try:
            backup.ICLOUD_ROOT = self.home / "no-icloud-here"
            self.assertIsNone(backup.icloud_dir())
            backup.ICLOUD_ROOT = self.home / "Library" / "Mobile Documents" / "com~apple~CloudDocs"; backup.ICLOUD_ROOT.mkdir(parents=True)
            d = backup.icloud_dir(create=True)
            self.assertTrue(d.is_dir()); self.assertEqual(d.name, "seCreds Backups")
        finally:
            backup.ICLOUD_ROOT = old

    def test_creating_needs_touch_id_and_a_good_passphrase(self):
        self.touch = False
        with self.assertRaises(ValueError): self.make()
        self.assertFalse(self.dest.exists() and list(self.dest.iterdir()))
        self.touch = True
        with self.assertRaises(ValueError): backup.create_backup(self.dest, "short")

    def test_info_shows_names_but_never_secrets(self):
        info = backup.backup_info(self.make()["path"], PASS)
        self.assertEqual(info["names"], ["alpha", "beta"]); self.assertEqual(info["count"], 2)
        for value in ("alpha-secret-AAAA-1111", "beta-secret-BBBB-2222"): self.assertNotIn(value, json.dumps(info))

    def test_wrong_passphrase_and_damaged_files_are_refused(self):
        path = self.make()["path"]
        with self.assertRaises(ValueError): backup.backup_info(path, "not the right passphrase")
        junk = self.home / "junk.secreds"; junk.write_text("{not json")
        with self.assertRaises(ValueError): backup.backup_info(junk, PASS)
        blob = json.loads(pathlib.Path(path).read_text()); blob["ct"] = blob["ct"][:-8] + "AAAAAAAA"
        tampered = self.home / "tampered.secreds"; tampered.write_text(json.dumps(blob))
        with self.assertRaises(ValueError): backup.backup_info(tampered, PASS)
        blob = json.loads(pathlib.Path(path).read_text()); blob["kdf"]["n"] = 2 ** 30                      # hostile cost value
        hostile = self.home / "hostile.secreds"; hostile.write_text(json.dumps(blob))
        with self.assertRaises(ValueError): backup.backup_info(hostile, PASS)

    def test_restore_onto_a_fresh_machine_brings_back_everything(self):
        path = self.make()["path"]
        new_home = pathlib.Path(tempfile.mkdtemp()); self.store.clear(); c.use_home(new_home)        # a brand new Mac
        self.assertEqual(c.list_creds(), {})
        r = backup.restore_backup(path, PASS)
        self.assertEqual(sorted(r["create"]), ["alpha", "beta"]); self.assertEqual(r["restored"], 2)
        self.assertEqual(self.store["alpha"], "alpha-secret-AAAA-1111"); self.assertEqual(self.store["beta"], "beta-secret-BBBB-2222")
        self.assertEqual(c.get_meta("alpha")["folder"], "Lab/NAS"); self.assertEqual(c.get_meta("beta")["bucket"], "b-bucket")
        self.assertIn("Lab/NAS", c.list_folders()); self.assertEqual(c.notice().strip(), "my custom agent notice")
        self.assertIn("backup-restored", (new_home / "audit.log").read_text())

    def test_merge_keeps_what_is_here_and_overwrite_lets_the_backup_win(self):
        path = self.make()["path"]
        self.store["alpha"] = "changed-since-the-backup"; c.save_cred("alpha", notes="edited later")
        r = backup.restore_backup(path, PASS)                                                          # default: merge
        self.assertEqual(r["skip_existing"], ["alpha", "beta"]); self.assertEqual(r["restored"], 0)
        self.assertEqual(self.store["alpha"], "changed-since-the-backup")
        r = backup.restore_backup(path, PASS, mode="overwrite")
        self.assertEqual(r["overwrite"], ["alpha", "beta"]); self.assertEqual(self.store["alpha"], "alpha-secret-AAAA-1111")
        self.assertEqual(c.get_meta("alpha")["notes"], "")

    def test_dry_run_changes_nothing_and_needs_no_touch_id(self):
        path = self.make()["path"]
        c.delete_cred("beta"); before = (self.home / "meta.json").read_text(); self.prompts.clear()
        r = backup.restore_backup(path, PASS, dry_run=True)
        self.assertEqual(r["create"], ["beta"]); self.assertEqual((self.home / "meta.json").read_text(), before)
        self.assertNotIn("beta", self.store); self.assertEqual(self.prompts, [])

    def test_restoring_needs_touch_id(self):
        path = self.make()["path"]; c.delete_cred("beta"); self.touch = False
        with self.assertRaises(ValueError): backup.restore_backup(path, PASS)
        self.assertNotIn("beta", self.store)

    def test_audit_history_can_be_left_out(self):
        path = self.make(include_audit=False)["path"]
        self.assertNotIn("audit.log", backup.backup_info(path, PASS)["settings"])


if __name__ == "__main__":
    unittest.main()
