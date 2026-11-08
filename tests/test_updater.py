import io, json, pathlib, plistlib, subprocess, tarfile, unittest
from helpers import CoreCase, c
from secreds import __version__, updater


def make_tarball(path, name="secreds", version="9.9.9", extra=None, top="owner-repo-abc123"):
    with tarfile.open(path, "w:gz") as t:
        def add(n, text):
            data = text.encode(); ti = tarfile.TarInfo(n); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
        add(f"{top}/pyproject.toml", f'[project]\nname = "{name}"\nversion = "{version}"\n')
        add(f"{top}/src/secreds/__init__.py", f'__version__ = "{version}"\n')
        for n, text in (extra or {}).items():
            add(n, text)


class UpdaterCase(CoreCase):
    def setUp(self):
        super().setUp()
        self.clock = [1_000_000.0]
        self.saved = (updater._now, updater.latest_release, updater.download_tarball, updater.notify, updater.subprocess.run, updater._launchctl, updater.plist_path)
        updater._now = lambda: self.clock[0]
        self.release = {"tag_name": "v9.9.9", "body": "Release notes here", "published_at": "2026-11-06", "html_url": "https://example.invalid/r"}
        self.calls = {"fetch": 0, "notify": [], "pip": [], "launchctl": []}
        def fake_latest(repo):
            self.calls["fetch"] += 1
            if isinstance(self.release, Exception): raise self.release
            return self.release
        updater.latest_release = fake_latest
        updater.notify = lambda text: self.calls["notify"].append(text)
        updater._launchctl = lambda *a: (self.calls["launchctl"].append(a), subprocess.CompletedProcess(a, 0, "", ""))[1]
        updater.plist_path = lambda: self.home / "LaunchAgents" / "x.plist"

    def tearDown(self):
        (updater._now, updater.latest_release, updater.download_tarball, updater.notify, updater.subprocess.run, updater._launchctl, updater.plist_path) = self.saved
        super().tearDown()


class VersionTests(unittest.TestCase):
    def test_comparison(self):
        self.assertTrue(updater.is_newer("v0.2.0", "0.1.0")); self.assertTrue(updater.is_newer("1.0.0", "0.9.9"))
        self.assertFalse(updater.is_newer("v0.1.0", "0.1.0")); self.assertFalse(updater.is_newer("v0.0.9", "0.1.0"))
        for odd in ("latest", "v1.2", "1.2.3-beta", "", None): self.assertFalse(updater.is_newer(odd, "0.1.0"))


class CheckTests(UpdaterCase):
    def test_a_check_only_reads_and_reports_what_it_found(self):
        st = updater.check(force=True)
        self.assertTrue(st["available"]); self.assertEqual(st["latest_tag"], "v9.9.9"); self.assertIn("Release notes", st["notes"])
        self.assertEqual(self.calls["pip"], [])                                    # checking never installs anything

    def test_it_asks_github_at_most_once_a_day(self):
        updater.check(); updater.check()
        self.assertEqual(self.calls["fetch"], 1)
        self.clock[0] += 23 * 3600; updater.check(); self.assertEqual(self.calls["fetch"], 1)
        self.clock[0] += 2 * 3600; updater.check(); self.assertEqual(self.calls["fetch"], 2)
        updater.check(force=True); self.assertEqual(self.calls["fetch"], 3)

    def test_same_or_older_release_is_not_an_update(self):
        self.release["tag_name"] = f"v{__version__}"
        self.assertFalse(updater.check(force=True)["available"])

    def test_no_releases_yet_and_network_trouble_are_reported_not_raised(self):
        self.release = None
        st = updater.check(force=True); self.assertFalse(st["available"]); self.assertEqual(st["error"], "")
        self.release = updater.UpdateError("Could not reach GitHub (URLError)")
        st = updater.check(force=True); self.assertIn("Could not reach", st["error"]); self.assertFalse(st["available"])

    def test_it_can_be_turned_off(self):
        self.write_config(update_repo="")
        st = updater.check(force=True)
        self.assertIn("turned off", st["error"]); self.assertEqual(self.calls["fetch"], 0)

    def test_quiet_daily_check_notifies_once_per_release(self):
        updater.check(force=True, quiet=True); updater.check(force=True, quiet=True)
        self.assertEqual(len(self.calls["notify"]), 1); self.assertIn("9.9.9", self.calls["notify"][0])


class ApplyTests(UpdaterCase):
    def setUp(self):
        super().setUp()
        self.build = lambda path: make_tarball(path)
        updater.download_tarball = lambda repo, tag, dest: self.build(dest)
        def fake_run(cmd, **kw):
            self.calls["pip"].append(cmd); return subprocess.CompletedProcess(cmd, self.pip_rc, "", "boom: it failed")
        self.pip_rc = 0
        updater.subprocess.run = fake_run

    def test_installing_needs_touch_id_and_then_runs_pip_on_the_checked_archive(self):
        self.touch = False
        with self.assertRaises(ValueError): updater.apply()
        self.assertEqual(self.calls["pip"], [])
        self.touch = True
        r = updater.apply()
        self.assertEqual(r, {"from": __version__, "to": "9.9.9"})
        cmd = self.calls["pip"][0]; self.assertEqual(cmd[1:5], ["-m", "pip", "install", "--upgrade"]); self.assertTrue(cmd[-1].endswith(".tar.gz[export]"))
        self.assertIn(f"{__version__} -> 9.9.9", self.audit_text()); self.assertEqual(updater.load_state()["previous_version"], __version__)

    def test_wrong_package_or_mismatched_version_or_unsafe_archive_is_refused(self):
        for label, build in (("another project", lambda p: make_tarball(p, name="something-else")),
                             ("version differs from the tag", lambda p: make_tarball(p, version="1.0.0")),
                             ("path escapes the folder", lambda p: make_tarball(p, extra={"../evil.txt": "x"}))):
            self.build = build
            with self.assertRaises(updater.UpdateError, msg=label): updater.apply()
        self.assertEqual(self.calls["pip"], [])

    def test_refuses_what_is_already_installed_and_odd_tags(self):
        with self.assertRaises(updater.UpdateError): updater.apply(tag=f"v{__version__}")
        with self.assertRaises(updater.UpdateError): updater.apply(tag="main")

    def test_a_failed_install_is_reported(self):
        self.pip_rc = 1
        with self.assertRaises(updater.UpdateError) as cm: updater.apply()
        self.assertIn("failed", str(cm.exception)); self.assertNotIn("updated", self.audit_text())

    def test_older_tag_can_be_installed_to_roll_back(self):
        self.build = lambda p: make_tarball(p, version="0.0.1")
        self.release["tag_name"] = "v0.0.1"
        self.assertEqual(updater.apply(tag="v0.0.1")["to"], "0.0.1")


class DailyAgentTests(UpdaterCase):
    def test_launch_agent_runs_a_quiet_check_once_a_day(self):
        d = updater.plist_dict("/x/bin/secreds", hour=9, minute=15)
        self.assertEqual(d["ProgramArguments"], ["/x/bin/secreds", "update", "--check", "--quiet"])
        self.assertEqual(d["StartCalendarInterval"], {"Hour": 9, "Minute": 15}); self.assertFalse(d["RunAtLoad"])

    def test_enable_and_disable(self):
        self.assertFalse(updater.daily_enabled())
        updater.enable_daily(exe="/bin/echo")
        self.assertTrue(updater.daily_enabled())
        with open(updater.plist_path(), "rb") as f: self.assertEqual(plistlib.load(f)["Label"], updater.LABEL)
        self.assertTrue(any("bootstrap" in a for a in self.calls["launchctl"]))
        updater.disable_daily(); self.assertFalse(updater.daily_enabled())

    def test_status_summarises_everything_the_gui_needs(self):
        updater.check(force=True)
        s = updater.status()
        self.assertEqual(s["current"], __version__); self.assertTrue(s["available"]); self.assertEqual(s["latest_version"], "9.9.9")
        self.assertIn("daily", s)


if __name__ == "__main__":
    unittest.main()
