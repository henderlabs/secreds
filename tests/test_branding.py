import json, pathlib, plistlib, re, unittest
from helpers import CoreCase, c
from secreds import HOMEPAGE, MAKER, PRODUCT, __version__, backup, cli, gui, signature
from test_cli_and_gui import run_cli

ROOT = pathlib.Path(__file__).resolve().parents[1]


class SignatureTests(CoreCase):
    def test_one_signature_everywhere(self):
        self.assertEqual(signature(), f"seCreds {__version__} by henderlabs")
        self.assertEqual((PRODUCT, MAKER), ("seCreds", "henderlabs"))

    def test_version_in_the_package_and_in_pyproject_agree(self):
        m = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M)
        self.assertEqual(m.group(1), __version__)

    def test_docs_carry_the_signature_with_the_current_version_and_a_feedback_link(self):
        for f in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "docs/claude-code.md"):
            text = (ROOT / f).read_text().rstrip()
            last = text.splitlines()[-1]
            self.assertIn(f"v{__version__}", last, f); self.assertIn("henderlabs", last, f); self.assertIn("issues/new/choose", last, f)
        self.assertIn("Copyright (c) 2026 henderlabs", (ROOT / "LICENSE").read_text())

    def test_feedback_form_exists_and_warns_about_secrets(self):
        form = (ROOT / ".github" / "ISSUE_TEMPLATE" / "feedback.yml").read_text()
        self.assertIn("Never paste a real password", form); self.assertIn("secreds --version", form)

    def test_command_line(self):
        code, out, err = run_cli("--version")
        self.assertEqual((code, out.strip()), (0, signature()))
        code, out, _ = run_cli("about")
        self.assertIn(signature(), out); self.assertIn("issues/new/choose", out); self.assertIn(HOMEPAGE, out)
        code, out, _ = run_cli("--help")
        self.assertIn(signature(), out); self.assertIn("feedback:", out)

    def test_feedback_link_can_be_overridden_in_config(self):
        self.write_config(feedback_url="https://example.invalid/feedback")
        self.assertEqual(c.about()["feedback_url"], "https://example.invalid/feedback")

    def test_the_gui_shows_it_at_the_bottom_of_every_page(self):
        page = gui.PAGE
        self.assertIn('<footer class=sig id=sig>', page)
        self.assertLess(page.index("</main></div>"), page.index("<footer class=sig"))       # after all the pages, so it appears on each
        self.assertEqual(gui.state()["about"]["signature"], signature())
        self.assertIn("Send feedback", page)

    def test_the_apps_it_builds_and_the_files_it_makes_are_signed(self):
        run_cli("install-app", "--dest", str(self.home / "apps"))
        with open(self.home / "apps" / "seCreds.app" / "Contents" / "Info.plist", "rb") as f: plist = plistlib.load(f)
        self.assertEqual(plist["CFBundleShortVersionString"], __version__); self.assertIn("henderlabs", plist["NSHumanReadableCopyright"])
        self.assertIn(signature(), c.notice())                                           # the notice agents see
        self.add("a"); old, backup.KDF_N = backup.KDF_N, 2 ** 14
        try:
            r = backup.create_backup(self.home / "b", "correct horse battery staple")
        finally:
            backup.KDF_N = old
        self.assertEqual(json.loads(pathlib.Path(r["path"]).read_text())["generator"], signature())


if __name__ == "__main__":
    unittest.main()
