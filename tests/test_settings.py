import json, unittest
from helpers import CoreCase, c, SECRET
from secreds import settings, gui


class SettingsTests(CoreCase):
    def test_defaults_and_save_agents(self):
        out = settings.save(agents=["claude", "gemini", "my-bot"], owner="Sam")
        self.assertEqual(c.AGENTS, ["claude", "gemini", "my-bot"]); self.assertEqual(c.OWNER, "Sam")
        self.assertEqual(json.loads(c.CONFIG_FILE.read_text())["agents"], ["claude", "gemini", "my-bot"])
        self.assertEqual(out["agents"], c.AGENTS)
        self.assertTrue(self.prompts)                      # changing agents asked for Touch ID

    def test_touch_id_declined_changes_nothing(self):
        self.touch = False
        with self.assertRaises(ValueError): settings.save(agents=["claude", "x"])
        self.assertEqual(c.AGENTS, c.DEFAULT_AGENTS)

    def test_validation(self):
        for bad in ([], ["bad name"], ["../x"]):
            with self.assertRaises(ValueError): settings.save(agents=bad)
        with self.assertRaises(ValueError): settings.save(feedback_url="http://insecure")
        with self.assertRaises(ValueError): settings.save(update_repo="not a repo")

    def test_removed_agent_is_stripped_from_credentials(self):
        settings.save(agents=["claude", "codex", "gemini"])
        c.save_cred("K", SECRET, agents=["claude", "gemini"], create=True)
        settings.save(agents=["claude", "codex"])
        self.assertEqual(c.get_meta("K")["agents"], ["claude"])

    def test_families(self):
        settings.save(agents=["claude", "claude-work", "codex"], families={"claude-work": "claude"})
        self.assertEqual(c.family("claude-work"), "claude"); self.assertNotIn("claude-work", c.PICKABLE)
        with self.assertRaises(ValueError):
            settings.save(agents=["a", "b", "c"], families={"b": "a", "c": "b"})

    def test_owner_and_links_need_no_touch_id(self):
        n = len(self.prompts)
        settings.save(owner="Pat", feedback_url="https://example.com/fb")
        self.assertEqual(len(self.prompts), n)
        self.assertEqual(c.about()["feedback_url"], "https://example.com/fb")
        settings.save(feedback_url="", owner="")
        self.assertEqual(c.OWNER, "the owner")

    def test_update_source_needs_touch_id(self):
        n = len(self.prompts)
        settings.save(update_repo="me/secreds")
        self.assertEqual(len(self.prompts), n + 1)
        settings.save(update_repo="me/secreds")          # unchanged: no prompt
        self.assertEqual(len(self.prompts), n + 1)
        settings.save(update_repo="")

    def test_agent_doc(self):
        d = settings.agent_doc("claude"); self.assertEqual(d["file"], "CLAUDE.md"); self.assertIn("SECREDS_AGENT=claude", d["text"])
        for must in ("--reason", "secreds note", "secreds info"): self.assertIn(must, d["text"])
        self.assertIn("secreds run", d["text"]); self.assertIn("seCreds", d["text"])
        ch = settings.agent_doc("chatgpt"); self.assertNotIn("SECREDS_AGENT", ch["text"])
        self.assertEqual(settings.agent_doc("unheard-of")["file"], "AGENTS.md")

    def test_doctor_never_includes_secret(self):
        c.save_cred("K", SECRET, create=True)
        s0, p0 = c.S, settings.sys.platform
        c.S, settings.sys.platform = object(), "darwin"          # pretend PyObjC is present (CI runs on Linux too)
        self.addCleanup(lambda: (setattr(c, "S", s0), setattr(settings.sys, "platform", p0)))
        r = settings.doctor(); self.assertNotIn(SECRET, json.dumps(r))
        self.assertTrue(any(x["key"] == "keychain" and x["status"] == "ok" for x in r))
        del self.store["K"]
        self.assertTrue(any(x["key"] == "keychain" and x["status"] == "bad" and "K" in x["detail"] for x in r + settings.doctor()))

    def test_gui_state_and_endpoints(self):
        st = gui.state(); self.assertIn("settings", st); self.assertIn("claude", st["agent_docs"])
        out = gui.act("/api/settings-save", {"agents": ["claude", "foo"], "owner": "Lee"})
        self.assertEqual(out["settings"]["agents"], ["claude", "foo"])
        self.assertIn("checks", gui.act("/api/doctor", {}))
        self.assertIn("foo", gui.state()["agent_docs"])


if __name__ == "__main__":
    unittest.main()
