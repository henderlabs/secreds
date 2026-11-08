import unittest
from helpers import CoreCase, SECRET, c


class FolderTests(CoreCase):
    def test_nested_folders_moves_rename_and_delete(self):
        self.add("a", folder="Lab/Synology"); self.add("b", folder="Lab/Proxmox"); self.add("loose")
        self.assertEqual(c.list_folders(), ["Lab", "Lab/Proxmox", "Lab/Synology"])    # ancestors are created
        c.add_folder("Lab/Empty/Deep"); self.assertIn("Lab/Empty/Deep", c.list_folders())
        c.set_folder("loose", "Lab"); self.assertEqual(c.get_meta("loose")["folder"], "Lab")
        c.rename_folder("Lab", "Home")
        self.assertEqual((c.get_meta("a")["folder"], c.get_meta("loose")["folder"]), ("Home/Synology", "Home"))
        c.delete_folder("Home/Synology")                                              # contents move up, nothing is lost
        self.assertEqual(c.get_meta("a")["folder"], "Home")
        self.assertEqual(c.get_meta("b")["agents"], ["claude"])                       # folders never touch access

    def test_bad_folder_operations(self):
        self.add("a", folder="X")
        for fn in (lambda: c.rename_folder("X", "X/Sub"), lambda: c.add_folder("a/b<c"), lambda: c.add_folder("a/b/c/d/e/f"), lambda: c.add_folder(" ")):
            with self.assertRaises(ValueError): fn()

    def test_moving_a_credential_needs_no_touch_id(self):
        self.add("a"); self.touch = False
        c.set_folder("a", "Anywhere")
        self.assertEqual(c.get_meta("a")["folder"], "Anywhere")


class RequestTests(CoreCase):
    def test_a_request_carries_no_secret_and_can_be_fulfilled(self):
        c.add_request("new-token", "claude", kind="login", username="u@pve!t", address="10.0.0.1", folder="Lab", notes="read only",
                      allowed_commands=["python3 /bin/echo"])
        r = c.list_requests()["new-token"]
        self.assertFalse({"value", "password", "secret"} & set(r)); self.assertEqual(r["requested_by"], "claude")
        self.add("new-token", kind="login", username="u@pve!t")      # the owner adds the secret in the GUI
        c.complete_request("new-token")
        self.assertNotIn("new-token", c.list_requests())
        self.assertIn("request-fulfilled", self.audit_text())

    def test_request_validation(self):
        self.add("exists")
        for fn in (lambda: c.add_request("exists", "claude"), lambda: c.add_request("bad name", "claude"),
                   lambda: c.add_request("x", "claude", kind="weird"), lambda: c.add_request("x", "claude", allowed_commands=["bash -c 'x'"]),
                   lambda: c.add_request("x", "claude", address="a\nb"), lambda: c.add_request("x", "claude", notes="n" * 501)):
            with self.assertRaises(ValueError): fn()

    def test_request_queue_is_capped_and_dismissable(self):
        for i in range(c.MAX_REQUESTS): c.add_request(f"r{i}", "claude")
        with self.assertRaises(ValueError): c.add_request("one-too-many", "claude")
        c.dismiss_request("r0"); self.assertNotIn("r0", c.list_requests())


class NoticeTests(CoreCase):
    def test_default_uses_owner_and_agents_from_config(self):
        self.write_config(owner="Alex", agents=["claude", "codex"])
        n = c.notice()
        self.assertIn("Alex", n); self.assertIn("claude / codex", n); self.assertNotIn("{owner}", n)

    def test_edit_needs_touch_id_and_reset_restores_the_default(self):
        default = c.notice()
        self.touch = False
        with self.assertRaises(ValueError): c.set_notice("my own words")
        self.touch = True
        c.set_notice("my own words"); self.assertEqual(c.notice().strip(), "my own words"); self.assertTrue(c.notice_is_custom())
        c.reset_notice(); self.assertEqual(c.notice(), default)
        for bad in ("", "x" * (c.NOTICE_MAX + 1), "a\x07b"):
            with self.assertRaises(ValueError): c.set_notice(bad)


if __name__ == "__main__":
    unittest.main()
