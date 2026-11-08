"""Shared test setup: a throwaway data folder, an in-memory 'Keychain', and a scriptable Touch ID."""
import json, pathlib, sys, tempfile, unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from secreds import core as c  # noqa: E402

SECRET = "s3cret-value-0123456789"


class CoreCase(unittest.TestCase):
    touch = True  # what the fake Touch ID answers

    def setUp(self):
        self._home0 = c.DATA
        self._tmp = tempfile.TemporaryDirectory()
        self.home = pathlib.Path(self._tmp.name)
        c.use_home(self.home)
        self.store, self.prompts = {}, []
        self._saved = (c.kc_set, c.kc_get, c.kc_has, c.kc_delete, c.touch_id)
        c.kc_set = lambda n, v: self.store.__setitem__(n, v)
        c.kc_get = self._kc_get
        c.kc_has = lambda n: n in self.store
        c.kc_delete = lambda n: self.store.pop(n, None)
        c.touch_id = self._touch_id

    def tearDown(self):
        c.kc_set, c.kc_get, c.kc_has, c.kc_delete, c.touch_id = self._saved
        c.use_home(self._home0)
        self._tmp.cleanup()

    def _kc_get(self, name):
        if name not in self.store:
            raise KeyError(name)
        return self.store[name]

    def _touch_id(self, reason, timeout=0):
        self.prompts.append(reason)
        return self.touch

    def add(self, name="svc", value=SECRET, **kw):
        kw.setdefault("agents", ["claude"])
        kw.setdefault("mode", "auto")
        return c.save_cred(name, value, create=True, **kw)

    def write_config(self, **cfg):
        (self.home / "config.json").write_text(json.dumps(cfg))
        c.use_home(self.home)

    def audit_text(self):
        p = self.home / "audit.log"
        return p.read_text() if p.exists() else ""
