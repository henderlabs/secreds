import unittest
from helpers import CoreCase, SECRET, c


class EnvTests(CoreCase):
    def test_api_key(self):
        self.add(kind="api-key")
        self.assertEqual(c.env_for("svc", SECRET), {"SVC": SECRET})

    def test_api_key_with_app_id(self):
        self.add(kind="api-key", username="ccode")
        self.assertEqual(c.env_for("svc", SECRET), {"SVC": SECRET, "SVC_ID": "ccode"})

    def test_login_and_several_hosts(self):
        self.add(kind="login", username="admin", address="10.0.0.1:8006, 10.0.0.2:8006 10.0.0.3:8006")
        e = c.env_for("svc", SECRET)
        self.assertEqual(e["SVC_USERNAME"], "admin"); self.assertEqual(e["SVC_PASSWORD"], SECRET)
        self.assertEqual(e["SVC_ADDRESS"], "10.0.0.1:8006")
        self.assertEqual(e["SVC_ADDRESSES"], "10.0.0.1:8006,10.0.0.2:8006,10.0.0.3:8006")

    def test_single_host_has_no_addresses_list(self):
        self.add(kind="login", username="u", address="10.0.0.1")
        e = c.env_for("svc", SECRET)
        self.assertEqual(e["SVC_ADDRESS"], "10.0.0.1"); self.assertNotIn("SVC_ADDRESSES", e)

    def test_s3_gets_standard_names_only_when_alone(self):
        self.add(kind="s3", access_key_id="AKIAEXAMPLE", bucket="my-bucket", address="s3.us-west-1.wasabisys.com")
        alone = c.env_for("svc", SECRET, std=True)
        self.assertEqual(alone["AWS_ACCESS_KEY_ID"], "AKIAEXAMPLE"); self.assertEqual(alone["AWS_SECRET_ACCESS_KEY"], SECRET)
        self.assertEqual(alone["AWS_DEFAULT_REGION"], "us-west-1")       # worked out from the endpoint
        self.assertEqual(alone["AWS_ENDPOINT_URL"], "https://s3.us-west-1.wasabisys.com")
        shared = c.env_for("svc", SECRET, std=False)
        self.assertFalse([k for k in shared if k.startswith("AWS_")])
        self.assertEqual(shared["SVC_BUCKET"], "my-bucket")

    def test_s3_validation(self):
        with self.assertRaises(ValueError): c.save_cred("a", SECRET, create=True, kind="s3")                      # needs a key id
        with self.assertRaises(ValueError): c.save_cred("b", SECRET, create=True, kind="s3", access_key_id="K1", bucket="Bad_Bucket")
        c.save_cred("ok", SECRET, create=True, kind="s3", access_key_id="K1", region="s3.us-west-1.wasabisys.com")
        self.assertEqual(c.get_meta("ok")["region"], "us-west-1")        # an endpoint pasted into Region is tidied


if __name__ == "__main__":
    unittest.main()
