import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("network_config", ROOT / "tools/network_config.py")
CONFIG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIG)


class ConfigurationTests(unittest.TestCase):
    def test_published_candidate_verifies(self):
        CONFIG.verify(ROOT)

    def test_unsigned_edit_and_duplicate_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            CONFIG.document(b'{"revision":1,"revision":2}')
        with tempfile.TemporaryDirectory(prefix="drakora-config-test-") as temporary:
            root = pathlib.Path(temporary)
            for name in ("network.json", "network.signed.json", "network-config.pub", "updates.json"):
                (root / name).write_bytes((ROOT / name).read_bytes())
            value = json.loads((root / "network.json").read_text())
            value["revision"] += 1
            (root / "network.json").write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                CONFIG.verify(root)

    def test_operator_can_sign_and_verify_with_an_external_private_key(self):
        with tempfile.TemporaryDirectory(prefix="drakora-config-test-") as temporary:
            directory = pathlib.Path(temporary)
            root = directory / "public"
            root.mkdir()
            key = directory / "private.key"
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key)],
                           check=True, capture_output=True)
            key.chmod(0o600)
            public = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                                    check=True, capture_output=True).stdout
            (root / "network-config.pub").write_bytes(public)
            (root / "network.json").write_bytes((ROOT / "network.json").read_bytes())
            CONFIG.sign(root, key)
            CONFIG.verify(root)
            key.chmod(0o644)
            with self.assertRaises(ValueError):
                CONFIG.sign(root, key)

    def test_invalid_endpoints_and_unapproved_downloads_are_rejected(self):
        for invalid in (0, 65536, True, "25598"):
            value = json.loads((ROOT / "network.json").read_text())
            value["addresses"][0]["ports"] = [invalid]
            with self.assertRaises(ValueError):
                CONFIG.validate(value)
        value = json.loads((ROOT / "network.json").read_text())
        value["releases"] = [{"loader": "fabric", "minecraft": "1.20.1", "version": "0.2.0",
                              "build": 1, "fileName": "PVelocity-Prom2-Patch-0.2.0.jar", "size": 1024,
                              "sha256": "a" * 64, "downloadUrl": "https://untrusted.invalid/v1/mod.jar",
                              "curseforgeUrl": value["curseforgeProject"] + "/files/12345"}]
        with self.assertRaises(ValueError):
            CONFIG.validate(value)


if __name__ == "__main__":
    unittest.main()
