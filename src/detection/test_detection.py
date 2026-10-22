import json
import tempfile
import unittest
from pathlib import Path

from static_detector import scan_config


class TestStaticDetector(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.folder = Path(self.temp_dir.name)

    def create_config(self, filename, content):
        path = self.folder / filename
        path.write_text(json.dumps(content), encoding="utf-8")
        return path

    def test_benign_config(self):
        path = self.create_config(
            "benign.json",
            {"model_type": "gpt2"}
        )
        self.assertEqual(scan_config(path), 0)

    def test_suspicious_attention_field(self):
        path = self.create_config(
            "suspicious.json",
            {"_attn_implementation_internal": "untrusted/kernel"}
        )
        self.assertEqual(scan_config(path), 1)

    def test_nested_attention_field(self):
        path = self.create_config(
            "nested.json",
            {
                "settings": {
                    "_attn_implementation_internal": "untrusted/kernel"
                }
            }
        )
        self.assertEqual(scan_config(path), 1)

    def test_experts_field(self):
        path = self.create_config(
            "experts.json",
            {"_experts_implementation_internal": "untrusted/kernel"}
        )
        self.assertEqual(scan_config(path), 1)

    def test_auto_map_field(self):
        path = self.create_config(
            "auto_map.json",
            {"auto_map": {"AutoModel": "custom.Model"}}
        )
        self.assertEqual(scan_config(path), 1)

    def test_custom_pipelines_field(self):
        path = self.create_config(
            "pipelines.json",
            {"custom_pipelines": {"task": {}}}
        )
        self.assertEqual(scan_config(path), 1)

    def test_invalid_json(self):
        path = self.folder / "invalid.json"
        path.write_text('{"model_type": invalid}', encoding="utf-8")
        self.assertEqual(scan_config(path), 2)

    def test_missing_file(self):
        path = self.folder / "missing.json"
        self.assertEqual(scan_config(path), 2)


if __name__ == "__main__":
    unittest.main()
