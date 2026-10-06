import hashlib
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import calculate_sha256, validate_sha256


class TestSHA256Integrity(unittest.TestCase):
    def test_known_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello")
            name = f.name
        try:
            expected = hashlib.sha256(b"hello").hexdigest()
            self.assertEqual(calculate_sha256(name), expected)
        finally:
            Path(name).unlink(missing_ok=True)

    def test_hash_validation(self):
        self.assertTrue(validate_sha256("a" * 64))
        self.assertFalse(validate_sha256("abc"))
        self.assertFalse(validate_sha256("g" * 64))

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            name = f.name
        try:
            expected = hashlib.sha256(b"").hexdigest()
            self.assertEqual(calculate_sha256(name), expected)
        finally:
            Path(name).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
