from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.validators.finding_validator import deduplicate, source_excerpt


class FindingValidatorTests(unittest.TestCase):
    def test_source_excerpt_verifies_range_and_hashes_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.c"
            path.write_text("one\ntwo\nthree\n", encoding="utf-8")
            excerpt = source_excerpt(path, 2, 2, padding=1)
            self.assertEqual(excerpt["start_line"], 1)
            self.assertEqual(excerpt["end_line"], 3)
            self.assertIn("2: two", excerpt["text"])
            self.assertEqual(len(excerpt["sha256"]), 64)

    def test_deduplicate_prefers_stronger_disposition(self) -> None:
        likely = {"duplicate_key": "same", "disposition": "likely", "validator_confidence": 0.9}
        confirmed = {"duplicate_key": "same", "disposition": "confirmed", "validator_confidence": 0.8}
        self.assertEqual(deduplicate([likely, confirmed]), [confirmed])


if __name__ == "__main__":
    unittest.main()
