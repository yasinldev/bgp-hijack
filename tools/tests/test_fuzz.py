import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fuzz


class CompletionTests(unittest.TestCase):
    def test_acceptance_requires_the_requested_duration(self):
        self.assertEqual(fuzz.completion("Done 12345 runs in 601 second(s)\n", 600),
                         {"executions": 12345, "fuzzer_seconds": 601})

    def test_missing_or_early_completion_is_not_success(self):
        for log in ("build finished", "interrupted", "Done 500 runs in 2 second(s)"):
            with self.subTest(log=log), self.assertRaises(RuntimeError):
                fuzz.completion(log, 600)


if __name__ == "__main__":
    unittest.main()
