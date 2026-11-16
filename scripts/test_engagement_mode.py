"""Legacy scopes and explicit mode transitions stay distinct."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import scope_target


class EngagementModeTests(unittest.TestCase):
    def test_mode_derived_for_existing_scopes(self):
        self.assertEqual(scope_target.engagement_mode({"target_ip": "10.10.10.10"}), "lab_machine")
        self.assertEqual(scope_target.engagement_mode({"target_url": "https://challenge.example"}), "web_challenge")
        self.assertEqual(scope_target.engagement_mode({"program_id": "demo-program"}), "bug_bounty")
        self.assertEqual(scope_target.engagement_mode({}), "unconfigured")
        self.assertEqual(scope_target.engagement_mode({"program_id": "demo-program",
                                                       "target_url": "https://challenge.example"}), "invalid")


if __name__ == "__main__":
    unittest.main()
