import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FrontendValidationContractTests(unittest.TestCase):
    def test_behavior_eval_blocks_on_full_frontend_ci_baseline(self):
        spec = json.loads((ROOT / "behavior_eval.json").read_text(encoding="utf-8"))
        check = next(
            row for row in spec["checks"]
            if row.get("name") == "frontend-ci-baseline"
        )
        self.assertEqual(check["type"], "cmd")
        self.assertIn("tools/validate_frontend.ps1", check["cmd"])
        self.assertGreaterEqual(check["timeout"], 600)

    def test_frontend_validator_preserves_zero_error_and_asset_baselines(self):
        source = (ROOT / "tools" / "validate_frontend.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("check_frontend_lint.ps1", source)
        self.assertIn("run build", source)
        self.assertIn("git diff --exit-code -- static", source)


if __name__ == "__main__":
    unittest.main()
