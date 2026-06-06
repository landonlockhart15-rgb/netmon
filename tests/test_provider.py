"""
Focused unit tests for ai/provider.py pure helpers.

Run from the project root:
    python -m unittest discover -s tests -v

Only the side-effect-free helpers are covered (JSON extraction, severity/list
coercion, error classification, the NullProvider shape). No network calls and
no API keys required — importing ai.provider is safe because each provider
imports the `openai` SDK lazily inside __init__, not at module load.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai.provider import (  # noqa: E402
    NullProvider,
    _ensure_list,
    _extract_json,
    _is_provider_specific_error,
    _is_transient_error,
    _validate_severity,
)


class ExtractJson(unittest.TestCase):
    def test_direct_json(self):
        self.assertEqual(_extract_json('{"a": 1}'), {"a": 1})

    def test_fenced_json_block(self):
        text = 'Here you go:\n```json\n{"severity": "high"}\n```\nthanks'
        self.assertEqual(_extract_json(text), {"severity": "high"})

    def test_garbage_returns_empty_dict(self):
        self.assertEqual(_extract_json("not json at all"), {})
        self.assertEqual(_extract_json(""), {})


class Coercion(unittest.TestCase):
    def test_validate_severity(self):
        for ok in ("low", "medium", "high"):
            self.assertEqual(_validate_severity(ok), ok)
        self.assertEqual(_validate_severity("CRITICAL"), "low")  # unknown -> low
        self.assertEqual(_validate_severity(""), "low")

    def test_ensure_list(self):
        self.assertEqual(_ensure_list(["a", "b"]), ["a", "b"])
        self.assertEqual(_ensure_list("solo"), ["solo"])
        self.assertEqual(_ensure_list(None), [])
        self.assertEqual(_ensure_list(42), [])


class ErrorClassification(unittest.TestCase):
    def test_transient_errors(self):
        self.assertTrue(_is_transient_error("RateLimitError: 429 too many requests"))
        self.assertTrue(_is_transient_error("connection timed out"))
        self.assertTrue(_is_transient_error("503 overloaded"))
        self.assertFalse(_is_transient_error("400 bad request: malformed prompt"))
        self.assertFalse(_is_transient_error(""))

    def test_provider_specific_errors(self):
        # These doom one provider but not the whole chain.
        self.assertTrue(_is_provider_specific_error("model_not_found: bad id"))
        self.assertTrue(_is_provider_specific_error("The model does not exist"))
        self.assertTrue(_is_provider_specific_error("401 invalid api key"))
        self.assertFalse(_is_provider_specific_error("500 internal server error"))


class NullProviderShape(unittest.TestCase):
    def test_disabled_result_contract(self):
        result = NullProvider("AI off").analyze({})
        self.assertEqual(result["error"], "AI off")
        self.assertIsNone(result["summary"])
        self.assertEqual(result["benign"], [])
        self.assertEqual(result["concerning"], [])
        self.assertEqual(result["next_steps"], [])
        # The whole app relies on these keys always being present.
        for key in ("summary", "severity", "benign", "concerning", "next_steps",
                    "model", "input_tokens", "output_tokens", "error"):
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
