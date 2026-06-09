"""
ai/test_provider.py — Unit tests for AI provider abstraction layer.

Run with: python -m unittest ai.test_provider
"""

import unittest
from unittest.mock import patch, MagicMock
from ai.provider import (
    get_provider,
    OllamaProvider,
    AnthropicProvider,
    NullProvider,
    ChainProvider,
    _extract_json,
    _validate_severity,
    _ensure_list,
)

class TestAIProvider(unittest.TestCase):
    def test_get_provider(self):
        # Test that get_provider returns the correct provider based on AI_PROVIDER env var
        with patch.dict('os.environ', {'AI_PROVIDER': 'ollama'}):
            provider = get_provider()
            self.assertIsInstance(provider, OllamaProvider)

        with patch.dict('os.environ', {'AI_PROVIDER': 'anthropic'}):
            provider = get_provider()
            self.assertIsInstance(provider, AnthropicProvider)

        with patch.dict('os.environ', {'AI_PROVIDER': 'chain'}):
            provider = get_provider()
            self.assertIsInstance(provider, ChainProvider)

        with patch.dict('os.environ', {'AI_PROVIDER': ''}):
            provider = get_provider()
            self.assertIsInstance(provider, NullProvider)

    def test_ollama_provider(self):
        # Test that OllamaProvider can be instantiated and analyze method returns a dict
        provider = OllamaProvider()
        context = {}
        result = provider.analyze(context)
        self.assertIsInstance(result, dict)

    def test_anthropic_provider(self):
        # Test that AnthropicProvider can be instantiated and analyze method returns a dict
        provider = AnthropicProvider()
        context = {}
        result = provider.analyze(context)
        self.assertIsInstance(result, dict)

    def test_null_provider(self):
        # Test that NullProvider can be instantiated and analyze method returns a dict
        provider = NullProvider()
        context = {}
        result = provider.analyze(context)
        self.assertIsInstance(result, dict)

    def test_chain_provider(self):
        # Test that ChainProvider can be instantiated and analyze method returns a dict
        providers = [OllamaProvider(), AnthropicProvider()]
        provider = ChainProvider(providers)
        context = {}
        result = provider.analyze(context)
        self.assertIsInstance(result, dict)

    def test_extract_json(self):
        # Test that _extract_json can parse a JSON object from a string
        json_str = '{"key": "value"}'
        result = _extract_json(json_str)
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {'key': 'value'})

    def test_validate_severity(self):
        # Test that _validate_severity returns a valid severity level
        self.assertEqual(_validate_severity('low'), 'low')
        self.assertEqual(_validate_severity('medium'), 'medium')
        self.assertEqual(_validate_severity('high'), 'high')
        self.assertEqual(_validate_severity('invalid'), 'low')

    def test_ensure_list(self):
        # Test that _ensure_list returns a list
        self.assertIsInstance(_ensure_list('string'), list)
        self.assertIsInstance(_ensure_list(['list']), list)
        self.assertIsInstance(_ensure_list(None), list)

if __name__ == '__main__':
    unittest.main()
