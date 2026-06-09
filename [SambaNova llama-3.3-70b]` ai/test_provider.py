"""
ai/test_provider.py — Unit tests for AI providers.

Run with: python -m unittest ai.test_provider
"""

import unittest
from unittest.mock import patch, MagicMock
from ai.provider import (
    get_provider,
    OllamaProvider,
    AnthropicProvider,
    ChainProvider,
    _extract_json,
    _validate_severity,
    _ensure_list,
)

class TestAIProvider(unittest.TestCase):
    def test_get_provider(self):
        # Test that get_provider returns the correct provider
        # based on the AI_PROVIDER environment variable.
        with patch.dict('os.environ', {'AI_PROVIDER': 'ollama'}):
            provider = get_provider()
            self.assertIsInstance(provider, OllamaProvider)

        with patch.dict('os.environ', {'AI_PROVIDER': 'anthropic'}):
            provider = get_provider()
            self.assertIsInstance(provider, AnthropicProvider)

        with patch.dict('os.environ', {'AI_PROVIDER': 'chain'}):
            provider = get_provider()
            self.assertIsInstance(provider, ChainProvider)

    def test_ollama_provider(self):
        # Test that OllamaProvider can be instantiated and used.
        provider = OllamaProvider()
        self.assertIsNotNone(provider)

    def test_anthropic_provider(self):
        # Test that AnthropicProvider can be instantiated and used.
        with patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test_key'}):
            provider = AnthropicProvider()
            self.assertIsNotNone(provider)

    def test_chain_provider(self):
        # Test that ChainProvider can be instantiated and used.
        provider = ChainProvider([OllamaProvider(), AnthropicProvider()])
        self.assertIsNotNone(provider)

    def test_extract_json(self):
        # Test that _extract_json can extract JSON from a string.
        json_string = '{"key": "value"}'
        extracted = _extract_json(json_string)
        self.assertEqual(extracted, {'key': 'value'})

    def test_validate_severity(self):
        # Test that _validate_severity returns the correct severity level.
        self.assertEqual(_validate_severity('low'), 'low')
        self.assertEqual(_validate_severity('medium'), 'medium')
        self.assertEqual(_validate_severity('high'), 'high')
        self.assertEqual(_validate_severity('invalid'), 'low')

    def test_ensure_list(self):
        # Test that _ensure_list returns a list.
        self.assertEqual(_ensure_list('string'), ['string'])
        self.assertEqual(_ensure_list(['list']), ['list'])
        self.assertEqual(_ensure_list(None), [])

if __name__ == '__main__':
    unittest.main()
