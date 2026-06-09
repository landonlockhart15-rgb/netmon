"""
ai/tests/test_provider.py — Unit tests for AI provider abstraction layer.

Run with: python -m unittest ai.tests.test_provider
"""

import unittest
from unittest.mock import patch, MagicMock
from ai.provider import (
    get_provider,
    ChainProvider,
    OllamaProvider,
    AnthropicProvider,
    GroqProvider,
    CerebrasProvider,
    SambaNovaProvider,
    OpenRouterProvider,
    GeminiProvider,
)

class TestAIProvider(unittest.TestCase):
    @patch.dict('os.environ', {'AI_PROVIDER': 'ollama'})
    def test_get_provider_ollama(self):
        provider = get_provider()
        self.assertIsInstance(provider, OllamaProvider)

    @patch.dict('os.environ', {'AI_PROVIDER': 'anthropic'})
    def test_get_provider_anthropic(self):
        provider = get_provider()
        self.assertIsInstance(provider, AnthropicProvider)

    @patch.dict('os.environ', {'AI_PROVIDER': 'chain'})
    def test_get_provider_chain(self):
        provider = get_provider()
        self.assertIsInstance(provider, ChainProvider)

    @patch('ai.provider.OllamaProvider')
    def test_chain_provider_ollama(self, mock_ollama):
        provider = ChainProvider([mock_ollama()])
        self.assertIn(mock_ollama(), provider.chain)

    @patch('ai.provider.AnthropicProvider')
    def test_chain_provider_anthropic(self, mock_anthropic):
        provider = ChainProvider([mock_anthropic()])
        self.assertIn(mock_anthropic(), provider.chain)

    def test_ollama_provider_init(self):
        provider = OllamaProvider()
        self.assertIsNotNone(provider._host)
        self.assertIsNotNone(provider._fast_model)
        self.assertIsNotNone(provider._deep_model)

    def test_anthropic_provider_init(self):
        with patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test_key'}):
            provider = AnthropicProvider()
            self.assertIsNotNone(provider._client)
            self.assertIsNotNone(provider._model)

    def test_groq_provider_init(self):
        with patch.dict('os.environ', {'GROQ_API_KEY': 'test_key'}):
            provider = GroqProvider()
            self.assertIsNotNone(provider._client)
            self.assertIsNotNone(provider._model)

    def test_cerebras_provider_init(self):
        with patch.dict('os.environ', {'CEREBRAS_API_KEY': 'test_key'}):
            provider = CerebrasProvider()
            self.assertIsNotNone(provider._client)
            self.assertIsNotNone(provider._model)

    def test_sambanova_provider_init(self):
        with patch.dict('os.environ', {'SAMBANOVA_API_KEY': 'test_key'}):
            provider = SambaNovaProvider()
            self.assertIsNotNone(provider._client)
            self.assertIsNotNone(provider._model)

    def test_openrouter_provider_init(self):
        with patch.dict('os.environ', {'OPENROUTER_API_KEY': 'test_key'}):
            provider = OpenRouterProvider()
            self.assertIsNotNone(provider._client)
            self.assertIsNotNone(provider._model)

    def test_gemini_provider_init(self):
        with patch.dict('os.environ', {'GEMINI_API_KEY': 'test_key'}):
            provider = GeminiProvider()
            self.assertIsNotNone(provider._client)
            self.assertIsNotNone(provider._model)

if __name__ == '__main__':
    unittest.main()
