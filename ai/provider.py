"""
ai/provider.py — AI provider abstraction layer.

Why this exists:
  We want to swap providers (Anthropic → Ollama → OpenAI → etc.) without
  touching the rest of the app. All provider logic is isolated here.
  The rest of the codebase only calls get_provider().analyze(context).

Provider hierarchy:
  BaseProvider        — abstract interface, defines the contract
  OllamaProvider      — calls a local Ollama instance (free, no API key)
  AnthropicProvider   — calls the Anthropic Messages API (paid)
  NullProvider        — returns a "disabled" result, no network call

Factory:
  get_provider()      — reads AI_PROVIDER from env, returns the right object.
                        Falls back to NullProvider on any failure so the
                        server never crashes regardless of AI config.

To add a new provider:
  1. Subclass BaseProvider
  2. Implement analyze(context) → dict
  3. Add a branch in get_provider()
"""

import json
import os
import time
from threading import Lock


# ── Live progress tracker (module-global, thread-safe) ────────────────────────
#
# Streaming providers update this dict as tokens arrive so the UI can poll
# /api/ai/progress and show the response forming in real-time. There's only
# one analysis at a time, so a single dict is enough.
#
# Keys:
#   id          int     — monotonically incrementing run id
#   kind        str     — "scan" | "traffic" | "combined"
#   status      str     — "running" | "done" | "error" | "idle"
#   partial     str     — accumulated raw response so far
#   chars       int     — len(partial), denormalised for cheap polling
#   started_at  float   — time.time() when the run started
#   updated_at  float   — last token time
#   error       str|None
_PROGRESS_LOCK = Lock()
_PROGRESS: dict = {
    "id":         0,
    "kind":       None,
    "status":     "idle",
    "partial":    "",
    "chars":      0,
    "started_at": 0.0,
    "updated_at": 0.0,
    "error":      None,
}


def progress_snapshot() -> dict:
    """Return a copy of the current progress state — safe for JSON serialization."""
    with _PROGRESS_LOCK:
        return dict(_PROGRESS)


def progress_begin(kind: str) -> int:
    """Mark a new analysis as starting. Returns the new run id."""
    with _PROGRESS_LOCK:
        _PROGRESS["id"]         = _PROGRESS["id"] + 1
        _PROGRESS["kind"]       = kind
        _PROGRESS["status"]     = "running"
        _PROGRESS["partial"]    = ""
        _PROGRESS["chars"]      = 0
        _PROGRESS["started_at"] = time.time()
        _PROGRESS["updated_at"] = time.time()
        _PROGRESS["error"]      = None
        return _PROGRESS["id"]


def progress_append(chunk: str) -> None:
    if not chunk:
        return
    with _PROGRESS_LOCK:
        _PROGRESS["partial"]   += chunk
        _PROGRESS["chars"]      = len(_PROGRESS["partial"])
        _PROGRESS["updated_at"] = time.time()


def progress_done(error: str | None = None) -> None:
    with _PROGRESS_LOCK:
        _PROGRESS["status"]     = "error" if error else "done"
        _PROGRESS["error"]      = error
        _PROGRESS["updated_at"] = time.time()


# ── Base ───────────────────────────────────────────────────────────────────────

class BaseProvider:
    """
    All providers must implement analyze().

    Input:  context dict built by ai/analyst.py
    Output: dict with keys:
              summary     str   — plain-English overview
              severity    str   — "low" | "medium" | "high"
              benign      list  — observations that look normal
              concerning  list  — observations that warrant attention
              next_steps  list  — specific actionable recommendations
              model       str   — model identifier used
              input_tokens  int | None
              output_tokens int | None
              error       str | None  — set if analysis failed
    """
    name: str = "base"

    def analyze(self, context: dict) -> dict:
        raise NotImplementedError


# ── Null provider (AI disabled or unavailable) ─────────────────────────────────

class NullProvider(BaseProvider):
    """
    Returned when AI is disabled or a provider can't be loaded.
    Returns a structured "disabled" result so the rest of the app
    doesn't need to handle None.
    """
    name = "none"

    def __init__(self, reason: str = "AI not configured"):
        self.reason = reason

    def analyze(self, context: dict) -> dict:
        return {
            "summary":      None,
            "severity":     None,
            "benign":       [],
            "concerning":   [],
            "next_steps":   [],
            "model":        None,
            "input_tokens": None,
            "output_tokens":None,
            "error":        self.reason,
        }


# ── Anthropic provider ─────────────────────────────────────────────────────────

class AnthropicProvider(BaseProvider):
    """
    Calls the Anthropic Messages API.

    Required env vars:
      ANTHROPIC_API_KEY   — your Anthropic API key
      AI_MODEL            — optional, default "claude-sonnet-4-6" (executor)

    Optional advisor mode env vars:
      AI_USE_ADVISOR      — set to "true" to enable the advisor tool (beta)
      AI_ADVISOR_MODEL    — advisor model, default "claude-opus-4-6"

    Advisor mode pairs a faster executor (Sonnet) with a smarter advisor
    (Opus) that gets consulted mid-generation for strategic guidance. You
    get near-Opus quality at Sonnet pricing on complex analysis tasks.

    Fail-safe: any exception (network error, API error, parse failure)
    is caught and returned as an error dict. The server never crashes.
    """
    name = "anthropic"

    def __init__(self):
        import anthropic as _anthropic
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set")
        self._client        = _anthropic.Anthropic(api_key=api_key)
        self._model         = os.getenv("AI_MODEL", "claude-sonnet-4-6")
        self._use_advisor   = os.getenv("AI_USE_ADVISOR", "false").lower() == "true"
        self._advisor_model = os.getenv("AI_ADVISOR_MODEL", "claude-opus-4-6")

    def analyze(self, context: dict, prompt: str | None = None, kind: str = "combined", deep: bool = False) -> dict:
        from ai.prompt import build_prompt

        if prompt is None:
            prompt = build_prompt(context)

        model_label = (
            f"{self._model}+advisor({self._advisor_model})"
            if self._use_advisor else self._model
        )

        try:
            if self._use_advisor:
                # Beta advisor tool: Sonnet executor consults Opus advisor mid-generation.
                # All of this happens server-side in a single API call — no extra round trips.
                message = self._client.beta.messages.create(
                    model      = self._model,
                    max_tokens = 1024,
                    betas      = ["advisor-tool-2026-03-01"],
                    tools      = [{
                        "type":  "advisor_20260301",
                        "name":  "advisor",
                        "model": self._advisor_model,
                    }],
                    messages   = [{"role": "user", "content": prompt}],
                )
                # Response content may include server_tool_use + advisor_tool_result blocks
                # alongside the actual text. Extract only the text blocks.
                raw_text = "".join(
                    block.text
                    for block in message.content
                    if hasattr(block, "text")
                )
                input_tokens  = message.usage.input_tokens
                output_tokens = message.usage.output_tokens
                # Sum advisor token usage from iterations if available
                iterations = getattr(message.usage, "iterations", None) or []
                advisor_output = sum(
                    it.output_tokens
                    for it in iterations
                    if getattr(it, "type", "") == "advisor_message"
                )
                if advisor_output:
                    print(f"[ai] Advisor used {advisor_output} output tokens (Opus rate)")
            else:
                message = self._client.messages.create(
                    model      = self._model,
                    max_tokens = 1024,
                    messages   = [{"role": "user", "content": prompt}],
                )
                raw_text      = message.content[0].text
                input_tokens  = message.usage.input_tokens
                output_tokens = message.usage.output_tokens

            parsed = _extract_json(raw_text)

            return {
                "summary":       parsed.get("summary", ""),
                "severity":      _validate_severity(parsed.get("severity", "low")),
                "benign":        _ensure_list(parsed.get("benign", [])),
                "concerning":    _ensure_list(parsed.get("concerning", [])),
                "next_steps":    _ensure_list(parsed.get("next_steps", [])),
                "model":         model_label,
                "input_tokens":  input_tokens,
                "output_tokens": output_tokens,
                "raw_response":  raw_text,
                "error":         None,
            }

        except Exception as exc:
            return {
                "summary":       None,
                "severity":      None,
                "benign":        [],
                "concerning":    [],
                "next_steps":    [],
                "model":         model_label,
                "input_tokens":  None,
                "output_tokens": None,
                "raw_response":  None,
                "error":         f"{type(exc).__name__}: {exc}",
            }


# ── Ollama provider (local, free) ─────────────────────────────────────────────

class OllamaProvider(BaseProvider):
    """
    Calls a locally running Ollama instance. Completely free — the model
    runs on your own hardware with no API key or account needed.

    Ollama exposes a simple HTTP API on localhost:11434.
    We use urllib.request (already in stdlib) so no extra packages are needed.

    Setup:
      1. Install Ollama from ollama.com
      2. Run: ollama pull phi3:mini   (or whichever model you choose)
      3. Set in .env:
           AI_PROVIDER=ollama
           AI_MODEL=phi3:mini

    Env vars:
      OLLAMA_HOST  — base URL of Ollama (default: http://localhost:11434)
      AI_MODEL     — model name as listed by `ollama list` (default: phi3:mini)

    Timeouts:
      Local inference can be slow on CPU — we give it 120 seconds.
      On a GPU it's typically 5-20 seconds.

    Fail-safe:
      If Ollama isn't running, we get a connection error which is caught
      and returned as an error dict. The dashboard shows the message.
    """
    name = "ollama"

    def __init__(self):
        self._host       = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        # Two-model split:
        #   AI_FAST_MODEL — small/fast model for routine analysis (default: qwen2.5:3b).
        #                   This is used for nearly every call.
        #   AI_DEEP_MODEL — bigger smarter model used only when caller asks for deep analysis.
        #                   Falls back to AI_FAST_MODEL if not set.
        #   AI_MODEL      — legacy single-model env var. If set, treated as the fast model
        #                   so existing .env files keep working.
        legacy = os.getenv("AI_MODEL", "").strip()
        self._fast_model = os.getenv("AI_FAST_MODEL", legacy or "qwen2.5:3b")
        self._deep_model = os.getenv("AI_DEEP_MODEL", legacy or self._fast_model)
        # Backwards compat: ai/analyst.py and tests still reference self._model.
        self._model      = self._fast_model

    def analyze(self, context: dict, prompt: str | None = None, kind: str = "combined", deep: bool = False) -> dict:
        """
        Run analysis against Ollama. Streams the response token-by-token,
        accumulating into the module-global progress dict so the UI can
        watch it form in real time via /api/ai/progress.

        Args:
            context: structured monitoring data dict
            prompt:  if provided, sent verbatim. If None, falls back to the
                     legacy combined build_prompt() (for callers that haven't
                     migrated to the focused scan/traffic prompts yet).
            kind:    "scan" | "traffic" | "combined" — recorded in progress
                     dict so the UI can label what's running.
        """
        import urllib.request
        import urllib.error

        if prompt is None:
            from ai.prompt import build_prompt
            prompt = build_prompt(context)

        # Pick the model up-front so we report it correctly in logs and in the result.
        active_model = self._deep_model if deep else self._fast_model

        print(f"[ai] [{kind}] Streaming to {active_model} ({len(prompt)} chars)...")
        progress_begin(kind)

        # NOTE: format:"json" REMOVED on purpose.
        # Ollama's grammar-constrained JSON mode buffers tokens internally
        # before flushing — so streaming arrives in big bursts and the UI
        # appears frozen. We instead instruct the model to emit JSON via the
        # prompt rules and parse defensively in _extract_json.
        payload_obj = {
            "model":    active_model,
            "messages": [{"role": "user", "content": prompt}],
            "stream":   True,
            "options": {
                "temperature": 0.1,
                "num_predict": 2048,
            },
        }
        # Thinking models (Gemma 4, Qwen3) emit a `<|channel>thought ... <channel|>`
        # block that would corrupt our JSON parsing of raw_text. think=False tells
        # Ollama to suppress it. Gated to thinking models so the non-thinking default
        # (qwen2.5:3b) is left untouched.
        if any(tok in active_model.lower() for tok in ("gemma4", "qwen3", "thinking")):
            payload_obj["think"] = False
        payload = json.dumps(payload_obj).encode("utf-8")

        try:
            req = urllib.request.Request(
                f"{self._host}/api/chat",
                data    = payload,
                headers = {"Content-Type": "application/json"},
                method  = "POST",
            )

            raw_text       = ""
            input_tokens   = None
            output_tokens  = None

            # No timeout — runs in a background thread.
            with urllib.request.urlopen(req, timeout=None) as resp:
                # Ollama streams NDJSON: one JSON object per line.
                for line in resp:
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line.decode("utf-8").strip())
                    except json.JSONDecodeError:
                        continue
                    msg = chunk.get("message") or {}
                    piece = msg.get("content", "")
                    if piece:
                        raw_text += piece
                        progress_append(piece)
                    if chunk.get("done"):
                        input_tokens  = chunk.get("prompt_eval_count")
                        output_tokens = chunk.get("eval_count")
                        break

            print(f"[ai] [{kind}] Stream finished ({len(raw_text)} chars, {output_tokens} tokens)")
            parsed = _extract_json(raw_text)
            progress_done(error=None)

            return {
                "summary":       parsed.get("summary", ""),
                "severity":      _validate_severity(parsed.get("severity", "low")),
                "benign":        _ensure_list(parsed.get("benign",     [])),
                "concerning":    _ensure_list(parsed.get("concerning", [])),
                "next_steps":    _ensure_list(parsed.get("next_steps", [])),
                "model":         f"ollama/{active_model}",
                "input_tokens":  input_tokens,
                "output_tokens": output_tokens,
                "raw_response":  raw_text,
                "error":         None,
            }

        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            if exc.code == 404:
                msg = f"Ollama model '{active_model}' not found — run: ollama pull {active_model}"
            else:
                msg = f"Ollama HTTP {exc.code} at {self._host}: {body or exc}"
            progress_done(error=msg)
            return _fail(f"ollama/{active_model}", msg)
        except urllib.error.URLError as exc:
            msg = f"Ollama not reachable at {self._host} — is it running? Start it with: ollama serve ({exc})"
            progress_done(error=msg)
            return _fail(f"ollama/{active_model}", msg)
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            progress_done(error=msg)
            return _fail(f"ollama/{active_model}", msg)


def _fail(model: str, message: str) -> dict:
    """Shared error-result builder for providers."""
    return {
        "summary":       None,
        "severity":      None,
        "benign":        [],
        "concerning":    [],
        "next_steps":    [],
        "model":         model,
        "input_tokens":  None,
        "output_tokens": None,
        "raw_response":  None,
        "error":         message,
    }


# ── Groq provider (free cloud, strong model) ──────────────────────────────────

class GroqProvider(BaseProvider):
    """
    Calls Groq's free cloud API using the OpenAI-compatible endpoint.
    llama-3.3-70b-versatile is far stronger than local qwen2.5:3b for
    device identification and security analysis.

    Required env var: GROQ_API_KEY (free at console.groq.com)
    Optional:         GROQ_INVESTIGATION_MODEL (default: llama-3.3-70b-versatile)
    """
    name = "groq"

    def __init__(self):
        from openai import OpenAI
        api_key = os.getenv("GROQ_API_KEY", "")
        if not api_key:
            raise ValueError("GROQ_API_KEY not set")
        self._client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
        )
        self._model = os.getenv("GROQ_INVESTIGATION_MODEL", "llama-3.3-70b-versatile")

    def analyze(self, context: dict, prompt: str | None = None, kind: str = "combined", deep: bool = False) -> dict:
        from ai.prompt import build_prompt
        if prompt is None:
            prompt = build_prompt(context)

        progress_begin(kind)
        progress_append(f"Sending to Groq ({self._model})...\n")

        try:
            stream = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=2048,
                stream=True,
                stream_options={"include_usage": True},
            )
            raw_text     = ""
            input_tokens = None
            output_tokens = None
            for chunk in stream:
                if chunk.choices:
                    piece = chunk.choices[0].delta.content or ""
                    if piece:
                        raw_text += piece
                        progress_append(piece)
                if chunk.usage:
                    input_tokens  = chunk.usage.prompt_tokens
                    output_tokens = chunk.usage.completion_tokens
            progress_done()
            parsed = _extract_json(raw_text)
            return {
                "summary":       parsed.get("summary", ""),
                "severity":      _validate_severity(parsed.get("severity", "low")),
                "benign":        _ensure_list(parsed.get("benign", [])),
                "concerning":    _ensure_list(parsed.get("concerning", [])),
                "next_steps":    _ensure_list(parsed.get("next_steps", [])),
                "model":         f"groq/{self._model}",
                "input_tokens":  input_tokens,
                "output_tokens": output_tokens,
                "raw_response":  raw_text,
                "error":         None,
            }
        except Exception as exc:
            progress_done(error=str(exc))
            return _fail(f"groq/{self._model}", f"{type(exc).__name__}: {exc}")


# ── OpenAI-compatible free providers ──────────────────────────────────────────
#
# Cerebras, SambaNova, OpenRouter and Gemini all expose OpenAI-compatible
# chat-completion endpoints, so each provider class is a near-clone of
# GroqProvider above. Kept as separate classes (no shared base) for clarity —
# each is small, and a future provider may need to diverge.
#
# Every provider:
#   • Raises ValueError in __init__ if its API key env var is missing.
#   • Streams tokens through progress_append so the UI updates live.
#   • Returns the standard result dict (see BaseProvider docstring) with
#     model = f"{provider}/{model_name}" so the UI can label the real source.

class CerebrasProvider(BaseProvider):
    """Cerebras free tier — 1M tokens/day, very fast. Default: gpt-oss-120b."""
    name = "cerebras"

    def __init__(self):
        from openai import OpenAI
        api_key = os.getenv("CEREBRAS_API_KEY", "")
        if not api_key:
            raise ValueError("CEREBRAS_API_KEY not set")
        self._client = OpenAI(api_key=api_key, base_url="https://api.cerebras.ai/v1")
        self._model  = os.getenv("CEREBRAS_MODEL", "gpt-oss-120b")

    def analyze(self, context: dict, prompt: str | None = None, kind: str = "combined", deep: bool = False) -> dict:
        from ai.prompt import build_prompt
        if prompt is None:
            prompt = build_prompt(context)

        progress_begin(kind)
        progress_append(f"Sending to Cerebras ({self._model})...\n")

        try:
            stream = self._client.chat.completions.create(
                model       = self._model,
                messages    = [{"role": "user", "content": prompt}],
                temperature = 0.1,
                max_tokens  = 2048,
                stream      = True,
                stream_options = {"include_usage": True},
            )
            raw_text      = ""
            input_tokens  = None
            output_tokens = None
            for chunk in stream:
                if chunk.choices:
                    piece = chunk.choices[0].delta.content or ""
                    if piece:
                        raw_text += piece
                        progress_append(piece)
                if chunk.usage:
                    input_tokens  = chunk.usage.prompt_tokens
                    output_tokens = chunk.usage.completion_tokens
            progress_done()
            parsed = _extract_json(raw_text)
            return {
                "summary":       parsed.get("summary", ""),
                "severity":      _validate_severity(parsed.get("severity", "low")),
                "benign":        _ensure_list(parsed.get("benign", [])),
                "concerning":    _ensure_list(parsed.get("concerning", [])),
                "next_steps":    _ensure_list(parsed.get("next_steps", [])),
                "model":         f"cerebras/{self._model}",
                "input_tokens":  input_tokens,
                "output_tokens": output_tokens,
                "raw_response":  raw_text,
                "error":         None,
            }
        except Exception as exc:
            progress_done(error=str(exc))
            return _fail(f"cerebras/{self._model}", f"{type(exc).__name__}: {exc}")


class SambaNovaProvider(BaseProvider):
    """SambaNova free tier — persistent free access. Default: Meta-Llama-3.3-70B-Instruct."""
    name = "sambanova"

    def __init__(self):
        from openai import OpenAI
        api_key = os.getenv("SAMBANOVA_API_KEY", "")
        if not api_key:
            raise ValueError("SAMBANOVA_API_KEY not set")
        self._client = OpenAI(api_key=api_key, base_url="https://api.sambanova.ai/v1")
        self._model  = os.getenv("SAMBANOVA_MODEL", "Meta-Llama-3.3-70B-Instruct")

    def analyze(self, context: dict, prompt: str | None = None, kind: str = "combined", deep: bool = False) -> dict:
        from ai.prompt import build_prompt
        if prompt is None:
            prompt = build_prompt(context)

        progress_begin(kind)
        progress_append(f"Sending to SambaNova ({self._model})...\n")

        try:
            stream = self._client.chat.completions.create(
                model       = self._model,
                messages    = [{"role": "user", "content": prompt}],
                temperature = 0.1,
                max_tokens  = 2048,
                stream      = True,
                stream_options = {"include_usage": True},
            )
            raw_text      = ""
            input_tokens  = None
            output_tokens = None
            for chunk in stream:
                if chunk.choices:
                    piece = chunk.choices[0].delta.content or ""
                    if piece:
                        raw_text += piece
                        progress_append(piece)
                if chunk.usage:
                    input_tokens  = chunk.usage.prompt_tokens
                    output_tokens = chunk.usage.completion_tokens
            progress_done()
            parsed = _extract_json(raw_text)
            return {
                "summary":       parsed.get("summary", ""),
                "severity":      _validate_severity(parsed.get("severity", "low")),
                "benign":        _ensure_list(parsed.get("benign", [])),
                "concerning":    _ensure_list(parsed.get("concerning", [])),
                "next_steps":    _ensure_list(parsed.get("next_steps", [])),
                "model":         f"sambanova/{self._model}",
                "input_tokens":  input_tokens,
                "output_tokens": output_tokens,
                "raw_response":  raw_text,
                "error":         None,
            }
        except Exception as exc:
            progress_done(error=str(exc))
            return _fail(f"sambanova/{self._model}", f"{type(exc).__name__}: {exc}")


class OpenRouterProvider(BaseProvider):
    """OpenRouter free tier auto-router. Default: nvidia/nemotron-3-super-120b-a12b:free."""
    name = "openrouter"

    def __init__(self):
        from openai import OpenAI
        api_key = os.getenv("OPENROUTER_API_KEY", "")
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY not set")
        self._client = OpenAI(api_key=api_key, base_url="https://openrouter.ai/api/v1")
        self._model  = os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")

    def analyze(self, context: dict, prompt: str | None = None, kind: str = "combined", deep: bool = False) -> dict:
        from ai.prompt import build_prompt
        if prompt is None:
            prompt = build_prompt(context)

        progress_begin(kind)
        progress_append(f"Sending to OpenRouter ({self._model})...\n")

        try:
            stream = self._client.chat.completions.create(
                model       = self._model,
                messages    = [{"role": "user", "content": prompt}],
                temperature = 0.1,
                max_tokens  = 2048,
                stream      = True,
                stream_options = {"include_usage": True},
            )
            raw_text      = ""
            input_tokens  = None
            output_tokens = None
            for chunk in stream:
                if chunk.choices:
                    piece = chunk.choices[0].delta.content or ""
                    if piece:
                        raw_text += piece
                        progress_append(piece)
                if chunk.usage:
                    input_tokens  = chunk.usage.prompt_tokens
                    output_tokens = chunk.usage.completion_tokens
            progress_done()
            parsed = _extract_json(raw_text)
            return {
                "summary":       parsed.get("summary", ""),
                "severity":      _validate_severity(parsed.get("severity", "low")),
                "benign":        _ensure_list(parsed.get("benign", [])),
                "concerning":    _ensure_list(parsed.get("concerning", [])),
                "next_steps":    _ensure_list(parsed.get("next_steps", [])),
                "model":         f"openrouter/{self._model}",
                "input_tokens":  input_tokens,
                "output_tokens": output_tokens,
                "raw_response":  raw_text,
                "error":         None,
            }
        except Exception as exc:
            progress_done(error=str(exc))
            return _fail(f"openrouter/{self._model}", f"{type(exc).__name__}: {exc}")


class GeminiProvider(BaseProvider):
    """Google Gemini free tier via OpenAI-compatible endpoint. Default: gemini-2.5-flash."""
    name = "gemini"

    def __init__(self):
        from openai import OpenAI
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not set")
        self._client = OpenAI(api_key=api_key, base_url="https://generativelanguage.googleapis.com/v1beta/openai/")
        self._model  = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    def analyze(self, context: dict, prompt: str | None = None, kind: str = "combined", deep: bool = False) -> dict:
        from ai.prompt import build_prompt
        if prompt is None:
            prompt = build_prompt(context)

        progress_begin(kind)
        progress_append(f"Sending to Gemini ({self._model})...\n")

        try:
            stream = self._client.chat.completions.create(
                model       = self._model,
                messages    = [{"role": "user", "content": prompt}],
                temperature = 0.1,
                max_tokens  = 2048,
                stream      = True,
                stream_options = {"include_usage": True},
            )
            raw_text      = ""
            input_tokens  = None
            output_tokens = None
            for chunk in stream:
                if chunk.choices:
                    piece = chunk.choices[0].delta.content or ""
                    if piece:
                        raw_text += piece
                        progress_append(piece)
                if chunk.usage:
                    input_tokens  = chunk.usage.prompt_tokens
                    output_tokens = chunk.usage.completion_tokens
            progress_done()
            parsed = _extract_json(raw_text)
            return {
                "summary":       parsed.get("summary", ""),
                "severity":      _validate_severity(parsed.get("severity", "low")),
                "benign":        _ensure_list(parsed.get("benign", [])),
                "concerning":    _ensure_list(parsed.get("concerning", [])),
                "next_steps":    _ensure_list(parsed.get("next_steps", [])),
                "model":         f"gemini/{self._model}",
                "input_tokens":  input_tokens,
                "output_tokens": output_tokens,
                "raw_response":  raw_text,
                "error":         None,
            }
        except Exception as exc:
            progress_done(error=str(exc))
            return _fail(f"gemini/{self._model}", f"{type(exc).__name__}: {exc}")


# ── Provider cooldown + transient-error detection ─────────────────────────────
#
# When a free provider rate-limits us mid-call, we don't want the next
# investigation in the same window to re-eat the 429. We mark the provider
# "hot" for _COOLDOWN_SECONDS so the chain skips it until it's likely usable
# again. Only transient errors (rate limit / 5xx / network) cool down a
# provider — a 400 / bad prompt is returned to the caller as-is, because
# retrying on another provider would just fail the same way.

_PROVIDER_COOLDOWN: dict[str, float] = {}   # provider.name -> unix ts when usable again
_COOLDOWN_SECONDS = 60.0

_TRANSIENT_KEYWORDS = (
    "rate limit", "429", "too many requests",
    "timeout", "timed out", "connection",
    "temporarily", "503", "502", "504", "overloaded",
)


def _mark_cooldown(name: str) -> None:
    _PROVIDER_COOLDOWN[name] = time.time() + _COOLDOWN_SECONDS


def _on_cooldown(name: str) -> bool:
    expiry = _PROVIDER_COOLDOWN.get(name)
    return expiry is not None and expiry > time.time()


def _is_transient_error(err: str) -> bool:
    err = (err or "").lower()
    return any(kw in err for kw in _TRANSIENT_KEYWORDS)


# Errors that doom THIS provider but not the whole chain. A model that doesn't
# exist or a bad/forbidden key is a provider-specific config problem — the next
# provider has a different model and key, so it can still answer. Skip to it
# instead of surfacing the error and dead-ending the chain.
_PROVIDER_SPECIFIC_KEYWORDS = (
    "model_not_found", "does not exist", "do not have access",
    "not_found_error", "invalid model", "unknown model", "model not found",
    "401", "403", "invalid api key", "incorrect api key", "invalid_api_key",
    "unauthorized", "permission", "authentication",
)


def _is_provider_specific_error(err: str) -> bool:
    err = (err or "").lower()
    return any(kw in err for kw in _PROVIDER_SPECIFIC_KEYWORDS)


# ── AI Router telemetry ───────────────────────────────────────────────────────
# Report every NetMon model call to the AI Router (:4000) /router/log endpoint so
# it shows up in the unified dashboard — per-model call counts, cost, and the
# fallback ledger (requested -> failed -> served). Fire-and-forget in a daemon
# thread with a short timeout: telemetry must never slow down or break analysis.

def _log_to_router(model_requested: str, model_selected: str, fallback_chain: list,
                   prompt_tokens, completion_tokens, latency_s: float,
                   status: str = "success", error: str | None = None) -> None:
    def _post():
        try:
            import urllib.request
            url = os.getenv("AI_ROUTER_LOG_URL", "http://localhost:4000/router/log")
            key = os.getenv("AI_ROUTER_KEY", "sk-1234")
            payload = json.dumps({
                "model_requested":  model_requested,
                "model_selected":   model_selected,
                "fallback_chain":   fallback_chain or [],
                "prompt_tokens":    prompt_tokens or 0,
                "completion_tokens": completion_tokens or 0,
                "latency_s":        round(latency_s, 3),
                "status":           status,
                "error":            error,
                "client":           "NetMon",
            }).encode("utf-8")
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
            )
            urllib.request.urlopen(req, timeout=3).read()
        except Exception:
            pass  # never let telemetry break analysis
    import threading
    threading.Thread(target=_post, daemon=True).start()


# ── Chain provider ────────────────────────────────────────────────────────────

class ChainProvider(BaseProvider):
    """
    Walks an ordered list of providers and returns the first successful
    result. On a transient failure (rate limit / 5xx / timeout) the provider
    is put on cooldown and the next one is tried. On a non-transient failure
    (bad prompt, auth) the error is returned immediately to avoid burning the
    whole chain on a request that will never succeed.

    The inner providers each manage progress_begin/progress_done themselves,
    so the UI naturally re-streams when the chain advances.
    """
    name = "chain"

    def __init__(self, providers: list[BaseProvider]):
        self.chain = providers

    def analyze(self, context: dict, prompt: str | None = None, kind: str = "combined", deep: bool = False) -> dict:
        t0 = time.time()
        chain_labels = [f"netmon/{p.name}/{getattr(p, '_model', '?')}" for p in self.chain]
        requested = chain_labels[0] if chain_labels else "netmon/chain"
        last_err: str | None = None
        for p in self.chain:
            if _on_cooldown(p.name):
                continue
            result = p.analyze(context, prompt, kind, deep)
            if result["error"] is None:
                _log_to_router(requested, f"netmon/{result.get('model') or p.name}", chain_labels,
                               result.get("input_tokens"), result.get("output_tokens"),
                               time.time() - t0, "success")
                return result
            last_err = result["error"]
            if _is_transient_error(last_err) or _is_provider_specific_error(last_err):
                # Transient (rate limit/5xx) OR provider-specific (bad model/key):
                # cool this provider down and fall through to the next one.
                _mark_cooldown(p.name)
                continue
            # Request-level failure (e.g. malformed prompt) — fails everywhere,
            # so surface it instead of burning the whole chain.
            _log_to_router(requested, f"netmon/{result.get('model') or p.name}", chain_labels,
                           result.get("input_tokens"), result.get("output_tokens"),
                           time.time() - t0, "failed", last_err)
            return result
        _log_to_router(requested, requested, chain_labels, 0, 0,
                       time.time() - t0, "failed", f"all providers exhausted (last: {last_err})")
        return _fail("chain", f"all providers exhausted or on cooldown (last error: {last_err})")


# ── Factory ────────────────────────────────────────────────────────────────────

def get_investigation_provider() -> BaseProvider:
    """
    Build the investigation fallback chain. Order is cheapest/fastest first,
    local last:

        Cerebras → Groq → SambaNova → OpenRouter → Gemini → Ollama

    Providers without API keys are silently skipped at construction time, so
    the chain ends up being whatever the user actually has configured.
    Ollama is always appended last when reachable — it's local and can't
    rate-limit, so it's a reliable floor.
    """
    providers: list[BaseProvider] = []
    for cls in (CerebrasProvider, GroqProvider, SambaNovaProvider,
                OpenRouterProvider, GeminiProvider):
        try:
            providers.append(cls())
        except Exception:
            pass
    try:
        providers.append(OllamaProvider())
    except Exception:
        pass
    if not providers:
        return NullProvider("No AI providers configured")
    return ChainProvider(providers)


def get_provider() -> BaseProvider:
    """
    Read AI_PROVIDER from environment and return the appropriate provider.

    Falls back to NullProvider if:
      - AI_PROVIDER is not set or empty
      - The required package is not installed
      - The API key is missing
      - Any other import/init error

    This means the server starts cleanly even if the user hasn't installed
    the anthropic package or set the API key — the AI panel just shows
    "AI not configured".
    """
    provider_name = os.getenv("AI_PROVIDER", "").strip().lower()

    if not provider_name:
        return NullProvider("AI_PROVIDER not set in .env")

    if provider_name in ("chain", "auto"):
        return get_investigation_provider()

    if provider_name == "ollama":
        return OllamaProvider()

    if provider_name == "anthropic":
        try:
            return AnthropicProvider()
        except ImportError:
            return NullProvider("anthropic package not installed — run: pip install anthropic")
        except ValueError as e:
            return NullProvider(str(e))
        except Exception as e:
            return NullProvider(f"Failed to init Anthropic provider: {e}")

    return NullProvider(f"Unknown provider: '{provider_name}' — valid options: chain, ollama, anthropic")


def chain_chat(messages: list[dict], max_tokens: int = 1024) -> str:
    """
    Send a raw multi-turn chat (list of {role, content} dicts) through the
    best available cloud provider, falling back to Ollama.

    Returns plain text — no JSON parsing. Used by Security Lab chat and
    any other endpoint that needs conversational (non-structured) AI.

    Priority: Groq → SambaNova → Cerebras → OpenRouter → Gemini → Ollama.
    """
    # Try OpenAI-compatible cloud providers first (they all use the same interface).
    # Cooldowns are keyed by the provider's .name attribute so chain_chat shares
    # the same hot-list with ChainProvider.analyze() — otherwise we'd retry a
    # provider here that was already rate-limited on the analysis path.
    cloud_candidates = []
    for cls, key_var, base_url, default_model in [
        (GroqProvider,       "GROQ_API_KEY",       "https://api.groq.com/openai/v1",       "llama-3.3-70b-versatile"),
        (SambaNovaProvider,  "SAMBANOVA_API_KEY",  "https://api.sambanova.ai/v1",           "Meta-Llama-3.3-70B-Instruct"),
        (CerebrasProvider,   "CEREBRAS_API_KEY",   "https://api.cerebras.ai/v1",            "gpt-oss-120b"),
        (OpenRouterProvider, "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1",          "openrouter/auto"),
        (GeminiProvider,     "GEMINI_API_KEY",     "https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-2.5-flash"),
    ]:
        key = os.getenv(key_var, "").strip()
        if not key:
            continue
        cloud_candidates.append((cls.name, key, base_url, default_model))

    _t0 = time.time()
    _chat_chain = [f"netmon/{n}/{m}" for (n, _k, _b, m) in cloud_candidates] + ["netmon/ollama"]
    _requested = _chat_chain[0] if _chat_chain else "netmon/chat"
    for provider_name, api_key, base_url, model in cloud_candidates:
        if _on_cooldown(provider_name):
            continue
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url)
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.3,
                max_tokens=max_tokens,
            )
            _u = getattr(resp, "usage", None)
            _log_to_router(_requested, f"netmon/{provider_name}/{model}", _chat_chain,
                           getattr(_u, "prompt_tokens", 0) if _u else 0,
                           getattr(_u, "completion_tokens", 0) if _u else 0,
                           time.time() - _t0, "success")
            return resp.choices[0].message.content.strip()
        except Exception as exc:
            err = str(exc)
            if _is_transient_error(err):
                _mark_cooldown(provider_name)
            continue

    # Ollama fallback
    try:
        import urllib.request
        active_model = os.getenv("AI_FAST_MODEL", os.getenv("AI_MODEL", "qwen2.5:3b"))
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        payload = json.dumps({
            "model":    active_model,
            "messages": messages,
            "stream":   False,
            "options":  {"temperature": 0.3, "num_predict": max_tokens},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        _txt = (data.get("message") or {}).get("content", "").strip()
        _log_to_router(_requested, f"netmon/ollama/{active_model}", _chat_chain,
                       data.get("prompt_eval_count", 0), data.get("eval_count", 0),
                       time.time() - _t0, "success")
        return _txt
    except Exception:
        pass

    _log_to_router(_requested, _requested, _chat_chain, 0, 0,
                   time.time() - _t0, "failed", "all providers exhausted")
    return "AI unavailable — no providers reachable."


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_json(text: str) -> dict:
    """
    Parse a JSON object from the model's response.
    The model is instructed to return only JSON, but sometimes wraps it
    in a markdown code block. We handle both cases.
    """
    text = text.strip()

    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Look for ```json ... ``` block
    if "```" in text:
        start = text.find("```")
        end   = text.rfind("```")
        if start != end:
            inner = text[start:end].strip()
            # Strip the language tag line (```json)
            lines = inner.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            try:
                return json.loads("\n".join(lines))
            except json.JSONDecodeError:
                pass

    # Give up — return empty structure
    return {}


def _validate_severity(value: str) -> str:
    if value in ("low", "medium", "high"):
        return value
    return "low"


def _ensure_list(value) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value]
    return []
