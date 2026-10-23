"""Server-side Gemini client for the XAI assistant (key read from the environment, never logged)."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = REPO_ROOT / ".env"

API_KEY_ENV = "GEMINI_API_KEY"
MODEL_ENV = "MLCN_LLM_MODEL"
VERTEXAI_ENV = "MLCN_LLM_USE_VERTEXAI"
TIMEOUT_ENV = "MLCN_LLM_TIMEOUT_SECONDS"
RETRIES_ENV = "MLCN_LLM_MAX_RETRIES"

DEFAULT_MODEL = "gemini-3.5-flash"
DEFAULT_TIMEOUT_SECONDS = 45.0
DEFAULT_MAX_RETRIES = 1
MAX_RETRIES_CAP = 3


class LLMError(RuntimeError):
    """A failure whose message is safe to show in the UI (never contains the key)."""


class LLMUnavailable(LLMError):
    """The assistant is not configured (missing key or SDK)."""


def load_env_file(path: Path = ENV_FILE) -> None:
    """Load ``.env`` without overriding variables already set in the process environment."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    if path.is_file():
        load_dotenv(path, override=False)


def _float(raw: str | None, default: float, low: float, high: float) -> float:
    try:
        return min(high, max(low, float(raw))) if raw else default
    except ValueError:
        return default


def _int(raw: str | None, default: int, low: int, high: int) -> int:
    try:
        return min(high, max(low, int(raw))) if raw else default
    except ValueError:
        return default


@dataclass(frozen=True)
class LLMSettings:
    api_key: str = field(repr=False)
    model: str = DEFAULT_MODEL
    use_vertexai: bool = False
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES

    @property
    def configured(self) -> bool:
        return bool(self.api_key)


def load_settings(env: Mapping[str, str] | None = None) -> LLMSettings:
    """Settings from ``env`` (default: process environment after loading ``.env``)."""
    if env is None:
        load_env_file()
        env = os.environ
    return LLMSettings(
        api_key=(env.get(API_KEY_ENV) or "").strip(),
        model=(env.get(MODEL_ENV) or "").strip() or DEFAULT_MODEL,
        use_vertexai=(env.get(VERTEXAI_ENV) or "").strip().lower() in ("1", "true", "yes"),
        timeout_seconds=_float(env.get(TIMEOUT_ENV), DEFAULT_TIMEOUT_SECONDS, 5.0, 300.0),
        max_retries=_int(env.get(RETRIES_ENV), DEFAULT_MAX_RETRIES, 0, MAX_RETRIES_CAP),
    )


def _status_message(code: int | None) -> str:
    if code == 429:
        return "The Gemini API rate limit or quota was exceeded. Wait a moment and try again."
    if code in (401, 403):
        return f"The Gemini API rejected the credentials (HTTP {code}). Check {API_KEY_ENV} in .env."
    if code == 404:
        return f"The configured Gemini model was not found (HTTP 404). Check {MODEL_ENV} in .env."
    if code == 400:
        return "The Gemini API rejected the request (HTTP 400)."
    if code is not None and code >= 500:
        return f"The Gemini service is temporarily unavailable (HTTP {code}). Try again shortly."
    return "The Gemini API request failed."


class GeminiClient:
    """Thin wrapper over the official ``google-genai`` SDK with bounded timeout/retries."""

    def __init__(self, settings: LLMSettings | None = None) -> None:
        self.settings = settings or load_settings()
        self._client: Any = None

    @property
    def model(self) -> str:
        return self.settings.model

    def _sdk(self) -> Any:
        if not self.settings.configured:
            raise LLMUnavailable(f"No Gemini API key configured. Set {API_KEY_ENV} in the project .env file.")
        if self._client is None:
            try:
                from google import genai
                from google.genai import types
            except ImportError as exc:
                raise LLMUnavailable("The google-genai package is not installed (pip install -r requirements.txt).") from exc
            options = types.HttpOptions(
                timeout=int(self.settings.timeout_seconds * 1000),
                retry_options=types.HttpRetryOptions(attempts=self.settings.max_retries + 1),
            )
            self._client = genai.Client(
                api_key=self.settings.api_key,
                vertexai=self.settings.use_vertexai,
                http_options=options,
            )
        return self._client

    def generate(
        self,
        system_instruction: str,
        messages: Sequence[Mapping[str, str]],
        *,
        temperature: float = 0.2,
        max_output_tokens: int = 4096,
        response_schema: Any = None,
    ) -> str:
        """Text reply for ``messages`` (``{"role": "user"|"assistant", "content": str}``)."""
        client = self._sdk()
        from google.genai import errors, types

        contents = [
            types.Content(
                role="model" if message["role"] == "assistant" else "user",
                parts=[types.Part.from_text(text=message["content"])],
            )
            for message in messages
        ]
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )
        if response_schema is not None:
            config.response_mime_type = "application/json"
            config.response_schema = response_schema
        try:
            response = client.models.generate_content(model=self.settings.model, contents=contents, config=config)
        except errors.APIError as exc:
            raise LLMError(_status_message(getattr(exc, "code", None))) from None
        except Exception as exc:
            if "timeout" in type(exc).__name__.lower() or "timed out" in str(exc).lower():
                raise LLMError(
                    f"The Gemini API did not respond within {self.settings.timeout_seconds:g} s. Try again."
                ) from None
            raise LLMError(f"Could not reach the Gemini API ({type(exc).__name__}). Check the network connection.") from None
        text = (getattr(response, "text", None) or "").strip()
        if not text:
            raise LLMError("The model returned an empty response (it may have been blocked). Try rephrasing.")
        return text
