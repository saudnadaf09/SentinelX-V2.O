"""Official-API clients for OpenAI, Google Gemini and Anthropic (stdlib urllib only).

Honesty rules: a call "succeeds" only when the API returns HTTP 2xx AND a non-empty text answer.
Every failure is classified, and API keys are scrubbed from all error messages.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

PROVIDERS = {
    "openai": {"label": "OpenAI", "base_url": "https://api.openai.com/v1", "default_model": "gpt-4o-mini",
               "models": ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1"]},
    "gemini": {"label": "Google Gemini", "base_url": "https://generativelanguage.googleapis.com/v1beta",
               "default_model": "gemini-2.0-flash", "models": ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]},
    "anthropic": {"label": "Anthropic", "base_url": "https://api.anthropic.com", "default_model": "claude-sonnet-5-5",
                  "models": ["claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5-5"]},
}
EXTRA_PROVIDERS = {"openai_compatible"}  # platform (env) config only: needs an explicit base URL
MODEL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,79}$"


class ProviderError(Exception):
    def __init__(self, kind: str, message: str, status: int | None = None):
        super().__init__(message)
        self.kind, self.message, self.status = kind, message, status


def _scrub(text: str, key: str) -> str:
    return text.replace(key, "[key]")[:300] if key else text[:300]


def build_request(provider: str, api_key: str, model: str, system: str, user: str, *, base_url: str | None = None,
                  max_tokens: int = 1500, json_mode: bool = True) -> tuple[str, dict, bytes]:
    if not api_key and provider != "openai_compatible":
        raise ProviderError("config", "no API key configured")
    if provider in ("openai", "openai_compatible"):
        base = (base_url or PROVIDERS["openai"]["base_url"]).rstrip("/")
        body: dict = {"model": model, "max_completion_tokens": max_tokens,
                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        return f"{base}/chat/completions", headers, json.dumps(body).encode()
    if provider == "gemini":
        base = (base_url or PROVIDERS["gemini"]["base_url"]).rstrip("/")
        gen: dict = {"maxOutputTokens": max_tokens}
        if json_mode:
            gen["responseMimeType"] = "application/json"
        body = {"systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}], "generationConfig": gen}
        return f"{base}/models/{model}:generateContent", {"x-goog-api-key": api_key}, json.dumps(body).encode()
    if provider == "anthropic":
        base = (base_url or PROVIDERS["anthropic"]["base_url"]).rstrip("/")
        body = {"model": model, "max_tokens": max_tokens, "system": system,
                "messages": [{"role": "user", "content": user}]}
        return f"{base}/v1/messages", {"x-api-key": api_key, "anthropic-version": "2023-06-01"}, json.dumps(body).encode()
    raise ProviderError("config", f"unknown provider: {provider}")


def parse_response(provider: str, data: dict) -> str:
    try:
        if provider in ("openai", "openai_compatible"):
            msg = data["choices"][0]["message"]
            text = msg.get("content") or ""
            if not text and msg.get("refusal"):
                raise ProviderError("bad_response", "the model refused the request")
        elif provider == "gemini":
            if data.get("promptFeedback", {}).get("blockReason"):
                raise ProviderError("bad_response", f"blocked by provider: {data['promptFeedback']['blockReason']}")
            parts = data["candidates"][0]["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts)
        else:  # anthropic
            text = "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderError("bad_response", "unexpected response format from provider") from exc
    if not text.strip():
        raise ProviderError("bad_response", "provider returned an empty answer")
    return text


def call(provider: str, api_key: str, model: str, system: str, user: str, *, base_url: str | None = None,
         timeout: int = 30, json_mode: bool = True, max_tokens: int = 1500) -> str:
    url, headers, body = build_request(provider, api_key, model, system, user, base_url=base_url,
                                       max_tokens=max_tokens, json_mode=json_mode)
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "SentinelX/1.0", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed official hosts or admin-set env URL
            raw = resp.read(2_000_000)
            status = resp.status
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(2000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        kind = {401: "auth", 403: "auth", 404: "model", 408: "network", 429: "rate_limit"}.get(
            exc.code, "bad_request" if exc.code < 500 else "server")
        label = {"auth": "authentication failed - check the API key and its permissions",
                 "model": "model or endpoint not found - check the model name",
                 "rate_limit": "rate limit or quota exceeded", "server": "provider server error",
                 "network": "request timed out"}.get(kind, "request rejected by provider")
        raise ProviderError(kind, f"HTTP {exc.code}: {label}. {_scrub(detail, api_key)}".strip(), exc.code) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise ProviderError("network", f"cannot reach provider: {_scrub(str(reason), api_key)}") from None
    if not 200 <= status < 300:
        raise ProviderError("bad_response", f"unexpected HTTP status {status}", status)
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise ProviderError("bad_response", "provider returned non-JSON data") from None
    return parse_response(provider, data)


def test_connection(provider: str, api_key: str, model: str, *, base_url: str | None = None, timeout: int = 15) -> dict:
    """Make one real, minimal API call. ok=True only if the provider genuinely answered."""
    started = time.monotonic()
    base = {"provider": provider, "model": model}
    try:
        text = call(provider, api_key, model, "You are a connectivity probe.", "Reply with the single word: OK",
                    base_url=base_url, timeout=timeout, json_mode=False, max_tokens=16)
    except ProviderError as exc:
        return {**base, "ok": False, "error_kind": exc.kind, "message": exc.message,
                "latency_ms": int((time.monotonic() - started) * 1000)}
    return {**base, "ok": True, "error_kind": None, "message": "Provider answered a live test request.",
            "latency_ms": int((time.monotonic() - started) * 1000), "sample": text.strip()[:40]}
