"""零第三方依赖的 OpenAI 兼容客户端。

刻意只用标准库：这个工具的核心价值在流程，不在依赖。
DeepSeek / OpenAI / Ollama / vLLM / OpenRouter 都是同一套 /chat/completions 协议。
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


class LLMError(RuntimeError):
    pass


DEFAULTS = {
    "base_url": "https://api.deepseek.com",
    "model": "deepseek-chat",
}

ENV_BASE = "BEE_LLM_BASE_URL"
ENV_KEY = "BEE_LLM_API_KEY"
ENV_MODEL = "BEE_LLM_MODEL"


@dataclass
class LLMConfig:
    base_url: str = DEFAULTS["base_url"]
    api_key: str = ""
    model: str = DEFAULTS["model"]
    temperature: float = 0.15
    max_tokens: int = 4096
    timeout: int = 240
    retries: int = 3

    @classmethod
    def from_env(cls) -> "LLMConfig":
        key = os.environ.get(ENV_KEY, "").strip()
        if not key:
            for fallback in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "LLM_SERVER_KEY"):
                key = os.environ.get(fallback, "").strip()
                if key:
                    break
        base = os.environ.get(ENV_BASE, "").strip()
        if not base and os.environ.get("OPENAI_API_KEY") and not os.environ.get("DEEPSEEK_API_KEY"):
            base = "https://api.openai.com/v1"
        model = os.environ.get(ENV_MODEL, "").strip()
        if not model:
            model = "gpt-4o-mini" if "openai.com" in (base or "") else DEFAULTS["model"]
        return cls(
            base_url=(base or DEFAULTS["base_url"]).rstrip("/"),
            api_key=key,
            model=model,
        )

    @property
    def usable(self) -> bool:
        return bool(self.api_key)


class LLMClient:
    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig.from_env()

    def _endpoint(self) -> str:
        base = self.config.base_url
        # 兼容用户填 base 或填完整 endpoint 两种写法
        if base.endswith("/chat/completions"):
            return base
        if base.endswith("/v1"):
            return f"{base}/chat/completions"
        return f"{base}/chat/completions"

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> str:
        if not self.config.usable:
            raise LLMError(
                f"未配置 API Key。请设置环境变量 {ENV_KEY}（或 DEEPSEEK_API_KEY / OPENAI_API_KEY）。"
            )

        payload: dict[str, object] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature if temperature is None else temperature,
            "max_tokens": self.config.max_tokens if max_tokens is None else max_tokens,
            "stream": False,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }

        last_error: Exception | None = None
        for attempt in range(self.config.retries):
            req = urllib.request.Request(
                self._endpoint(), data=body, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                return self._extract(data)
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", "replace")[:500]
                except Exception:  # noqa: BLE001
                    pass
                # 429 / 5xx 可重试，4xx 其余直接失败
                if exc.code in (429, 500, 502, 503, 504) and attempt < self.config.retries - 1:
                    last_error = LLMError(f"HTTP {exc.code}: {detail}")
                    time.sleep(2 ** attempt)
                    continue
                raise LLMError(f"LLM 请求失败 HTTP {exc.code}: {detail}") from exc
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt < self.config.retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise LLMError(f"LLM 请求失败: {exc}") from exc

        raise LLMError(f"LLM 请求重试耗尽: {last_error}")

    @staticmethod
    def _extract(data: dict) -> str:
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"LLM 返回为空: {json.dumps(data, ensure_ascii=False)[:300]}")
        message = choices[0].get("message") or {}
        content = message.get("content")
        if isinstance(content, list):
            # 部分模型返回 content 数组
            content = "".join(
                part.get("text", "") for part in content if isinstance(part, dict)
            )
        if not content:
            raise LLMError("LLM 返回的 content 为空")
        return str(content).strip()
