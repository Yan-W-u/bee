"""成本与规模预算。

为什么要这个：一次 audit/fix 对每条 finding 最多调 5 次模型（解释 2 轮 + 补丁 3 轮），
在大仓库上很容易变成「跑一晚上 + 账单失控」。预算是把「不可控」变成「可预测」的最简手段。

三个维度分别兜不同的底：
  max_findings  —— 处理条数上限（最常见）
  max_llm_calls —— 调用次数上限（成本直接挂钩）
  max_seconds   —— 墙钟时间上限（防止单条卡死拖垮整批）

**前两个维度的适用范围不同，必须分开判定**：
  - `max_findings` / `max_seconds` 是「处理规模」，与有没有配模型无关。
    无 key 时只做规则解释，大仓库照样跑不完，所以照样要限。
  - `max_llm_calls` 只在真的会调模型时才成立。无 key 时一条 finding 消耗 0 次调用，
    拿它当门槛会让 `--max-findings` 连带失效（v1.1.0 的实际 bug）。
  所以对外分成 `allows_count()` / `allows_llm()` 两个判定。

调用次数是按「每条最多 2+rounds 次」估算的，不精确计数——精确计数需要给
LLMClient 加钩子，收益不抵复杂度。估算值在报告里明确标注为估算。
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class Budget:
    max_findings: int = 20
    max_llm_calls: int = 120
    max_seconds: int = 1800

    def __post_init__(self) -> None:
        self._started = time.monotonic()
        self.llm_calls = 0
        self.processed = 0
        self.skipped = 0
        self.stopped_reason = ""

    # ---- 时间
    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._started

    def time_left(self) -> float:
        return max(0.0, self.max_seconds - self.elapsed) if self.max_seconds else float("inf")

    # ---- 判定：规模（与是否配模型无关）
    def allows_count(self) -> bool:
        """条数 / 时间上限。纯规则解释也要拦，否则 --max-findings 在无 key 时形同虚设。"""
        if self.max_findings and self.processed >= self.max_findings:
            self.stopped_reason = f"已达 --max-findings={self.max_findings}"
            return False
        if self.max_seconds and self.elapsed >= self.max_seconds:
            self.stopped_reason = f"已达 --max-seconds={self.max_seconds}"
            return False
        return True

    # ---- 判定：模型调用（只在会调模型时检查）
    def allows_llm(self, per_finding_calls: int) -> bool:
        if self.max_llm_calls and self.llm_calls + per_finding_calls > self.max_llm_calls:
            self.stopped_reason = (
                f"预计调用次数将超过 --max-llm-calls={self.max_llm_calls}"
                f"（每条最多 {per_finding_calls} 次）"
            )
            return False
        return True

    # ---- 兼容旧调用：两个维度都查
    def allows_more(self, per_finding_calls: int) -> bool:
        """是否还能再处理一条 finding（规模 + 模型调用都满足）。

        CLI 里请分别调用 `allows_count()` / `allows_llm()`：无 key 时不该受
        `max_llm_calls` 约束，而这个合并判定会一并检查。
        """
        return self.allows_count() and self.allows_llm(per_finding_calls)

    def charge(self, calls: int) -> None:
        """记一条已处理的 finding。calls 是本次估算的模型调用次数（无 key 时传 0）。"""
        self.llm_calls += calls
        self.processed += 1

    def skip(self) -> None:
        self.skipped += 1

    def summary(self) -> str:
        if not self.stopped_reason:
            return ""
        if self.skipped:
            tail = f"剩余 {self.skipped} 条未处理（未生成解释）。"
        else:
            tail = "剩余条目未调用模型，只做了规则检测。"
        calls = f"，约 {self.llm_calls} 次模型调用" if self.llm_calls else ""
        return (
            f"预算用尽（{self.stopped_reason}）：已处理 {self.processed} 条{calls}，"
            f"耗时 {self.elapsed:.0f}s。{tail}"
        )
