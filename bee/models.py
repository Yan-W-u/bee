"""全链路统一数据契约。

设计原则：检测器可插拔，所以所有检测结果先归一化到 Finding；
可解释性修复的产出物是 Explanation（四段式）+ PatchAttempt（带验证信号）。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"

    @classmethod
    def parse(cls, raw: str) -> "Severity":
        try:
            return cls(str(raw).upper())
        except ValueError:
            return cls.WARNING


@dataclass
class TraceStep:
    """污点路径上的一步：数据从哪来、经过谁、最后落到哪个危险函数。"""

    label: str  # source | intermediate | sink
    path: str
    line: int
    content: str


@dataclass
class Finding:
    """归一化后的漏洞发现。"""

    rule_id: str
    severity: Severity
    message: str
    path: str
    start_line: int
    end_line: int
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    trace: list[TraceStep] = field(default_factory=list)
    snippet: str = ""
    # 命中行的规范化内容。指纹基于它而不是行号——
    # 代码上下移动时行号会变，但漏洞还是同一个，baseline 不能因此失效。
    code_line: str = ""
    detector: str = "bee-rules"
    fingerprint: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.fingerprint:
            basis = self.path + "|" + self.rule_id + "|" + " ".join(
                (self.code_line or self.snippet).split()
            )
            # usedforsecurity=False：这里只做指纹去重，不是加密用途。
            # 显式声明也让 weak-crypto 规则不误报这一行。
            self.fingerprint = hashlib.sha1(
                basis.encode("utf-8"), usedforsecurity=False
            ).hexdigest()[:16]

    @property
    def location(self) -> str:
        return f"{self.path}:{self.start_line}"

    @property
    def title(self) -> str:
        return f"{self.rule_id} @ {self.location}"

    @property
    def is_blocking(self) -> bool:
        return self.severity is Severity.ERROR


@dataclass
class Explanation:
    """可解释性修复的第一半：说清楚为什么，而不只是说有什么问题。

    四段式是刻意设计的 —— 少了任何一段，这个修复都不可信：
    不知道根因的补丁是猜的，不知道攻击路径的补丁会漏变体，
    不知道影响面的补丁优先级排不对，没有修复原理的补丁不可 review。
    """

    root_cause: str = ""
    attack_path: str = ""
    impact: str = ""
    fix_rationale: str = ""
    confidence: float = 0.0
    # 每条结论指向的具体证据（行号 / 数据流步骤），用于反幻觉
    evidence: list[str] = field(default_factory=list)
    # True = 多轮校验后证据仍不合格，内容不可信。
    # 降级的解释可以进报告（附带标注），但**不许再作为补丁 prompt 的输入**——
    # 编造的根因会直接把补丁带偏。
    degraded: bool = False
    degrade_reason: str = ""

    def is_complete(self) -> bool:
        return all(
            len(getattr(self, f).strip()) >= 12
            for f in ("root_cause", "attack_path", "impact", "fix_rationale")
        )

    def missing_fields(self) -> list[str]:
        names = {"root_cause": "根因", "attack_path": "攻击路径", "impact": "影响面", "fix_rationale": "修复原理"}
        return [names[f] for f in ("root_cause", "attack_path", "impact", "fix_rationale")
                if len(getattr(self, f).strip()) < 12]


@dataclass
class PatchAttempt:
    """一次补丁尝试及其机器验证信号。

    验证信号是这套东西和「让 LLM 随手改改」的本质区别：
    applied / finding_gone / compiles / tests_pass 四项全绿才算修复成立。
    """

    round: int
    diff: str
    explanation: str = ""
    # 保留可直接落盘的编辑序列，避免只有 diff 无法反推
    # 每条是 (文件, 原片段, 新片段)，文件可以是不同路径（跨文件修复）
    file: str = ""
    old_string: str = ""
    new_string: str = ""
    edits: list[tuple[str, str, str]] = field(default_factory=list)
    applied: bool = False
    finding_gone: bool = False
    compiles: bool = False
    compile_checked: bool = False  # False 表示该环境没有对应语言的语法检查器
    tests_pass: bool | None = None  # None 表示没有测试可跑，不算失败也不算通过
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return (
            self.applied
            and self.finding_gone
            and self.compiles
            and (self.tests_pass is not False)
        )

    def failure_reason(self) -> str:
        if self.succeeded:
            return ""
        parts: list[str] = []
        if not self.applied:
            parts.append("补丁无法应用（上下文不匹配）")
        if not self.finding_gone:
            parts.append("重新扫描后漏洞仍然存在")
        if not self.compiles:
            parts.append("修改后代码无法通过编译/语法检查")
        if self.tests_pass is False:
            parts.append("现有测试失败")
        if self.errors:
            parts.append("；".join(self.errors[:3]))
        return " | ".join(parts)


@dataclass
class RepairResult:
    finding: Finding
    explanation: Explanation | None = None
    attempts: list[PatchAttempt] = field(default_factory=list)
    accepted: PatchAttempt | None = None
    # 前一条补丁已顺带修掉该处，不是失败也不是未修
    covered_elsewhere: bool = False

    @property
    def status(self) -> str:
        if self.accepted:
            return "verified"
        if self.covered_elsewhere:
            return "covered"
        if self.attempts:
            return "unverified"
        return "explained"
