"""bee：漏洞检测 + 可解释性修复 + 机器验证。

核心主张：LLM 生成的修复在没有验证之前只是猜测。
这个工具的价值不在「能改代码」，而在「能证明改对了」。
"""

from .explain import explain
from .llm import LLMClient, LLMConfig
from .models import Explanation, Finding, PatchAttempt, RepairResult, Severity
from .patch import repair_finding
from .verify import EditProposal, verify_patch

__version__ = "1.1.0"

__all__ = [
    "Explanation",
    "EditProposal",
    "Finding",
    "LLMClient",
    "LLMConfig",
    "PatchAttempt",
    "RepairResult",
    "Severity",
    "explain",
    "repair_finding",
    "verify_patch",
]
