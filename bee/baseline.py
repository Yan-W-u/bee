"""增量扫描基线。

存在的理由很实际：把 bee 接进 CI 后，第一次扫一个成熟项目会报出几百条历史问题。
每次都全量报告，开发者会直接关掉这条流水线。基线让工具只对**新引入**的问题负责，
这是任何静态分析工具能长期存活的前提。

基线比对的键是指纹，不是行号。指纹由 path + rule_id + 命中行内容哈希组成，
代码上下移动、文件里插入注释都不会让已有问题变成「新增」。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .models import Finding

BASELINE_VERSION = 1


@dataclass
class Baseline:
    version: int = BASELINE_VERSION
    generated_at: str = ""
    tool: str = "bee"
    entries: dict[str, dict] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.entries)


def load(path: Path) -> Baseline:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"基线文件不是合法 JSON（{path}）：{exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"基线文件格式不对（顶层应是对象）：{path}")
    entries: dict[str, dict] = {}
    for item in data.get("findings") or []:
        fp = str(item.get("fingerprint") or "")
        if fp:
            entries[fp] = item
    return Baseline(
        version=int(data.get("version") or BASELINE_VERSION),
        generated_at=str(data.get("generated_at") or ""),
        tool=str(data.get("tool") or "bee"),
        entries=entries,
    )


def build(findings: list[Finding]) -> Baseline:
    entries: dict[str, dict] = {}
    for f in findings:
        entries[f.fingerprint] = {
            "fingerprint": f.fingerprint,
            "rule_id": f.rule_id,
            "path": f.path,
            "line": f.start_line,
            "severity": f.severity.value,
            "title": f.message,
        }
    return Baseline(
        generated_at=datetime.now().isoformat(timespec="seconds"),
        entries=entries,
    )


def save(baseline: Baseline, path: Path) -> None:
    payload = {
        "version": baseline.version,
        "tool": baseline.tool,
        "generated_at": baseline.generated_at,
        "count": len(baseline.entries),
        "findings": sorted(baseline.entries.values(), key=lambda x: (x["path"], x["line"])),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def split(findings: list[Finding], baseline: Baseline) -> tuple[list[Finding], list[Finding]]:
    """把发现拆成 (新增, 已在基线中)。

    「已在基线中」不代表已修复，只代表团队已经知情并决定先放着。
    """
    new: list[Finding] = []
    known: list[Finding] = []
    for f in findings:
        if f.fingerprint in baseline.entries:
            known.append(f)
        else:
            new.append(f)
    return new, known


def summary(baseline: Baseline) -> str:
    when = baseline.generated_at or "未知时间"
    return f"基线含 {baseline.size} 条已知问题（生成于 {when}）"
