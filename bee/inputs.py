"""从外部 SARIF 读取 finding。

定位转变：检测不该由 bee 来做——Semgrep / CodeQL 更全。bee 的价值在
「已有 finding → 解释 → 补丁 → 验证」。这个模块就是那条接缝。

已知限制：外部规则不在 bee 的规则表里，补丁无法用「重扫该规则」验证，
所以 finding_gone 记为 None（未验证），报告里会明确标注。
这比假装验证通过要诚实。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding, Severity

_LEVEL_SEVERITY = {
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "note": Severity.INFO,
    "none": Severity.INFO,
}


def _severity(raw: str | None, rule_level: str | None = None) -> Severity:
    text = (raw or rule_level or "warning").lower()
    return _LEVEL_SEVERITY.get(text, Severity.WARNING)


def _rule_levels(data: dict) -> dict[str, str]:
    """规则默认 level：有些工具只在 rule 定义里写 level，result 上不写。"""
    levels: dict[str, str] = {}
    for run in data.get("runs") or []:
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        for rule in rules:
            rid = rule.get("id")
            level = ((rule.get("defaultConfiguration") or {}).get("level")) or ""
            if rid and level:
                levels[rid] = level
    return levels


def findings_from_sarif(sarif_path: Path, root: Path) -> list[Finding]:
    """把 SARIF 2.1.0 的结果转成 Finding 列表。

    路径处理要小心：uri 可能是相对路径、file:// URI、或带 %SRCROOT% 的绝对路径。
    统一转成「相对 root 的 posix 路径」，跟内置检测的输出保持一致，
    否则后续 safe_join / 报告都会错位。
    """
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "runs" not in data:
        raise ValueError(f"不是 SARIF 2.1.0 文件: {sarif_path}")

    levels = _rule_levels(data)
    out: list[Finding] = []
    root_resolved = root.resolve()

    for run in data.get("runs") or []:
        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            loc = (res.get("locations") or [{}])[0]
            physical = loc.get("physicalLocation") or {}
            region = physical.get("region") or {}
            artifact = physical.get("artifactLocation") or {}
            uri = str(artifact.get("uri") or "").replace("\\", "/")
            if not uri:
                continue
            if uri.startswith("file://"):
                # 只去掉 "file://"，保留后面的 "/"——POSIX 上那是根，
                # 去掉就变成相对路径了（Linux CI 上就是这么挂的）
                uri = uri[len("file://"):]
                if re.match(r"^/[A-Za-z]:", uri):   # Windows: /C:/x -> C:/x
                    uri = uri[1:]
            rel = uri
            try:
                candidate = Path(uri)
                if candidate.is_absolute():
                    rel = str(candidate.resolve().relative_to(root_resolved)).replace("\\", "/")
            except (ValueError, OSError):
                rel = uri.lstrip("/")

            rid = str(res.get("ruleId") or (res.get("rule") or {}).get("id") or "external")
            message = (res.get("message") or {}).get("text") or rid
            start = int(region.get("startLine") or 1)
            end = int(region.get("endLine") or start)
            props = res.get("properties") or {}
            cwe = [str(c) for c in (props.get("cwe") or []) if c]

            out.append(
                Finding(
                    rule_id=rid,
                    severity=_severity(res.get("level"), levels.get(rid)),
                    message=message[:200],
                    path=rel,
                    start_line=start,
                    end_line=max(end, start),
                    cwe=cwe,
                    owasp=[],
                    references=[str(res["helpUri"])] if res.get("helpUri") else [],
                    snippet="",
                    code_line="",
                    detector="sarif",
                    raw={
                        "title": message[:120],
                        "root_cause_hint": props.get("root_cause_hint") or "",
                        "fix_hint": props.get("fix_hint") or "",
                        "sarif": {"ruleId": rid, "level": res.get("level")},
                        "external": True,
                    },
                )
            )

    # 同一文件同一行同一规则去重（多 run/多结果重复上报很常见）
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for f in out:
        key = (f.path, f.start_line, f.rule_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return sorted(unique, key=lambda x: (x.path, x.start_line, x.rule_id))


def looks_like_sarif(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8")[:2048]
    except OSError:
        return False
    return '"runs"' in head or '"$schema"' in head and "sarif" in head.lower()
