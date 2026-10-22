"""SARIF 2.1.0 输出。

用途很明确：让结果能被 GitHub Code Scanning、VS Code SARIF Viewer、
Azure DevOps 直接消费。没有这个格式，bee 就只能自己看自己的报告，
进不了任何现有工作流。

字段取舍上有个细节值得记：GitHub 用 `security-severity` 排序问题优先级
（0.0–10.0），不是用 SARIF 的 level。只填 level 会导致所有问题在
Security 面板里权重一样，修复优先级就失去了意义。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import Finding, Severity

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Yan-W-u/bee"

LEVEL = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}

# 直接导致代码执行或数据全量泄露的类型给更高权重，用于 GitHub 的优先级排序
HIGH_IMPACT_CWE = {
    "CWE-89", "CWE-78", "CWE-94", "CWE-95", "CWE-502", "CWE-22",
    "CWE-1336", "CWE-611", "CWE-1321", "CWE-943",
}


def _security_severity(finding: Finding) -> str:
    if finding.severity is Severity.INFO:
        return "3.5"
    if any(cwe in HIGH_IMPACT_CWE for cwe in finding.cwe):
        return "9.8" if finding.severity is Severity.ERROR else "7.5"
    return "8.0" if finding.severity is Severity.ERROR else "5.5"


def _rule_entry(finding: Finding) -> dict:
    hint = str(finding.raw.get("root_cause_hint") or "").strip()
    fix = str(finding.raw.get("fix_hint") or "").strip()
    help_parts = [p for p in (f"**根因**：{hint}" if hint else "", f"**修复**：{fix}" if fix else "") if p]

    # tags 必须去重：SARIF schema 对它有 uniqueItems 约束，GitHub Code Scanning
    # 一旦发现重复项会拒收整份文件（实测 rules[i].properties.tags 含重复就 400）。
    tags = list(dict.fromkeys(
        ["security", "static-analysis"] + [str(t) for t in finding.cwe] + [str(t) for t in finding.owasp]
    ))
    return {
        "id": finding.rule_id,
        "name": finding.rule_id.split(".")[-1].replace("-", " "),
        "shortDescription": {"text": finding.message},
        "fullDescription": {"text": hint or finding.message},
        "helpUri": (finding.references[0] if finding.references else INFORMATION_URI),
        "help": {"text": "\n".join(help_parts) or finding.message},
        "defaultConfiguration": {"level": LEVEL[finding.severity]},
        "properties": {
            "tags": tags,
            "security-severity": _security_severity(finding),
            "precision": "high" if finding.trace else "medium",
        },
    }


def _result_entry(finding: Finding, rule_index: int) -> dict:
    region: dict = {"startLine": finding.start_line}
    if finding.end_line > finding.start_line:
        region["endLine"] = finding.end_line
    snippet = (finding.code_line or finding.snippet or "").strip()
    if snippet:
        region["snippet"] = {"text": snippet[:1000]}

    result = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVEL[finding.severity],
        "message": {"text": f"{finding.title}\n\n{str(finding.raw.get('root_cause_hint') or '').strip()}".strip()},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                "region": region,
            }
        }],
        "partialFingerprints": {"beeFingerprint/v1": finding.fingerprint},
        "properties": {
            "cwe": list(dict.fromkeys(str(c) for c in finding.cwe)),
            "owasp": list(dict.fromkeys(str(o) for o in finding.owasp)),
            "detector": finding.detector,
            "severity": finding.severity.value,
        },
    }

    if finding.trace:
        result["codeFlows"] = [{
            "threadFlows": [{
                "locations": [
                    {
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": step.path, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": max(step.line, 1), "snippet": {"text": step.content[:500]}},
                            },
                            "message": {"text": step.label},
                        }
                    }
                    for step in finding.trace
                ]
            }]
        }]

    return result


def to_sarif(findings: list[Finding], *, tool_version: str = __version__) -> dict:
    """构建 SARIF 文档。规则按 id 去重后建立索引，结果用 ruleIndex 回指。"""
    rules: list[dict] = []
    index: dict[str, int] = {}

    for finding in findings:
        if finding.rule_id in index:
            continue
        index[finding.rule_id] = len(rules)
        rules.append(_rule_entry(finding))

    results = [_result_entry(f, index[f.rule_id]) for f in findings]

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "bee",
                    "version": tool_version,
                    "semanticVersion": tool_version,
                    "informationUri": INFORMATION_URI,
                    "rules": rules,
                }
            },
            "automationDetails": {"id": "bee/scan"},
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }],
            "results": results,
        }],
    }


def write(findings: list[Finding], path: Path, *, tool_version: str = __version__) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(to_sarif(findings, tool_version=tool_version), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path
