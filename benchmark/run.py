"""benchmark runner：把「感觉挺好用」变成可复现的数字。

只衡量检测层（规则引擎），不调 LLM——因为补丁质量依赖模型版本和温度，
不可复现；检测层的准确率是确定的，可以进 CI 看趋势。

用法：
    python benchmark/run.py              # 人类可读表格
    python benchmark/run.py --markdown   # 输出 markdown，用于贴 README
    python benchmark/run.py --strict     # 有 FN 或 FP 时退出码 1
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bee.detect import scan_tree  # noqa: E402
from bee.models import Severity  # noqa: E402

CASES_DIR = Path(__file__).resolve().parent / "cases"
MANIFEST = Path(__file__).resolve().parent / "manifest.json"
LINE_TOLERANCE = 1


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def run_scan() -> list:
    return scan_tree(CASES_DIR)


def evaluate(findings: list, manifest: dict) -> dict:
    actual = [(f.path, f.start_line, f.rule_id) for f in findings]

    tp: list[dict] = []
    fn: list[dict] = []
    for case in manifest["positives"]:
        hit = next(
            (
                a for a in actual
                if a[0] == case["file"]
                and a[2] == case["rule"]
                and abs(a[1] - case["line"]) <= LINE_TOLERANCE
            ),
            None,
        )
        if hit:
            tp.append({**case, "actual_line": hit[1]})
        else:
            same_rule = [a for a in actual if a[0] == case["file"] and a[2] == case["rule"]]
            fn.append({**case, "observed": same_rule})

    negative_files = {n["file"] for n in manifest["negatives"]}
    fp = [
        {"file": f.path, "line": f.start_line, "rule": f.rule_id, "title": f.message}
        for f in findings
        if f.path in negative_files
    ]

    n_pos = len(manifest["positives"])
    n_neg = len(manifest["negatives"])
    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    recall = len(tp) / n_pos if n_pos else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    by_lang: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    for item in tp:
        by_lang[item["file"].split("/")[0]]["tp"] += 1
    for item in fn:
        by_lang[item["file"].split("/")[0]]["fn"] += 1
    for item in fp:
        by_lang[item["file"].split("/")[0]]["fp"] += 1

    return {
        "tp": tp, "fn": fn, "fp": fp,
        "n_pos": n_pos, "n_neg": n_neg,
        "precision": precision, "recall": recall, "f1": f1,
        "by_lang": dict(by_lang),
        "total_findings": len(findings),
    }


def render(metrics: dict, as_markdown: bool) -> str:
    lines: list[str] = []
    pct = lambda x: f"{x * 100:.1f}%"  # noqa: E731

    if as_markdown:
        lines += [
            "## benchmark 结果",
            "",
            "| 指标 | 值 |",
            "| --- | --- |",
            f"| 正例（应检出） | {metrics['n_pos']} |",
            f"| 负例（应沉默） | {metrics['n_neg']} |",
            f"| 真阳性 TP | {len(metrics['tp'])} |",
            f"| 假阴性 FN | {len(metrics['fn'])} |",
            f"| 假阳性 FP | {len(metrics['fp'])} |",
            f"| 精确率 Precision | {pct(metrics['precision'])} |",
            f"| 召回率 Recall | {pct(metrics['recall'])} |",
            f"| F1 | {pct(metrics['f1'])} |",
            "",
        ]
    else:
        lines += [
            "=" * 58,
            "  bee benchmark（仅规则引擎，不含 LLM）",
            "=" * 58,
            f"  正例 {metrics['n_pos']} 个 / 负例 {metrics['n_neg']} 个",
            f"  TP {len(metrics['tp'])}   FN {len(metrics['fn'])}   FP {len(metrics['fp'])}",
            f"  Precision {pct(metrics['precision'])}   "
            f"Recall {pct(metrics['recall'])}   F1 {pct(metrics['f1'])}",
            "",
        ]

    if metrics["fn"]:
        lines.append("漏报：")
        for item in metrics["fn"]:
            observed = (
                f"（实际命中 {item['observed']}）" if item["observed"] else "（完全未命中）"
            )
            lines.append(f"  ✗ {item['file']}:{item['line']} 期望 {item['rule']} {observed}")
        lines.append("")

    if metrics["fp"]:
        lines.append("误报：")
        for item in metrics["fp"]:
            lines.append(f"  ✗ {item['file']}:{item['line']} {item['rule']} — {item['title']}")
        lines.append("")

    if metrics["by_lang"]:
        lines.append("按语言：")
        for lang, stat in sorted(metrics["by_lang"].items()):
            lines.append(
                f"  {lang:8} TP {stat['tp']}  FN {stat['fn']}  FP {stat['fp']}"
            )
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="bee benchmark")
    parser.add_argument("--markdown", action="store_true", help="输出 markdown 表格")
    parser.add_argument("--strict", action="store_true", help="有 FN/FP 时返回非零")
    args = parser.parse_args()

    findings = run_scan()
    metrics = evaluate(findings, load_manifest())
    print(render(metrics, args.markdown))

    if args.strict:
        failed = bool(metrics["fn"] or metrics["fp"])
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
