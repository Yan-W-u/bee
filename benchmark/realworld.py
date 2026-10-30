"""真实代码语料评测。

benchmark/cases 里的 24 个样本是照着规则能力写的，只能证明「规则按设计工作」。
这个脚本换成真实代码：CPython stdlib、pip 的 site-packages、bee 自己。
它衡量的是**误报噪音**，因为那才是真实项目里最先劝退人的东西。

用法：
    python benchmark/realworld.py                 # 人类可读表格
    python benchmark/realworld.py --check         # 超阈值退出码 1（CI 用）
    python benchmark/realworld.py --sample 12 --out review_sample.md

语料路径支持 `$VAR` / `${VAR}` 展开；内置语料用 sysconfig / sys.executable 自动定位，
所以 CI 上不需要额外准备数据。
"""

from __future__ import annotations


def _force_utf8() -> None:
    """Windows runner 的默认 stdout 编码不是 UTF-8，打印中文会 UnicodeEncodeError。

    这个脚本的输出来自 CI（Windows 矩阵），所以必须在最前面就把编码钉死。
    """
    import sys as _sys
    for stream in (_sys.stdout, _sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            continue


import argparse
import json
import os
import sys
import sysconfig
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bee.detect import BUILTIN_RULES, Confidence, scan_tree  # noqa: E402
from bee.models import Finding  # noqa: E402

CORPORA = ROOT / "benchmark" / "corpora.json"
EXPECTED = ROOT / "benchmark" / "expected.json"


def _builtin_paths() -> dict[str, str]:
    return {
        "PY_STDLIB": sysconfig.get_paths().get("stdlib", ""),
        "PY_SITE_PACKAGES": sysconfig.get_paths().get("purelib", ""),
        "BEE_REPO": str(ROOT),
    }


def _expand(raw: str) -> str:
    vars_ = _builtin_paths()
    vars_.update(os.environ)
    out = raw
    for key, value in vars_.items():
        out = out.replace("${" + key + "}", value).replace("$" + key, value)
    return out


def load_corpora() -> list[dict]:
    data = json.loads(CORPORA.read_text(encoding="utf-8"))
    return data["corpora"] if isinstance(data, dict) else data


_ORDER = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
_FLOOR = {"strict": Confidence.HIGH, "default": Confidence.MEDIUM, "full": Confidence.LOW}


def rules_for(profile: str) -> list:
    """按档位取规则，和 CLI 的 --profile 保持同一语义。

    评测必须反映使用者默认看到的噪音量，所以默认用 default 档而不是全量。
    """
    floor = _ORDER[_FLOOR.get(profile, Confidence.MEDIUM)]
    return [r for r in BUILTIN_RULES if _ORDER.get(r.confidence, 1) >= floor]


def _git_tracked(repo: Path) -> list[str]:
    """列出 git 追踪的（相对）文件路径。

    self 语料必须用它：只要本地留了 tmp/、build/、dist/ 这类临时产物，
    全目录扫描就会把作者自己的草稿算进「自扫误报」，门禁变成看心情红。
    只用 tracked 文件才是「仓库本身干净」的正确语义。
    不是 git 仓库（比如下载的 tarball）时返回空列表，由调用方回退到全目录。
    """
    import subprocess

    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=repo, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    return [p for p in out.stdout.split("\0") if p]


def run_corpus(spec: dict, profile: str = "default") -> dict:
    path = Path(_expand(spec["path"]))
    result = {"name": spec["name"], "path": str(path), "exists": path.exists()}
    if not path.exists():
        result["error"] = "路径不存在"
        return result

    only_paths = None
    if spec.get("git_tracked"):
        tracked = _git_tracked(path)
        if tracked:
            only_paths = tracked
            result["tracked_only"] = len(tracked)

    started = time.perf_counter()
    findings: list[Finding] = scan_tree(
        path,
        rules=rules_for(profile),
        include_globs=spec.get("include"),
        only_paths=only_paths,
        exclude_globs=spec.get("exclude"),
    )
    elapsed = time.perf_counter() - started
    files = len({f.path for f in findings})
    result.update(
        findings=len(findings),
        files_with_findings=files,
        seconds=round(elapsed, 2),
        by_rule=dict(Counter(f.rule_id for f in findings).most_common()),
        items=findings,
    )
    return result


def print_table(results: list[dict]) -> None:
    print(f"{'语料':<22}{'发现':>6}{'文件':>6}{'秒':>7}  主要规则")
    print("-" * 78)
    for r in results:
        if not r.get("exists"):
            print(f"{r['name']:<22}{'—':>6}{'—':>6}{'—':>7}  {r.get('error', '')}")
            continue
        top = ", ".join(f"{k.split('.')[-1]}×{v}" for k, v in list(r["by_rule"].items())[:3])
        print(f"{r['name']:<22}{r['findings']:>6}{r['files_with_findings']:>6}{r['seconds']:>7}  {top}")


def check(results: list[dict]) -> int:
    """按 expected.json 的阈值判定，任何一项超限即失败。"""
    if not EXPECTED.exists():
        print(f"缺少阈值文件: {EXPECTED}")
        return 2
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    failed = 0
    for r in results:
        limits = expected.get(r["name"])
        if not limits or not r.get("exists"):
            continue
        for key in ("max_findings", "max_seconds"):
            limit = limits.get(key)
            if limit is None:
                continue
            value = r["findings"] if key == "max_findings" else r["seconds"]
            if value > limit:
                print(f"✗ {r['name']}: {key}={value} 超过阈值 {limit}")
                failed += 1
    if failed:
        print(f"\n{failed} 项超阈值。误报回涨通常意味着某条抑制逻辑被改坏了。")
        return 1
    print("全部语料在阈值内。")
    return 0


def write_sample(results: list[dict], count: int, out: Path) -> None:
    """按规则分层抽样，供人工标注 TP/FP。

    直接随机抽会被数量最多的规则淹没，所以先按规则分组再轮流取。
    """
    buckets: dict[str, list[Finding]] = {}
    for r in results:
        for f in r.get("items") or []:
            buckets.setdefault(f.rule_id, []).append(f)

    # 确定性抽样：按规则名排序后轮流取，不用 random（随机源会触发
    # 自己的 insecure-random 规则，自扫就不再是 0）
    picked: list[Finding] = []
    keys = sorted(buckets)
    cursors = {k: 0 for k in keys}
    while len(picked) < count:
        progressed = False
        for key in keys:
            pool = buckets[key]
            idx = cursors[key]
            if idx < len(pool) and len(picked) < count:
                picked.append(pool[idx])
                cursors[key] = idx + 1
                progressed = True
        if not progressed:
            break

    lines = [
        "# 真实语料抽样（人工标注用）",
        "",
        "逐条在 `结果` 里填 `TP`（真漏洞）或 `FP`（误报）。",
        "统计出的 FP 率写进 docs/validation.md。",
        "",
        "| # | 规则 | 位置 | 代码 | 结果 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for i, f in enumerate(picked, 1):
        code = (f.code_line or "").strip().replace("|", "\\|")[:90]
        lines.append(f"| {i} | `{f.rule_id}` | `{f.location}` | `{code}` |  |")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"抽样 {len(picked)} 条 → {out}")


def main() -> int:
    _force_utf8()
    ap = argparse.ArgumentParser(description="真实语料评测")
    ap.add_argument("--check", action="store_true", help="按 expected.json 阈值判定")
    ap.add_argument("--sample", type=int, default=0, help="额外输出 N 条分层抽样")
    ap.add_argument("--out", type=Path, default=ROOT / "benchmark" / "review_sample.md")
    ap.add_argument("--only", action="append", help="只跑指定语料（可多次）")
    ap.add_argument("--profile", choices=["strict", "default", "full"], default="default",
                    help="规则档位，默认 default（与 CLI 一致）")
    args = ap.parse_args()

    specs = load_corpora()
    if args.only:
        wanted = {x.strip() for x in args.only}
        specs = [s for s in specs if s["name"] in wanted]
    if not specs:
        print("没有可跑的语料。检查 benchmark/corpora.json 或 --only 参数。")
        return 2

    results = [run_corpus(s, args.profile) for s in specs]
    print_table(results)
    print()

    if args.sample:
        write_sample(results, args.sample, args.out)
        print()

    if args.check:
        return check(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
