"""源码读写：全程保留原始换行符。

为什么单独抽出来：在 Windows 上 `Path.write_text(text)` 会把 `\\n` 写成 `\\r\\n`，
`read_text()` 又会反向转换。后果是——补丁只改了一行，落盘后整个文件的换行符全变，
git diff 一片红，review 完全没法看。

这里统一用 `newline=""`：读进来是什么样，写回去就是什么样。
"""

from __future__ import annotations

from pathlib import Path


def read_source(path: Path) -> str:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        return fh.read()


def write_source(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
