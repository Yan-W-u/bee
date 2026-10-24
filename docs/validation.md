# 检测层实测数据

所有数字都可以用一条命令复现（见文末）。这里只记录**检测层**，
不涉及 LLM——补丁质量依赖模型版本和温度，不可复现的东西不该进这张表。

## 真实语料（2026-10-24，v1.1.0）

`default` 档，即使用者默认看到的噪音量：

| 语料 | 文件 | 发现 | 耗时 | 主要来源 |
| --- | --- | --- | --- | --- |
| CPython 3.13 stdlib（排除 test/idlelib/site-packages） | 536 | **77** | 7.2s | code-injection×43、command-injection×8、unsafe-deserialization×8 |
| 本机 site-packages（第三方包） | — | 18 | 3.5s | tls-verify-disabled×7、code-injection×5 |
| bee 自身 | 23 | **0** | 0.3s | — |

## 降噪前后对比

| 版本 | stdlib 发现数 | 说明 |
| --- | --- | --- |
| v1.0.0 | 321 | `iscoroutinefunction(` 被 JS 的 `Function(` 分支命中；docstring 里的示例代码；`token_type = '...'` 当凭据 |
| v1.1.0 | 77 | 按语言拆分 pattern + 词边界 + 字符串/注释过滤 + 凭据启发式 + timing 收紧 |

按规则拆解降噪贡献（stdlib）：

| 规则 | 改前 | 改后 | 手段 |
| --- | --- | --- | --- |
| code-injection | 175 | 43 | `Function(` 加左边界并按语言拆分，Python 不再套用 JS 分支 |
| hardcoded-credential | 44 | 0 | 名字后缀（`_type`/`_name`）+ 值启发式（长度≥12、≥2 类字符、排除占位符） |
| timing-attack | 18 | 3 | 去掉 `token` 关键词，排除与数字字面量比较 |
| path-traversal | 11 | 0 | `os.path.join(self._path, ...)` 这类对象内部目录不报 |
| zip-slip | 10 | 1 | 去掉 `tarfile.open`（只是打开不是解压）；`extractall(filter=...)` 视为已修 |
| tls-verify-disabled | 8 | 1 | `verify_mode != CERT_NONE` 是正常校验，不再是「关闭校验」 |
| xxe | 7 | 1 | 标准库 `ElementTree` 不解析外部实体，只保留 lxml |

## 剩下 77 条是什么

不是「误报率降到 0」——那是做不到的。剩余的绝大多数是**真实的危险 API 调用**，
只是出现在「实现这些功能的地方」：

- `eval(code, globals, locals)` 在 `_pyrepl`（REPL 实现）、`pdb`（调试器）里
- `marshal.loads` / `pickle.load` 在 `importlib`、`multiprocessing` 内部
- `shell=True` 在 `asyncio`、`pager` 里

对业务代码来说这些确实是危险模式；对标准库来说它们是功能本身。
**规则只看单行，看不到这个区别**——所以报告必须人 review，这不是缺陷，是边界。

## 为什么不在 stdlib 上算 FP 率

在 stdlib 上抽样标 FP 没有意义：标准库就是这些危险 API 的实现方，
天然会把命中率推向 100% 的「FP」。要测 FP 率，语料必须是**应用代码**
（Web 服务、CLI 工具、数据处理脚本），而不是基础设施。

目前还没有这样的公开语料。这是 v1.1.0 的真实缺口，写在 README 的已知限制里。
如果有人愿意贡献一个「应用代码 + 人工标注」的小语料（20–50 个文件即可），
那比扩规则有用得多。

## 复现

```bash
# 规则层 accuracy（24 个构造样本，0 误报 0 漏报是硬门槛）
python benchmark/run.py --strict

# 真实语料噪音（自动定位 stdlib / site-packages，CI 也在跑）
python benchmark/realworld.py --check
python benchmark/realworld.py --sample 12      # 生成人工标注用的抽样表
```

`benchmark/expected.json` 里是阈值。超阈值退出码 1——目的是抓「某条抑制被改坏了」，
不是卡死具体数字。
