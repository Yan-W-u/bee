# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 1.1.x | ✅ |
| 1.0.x | ✅（仅安全修复） |
| < 1.0 | ❌ |

## Reporting a Vulnerability

**不要开公开 issue。** 用以下任一方式私下报告：

- GitHub 仓库页 → Security → Report a vulnerability（私有安全公告，推荐）
- 邮件：`yan.w.u@outlook.com`（48 小时内回复）

报告时请附：bee 版本（`bee --version`）、复现命令、目标仓库的最小结构、影响说明。
如果问题出在被扫描的目标仓库而不是 bee 本身，请同时说明你是否授权我们引用那段代码。

## Scope

**在范围内**

- bee 自身的漏洞：路径穿越（`safe_join` 绕过）、任意文件读写、命令执行、凭据泄露、
  临时副本残留、SARIF/JSON 输出中的敏感信息
- 验证层的绕过：能让「未修复的补丁」被判为 `succeeded` 的构造
- 供应链：workflow、依赖、发布产物的完整性问题

**不在范围内**

- 内置规则在具体项目上的漏报/误报（请开普通 issue，附最小复现片段）
- 目标仓库自身的漏洞（bee 只是报告它）
- 需要先取得目标机器写权限才能利用的问题

## 使用者需要知道的边界

- `bee scan` / `audit`（不带 `fix`）是纯静态读取，对任何仓库都可安全运行。
- `bee fix` 在 `--run-tests` 时会**执行目标仓库的测试代码**（等于执行任意代码）。
  只对可信仓库开启，或放进容器里跑。测试子进程的环境变量已按名单剥离
  （`BEE_LLM_*` / `*_KEY` / `*_TOKEN` / 云凭据），但这只是缓解，不是沙箱。
- `--rules-file` 会 **exec 该 Python 文件**，等价于 `python your_rules.py`。
