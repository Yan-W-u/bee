# Changelog

## v1.0.0 (2026-10-24)

第一个正式版本。在此之前的 `main` 只有开发提交，无 tag。

### 能力

- 检测：内置 30 条规则（Py/JS/TS/Go/Java/PHP + YAML/JSON/.env），含轻量数据流
  （SQL 拼接变量追踪）；可选合并 semgrep（`--detector auto|rules|semgrep|both`）
- 可解释性：四段式（根因/攻击路径/影响面/修复原理），证据强制 `L行号: 结论`
  格式 + 行号真实性/距离校验，不合格打回重写，两轮后标记降级且不喂给补丁
- 补丁：`old_string`/`new_string` 精确替换，多编辑/跨文件，缩进容错，失败原因回灌重试
- 验证：四项信号（applied / finding_gone / compiles / tests_pass）+ 基线对照
  （红基线记「不可用」而非「失败」）+ 缺 import 检查 + 受保护文件硬拦截
- 输出：Markdown 报告、JSON、SARIF 2.1.0（`security-severity` + codeFlows）
- 增量：baseline 指纹不含行号，`--fail-on-new` / `--fail-on-findings` 供 CI 门禁
- 集成：GitHub Actions（PR 检查 + SARIF 上传 + 自检）、pre-commit、GitLab/Jenkins 文档

### 安全边界（对外/对不可信仓库使用前的必要防护）

- `fix` 的回归测试**默认关闭**，`--run-tests` 显式开启并二次确认
- 测试子进程环境变量按名单剥离（`BEE_LLM_*` / `*_KEY` / `*_TOKEN` / 云凭据）
- 补丁路径 `safe_join`：`../`、绝对路径、符号链接一律拒绝读写
- 受保护名单：测试/CI/构建配置、`.env*`、`*.pem`/`*.key`、`.git/`，大小写不敏感
- semgrep docker 模式只读挂载 + 固定镜像版本（可用 `BEE_SEMGREP_IMAGE` 覆盖）
- `--rules-file` 会执行该 Python 文件，文档明确警告

### 已知限制

见 README「已知限制」十条。要点：检测上限由规则决定、`finding_gone` ≠ 逻辑安全、
benchmark 数字偏乐观（自建样本）、大仓库无硬成本预算、只对可信仓库运行 fix。

### 验收

- 103 个单元测试全绿（`python -m unittest discover -s tests`）
- 检测层 benchmark：16 正例 / 8 负例，TP 16 / FN 0 / FP 0（`--strict` 退出码 0）
- GitHub Actions：push 触发单测 + benchmark + 扫描 + SARIF 上传
