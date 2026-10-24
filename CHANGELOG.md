# Changelog

## Unreleased

- README 改为中英双语：英文版在前（面向 GitHub 上的英文读者），中文版在后，
  顶部提供 `English | 简体中文` 跳转锚点

## v1.1.0 (2026-10-24)

目标是「能装、能看」：把误报压到可用范围，让 `pipx install` 一条命令装得上，
并把边界写清楚。

### 检测降噪（最大改动）

CPython stdlib（536 文件）上的发现数 **321 → 77**：

- **按语言拆分 pattern**：`code-injection` 的 `Function(` 分支只对 JS/TS 生效，
  Python 不再被 `iscoroutinefunction(` 误伤（175 → 43）
- **字符串/注释过滤**：Python 用 `tokenize` 取真实 STRING/COMMENT 区间，
  其它语言走轻量扫描；`allow_in_strings` 保留 PEM 私钥等天然命中的规则
- **凭据规则收紧**：新增 `looks_like_secret()`——名字后缀（`token_type`）+
  值长度 ≥12 + ≥2 类字符 + 排除占位符（44 → 0）
- **timing-attack**：去掉歧义太大的 `token` 关键词，排除与数字字面量比较（18 → 3）
- **path-traversal**：`os.path.join(self._path, ...)` 这类对象内部目录不再报（11 → 0）
- **zip-slip**：`tarfile.open` 不是解压，移除；`extractall(filter=...)` 视为已修复（10 → 1）
- **tls-verify-disabled**：`verify_mode != CERT_NONE` 是正常校验，不再命中（8 → 1）
- **xxe**：标准库 `ElementTree` 不解析外部实体，只保留 lxml（7 → 1）

### 新增能力

- `--profile {strict,default,full}`：规则按把握度分档，默认档只报有把握的
- `--input <sarif>`：接收 Semgrep / CodeQL 的结果，跳过内置检测直接做解释与修复
  （`finding_gone` 记为 `None`，不谎报「已验证」）
- `--max-findings` / `--max-llm-calls` / `--max-seconds`：成本上限，超限时剩余条目
  标「未处理」而不是假装没问题
- `bee --version`；PyPI 发行名 `bee-scanner`（`bee` 已被占用），命令仍是 `bee`
- `benchmark/realworld.py`：真实语料噪音评测，`--check` 可进 CI
- `docs/scope.md` / `docs/validation.md` / `docs/semgrep-integration.md` / `docs/docker.md`

### 修复

- `SKIP_DIRS` 用绝对路径判断，目标落在 `vendor/`、`site-packages/` 下时**静默扫 0 个文件**
  并报告「无问题」——现在按相对路径判断，0 文件会明确告警
- 符号链接目录下 `scan_tree` 与 `scan_file` 的 root 不一致导致 `ValueError`

### 工程

- 供应链：所有 `uses:` 固定到 commit SHA，加 Dependabot、SECURITY.md
- CI 矩阵：ubuntu + windows × Python 3.10 / 3.12 / 3.13
- 打 tag 自动构建 wheel/sdist 并挂到 Release（`release.yml`）
- 测试 110 → 138，新增降噪边界、SARIF 导入、预算、规则分级四组

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

- 110 个单元测试全绿（`python -m unittest discover -s tests`）
- 检测层 benchmark：16 正例 / 8 负例，TP 16 / FN 0 / FP 0（`--strict` 退出码 0）
- GitHub Actions：push 触发单测 + benchmark + 增量扫描 + SARIF 上传（Linux 实跑全绿）
