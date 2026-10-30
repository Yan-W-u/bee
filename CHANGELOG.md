# Changelog

## v1.2.0 (2026-10-30)

外部复核（V1.1-REVIEW）提出的 3 个缺陷、1 个体验问题、2 条主线建议全部落地。

### 修复

- **`--max-findings` 在没有 API key 时完全不生效**：预算把「处理条数」和「模型调用次数」
  合成一个判定，无 key 时 `llm_calls` 恒 0 却仍被 `max_llm_calls` 拦住，
  `--no-llm --max-findings 2` 处理了全部 8 条。现在拆成 `allows_count()` /
  `allows_llm()`：条数与墙钟任何模式都生效，调用次数只在真会调模型时生效。
  被截断的条目标「未处理」并写明原因，不再假装没问题。
- **`Typing :: Typed` 声明了却没有 `bee/py.typed`**：按 PEP 561 补上标记文件与
  `[tool.setuptools.package-data]`，release 工作流新增断言「wheel 里必须有
  `bee/py.typed`」，本地没有 setuptools 时也能靠 CI 卡住回归。
- **外部 SARIF 的 CWE / OWASP / helpUri 全部丢失**：`--input` 只读 `result.properties.cwe`，
  而 Semgrep / CodeQL 都把标签放在**规则级** `tags`（`CWE-89: …`、`external/cwe/cwe-089`）。
  现在统一归一到 `CWE-89` / `A03:2021`，并补 CWE 参考链接。此前重导出 SARIF 时
  `security-severity` 会掉回默认值，GitHub 的优先级排序因此失效。
- `--input` 模式下目标目录为空时不再误报「扫描到 0 个文件」。

### 新增：外部 finding 的验证闭环

`--input` 曾经有个断链——外部规则 id 在 bee 里不存在，重扫必然扫不到，所以
`finding_gone` 只能记 `None`，这条产品线永远拿不到「已验证」。

- `bee/aliases.py`：约 50 条人工核对的 Semgrep / CodeQL → 内置规则映射，**默认启用**。
- `--rescan-rules my_rules.py`：自定义规则 `id` 与外部 `ruleId` 相同时直接用于重扫；
  与 `--rules-file` 的区别是「追加」而不是「替换」。
- 映射不上的条目保持 `finding_gone = None`，报告只写「仅解释」，绝不冒充已验证。
- 按规则名推测（heuristic）只在显式给了 `--rescan-rules` 时启用，且报告里标注。

### 门禁与工程

- `benchmark/expected.json` 的 stdlib 阈值 130 → **100**（实测 77，余量从 65% 收到 30%）：
  原来的门禁只能抓「整条抑制被删掉」，抓不到渐进放宽。
- `self` 语料改用 `git ls-files`：本地留了 `tmp/`、`build/` 这类产物时，自扫不再变红。
- 新增测试 `tests/test_v120.py`（20 条）覆盖上述全部改动；版本号一致性也有测试卡住
  （`pyproject.toml` 与 `bee/__init__.py` 两处手写）。

测试 143 → **163**，benchmark 16/8 保持 0 FP / 0 FN，真实语料 77 / 18 / 0。

### 修复（v1.1.0 发布后由周扫 CI 暴露）

- **`--json` 的 stdout 被提示信息污染**：`--sarif` / `-o` / `--write-baseline` 写完文件后
  会往 stdout 打「已写入 …」，与 JSON 文档混在一行之外，`json.loads` 直接报
  `Extra data`。周扫 CI 的「汇总」步骤就是这么红的（第一次定时运行才发现）。
  现在提示一律走 stderr，stdout 只留报告或 JSON。
- `audit` / `fix` 在无发现时不再用中文提示顶替 JSON：`--json` 输出 `[]`。
  `--apply` 的交互提示也改走 stderr。
- 补 5 条回归测试：`--json` 分别叠加 `--sarif` / `-o` / `--write-baseline` 时都必须
  可解析，`audit` / `fix` 空结果必须是 `[]`。
- 周扫的「汇总」步骤解析失败时输出 `::error` annotation（含文件开头内容），
  不再只留一句 `exit code 1`。

### 文档

- README 改为中英双语：英文版在前（面向 GitHub 上的英文读者），中文版在后，
  顶部提供 `English | 简体中文` 跳转锚点。补 stdout/stderr 约定说明。

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
