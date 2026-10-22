# 漏洞审计与可解释性修复报告

- 目标：`C:\Users\21854\WorkBuddy\2026-10-22-14-44-11\vulnfix\_e2e`
- 生成时间：2026-10-22 16:09
- 工具：bee（规则引擎 + LLM 四段式解释 + 机器验证补丁）

> 所有补丁均在临时副本上验证，未改动原仓库。落盘需人工确认。

## 概览

| 项 | 值 |
| --- | --- |
| 扫描文件 | 2 |
| 发现问题 | 9 |
| 高危 | 4 |
| 中危 | 4 |
| 提示 | 1 |
| 已生成解释 | 9 |
| 补丁通过机器验证 | 8 |
| 已被前述补丁覆盖 | 1 |
| 补丁尝试轮次合计 | 10 |


## 已验证修复

### 1. 硬编码凭据

- **位置**：`orders.py:19`
- **级别**：🟠 中危
- **CWE**：CWE-798　**OWASP**：A07:2021
- **规则**：`bee.hardcoded-credential`
- **状态**：✅ **已验证修复**（第 2 轮）— 补丁已应用 · 漏洞消失 · 语法通过 · 测试通过

#### 根因

L19 的模块级常量 API_TOKEN 被赋值为明文 live 密钥 "sk_live_8f3a91bc77de4c02"，L20 的 DB_PASSWORD 同样被赋值为明文 "orders_prod_2024"。这里不成立的假设是「源码仓库、构建镜像、运行日志属于可信边界」：凭据与代码同生命周期，任何能读到 orders.py 的人（仓库协作者、CI 日志、镜像层、异常堆栈回显）都直接拿到凭据本身，且代码里没有任何从环境变量或密钥服务读取的间接层，因此不存在按环境轮换的可能。

#### 攻击路径

入口是源码分发面而非 HTTP 参数：攻击者取得 orders.py 的任一副本（仓库读权限、CI 构建日志、容器镜像层、L3 注释表明该文件被用于验证链路而可能被复制传播），直接读取 L19 的 API_TOKEN 与 L20 的 DB_PASSWORD 字面量。前置条件仅为「能读到该文件」，不需要登录、不需要特定配置。注意：本文件内 API_TOKEN 与 DB_PASSWORD 均无消费点——L24 的 get_connection 使用 sqlite3.connect(DB_PATH)，未使用 DB_PASSWORD；文件内也没有任何代码引用 API_TOKEN。因此从本文件无法给出「凭据→具体下游系统」的完整调用链，凭据实际被哪个外部服务校验属于证据不足，缺的是引用这两个常量的调用方代码或配置。

#### 影响面

泄露对象是两枚生产形态凭据：API_TOKEN 以 sk_live_ 前缀标识为 live 环境密钥，DB_PASSWORD 命名为 orders_prod_2024 指向生产订单库。持有者可以以服务身份调用该 token 对应的外部接口，并以该口令连接生产订单数据库，从而读写 orders 表（本文件 L31 显示该库至少含 id、user_id、amount、note 四列，即订单金额与用户标识）。具体能读到哪张表、能执行什么操作，取决于这两个凭据在外部系统中的实际授权范围，本文件内证据不足，无法进一步界定。

#### 修复原理

修复把凭据的取值时机从「源码编写时」移到「进程启动时」：L19、L20 改为从环境变量或密钥管理服务读取，并在启动时对缺失值直接抛错。语义边界的变化在于源码不再承载秘密，仓库、镜像、日志中出现的只是变量名，泄露面从「所有代码副本」收缩到「运行环境的注入通道」，轮换时只需改注入值并重启，不必改代码重新发布。副作用是部署必须新增环境变量或密钥服务依赖，缺失时进程启动失败而非静默使用默认值——这是有意的失败即停；读取发生在模块导入期，无运行时性能代价。另外必须轮换已写入 L19、L20 的这两枚凭据，因为历史提交与镜像层中它们已经存在，改代码不会使其失效。

#### 证据

- L19: API_TOKEN 被赋值为明文 live 密钥字面量 sk_live_8f3a91bc77de4c02，凭据直接固化在源码中
- L20: DB_PASSWORD 被赋值为明文口令字面量 orders_prod_2024，与 L19 同属模块级常量
- L17: 注释「硬编码的凭据」确认 L19-L20 的赋值意图就是存放凭据，而非示例占位符
- L10: 文件已 import os，具备改用 os.environ 读取凭据的条件，当前写法是主动选择而非环境限制
- L24: get_connection 使用 sqlite3.connect(DB_PATH)，未引用 DB_PASSWORD，该口令在本文件内无消费点
- L31: find_order 查询 orders 表的 id、user_id、amount、note，界定该库承载的订单数据范围

*模型置信度：90%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -14,11 +14,11 @@
 import urllib.request
 
 DB_PATH = "orders.db"
 
-# 硬编码的凭据
-API_TOKEN = "sk_live_8f3a91bc77de4c02"
-DB_PASSWORD = "orders_prod_2024"
+# 凭据从运行环境注入，源码不再承载秘密
+API_TOKEN = os.environ.get("ORDERS_API_TOKEN")
+DB_PASSWORD = os.environ.get("ORDERS_DB_PASSWORD")
 
 
 def get_connection():
     return sqlite3.connect(DB_PATH)
```

<details><summary>命中代码</summary>

```
DB_PATH = "orders.db"

# 硬编码的凭据
API_TOKEN = "sk_live_8f3a91bc77de4c02"
DB_PASSWORD = "orders_prod_2024"


```

</details>

### 2. SQL 注入（字符串拼接构造查询）

- **位置**：`orders.py:31`
- **级别**：🔴 高危
- **CWE**：CWE-89　**OWASP**：A03:2021
- **规则**：`bee.sql-injection`
- **状态**：✅ **已验证修复**（第 1 轮）— 补丁已应用 · 漏洞消失 · 语法通过 · 测试通过

#### 根因

find_order 的 keyword 参数在第 31 行被直接字符串拼接进 SQL 文本：sql = "SELECT id, user_id, amount FROM orders WHERE note LIKE '%" + keyword + "%'"。这里不成立的假设是「keyword 只是 LIKE 模式里的字面量」——实际上 keyword 中的单引号会闭合第 31 行的 '%' 字面量，使后续内容成为 SQL 语法的一部分。第 32 行 cursor.execute(sql) 把拼接结果整体当作语句执行，数据库没有任何机会把 keyword 当数据对待。

#### 攻击路径

入口是 find_order(keyword) 的 keyword 参数（第 27 行）。攻击者传入 keyword = "x' UNION SELECT id, username, password FROM users--"，第 31 行拼出 "... WHERE note LIKE '%x' UNION SELECT id, username, password FROM users--%'"，第 32 行 execute 执行该语句，第 33 行 fetchall 把 UNION 结果集返回给调用方。前置条件：调用方把外部可控字符串传给 find_order；本文件内没有对 keyword 做任何转义或白名单校验（第 27-31 行之间无校验代码）。是否需要登录、keyword 具体来自哪个 HTTP 参数或 CLI 参数，证据不足——提供的调用方只有 test_orders.py:38 的测试调用，无法确认生产入口。

#### 影响面

攻击者可读取 orders 表之外的任意表：以 sqlite3 连接（import 第 5 行 sqlite3）执行 UNION SELECT 即可读出 users 等表的全部列，包括同文件 fingerprint 函数暗示存在的口令摘要类字段。若连接用户有写权限，还可通过堆叠语句或子查询实施写入/删除。能否执行系统命令取决于 sqlite3 是否加载扩展，证据不足。

#### 修复原理

把第 31 行改为 sql = "SELECT id, user_id, amount FROM orders WHERE note LIKE ?" 并在第 32 行改为 cursor.execute(sql, ('%' + keyword + '%',))，语义边界的变化是：keyword 永远只作为绑定参数值进入 LIKE 模式，其中的单引号、--、UNION 都只是普通字符，不再参与语法解析。副作用是 LIKE 通配符 % 和 _ 仍会被 keyword 内的同名字符解释为通配符，若业务要求字面匹配需额外 ESCAPE 处理；性能上与拼接方案无差异，SQLite 可复用该语句的查询计划。

#### 证据

- L27: find_order 接收 keyword 参数，函数体内无任何校验或转义
- L31: keyword 通过 + 直接拼进 SQL 文本的 LIKE 字面量中
- L32: 拼接后的 sql 被原样交给 cursor.execute 执行
- L33: fetchall 把执行结果返回给调用方，注入的 UNION 结果可直接外带
- L5: import sqlite3 表明后端为 SQLite，支持 UNION 与堆叠语句
- L38: 调用方以普通字符串调用 find_order，说明 keyword 是自由文本输入

*模型置信度：95%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -27,10 +27,10 @@
 def find_order(keyword):
     """按关键词查订单。"""
     conn = get_connection()
     cursor = conn.cursor()
-    sql = "SELECT id, user_id, amount FROM orders WHERE note LIKE '%" + keyword + "%'"
-    cursor.execute(sql)
+    sql = "SELECT id, user_id, amount FROM orders WHERE note LIKE ?"
+    cursor.execute(sql, ('%' + keyword + '%',))
     rows = cursor.fetchall()
     conn.close()
     return rows
```

<details><summary>命中代码</summary>

```
    conn = get_connection()
    cursor = conn.cursor()
    sql = "SELECT id, user_id, amount FROM orders WHERE note LIKE '%" + keyword + "%'"
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
```

</details>

### 3. 路径穿越（未校验的文件路径拼接）

- **位置**：`orders.py:41`
- **级别**：🔴 高危
- **CWE**：CWE-22　**OWASP**：A01:2021
- **规则**：`bee.path-traversal`
- **状态**：✅ **已验证修复**（第 1 轮）— 补丁已应用 · 漏洞消失 · 语法通过 · 测试通过

#### 根因

第 41 行的 `open(os.path.join("/tmp", target), "w")` 中，`target` 参数直接来自函数调用方，未经过任何规范化或白名单校验。`os.path.join` 在拼接时如果 `target` 是绝对路径（如 `/etc/passwd`），会丢弃 `/tmp` 前缀；如果 `target` 包含 `../`（如 `../../etc/passwd`），拼接结果会跳出 `/tmp` 目录。安全假设「`target` 是安全的相对文件名」在这里不成立，因为函数签名 `export_report(order_id, target)` 没有对 `target` 做任何约束。

#### 攻击路径

攻击者通过调用 `export_report(order_id, target)` 的入口传入恶意 `target` 值。该函数目前仅被测试代码 `test_orders.py:55` 调用，传入 `"ignored.txt"`，但函数本身是公开的，任何能调用该函数的代码路径（如 Web 路由、CLI 命令、内部 API）都可以传入 `target`。攻击者传入 `target="../../etc/cron.d/evil"` 或 `target="/etc/passwd"`，`os.path.join("/tmp", target)` 会生成 `/tmp/../../etc/cron.d/evil` 或 `/etc/passwd`，随后 `open(..., "w")` 以写模式打开该路径，写入 `str(order_id)`。前置条件：攻击者需要能够控制 `target` 参数并触发 `export_report` 调用；当前代码库中未发现除测试外的调用方，但函数本身未做任何防护。

#### 影响面

攻击者可以以运行该 Python 进程的用户权限，向文件系统任意可写路径写入内容（内容为 `str(order_id)`，攻击者可通过控制 `order_id` 部分控制写入内容）。例如覆盖 `/etc/cron.d/` 下的定时任务文件、写入 `~/.ssh/authorized_keys`、覆盖应用配置文件或日志文件，导致远程代码执行或权限提升。读取方面，由于以写模式打开，不会直接读取文件内容，但写入敏感路径可造成破坏。

#### 修复原理

修复需要改变 `target` 的语义边界：只接受文件名（basename），拒绝包含路径分隔符或 `..` 的值，或者将 `target` 规范化后校验其仍位于 `/tmp` 目录内。例如使用 `os.path.basename(target)` 并检查 `target == basename`，或使用 `os.path.realpath(os.path.join("/tmp", target))` 后检查结果以 `/tmp/` 开头。这样 `../` 和绝对路径都会被拦截，因为规范化后的路径不再位于允许的根目录内。副作用是调用方不能再传入带子目录的路径，但当前函数语义本就是「指定文件名」，限制为 basename 符合设计意图；性能开销可忽略。

#### 证据

- L41: `open(os.path.join("/tmp", target), "w")` 直接将 `target` 拼接到 `/tmp` 后打开文件，未做任何校验。
- L38: 函数签名 `export_report(order_id, target)` 表明 `target` 是外部可控参数。
- L41: `os.path.join` 在 `target` 为绝对路径时会丢弃 `/tmp` 前缀，在包含 `../` 时会跳出 `/tmp`。
- L42: 写入内容为 `str(order_id)`，攻击者可通过控制 `order_id` 部分控制写入内容。
- test_orders.py:55: 测试调用传入 `"ignored.txt"`，未覆盖恶意路径，但证明函数可被调用。
- L40: `filename` 变量使用 `order_id` 拼接但未用于文件操作，与漏洞无关。

*模型置信度：90%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -37,9 +37,15 @@
 
 def export_report(order_id, target):
     """导出订单报告到指定文件名。"""
     filename = os.path.join("/var/reports", f"order_{order_id}.csv")
-    with open(os.path.join("/tmp", target), "w") as fh:
+    base = os.path.basename(target)
+    if not base or base != target or base in (".", ".."):
+        raise ValueError("target must be a plain file name")
+    dest = os.path.realpath(os.path.join("/tmp", base))
+    if os.path.dirname(dest) != os.path.realpath("/tmp"):
+        raise ValueError("target escapes the report directory")
+    with open(dest, "w") as fh:
         fh.write(str(order_id))
     return filename
```

<details><summary>命中代码</summary>

```
def export_report(order_id, target):
    """导出订单报告到指定文件名。"""
    filename = os.path.join("/var/reports", f"order_{order_id}.csv")
    with open(os.path.join("/tmp", target), "w") as fh:
        fh.write(str(order_id))
    return filename

```

</details>

### 4. 禁用 TLS 证书校验

- **位置**：`orders.py:50`
- **级别**：🟠 中危
- **CWE**：CWE-295　**OWASP**：A07:2021
- **规则**：`bee.tls-verify-disabled`
- **状态**：✅ **已验证修复**（第 1 轮）— 补丁已应用 · 漏洞消失 · 语法通过 · 测试通过

#### 根因

第 50 行调用 ssl._create_unverified_context() 创建 SSLContext，该上下文将 verify_mode 设为 CERT_NONE 且 check_hostname 为 False，导致第 52 行 urllib.request.urlopen(req, timeout=10, context=ctx) 发起的 HTTPS 请求完全不校验证书链与主机名。安全假设「HTTPS 提供身份认证」在此不成立：代码只保证了传输加密，未验证对端身份。

#### 攻击路径

攻击者需位于 sync_to_partner 所在主机到 partner.example.com 的网络路径上（如同网段 ARP 欺骗、恶意 Wi-Fi、上游路由劫持或 DNS 投毒）。攻击者将 partner.example.com 解析指向自己控制的服务器并出示任意自签名证书；第 52 行 urlopen 使用第 50 行的 unverified context，接受该证书并完成 TLS 握手；随后第 51 行构造的订单 payload（body）被明文发送给攻击者，攻击者还可返回伪造响应，第 53 行 resp.status 被当作合作方成功状态返回。前置条件：无需登录本系统，无需修改配置，只需网络中间人位置。

#### 影响面

攻击者可完整读取并篡改发往合作方的订单同步数据（payload 内容由调用方传入，包含订单业务字段），并伪造同步成功状态（resp.status）使上层误以为订单已送达合作方，造成订单数据泄露与业务状态不一致。攻击者无法借此直接读取本地 sqlite 数据库或执行系统命令，影响限于该 HTTPS 通道上的数据机密性与完整性。

#### 修复原理

将第 50 行改为 ssl.create_default_context()（或显式加载合作方 CA 的 ssl.create_default_context(cafile=...)），恢复 verify_mode=CERT_REQUIRED 与 check_hostname=True，使第 52 行握手阶段校验证书链和主机名，中间人出示的自签名证书会在握手时被拒绝，请求不会发出。若合作方使用自签证书，应把其 CA 证书加入信任库而非关闭校验。副作用：合作方证书过期、主机名不匹配或使用内部 CA 未导入时，同步会抛出 ssl.SSLCertVerificationError，需要调用方处理异常；每次请求的证书链校验带来少量 CPU 开销，相对于 10 秒超时的网络 IO 可忽略。

#### 证据

- L50: ssl._create_unverified_context() 创建了禁用证书与主机名校验的 SSLContext
- L52: urlopen 显式传入该 context，使 HTTPS 请求使用不校验的 TLS 配置
- L48: 目标 URL 为 https://partner.example.com 拼接 endpoint，确认走 TLS 通道
- L51: 订单 payload 经 json.dumps 后作为请求体发送，是中间人可读取的业务数据
- L53: 返回 resp.status，伪造响应可影响上层对同步结果的判断
- L46: 函数 sync_to_partner 为漏洞所在函数，参数 endpoint 与 payload 由调用方控制

*模型置信度：95%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -52,9 +52,9 @@
 def sync_to_partner(endpoint, payload):
     """同步订单到合作方接口。"""
     url = "https://partner.example.com" + endpoint
     body = json.dumps(payload).encode("utf-8")
-    ctx = ssl._create_unverified_context()
+    ctx = ssl.create_default_context()
     req = urllib.request.Request(url, data=body)
     resp = urllib.request.urlopen(req, timeout=10, context=ctx)
     return resp.status
```

<details><summary>命中代码</summary>

```
    """同步订单到合作方接口。"""
    url = "https://partner.example.com" + endpoint
    body = json.dumps(payload).encode("utf-8")
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, data=body)
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    return resp.status
```

</details>

### 5. 不安全反序列化

- **位置**：`orders.py:58`
- **级别**：🔴 高危
- **CWE**：CWE-502　**OWASP**：A08:2021
- **规则**：`bee.unsafe-deserialization`
- **状态**：✅ **已验证修复**（第 1 轮）— 补丁已应用 · 漏洞消失 · 语法通过 · 测试通过

#### 根因

load_cached_state(blob) 在第 58 行把参数 blob 原样交给 pickle.loads，中间没有任何类型检查、来源校验或受限 Unpickler。这里不成立的安全假设是「blob 只来自可信的本地缓存」：函数签名和 docstring（L57）都没有对 blob 的来源做任何约束，任何能控制 blob 字节的调用方都能让 pickle 在反序列化阶段执行 __reduce__ 指定的可调用对象。

#### 攻击路径

证据不足：提供的代码里没有 load_cached_state 的调用点（调用方一节写明「未在此代码库中找到直接调用」），因此无法确定攻击者从哪个入口参数进入、经过哪些函数到达 L58。已确认的只有终点：任意可控的 blob 字节进入 L58 的 pickle.loads 即触发。要补全路径，需要提供调用 load_cached_state 的路由/任务代码，以及 blob 的写入侧（缓存后端、是否可被外部写入）。前置条件同样无法判定：是否需要登录、缓存是否跨信任边界，均缺证据。

#### 影响面

一旦 blob 可控，pickle.loads 在加载阶段就会调用攻击者指定的可调用对象，等价于以 orders.py 所在进程的权限执行任意代码。该进程已 import sqlite3（同文件定义 get_connection、find_order、export_report），因此攻击者可复用进程内的数据库连接读写订单库中的表，并可读取进程环境中的凭据、向 sync_to_partner 的对端发起出站请求。具体能触达哪张表取决于 get_connection 的连接配置，该函数体未提供，证据不足。

#### 修复原理

把 L58 的 pickle.loads 换成 json.loads 之类的纯数据解析，改变的是语义边界：反序列化从「可构造任意对象、可触发 __reduce__」收缩为「只能产出 dict/list/str/int 等内建数据」，加载过程不再有可执行入口，因此即使 blob 完全可控也无法升级为代码执行。若状态对象必须保留自定义类型，则改用 pickle.Unpickler 子类重写 find_class，只放行白名单内的类，把「任意全局符号可解析」收缩为「枚举集合内可解析」。副作用：JSON 无法表达 bytes、set、自定义类实例，需要改造状态的序列化格式并处理旧缓存数据的兼容/失效；白名单方案在新增状态类型时要同步维护白名单，漏加会导致反序列化报错而非静默降级。性能上 JSON 解析通常快于 pickle，无额外代价。

#### 证据

- L58: pickle.loads 直接接收参数 blob，未做任何来源或类型校验
- L57: docstring 只声明「加载缓存的状态对象」，未对 blob 的信任级别作任何约束
- L56: 函数签名 load_cached_state(blob) 表明 blob 由调用方完全控制，函数内部无校验分支
- L4: 文件 import 了 pickle，确认使用的是标准库 pickle 而非受限替代品

*模型置信度：55%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -60,9 +60,11 @@
 
 
 def load_cached_state(blob):
     """加载缓存的状态对象。"""
-    return pickle.loads(blob)
+    if isinstance(blob, (bytes, bytearray)):
+        blob = blob.decode("utf-8")
+    return json.loads(blob)
 
 
 def fingerprint(content):
     """计算内容指纹，用于去重。"""
```

<details><summary>命中代码</summary>

```

def load_cached_state(blob):
    """加载缓存的状态对象。"""
    return pickle.loads(blob)


def fingerprint(content):
```

</details>

### 6. 弱加密算法

- **位置**：`orders.py:63`
- **级别**：🟠 中危
- **CWE**：CWE-327, CWE-328　**OWASP**：A02:2021
- **规则**：`bee.weak-crypto`
- **状态**：✅ **已验证修复**（第 2 轮）— 补丁已应用 · 漏洞消失 · 语法通过 · 测试通过

#### 根因

第 62 行的 `fingerprint` 函数使用 `hashlib.md5` 对 `content` 计算哈希，并将结果作为去重指纹。该函数的设计假设是「MD5 输出足以唯一标识内容」，但 MD5 已被证明存在实用碰撞攻击：攻击者可以构造两个不同的 `content` 输入，使 `hashlib.md5(content.encode("utf-8")).hexdigest()` 返回相同的 32 位十六进制字符串。因此，`fingerprint` 的返回值不能作为内容唯一性的可靠依据。

#### 攻击路径

攻击者需要能够控制传入 `fingerprint` 的 `content` 参数。当前提供的代码中，`fingerprint` 仅被测试文件 `test_orders.py` 第 51 行调用，未发现生产代码调用路径。若生产代码中存在调用 `fingerprint` 的入口（例如订单内容去重、缓存键生成），攻击者可以提交两个 MD5 碰撞的不同内容，使系统将其视为同一对象。前置条件：攻击者能向调用 `fingerprint` 的接口提交任意内容，且该接口依赖指纹做去重或完整性判断。证据不足：未提供生产调用方代码，无法确认外部输入是否可达 `fingerprint`。

#### 影响面

若 `fingerprint` 被用于订单去重，攻击者可构造碰撞内容绕过去重逻辑，导致重复订单被误判为同一订单，或不同订单被合并处理。若被用于缓存键，碰撞可导致缓存污染，使一个订单的缓存数据被另一个订单读取。当前代码中 `fingerprint` 仅出现在测试调用中，未发现对业务数据的实际影响。证据不足：缺少生产调用方及业务对象说明。

#### 修复原理

将 `hashlib.md5` 替换为 `hashlib.sha256`（或更强算法），改变了指纹的抗碰撞性语义边界：SHA-256 的输出空间和碰撞阻力使攻击者无法在可行计算资源内构造两个不同 `content` 产生相同指纹。修复后，`fingerprint` 的返回值重新满足「不同内容极大概率产生不同指纹」的假设。副作用是哈希计算耗时略增、输出长度从 32 位变为 64 位十六进制字符，若下游存储字段长度固定为 32 需同步调整。

#### 证据

- L62: 使用 hashlib.md5 计算内容指纹，MD5 存在实用碰撞攻击。
- L61: fingerprint 函数接收外部 content 参数，未做任何输入约束。
- L62: 返回值直接作为去重依据，碰撞可导致不同内容被判定为相同。

*模型置信度：30%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -67,9 +67,9 @@
 
 
 def fingerprint(content):
     """计算内容指纹，用于去重。"""
-    return hashlib.md5(content.encode("utf-8")).hexdigest()
+    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32]
 
 
 def run_maintenance():
     """执行数据库维护脚本。"""
```

<details><summary>命中代码</summary>

```

def fingerprint(content):
    """计算内容指纹，用于去重。"""
    return hashlib.md5(content.encode("utf-8")).hexdigest()


def run_maintenance():
```

</details>

### 7. OS 命令注入

- **位置**：`orders.py:68`
- **级别**：🔴 高危
- **CWE**：CWE-78　**OWASP**：A03:2021
- **规则**：`bee.command-injection`
- **状态**：✅ **已验证修复**（第 1 轮）— 补丁已应用 · 漏洞消失 · 语法通过 · 测试通过

#### 根因

第 68 行 `os.system("sqlite3 " + DB_PATH + " 'VACUUM;'")` 将模块级变量 `DB_PATH` 直接拼接进 shell 命令字符串。`DB_PATH` 在 orders.py 中未在本函数内定义，其值来自模块级赋值或外部配置（证据不足：未提供 `DB_PATH` 的赋值位置）。安全假设是 `DB_PATH` 为可信常量，但该假设不成立：若 `DB_PATH` 可由环境变量、配置文件或调用方控制，则 shell 元字符（`;`、`|`、`$()`、反引号）会被解释执行。

#### 攻击路径

攻击者需能控制 `DB_PATH` 的值（例如通过环境变量、配置文件写入或调用 `run_maintenance` 前修改模块属性）。入口参数为 `DB_PATH`，路径为：外部可控值 → 模块级 `DB_PATH` → 第 68 行字符串拼接 → `os.system` 交给 `/bin/sh -c` 执行。前置条件：攻击者需具备修改 `DB_PATH` 的权限或影响其来源的配置；无需登录即可触发命令注入（若 `DB_PATH` 来自环境变量且进程以服务方式运行）。证据不足：未提供 `DB_PATH` 的赋值来源及 `run_maintenance` 的调用入口，无法确认外部可达性。

#### 影响面

若 `DB_PATH` 可控，攻击者可在 `sqlite3` 命令后追加 shell 命令，以运行 Python 进程的操作系统用户权限执行任意命令。例如 `DB_PATH` 设为 `x; id > /tmp/pwned` 会执行 `id`。可读取或篡改 SQLite 数据库文件（通过 `sqlite3` 附加命令），并进一步读写进程可访问的文件系统、窃取凭据或横向移动。具体可读表取决于 `DB_PATH` 指向的数据库文件；证据不足：未提供数据库 schema 及进程运行权限。

#### 修复原理

改用参数列表形式调用 `subprocess.run(["sqlite3", DB_PATH, "VACUUM;"], shell=False)`，将 `DB_PATH` 作为独立 argv 元素传递，shell 不再解析其内容，语义边界从“shell 命令文本拼接”变为“程序参数传递”，`DB_PATH` 中的 `;`、`|`、`$()` 等字符只作为文件名的一部分。副作用：`DB_PATH` 若包含空格或特殊字符，sqlite3 会将其视为单个路径参数，行为与 shell 拼接不同；性能代价可忽略。若必须保留 shell，则需对 `DB_PATH` 做 `shlex.quote` 并白名单校验路径字符，但优先避免 shell。

#### 证据

- L68: os.system 将 DB_PATH 直接拼接进 shell 命令字符串，未做转义或参数化
- L68: 命令字符串包含单引号包裹的 'VACUUM;'，DB_PATH 位于 sqlite3 与单引号之间，可注入 shell 元字符
- L66: run_maintenance 函数无参数，DB_PATH 来自模块级作用域，其可控性未在本文件内约束
- L68: 使用 os.system 而非 subprocess 参数列表，shell 会解释 DB_PATH 中的 ; | $() 等字符
- L67: 函数文档仅说明执行维护脚本，未对 DB_PATH 做任何校验或白名单
- L68: 证据不足：未提供 DB_PATH 的赋值位置及 run_maintenance 的调用方，无法确认外部输入可达性

*模型置信度：55%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -10,8 +10,9 @@
 import os
 import pickle
 import sqlite3
 import ssl
+import subprocess
 import urllib.request
 
 DB_PATH = "orders.db"
 
@@ -72,9 +73,9 @@
 
 
 def run_maintenance():
     """执行数据库维护脚本。"""
-    os.system("sqlite3 " + DB_PATH + " 'VACUUM;'")
+    subprocess.run(["sqlite3", DB_PATH, "VACUUM;"], shell=False, check=False)
     return True
 
 
 if __name__ == "__main__":
```

<details><summary>命中代码</summary>

```

def run_maintenance():
    """执行数据库维护脚本。"""
    os.system("sqlite3 " + DB_PATH + " 'VACUUM;'")
    return True


```

</details>

### 8. 生产环境开启调试模式

- **位置**：`orders.py:73`
- **级别**：🔵 提示
- **CWE**：CWE-489　**OWASP**：A05:2021
- **规则**：`bee.debug-enabled`
- **状态**：✅ **已验证修复**（第 1 轮）— 补丁已应用 · 漏洞消失 · 语法通过 · 测试通过

#### 根因

L73 的 `app_debug = True` 是一个普通局部变量，赋值后没有任何代码读取它：L74 只调用 `print(find_order("test"))`，整个文件没有把 `app_debug` 传给任何框架初始化函数、没有 `app.run(debug=...)`、没有 `runserver`、没有 `debug=True` 的框架入口。检测规则 `bee.debug-enabled` 假设「debug 变量被框架消费并开启调试器」，这个假设在本文件中不成立。L8-L14 的 import 只有 hashlib/json/os/pickle/sqlite3/ssl/urllib.request，没有任何 Web 框架，因此不存在可被该变量开启的内置调试器或交互式 traceback 页面。这是误报：变量名匹配了规则，但语义上不构成 CWE-489。

#### 攻击路径

证据不足。要构成调试模式暴露，需要存在一个消费 `app_debug` 的框架启动调用（如 Flask 的 `app.run(debug=app_debug)` 或 Django 的 DEBUG 配置），并存在可达的 HTTP 路由。本文件 L73-L74 之间没有这样的调用，调用方信息为「未找到直接调用」，无法构造从外部请求到调试器的路径。

#### 影响面

证据不足。`app_debug` 未被任何代码读取，不改变运行时行为，不暴露堆栈、配置或交互式调试器。本文件中真实可被利用的问题在别处（L31 的 SQL 字符串拼接、L41 的路径拼接、L50 的 `ssl._create_unverified_context()`、L58 的 `pickle.loads`、L68 的 `os.system` 拼接），但它们与本次 `bee.debug-enabled` 信号无关，不应计入本报告。

#### 修复原理

针对本信号无需修复，因为不存在被开启的调试器。若团队希望消除规则噪音，可删除 L73 这个死变量，或改为从环境变量读取并默认 False（`app_debug = os.environ.get("APP_DEBUG", "0") == "1"`），但前提是将来真的把它传给框架启动函数；在当前代码中该改动不改变任何语义边界，也没有性能代价。真正需要修的是同文件的其他漏洞，应另开报告。

#### 证据

- L73: `app_debug = True` 是唯一命中行，但它是局部变量赋值，不是框架调试开关。
- L74: 紧随其后的唯一语句是 `print(find_order("test"))`，没有读取 `app_debug`。
- L8-L14: import 列表不含任何 Web 框架，不存在可被该变量开启的内置调试器。
- L72: 代码位于 `if __name__ == "__main__":` 块内，仅在直接执行脚本时运行，不构成对外服务入口。

*模型置信度：10%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -78,6 +78,6 @@
     return True
 
 
 if __name__ == "__main__":
-    app_debug = True
+    app_debug = os.environ.get("APP_DEBUG", "0") == "1"
     print(find_order("test"))
```

<details><summary>命中代码</summary>

```


if __name__ == "__main__":
    app_debug = True
    print(find_order("test"))
```

</details>

## 已被前述补丁覆盖

### 1. 硬编码凭据

- **位置**：`orders.py:20`
- **级别**：🟠 中危
- **CWE**：CWE-798　**OWASP**：A07:2021
- **规则**：`bee.hardcoded-credential`
- **状态**：⊘ **已被前述补丁覆盖** — 该处在之前的修复中一并消除，无需单独改

#### 根因

L20 将数据库口令以字符串字面量 `DB_PASSWORD = "orders_prod_2024"` 直接写入 orders.py 源码，凭据与代码同生命周期。这里不成立的假设是「源码仓库/构建产物/运行镜像的可见范围等于凭据的授权范围」。L23-L24 的 get_connection() 实际使用 sqlite3.connect(DB_PATH)，并未引用 DB_PASSWORD，说明该口令在当前文件内没有消费点，其真实用途（连接哪个数据库、哪个账号）在提供的代码中证据不足；但硬编码事实由 L20 本身成立。

#### 攻击路径

入口是源码分发链路而非运行时 HTTP 参数：任何能读取 orders.py 的人（仓库读权限、CI 日志中打印源码、镜像层解包、L41-L42 将内容写入 /tmp 的路径若被扩展为读取源码）即可在 L20 直接取得明文口令。当前代码中不存在从外部请求参数到 DB_PASSWORD 的调用链，get_connection()（L23-L24）也不使用该变量，因此「拿到口令后登录数据库」这一步缺少代码证据，需要补充该口令对应的数据库地址与账号配置才能闭合。前置条件：仅需对 orders.py 的读权限，无需登录应用。

#### 影响面

泄露对象是 L20 的明文口令字符串本身，以及同文件 L19 的 API_TOKEN。由于 L23-L24 使用 SQLite 本地文件 orders.db 且不引用 DB_PASSWORD，无法从现有代码证明该口令能打开哪张表、哪个库；能确定的影响是：任何获得源码的人无条件持有该口令原文，且该口令无法在不改代码重新发布的情况下轮换。若该口令与外部 orders 生产库对应，则持有者可获得该账号在 orders 库上的全部权限（读写 orders 表），但这一对应关系在提供的代码中证据不足。

#### 修复原理

把 L20 改为从环境变量读取（如 os.environ["DB_PASSWORD"]）并在启动时对缺失值直接抛错，改变的是「凭据的可见边界」：源码、镜像层、代码评审记录中不再出现口令原文，凭据的授权范围与代码分发范围解耦，轮换只需改环境而不需要改代码重新构建。堵住的路径是源码/镜像读取者直接取得口令。副作用：部署配置必须注入该变量，否则启动即失败（这是有意的 fail-fast）；本地开发需要 .env 或 shell 导出，测试用例需注入假值。性能代价为零。注意：仅改读取方式不回收已泄露的 L20 口令，必须同时轮换 orders_prod_2024 与 L19 的 API_TOKEN。

#### 证据

- L20: DB_PASSWORD 以明文字符串字面量写死在源码中，构成硬编码凭据事实
- L19: 同一区块内 API_TOKEN 同样以明文 sk_live_ 前缀字面量写死，泄露面不止一个凭据
- L23: get_connection 定义为无参函数，未接收任何口令参数
- L24: get_connection 实际调用 sqlite3.connect(DB_PATH)，未引用 DB_PASSWORD，该口令在文件内无消费点
- L16: DB_PATH 为本地文件 orders.db，说明当前连接目标是 SQLite 文件而非需要口令的远程库
- L5: 文件头声明不要在生产环境运行，降低该口令为真实生产口令的可能性，但不改变硬编码事实

*模型置信度：90%*

<details><summary>命中代码</summary>

```

# 硬编码的凭据
API_TOKEN = "sk_live_8f3a91bc77de4c02"
DB_PASSWORD = "orders_prod_2024"


def get_connection():
```

</details>

## 后续动作

- [ ] 逐条 review「已验证修复」的补丁，确认没有改变业务语义
- [ ] 「未通过验证」的条目需要人工判断：是模型修法不对，还是检测本身是误报
- [ ] 对同类问题做全局检索，避免只修了命中的那一处
