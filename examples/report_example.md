# 漏洞审计与可解释性修复报告

- 目标：`samples/vulnerable_app`
- 生成时间：2026-10-22 19:10
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

L19 的 API_TOKEN 和 L20 的 DB_PASSWORD 以字符串字面量形式硬编码在 orders.py 源码中，变量名直接暴露了凭据用途。安全假设「源码仅对开发者可见」不成立：该文件会进入版本库、构建镜像、CI 日志和部署包，任何能读取 orders.py 的人（包括仓库协作者、镜像拉取者、日志查看者）都能直接获得这两个凭据。

#### 攻击路径

攻击者获取 orders.py 的途径包括：克隆/浏览代码仓库、拉取容器镜像并解包、读取 CI/CD 构建日志或异常堆栈中打印的模块级变量。拿到 L19 的 API_TOKEN 后，可冒充订单服务调用合作方接口（L46-L53 的 sync_to_partner 使用该 token 的语义虽未在本文件显式引用，但变量名和注释表明其用于生产 API 认证）；拿到 L20 的 DB_PASSWORD 后，可直连订单数据库。前置条件仅为读取源码的权限，无需登录目标系统。

#### 影响面

泄露的 API_TOKEN 可让攻击者以订单服务身份调用合作方生产接口，伪造或篡改订单同步数据；泄露的 DB_PASSWORD 可让攻击者直连订单数据库，读取 orders 表的 id、user_id、amount、note 字段（L31 的 SELECT 语句列出了这些字段），进而批量导出用户订单和金额信息。凭据无法按环境轮换，一旦泄露只能改代码重新发布。

#### 修复原理

将 L19/L20 改为从环境变量读取（如 os.environ['API_TOKEN']），把凭据的存储边界从「源码」移到「运行时环境」，使源码、镜像和日志不再携带秘密；启动时对缺失变量抛异常，避免空值静默运行。副作用是部署流程需注入环境变量，本地开发需配置 .env 或启动脚本；无性能代价。已泄露的凭据必须轮换，否则修复无效。

#### 证据

- L19: API_TOKEN 以字符串字面量硬编码，值为 prod_api_token_8f3a91bc77de
- L20: DB_PASSWORD 以字符串字面量硬编码，值为 db_pass_7c4e19d2
- L18: 注释明确标注「硬编码的凭据」，确认变量用途为认证凭据
- L31: SELECT 语句列出 orders 表的 id、user_id、amount、note 字段，是 DB_PASSWORD 泄露后可读的数据范围
- L46: sync_to_partner 函数向合作方接口发送数据，API_TOKEN 的命名表明其用于此类外部调用认证
- L10: 文件已 import os，具备改用 os.environ 读取环境变量的条件，但 L19/L20 未使用

*模型置信度：95%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -14,11 +14,17 @@
 import urllib.request
 
 DB_PATH = "orders.db"
 
-# 硬编码的凭据（示例值，不是真实密钥）
-API_TOKEN = "prod_api_token_8f3a91bc77de"
-DB_PASSWORD = "db_pass_7c4e19d2"
+# 凭据从运行时环境读取，源码中不再保存秘密
+API_TOKEN = os.environ.get("API_TOKEN")
+DB_PASSWORD = os.environ.get("DB_PASSWORD")
+
+
+def require_credentials():
+    """在真正使用凭据前校验环境变量已注入。"""
+    if not API_TOKEN or not DB_PASSWORD:
+        raise RuntimeError("缺少必需的环境变量 API_TOKEN / DB_PASSWORD")
 
 
 def get_connection():
     return sqlite3.connect(DB_PATH)
```

<details><summary>命中代码</summary>

```
DB_PATH = "orders.db"

# 硬编码的凭据（示例值，不是真实密钥）
API_TOKEN = "prod_api_token_8f3a91bc77de"
DB_PASSWORD = "db_pass_7c4e19d2"


```

</details>

### 2. SQL 注入（字符串拼接构造查询）

- **位置**：`orders.py:31`
- **级别**：🔴 高危
- **CWE**：CWE-89　**OWASP**：A03:2021
- **规则**：`bee.sql-injection`
- **状态**：✅ **已验证修复**（第 1 轮）— 补丁已应用 · 漏洞消失 · 语法通过 · 测试通过

#### 根因

find_order 函数第 31 行将参数 keyword 直接拼接到 SQL 文本中：sql = "SELECT id, user_id, amount FROM orders WHERE note LIKE '%" + keyword + "%'"。keyword 是函数入参，没有任何类型检查、转义或白名单过滤。第 32 行 cursor.execute(sql) 将拼接后的完整字符串作为 SQL 语句执行，数据库解析器无法区分 keyword 中的单引号是数据还是语句结构，导致 keyword 中的 SQL 片段被当作语句执行。安全假设「keyword 只包含普通搜索词」不成立。

#### 攻击路径

攻击者控制传入 find_order 的 keyword 参数（例如通过 Web 接口的搜索框、CLI 参数或任何调用该函数的入口）。构造 keyword 为 `' UNION SELECT id, username, password FROM users -- `，第 31 行拼接后 SQL 变为 `SELECT id, user_id, amount FROM orders WHERE note LIKE '%' UNION SELECT id, username, password FROM users -- %'`，第 32 行 execute 执行该语句，第 33 行 fetchall 返回注入查询的结果。前置条件：攻击者能控制 keyword 的值；无需登录（函数本身无鉴权逻辑）；无需特殊配置（SQLite 默认支持 UNION）。

#### 影响面

攻击者可读取 orders 表之外的任意表数据。例如通过 UNION SELECT 读取 users 表的 username、password 字段，直接获取账户凭据；也可通过 SQLite 的 sqlite_master 表枚举所有表结构。若数据库连接用户权限较高，还可通过 ATTACH DATABASE 或 load_extension 等手法进一步操作文件系统或执行代码。业务上，订单查询接口会变成任意数据读取入口，泄露全部订单、用户及凭据数据。

#### 修复原理

将第 31-32 行改为参数化查询：sql = "SELECT id, user_id, amount FROM orders WHERE note LIKE ?"，然后 cursor.execute(sql, ('%' + keyword + '%',))。这改变了语义边界：SQL 文本在编译时固定，keyword 的值仅作为绑定参数传入，数据库不会将其解析为 SQL 语法，单引号、UNION、注释符等均被当作普通字符处理。副作用是 LIKE 通配符 % 和 _ 仍会生效，若业务要求字面匹配需额外转义；性能上参数化查询可复用执行计划，无额外代价。

#### 证据

- L31: sql 变量由 keyword 直接字符串拼接构造，keyword 未做任何过滤或转义
- L32: cursor.execute(sql) 将拼接后的完整字符串作为 SQL 语句执行
- L27: find_order 函数签名接收 keyword 参数，该参数直接流入 L31 的拼接
- L33: rows = cursor.fetchall() 返回注入查询的结果集，攻击者可读取任意表数据
- L30: 使用 sqlite3 连接，SQLite 支持 UNION SELECT 等注入手法

*模型置信度：95%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -33,10 +33,10 @@
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

第 41 行 `open(os.path.join("/tmp", target), "w")` 直接把 `export_report` 的第二个形参 `target` 拼进路径。`os.path.join` 在 `target` 以 `/` 开头时会丢弃 `/tmp` 前缀，在 `target` 含 `../` 时不做任何规范化，因此「`target` 是 /tmp 下的文件名」这个安全假设不成立。第 40 行用 `order_id` 拼出的 `filename` 只用于返回值，与第 41 行实际写入的路径无关，说明写入路径完全由 `target` 决定。

#### 攻击路径

外部调用方把攻击者可控的字符串作为第二个实参传给 `export_report(order_id, target)`，例如 `target="../../etc/cron.d/x"` 或 `target="/root/.ssh/authorized_keys"`。函数在第 41 行执行 `os.path.join("/tmp", target)` 得到 `/tmp/../../etc/cron.d/x` 或 `/root/.ssh/authorized_keys`，随即以 `"w"` 模式打开并写入 `str(order_id)`。前置条件：调用方必须把外部输入直接作为 `target` 传入；本文件内没有对 `target` 做任何校验。是否需登录、是否需特定配置，证据不足——提供的调用方只有 `test_orders.py:55` 传入常量 `"ignored.txt"`，没有展示真实 HTTP/CLI 入口如何把外部参数接到 `target` 上。

#### 影响面

写入内容受限于 `str(order_id)`，攻击者能控制写入的字节（把 `order_id` 传成任意字符串即可写入任意内容），但只能覆盖/创建文件，不能读取文件内容。可覆盖运行进程有写权限的任意文件：覆盖 `/etc/cron.d/*` 或用户 crontab 可触发命令执行；覆盖 `~/.ssh/authorized_keys` 可植入公钥获得登录权限；覆盖应用自身的 `.py` 文件或配置可在下次加载时执行代码。若进程以 root 运行，影响面覆盖整机文件系统。

#### 修复原理

修复要改变「`target` 可以是任意路径」这一语义边界：先 `os.path.realpath(os.path.join("/tmp", target))` 规范化，再用 `os.path.commonpath` 或 `startswith("/tmp" + os.sep)` 校验结果仍在 `/tmp` 内，不满足则拒绝；或只取 `os.path.basename(target)` 并加扩展名白名单。规范化后 `../` 和绝对路径都会被折叠成真实路径，越界检查在打开文件之前完成，因此 `open` 拿到的路径必然落在允许根目录内。副作用：合法的子目录写入会被拒绝，需要按业务确认是否允许子目录；`realpath` 会解析符号链接，若 `/tmp` 下存在指向外部的 symlink，校验会正确拒绝而不是跟随，这是预期行为。性能代价是一次 `realpath` 系统调用，可忽略。

#### 证据

- L41: `open(os.path.join("/tmp", target), "w")` 把形参 `target` 直接拼进路径并以写模式打开，是危险操作本身
- L38: `target` 是 `export_report` 的公开形参，函数体内没有任何对它的校验或规范化
- L40: 用 `order_id` 拼出的 `filename` 只被返回，与 L41 实际写入路径无关，写入路径完全由 `target` 决定
- L41: `os.path.join` 遇到以 `/` 开头的 `target` 会丢弃 `/tmp` 前缀，遇到 `../` 不做折叠，拼接结果可越出 `/tmp`
- L42: 写入内容为 `str(order_id)`，攻击者可通过 `order_id` 控制写入文件的字节内容
- test_orders.py:55: 现有调用方只传入常量 `"ignored.txt"`，未展示外部入口如何把用户输入接到 `target`，入口可达性证据不足

*模型置信度：75%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -43,9 +43,13 @@
 
 def export_report(order_id, target):
     """导出订单报告到指定文件名。"""
     filename = os.path.join("/var/reports", f"order_{order_id}.csv")
-    with open(os.path.join("/tmp", target), "w") as fh:
+    base_dir = os.path.realpath("/tmp")
+    dest = os.path.realpath(os.path.join(base_dir, target))
+    if os.path.commonpath([base_dir, dest]) != base_dir:
+        raise ValueError("target path escapes /tmp")
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

第 50 行调用 ssl._create_unverified_context() 创建 SSLContext，该上下文将 verify_mode 设为 CERT_NONE 且 check_hostname 为 False，随后第 52 行将该 ctx 传给 urllib.request.urlopen。这里不成立的假设是：urlopen 默认会校验证书链与主机名。显式传入未校验的 context 后，TLS 握手只完成加密协商，不验证对端证书是否由受信 CA 签发、是否匹配 partner.example.com，也不检查证书有效期。

#### 攻击路径

攻击者需位于 sync_to_partner 所在主机到 partner.example.com 的网络路径上（同网段 ARP 欺骗、恶意 Wi-Fi、上游 DNS 劫持或 BGP 劫持），并持有任意自签证书。攻击者将 partner.example.com 解析到自己控制的 IP，用自签证书完成 TLS 握手；第 50 行的 ctx 使客户端跳过证书链与主机名校验，第 52 行 urlopen 正常建立连接，第 51 行构造的订单 payload（body）被完整发送给攻击者，第 53 行返回攻击者伪造的 HTTP 状态码。前置条件仅为网络中间人位置，不需要登录凭证，也不需要修改任何配置。

#### 影响面

攻击者以中间人身份读取并篡改 sync_to_partner 发出的全部订单同步数据：payload 经 json.dumps 序列化后包含订单字段，攻击者可直接获取订单内容；同时可返回任意状态码（如 200）使调用方误认为同步成功，从而掩盖订单被截获或篡改的事实。该函数不涉及数据库连接与命令执行，影响范围限于该 HTTPS 通道上传输的订单数据及其响应状态。

#### 修复原理

删除第 50 行的 ssl._create_unverified_context()，第 52 行改为不传 context（使用 urllib 默认的受信 CA 校验与主机名校验），或显式构造 ssl.create_default_context() 并仅对合作方自签证书通过 load_verify_locations 加载指定 CA。语义边界的变化是：TLS 对端身份从「不验证」变为「必须由受信 CA 签发且证书 SAN 匹配 partner.example.com」，中间人无法再用任意证书冒充服务端。副作用是若合作方确实使用自签证书，需把其 CA 证书部署到信任库，否则握手会抛 ssl.SSLCertVerificationError；性能上仅增加一次证书链校验，可忽略。

#### 证据

- L50: ssl._create_unverified_context() 创建了 verify_mode=CERT_NONE、check_hostname=False 的 SSLContext
- L52: 该 ctx 被传入 urllib.request.urlopen，使本次 HTTPS 请求跳过证书链与主机名校验
- L48: 目标 URL 固定为 https://partner.example.com，说明本应校验该主机名但实际未校验
- L51: 订单 payload 经 json.dumps 编码后作为请求体发送，中间人可直接读取
- L53: 返回值仅为 resp.status，攻击者可伪造状态码使调用方误判同步成功
- L46: sync_to_partner 是公开函数，任何调用方都会继承未校验 TLS 的行为

*模型置信度：95%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -56,9 +56,9 @@
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

load_cached_state(blob) 在第 58 行直接把参数 blob 交给 pickle.loads，函数体内没有任何类型检查、来源校验或签名验证。这里不成立的安全假设是「blob 来自可信的缓存后端」：pickle 的 opcode 流在 loads 阶段就会解析 GLOBAL/STACK_GLOBAL 并导入、调用任意模块属性，因此只要 blob 可控，反序列化动作本身就等价于执行 blob 指定的可调用对象。

#### 攻击路径

证据不足。提供的代码只覆盖 L56-L59，调用方明确标注为「未在此代码库中找到直接调用，可能通过框架路由或反射调用」。要写出完整路径，需要补充：哪个路由/任务/CLI 入口把外部数据传给 load_cached_state，blob 是来自 HTTP 参数、Cookie、缓存键值还是消息队列，以及进入前是否经过签名或来源限制。缺少这些文件，无法判断是否需要登录、是否需要特定配置。

#### 影响面

证据不足。同文件定义了 get_connection、find_order、export_report、sync_to_partner 等函数，说明进程持有 sqlite3 连接并会向合作方发起网络请求，但未提供这些函数体，无法确认可读取的具体表名、可外联的具体地址。可确定的是：一旦 blob 可控，攻击者在应用进程权限内执行任意 Python 代码，进而操作该进程持有的 sqlite3 连接与 urllib.request 出网能力。

#### 修复原理

把第 58 行的 pickle.loads 换成纯数据格式（json.loads）或受限的 Unpickler（find_class 白名单只放行明确需要的类），改变的是「反序列化阶段允许触达的对象空间」这一语义边界：前者把可表达的内容限制为 JSON 基本类型，后者把可导入的模块属性收敛到白名单，GLOBAL opcode 指向 os.system 之类的引用会在加载时被拒绝，而不是被执行。副作用是缓存中已有的 pickle 数据不再兼容，需要一次性迁移或双读过渡；JSON 不支持 bytes/自定义类，需为这些字段补编码层。性能上 json 解析通常快于 pickle，无额外代价。

#### 证据

- L58: pickle.loads(blob) 直接反序列化入参，函数内无任何校验分支
- L56: 函数签名 load_cached_state(blob) 表明 blob 是外部传入参数而非函数内生成
- L57: docstring 只说明用途为加载缓存状态，未声明来源可信约束

*模型置信度：55%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -64,9 +64,11 @@
 
 
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

第 63 行的 `fingerprint` 函数直接调用 `hashlib.md5(content.encode("utf-8")).hexdigest()` 生成内容指纹。该函数的设计假设是「MD5 足以作为去重标识」，但 MD5 的碰撞攻击已实用化：攻击者可以构造两段不同内容产生相同 MD5 值，导致去重逻辑把不同订单内容误判为同一份。变量 `content` 是唯一输入，没有任何加盐或二次哈希，安全假设「相同指纹意味着相同内容」在 MD5 下不成立。

#### 攻击路径

证据不足：提供的代码只包含 `fingerprint` 函数定义（L61-L64）和单元测试调用（test_orders.py:51），没有展示 `content` 参数从哪个外部入口（HTTP 请求、文件上传、数据库字段）传入，也没有展示 `fingerprint` 的返回值被用于哪张表的去重判断或缓存键。无法写出从攻击者可控参数到危险操作的完整路径。缺少调用链上游（如 `find_order`、`export_report`、`sync_to_partner` 中是否调用 `fingerprint`）和下游（指纹写入哪张表、是否作为唯一键）的代码。

#### 影响面

证据不足：无法确认 `fingerprint` 的返回值被用于哪张表或哪个业务对象。若指纹用于订单去重，碰撞可导致不同订单被合并、覆盖或跳过处理；若用于缓存键，可导致缓存投毒。但当前代码上下文没有展示这些使用点，不能断言具体能读到哪张表或执行什么操作。

#### 修复原理

将 L63 的 `hashlib.md5` 替换为 `hashlib.sha256`（或 blake2b），改变的是「指纹抗碰撞性」这一语义边界：SHA-256 下构造相同指纹需要约 2^128 次操作，去重逻辑的「相同指纹即相同内容」假设重新成立。副作用是摘要长度从 32 字符变为 64 字符，若指纹列有长度约束（如 VARCHAR(32)）需同步迁移；性能上 SHA-256 比 MD5 慢约 2-3 倍，但对去重场景可忽略。若指纹用于安全敏感场景（如签名校验），应改用 HMAC-SHA256 并引入密钥。

#### 证据

- L63: `hashlib.md5(content.encode("utf-8")).hexdigest()` 是 MD5 的唯一使用点，输入 `content` 无加盐或二次哈希。
- L61: 函数名为 `fingerprint`，docstring 写明「用于去重」，说明指纹的语义边界是内容等价性判断。
- L62: docstring 只声明去重用途，未声明任何抗碰撞或安全校验需求。

*模型置信度：30%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -71,9 +71,9 @@
 
 
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

第 68 行 `os.system("sqlite3 " + DB_PATH + " 'VACUUM;'")` 把模块级变量 `DB_PATH` 直接拼接进 shell 命令字符串。这里的安全假设是「`DB_PATH` 是可信的常量」，但代码库中没有任何证据表明 `DB_PATH` 在赋值时被校验或固定为字面量；只要 `DB_PATH` 来自环境变量、配置文件或启动参数，shell 就会把其中的 `;`、`$()`、反引号当作命令语法执行。检测器命中的 `os.system("sqlite3 " + D` 正是这个拼接点。

#### 攻击路径

入口是 `DB_PATH` 的赋值来源（本文件未提供该赋值行，证据不足，无法确认是环境变量、配置文件还是硬编码）。若 `DB_PATH` 可被外部影响，攻击者构造如 `DB_PATH="/tmp/x.db; id > /tmp/pwned"` 的值，`run_maintenance()` 在第 68 行执行 `os.system` 时，shell 先执行 `sqlite3 /tmp/x.db 'VACUUM;'`，再执行 `id > /tmp/pwned`。前置条件：攻击者能控制 `DB_PATH` 的取值（例如通过环境变量注入或配置文件写入），且 `run_maintenance` 被触发；调用方未在代码库中找到，触发方式证据不足。

#### 影响面

命令以运行本服务的 OS 用户权限执行。攻击者可读取该用户可访问的任意文件（包括同目录下的 SQLite 数据库文件、`pickle` 缓存文件）、写入任意路径、反弹 shell，进而横向移动到该用户可访问的其他服务。由于同文件存在 `pickle` 反序列化（`load_cached_state`）和 `urllib.request`（`sync_to_partner`），拿到命令执行后可篡改缓存文件或外联地址，扩大影响面。

#### 修复原理

把 `os.system` 换成 `subprocess.run(["sqlite3", DB_PATH, "VACUUM;"], shell=False)`，语义边界从「把拼接后的字符串交给 shell 解析」变为「把 `DB_PATH` 作为单个 argv 元素传给 `sqlite3` 进程」。shell 不再参与，`;`、`$()`、反引号都只是 `DB_PATH` 字符串里的普通字符，不会产生第二条命令。副作用：`sqlite3` 的 `VACUUM;` 作为单个参数传入时，sqlite3 CLI 会把它当作一条 SQL 语句执行，行为与原来一致；性能代价可忽略（少一次 shell fork）。若 `DB_PATH` 本身不可信，还应校验其为预期路径下的文件，但仅此改动已堵住命令注入。

#### 证据

- L68: os.system 把 DB_PATH 拼接进 shell 命令字符串，是命令注入的汇聚点
- L68: 拼接后字符串包含单引号包裹的 'VACUUM;'，DB_PATH 中的分号可提前闭合并追加命令
- L66: run_maintenance 无参数、无鉴权检查，任何能触发该函数的路径都会执行第 68 行
- L67: 函数体只有 os.system 一行，没有对 DB_PATH 做任何校验或转义
- L1-L7: import 列表包含 os，确认 os.system 可用；未提供 DB_PATH 赋值行，无法确认其来源

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
 
@@ -76,9 +77,9 @@
 
 
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

L73 的 `app_debug = True` 是一个局部变量，赋值后在整个文件中没有任何读取点：L74 只调用 `print(find_order("test"))`，`app_debug` 既没有传给任何框架（本文件未 import Flask/Django 等任何 Web 框架，见 L8-L14 的 import 列表），也没有被任何函数引用。检测器把「变量名含 debug 且值为 True」当作「生产环境开启调试模式」，但这里不存在任何调试开关的消费方，安全假设「该赋值会激活调试器/堆栈回显」不成立。此外 L1-L6 的模块注释明确声明这是故意包含漏洞的示例文件、不要在生产环境运行，L72 的 `if __name__ == "__main__"` 表明该分支只在直接执行脚本时进入，不构成服务端配置。

#### 攻击路径

证据不足。要构成 CWE-489 的真实攻击路径，需要证明 `app_debug` 被某个 Web 框架的 debug 参数消费（例如 `app.run(debug=app_debug)`）或控制错误页渲染，但本文件 L8-L14 未 import 任何框架，L23-L69 的全部函数定义均未引用 `app_debug`，调用方信息也标注为「未在此代码库中找到直接调用」。缺少的关键证据是：消费 `app_debug` 的框架初始化代码，以及该脚本对外暴露 HTTP 端口的入口。

#### 影响面

证据不足。当前代码中 `app_debug` 无任何运行时作用，不会暴露堆栈、配置或交互式调试器，因此不存在由该行直接导致的业务影响。需要说明的是，本文件确实存在其他可被利用的真实缺陷（L31 的 `keyword` 字符串拼接进 SQL、L41 的 `target` 直接拼进 `/tmp` 路径、L50 的 `ssl._create_unverified_context()` 关闭证书校验、L58 的 `pickle.loads`、L68 的 `os.system` 拼接），但这些与 L73 的 `app_debug` 无关，不应计入本条告警的影响。

#### 修复原理

本条为误报，不需要针对 L73 做修复。若团队希望消除静态扫描噪音，可删除 L73 这个未被使用的变量，或改为从环境变量读取（`app_debug = os.environ.get("APP_DEBUG", "0") == "1"`）——但后者只有在真正存在框架消费该变量时才有语义意义，当前代码中它只是改变一个死变量的值，不改变任何安全边界，也无性能代价。真正需要修的是同文件的其他缺陷，与本条无关。

#### 证据

- L73: `app_debug = True` 是普通局部变量赋值，不是任何框架的 debug 配置项。
- L74: 该分支内唯一语句是 `print(find_order("test"))`，未读取 `app_debug`。
- L8: import 列表从 hashlib 开始，L14 结束于 urllib.request，全程未引入 Web 框架，无 debug 开关消费方。
- L72: `if __name__ == "__main__"` 表明该分支仅在直接执行脚本时进入，不是服务端运行配置。
- L1: 模块 docstring 声明该文件是故意包含漏洞的示例，不要在生产环境运行。

*模型置信度：10%*

#### 补丁（已通过机器验证，待人工 review）

```diff
--- a/orders.py
+++ b/orders.py
@@ -82,6 +82,6 @@
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

L20 的模块级赋值 `DB_PASSWORD = "db_pass_7c4e19d2"` 把数据库口令以明文字面量固化在源码里，安全假设「凭据只存在于部署环境的密钥存储中」在这里不成立：口令的生命周期与 git 提交历史、构建产物、镜像层绑定，任何能读到 orders.py 的人（仓库协作者、CI 日志、镜像解包者）都直接拿到口令。同一模式在 L19 的 `API_TOKEN = "prod_api_token_8f3a91bc77de"` 重复出现。需要说明的是：本文件中 `get_connection()`（L23-L24）走的是 `sqlite3.connect(DB_PATH)`，并未使用 DB_PASSWORD，因此该常量在当前代码里没有消费点，它是「已泄露但尚未接线」的凭据，危害取决于仓库外是否有其他服务复用同一口令——这一点证据不足，缺少仓库外的部署配置与消费方代码。

#### 攻击路径

入口不是 HTTP 参数，而是源码读取面：攻击者获得 orders.py 的任一副本即可。路径一，拿到仓库读权限（内部人员、被投毒的依赖、泄露的 fork）→ 直接读取 L20 字面量。路径二，CI/CD 把构建日志或制品上传到可访问的存储 → 从镜像层或日志中提取 L20。路径三，若该文件被打进容器镜像，任何能拉取镜像的人执行 `docker save` 后解包即可读到 L20。前置条件仅为「能读到文件内容」，不需要登录业务系统、不需要任何运行时配置。当前代码内不存在从网络输入到 L20 的读取路径，因此不存在远程直接回显该口令的链路。

#### 影响面

泄露对象是数据库口令字符串本身。在本文件范围内，`get_connection()`（L23-L24）连接的是本地 SQLite 文件 orders.db，不使用该口令，所以仅凭本文件无法证明攻击者能凭此登录哪台数据库、读到 orders 表的哪些行。真实后果取决于该口令在仓库外被哪些服务复用：若被用于生产数据库账号，攻击者获得该账号的全部库权限（对 orders 表的读写、可能的 DROP/UPDATE）；若被用于其他系统，则横向到对应系统。这部分证据不足，缺少部署配置、数据库账号授权清单与消费方代码，无法给出确定的权限边界。

#### 修复原理

把 L20 改为从环境变量读取（本文件 L10 已 import os，无需新增依赖），例如在模块加载时执行 `DB_PASSWORD = os.environ["DB_PASSWORD"]`，缺失时抛 KeyError 使进程启动失败。语义边界的变化是：口令不再属于源码，而属于进程运行环境，源码副本、git 历史、镜像层不再携带秘密，轮换口令只需改环境变量并重启，不必改代码重新发版。用 `os.environ[...]` 而非 `.get()` 是为了让缺失配置在启动时立刻暴露，而不是把 None 带进后续连接逻辑。副作用：本地开发与测试需要额外注入环境变量，否则启动即失败；同时必须轮换 db_pass_7c4e19d2 本身，因为 L20 已存在于提交历史中，改代码不会让旧值失效。性能代价为零，环境变量读取发生在模块导入期一次。

#### 证据

- L20: DB_PASSWORD 以明文字符串字面量赋值，凭据直接固化在源码中
- L19: 同一文件重复出现硬编码凭据 API_TOKEN，说明是系统性写法而非孤例
- L23: get_connection 使用 sqlite3.connect(DB_PATH) 而非 DB_PASSWORD，证明该常量在当前文件内无消费点
- L10: 文件已 import os，具备改为 os.environ 读取的现成条件
- L16: DB_PATH 为本地文件名，说明当前连接目标是本地 SQLite，不涉及远程数据库认证

*模型置信度：85%*

<details><summary>命中代码</summary>

```

# 硬编码的凭据（示例值，不是真实密钥）
API_TOKEN = "prod_api_token_8f3a91bc77de"
DB_PASSWORD = "db_pass_7c4e19d2"


def get_connection():
```

</details>

## 后续动作

- [ ] 逐条 review「已验证修复」的补丁，确认没有改变业务语义
- [ ] 「未通过验证」的条目需要人工判断：是模型修法不对，还是检测本身是误报
- [ ] 对同类问题做全局检索，避免只修了命中的那一处
