# 真实语料抽样（人工标注用）

逐条在 `结果` 里填 `TP`（真漏洞）或 `FP`（误报）。
统计出的 FP 率写进 docs/validation.md。

| # | 规则 | 位置 | 代码 | 结果 |
| --- | --- | --- | --- | --- |
| 1 | `bee.code-injection` | `_pyrepl/console.py:181` | `exec(code, self.locals)` |  |
| 2 | `bee.command-injection` | `_osx_support.py:292` | `status = os.system(` |  |
| 3 | `bee.sql-injection` | `platform.py:330` | `data = _wmi.exec_query("SELECT {} FROM {}".format(` |  |
| 4 | `bee.tls-verify-disabled` | `asyncio/sslproto.py:57` | `sslcontext.check_hostname = False` |  |
| 5 | `bee.unsafe-deserialization` | `importlib/_bootstrap_external.py:781` | `code = marshal.loads(data)` |  |
| 6 | `bee.weak-crypto` | `poplib.py:346` | `digest = hashlib.md5(digest).hexdigest()` |  |
| 7 | `bee.xxe` | `xml/etree/ElementInclude.py:90` | `data = ElementTree.parse(file).getroot()` |  |
| 8 | `bee.zip-slip` | `zipfile/__init__.py:2354` | `zf.extractall(curdir)` |  |
| 9 | `bee.code-injection` | `_pyrepl/main.py:47` | `exec(startup_code, namespace)` |  |
| 10 | `bee.command-injection` | `_pyrepl/pager.py:142` | `proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,` |  |
| 11 | `bee.sql-injection` | `sqlite3/dump.py:81` | `res = cu.execute(f'PRAGMA table_info({table_name_ident})')` |  |
| 12 | `bee.tls-verify-disabled` | `ssl.py:718` | `elif context.verify_mode != CERT_NONE:` |  |
