"""规则引擎本身的回归测试。

benchmark 负责整体准确率，这里负责「单条规则的判定边界」——
尤其是 safe_when 的压制是否生效。规则改宽一点点，误报就会回来，
这类退化必须在这里被拦住。

写法上刻意用临时文件而不是内存字符串：scan_file 依赖真实路径推断语言，
用内存字符串测出来的结论跟实际调用路径不一致，等于没测。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bee.detect import scan_file


def scan_snippet(name: str, code: str) -> list:
    """把一段代码写成临时文件再扫，返回其中的规则 id 列表。"""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8")
        return [f.rule_id for f in scan_file(target, root)]


class TestXxe(unittest.TestCase):
    def test_default_parser_is_flagged(self):
        """lxml 默认开外部实体，必须报。"""
        hits = scan_snippet("xxe.py", "from lxml import etree\n"
                                      "\n"
                                      "def parse(payload):\n"
                                      "    parser = etree.XMLParser()\n"
                                      "    return etree.fromstring(payload, parser)\n")
        self.assertIn("bee.xxe", hits)

    def test_hardened_parser_is_silent(self):
        """resolve_entities=False + no_network=True 是标准修法，不能报。"""
        hits = scan_snippet("xxe_safe.py", "from lxml import etree\n"
                                           "\n"
                                           "def parse(payload):\n"
                                           "    parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
                                           "    return etree.fromstring(payload, parser)\n")
        self.assertNotIn("bee.xxe", hits)

    def test_defusedxml_is_silent(self):
        hits = scan_snippet("xxe_defused.py", "from defusedxml.lxml import fromstring\n"
                                              "\n"
                                              "def parse(payload):\n"
                                              "    return fromstring(payload)\n")
        self.assertNotIn("bee.xxe", hits)

    def test_java_factory_is_flagged(self):
        hits = scan_snippet("Parser.java", "class P {\n"
                                           "  void f() {\n"
                                           "    DocumentBuilderFactory.newInstance();\n"
                                           "  }\n"
                                           "}\n")
        self.assertIn("bee.xxe", hits)

    def test_java_disallow_doctype_is_silent(self):
        hits = scan_snippet("ParserSafe.java", "class P {\n"
                                               "  void f() {\n"
                                               "    setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
                                               "  }\n"
                                               "}\n")
        self.assertNotIn("bee.xxe", hits)


class TestSuppression(unittest.TestCase):
    """safe_when 的压制逻辑：这些写法必须是安静的。"""

    def test_parameterized_sql_is_silent(self):
        hits = scan_snippet("safe_sql.py", "def get(uid):\n"
                                           "    return db.execute(\"SELECT * FROM t WHERE id = ?\", (uid,))\n")
        self.assertNotIn("bee.sql-injection", hits)

    def test_shell_false_is_silent(self):
        hits = scan_snippet("safe_cmd.py", "import subprocess\n"
                                           "\n"
                                           "def run(name):\n"
                                           "    return subprocess.run([\"ls\", name], shell=False)\n")
        self.assertNotIn("bee.command-injection", hits)

    def test_like_parameter_is_silent(self):
        """参数值里的 % 拼接不进 SQL 文本，属于经典误报。"""
        hits = scan_snippet("safe_like.py", "def search(kw):\n"
                                            "    return db.execute(\"SELECT * FROM t WHERE n LIKE ?\", (\"%\" + kw + \"%\",))\n")
        self.assertNotIn("bee.sql-injection", hits)

    def test_fstring_whitelist_table_with_params_is_silent(self):
        """f-string 只拼白名单表名 + 用户输入走占位符，是安全写法。"""
        hits = scan_snippet("safe_whitelist.py",
                            "TABLES = {'orders': 'orders'}\n"
                            "\n"
                            "def find(conn, key, kw):\n"
                            "    table = TABLES[key]\n"
                            "    sql = f\"SELECT id FROM {table} WHERE note LIKE ?\"\n"
                            "    return conn.execute(sql, (\"%\" + kw + \"%\",)).fetchall()\n")
        self.assertNotIn("bee.sql-injection", hits)

    def test_concat_sql_with_params_still_flagged(self):
        """多参数不等于安全：SQL 文本里混着用户输入，加 params 也没用。"""
        hits = scan_snippet("bad_params.py",
                            "def find(conn, name):\n"
                            "    sql = f\"SELECT * FROM t WHERE n = '{name}' AND x = ?\"\n"
                            "    return conn.execute(sql, (1,)).fetchall()\n")
        self.assertIn("bee.sql-injection", hits)

    def test_request_arg_table_still_flagged(self):
        """request.args['table'] 也是下标访问，但那是用户输入，不能当白名单。"""
        hits = scan_snippet("bad_table.py",
                            "def find(conn, request):\n"
                            "    table = request.args['table']\n"
                            "    sql = f\"SELECT * FROM {table} WHERE id = ?\"\n"
                            "    return conn.execute(sql, (1,)).fetchall()\n")
        self.assertIn("bee.sql-injection", hits)

    def test_php_concat_is_flagged(self):
        hits = scan_snippet("bad.php", "<?php\n"
                                       "$sql = \"SELECT * FROM u WHERE id = \" . $_GET['id'];\n"
                                       "mysqli_query($conn, $sql);\n")
        self.assertIn("bee.sql-injection", hits)

    def test_yaml_credential_is_flagged(self):
        hits = scan_snippet("app.yml", "db:\n"
                                       "  host: localhost\n"
                                       "  password: \"prod_api_token_9f3c1a\"\n")
        self.assertIn("bee.hardcoded-credential", hits)

    def test_env_credential_is_silent(self):
        hits = scan_snippet("app_env.yml", "db:\n"
                                           "  password: ${DB_PASSWORD}\n")
        self.assertNotIn("bee.hardcoded-credential", hits)


class TestNoiseReduction(unittest.TestCase):
    """真实语料上的误报结构回归。

    stdlib 扫描从 321 条降到 81 条，靠的就是这几类抑制。
    每一条都必须有测试，否则下次改规则会把噪音放回来。
    """

    def test_js_function_keyword_not_matched_in_python(self):
        # iscoroutinefunction( / this_function( 曾因 `Function` 无左边界全部命中
        hits = scan_snippet("a.py", "x = iscoroutinefunction(cb)\n")
        self.assertNotIn("bee.code-injection", hits)
        hits = scan_snippet("a.py", "y = this_function(1)\n")
        self.assertNotIn("bee.code-injection", hits)

    def test_function_constructor_not_matched_in_python(self):
        hits = scan_snippet("a.py", "Function(x)\n")
        self.assertNotIn("bee.code-injection", hits)

    def test_function_constructor_still_matched_in_js(self):
        hits = scan_snippet("a.js", "Function(userInput)()\n")
        self.assertIn("bee.code-injection", hits)

    def test_eval_in_docstring_not_matched(self):
        hits = scan_snippet("a.py", '"""use eval() carefully"""\n')
        self.assertNotIn("bee.code-injection", hits)

    def test_eval_in_comment_not_matched(self):
        hits = scan_snippet("a.py", "# call eval(x) here\ndef f():\n    return 1\n")
        self.assertNotIn("bee.code-injection", hits)

    def test_real_eval_still_matched(self):
        hits = scan_snippet("a.py", "def f(src):\n    return eval(src)\n")
        self.assertIn("bee.code-injection", hits)

    def test_credential_meta_name_not_matched(self):
        # token_type / api_key_name 这类是名字里的关键词，不是凭据
        hits = scan_snippet("a.py", "token_type = 'unstructured'\n")
        self.assertNotIn("bee.hardcoded-credential", hits)
        hits = scan_snippet("a.py", "api_key_name = 'X-Api-Key'\n")
        self.assertNotIn("bee.hardcoded-credential", hits)

    def test_short_or_placeholder_value_not_matched(self):
        hits = scan_snippet("a.py", 'password = "changeme"\n')
        self.assertNotIn("bee.hardcoded-credential", hits)
        hits = scan_snippet("a.py", 'password = "YOUR_TOKEN_HERE"\n')
        self.assertNotIn("bee.hardcoded-credential", hits)

    def test_real_hardcoded_secret_still_matched(self):
        hits = scan_snippet("a.py", 'api_key = "sk_live_9f8a7b6c5d4e3f2a"\n')
        self.assertIn("bee.hardcoded-credential", hits)

    def test_timing_token_compare_not_matched(self):
        hits = scan_snippet("a.py", "if tokenL == 0xF:\n    pass\n")
        self.assertNotIn("bee.timing-attack", hits)

    def test_timing_real_secret_compare_still_matched(self):
        hits = scan_snippet("a.py", "if expected_signature == provided_signature:\n    pass\n")
        self.assertIn("bee.timing-attack", hits)

    def test_self_join_base_not_reported(self):
        # open(os.path.join(self._path, key)) 是对象内部目录，不是外部可控根
        hits = scan_snippet("a.py",
                            "class M:\n"
                            "    def get(self, key):\n"
                            "        return open(os.path.join(self._path, key), 'rb')\n")
        self.assertNotIn("bee.path-traversal", hits)

    def test_module_join_base_still_reported(self):
        hits = scan_snippet("a.py",
                            "def read(name):\n"
                            "    return open(os.path.join('/var/data', name), 'rb')\n")
        self.assertIn("bee.path-traversal", hits)

    def test_extractall_with_filter_not_reported(self):
        hits = scan_snippet("a.py",
                            "def unpack(zf, dest):\n"
                            "    zf.extractall(dest, filter='data')\n")
        self.assertNotIn("bee.zip-slip", hits)

    def test_plain_extractall_still_reported(self):
        hits = scan_snippet("a.py",
                            "def unpack(zf, dest):\n"
                            "    zf.extractall(dest)\n")
        self.assertIn("bee.zip-slip", hits)


class TestProfiles(unittest.TestCase):
    def test_every_rule_has_confidence(self):
        from bee.detect import BUILTIN_RULES, Confidence
        for rule in BUILTIN_RULES:
            self.assertIsInstance(rule.confidence, Confidence, f"{rule.id} 未登记 confidence")

    def test_profile_filtering(self):
        from bee.cli import _select_rules
        strict = {r.id for r in _select_rules(None, None, "strict")}
        default = {r.id for r in _select_rules(None, None, "default")}
        full = {r.id for r in _select_rules(None, None, "full")}
        self.assertLess(len(strict), len(default))
        self.assertLess(len(default), len(full))
        self.assertIn("bee.sql-injection", strict)
        self.assertNotIn("bee.timing-attack", strict)
        self.assertIn("bee.timing-attack", full)

    def test_explicit_rule_ignores_profile(self):
        from bee.cli import _select_rules
        rules = _select_rules(["bee.timing-attack"], None, "strict")
        self.assertEqual([r.id for r in rules], ["bee.timing-attack"])


if __name__ == "__main__":
    unittest.main()
