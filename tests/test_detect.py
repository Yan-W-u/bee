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


if __name__ == "__main__":
    unittest.main()
