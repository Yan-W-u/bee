"""修复循环测试：验证「失败回灌」真的把失败原因喂回了模型。

这个机制是整个工具区别于「让 LLM 随手改代码」的地方。
如果回灌没生效，模型会在同一个错误上重复，轮次全浪费。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from bee.context import build_context
from bee.detect import scan_file
from bee.llm import LLMConfig
from bee.models import Explanation
from bee.patch import repair_finding

VULNERABLE = '''import sqlite3


def find_order(keyword):
    conn = sqlite3.connect("x.db")
    cursor = conn.cursor()
    sql = "SELECT id FROM orders WHERE note LIKE '%" + keyword + "%'"
    cursor.execute(sql)
    return cursor.fetchall()
'''


class MockClient:
    """按脚本返回预设响应，同时记录每次发给模型的 prompt。"""

    def __init__(self, responses: list[str]) -> None:
        self.responses = responses
        self.prompts: list[str] = []
        self.config = LLMConfig(api_key="mock-key", model="mock")

    def chat(self, messages, **kwargs):  # noqa: ANN001, ANN003
        self.prompts.append(messages[-1]["content"])
        idx = min(len(self.prompts) - 1, len(self.responses) - 1)
        return self.responses[idx]


BAD_PATCH = json.dumps({
    "file": "service.py",
    "old_string": '    sql = "SELECT id FROM orders WHERE note LIKE \'%" + keyword + "%\'"',
    "new_string": '    sql = "SELECT id FROM orders WHERE note LIKE \'%" + keyword.strip() + "%\'"',
    "rationale": "对输入做 trim",
    "side_effects": "无",
}, ensure_ascii=False)

GOOD_PATCH = json.dumps({
    "file": "service.py",
    "old_string": '    sql = "SELECT id FROM orders WHERE note LIKE \'%" + keyword + "%\'"\n    cursor.execute(sql)',
    "new_string": '    cursor.execute(\n        "SELECT id FROM orders WHERE note LIKE ?", ("%" + keyword + "%",)\n    )',
    "rationale": "改为参数化查询，SQL 文本固定，外部数据只通过参数绑定进入",
    "side_effects": "无",
}, ensure_ascii=False)


class TestRepairLoop(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-loop-"))
        self.file = self.tmp / "service.py"
        self.file.write_text(VULNERABLE, encoding="utf-8", newline="")
        findings = scan_file(self.file, self.tmp)
        self.finding = next(f for f in findings if f.rule_id == "bee.sql-injection")
        self.ctx = build_context(self.finding, self.tmp)
        self.expl = Explanation(
            root_cause="第 7 行的 sql 变量把 keyword 直接拼进 SELECT 语句",
            attack_path="攻击者控制 keyword 参数，注入 ' OR 1=1 -- 改变查询语义",
            impact="可读取 orders 表全部内容",
            fix_rationale="改为参数化查询",
            confidence=0.9,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_retries_after_failed_patch_and_feeds_back_reason(self):
        client = MockClient([BAD_PATCH, GOOD_PATCH])
        attempts = repair_finding(
            self.finding, self.expl, self.ctx, client, self.tmp,
            max_rounds=3, run_tests=False,
        )

        self.assertEqual(len(attempts), 2, "第一轮失败后应再试一次")
        self.assertFalse(attempts[0].succeeded, "只做 trim 的补丁不应通过")
        self.assertTrue(attempts[1].succeeded, attempts[1].failure_reason())

        # 核心断言：第二轮 prompt 必须携带第一轮的失败原因
        self.assertIn("上一轮补丁未通过验证", client.prompts[1])
        self.assertIn("重扫仍命中", client.prompts[1])
        # 也必须携带上一轮的具体改动，否则模型不知道要改什么
        self.assertIn("diff", client.prompts[1])

    def test_gives_up_after_max_rounds(self):
        client = MockClient([BAD_PATCH])
        attempts = repair_finding(
            self.finding, self.expl, self.ctx, client, self.tmp,
            max_rounds=2, run_tests=False,
        )
        self.assertEqual(len(attempts), 2)
        self.assertFalse(any(a.succeeded for a in attempts))

    def test_no_client_returns_empty(self):
        attempts = repair_finding(
            self.finding, self.expl, self.ctx, None, self.tmp, run_tests=False
        )
        self.assertEqual(attempts, [])

    def test_indent_repair_handles_misindented_old_string(self):
        """模型把缩进写错两格时，应通过空白容错仍然落地。"""
        misindented = json.dumps({
            "file": "service.py",
            "old_string": '  sql = "SELECT id FROM orders WHERE note LIKE \'%" + keyword + "%\'"\n  cursor.execute(sql)',
            "new_string": '  cursor.execute(\n      "SELECT id FROM orders WHERE note LIKE ?", ("%" + keyword + "%",)\n  )',
            "rationale": "参数化",
        }, ensure_ascii=False)
        client = MockClient([misindented])
        attempts = repair_finding(
            self.finding, self.expl, self.ctx, client, self.tmp,
            max_rounds=1, run_tests=False,
        )
        self.assertTrue(attempts[0].applied, "缩进容错未生效")
        self.assertTrue(attempts[0].compiles, "缩进修正后的补丁应能编译")


if __name__ == "__main__":
    unittest.main(verbosity=2)
