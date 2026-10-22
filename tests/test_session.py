"""累积会话测试：验证同一文件多处漏洞不会互相踩。

真实项目里一个文件经常同时有多个漏洞（比如硬编码凭据 + SQL 注入）。
如果每条补丁都对着磁盘原文验证，第二条的 old_string 会指向被第一条
改过的内容，各自都能通过、合并时全废。这个测试盯的就是这件事。
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from bee.verify import EditProposal, PatchSession, apply_session, replace_once


class TestAccumulation(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bee-session-"))
        self.file = self.tmp / "app.py"
        self.file.write_text(
            'TOKEN = "abc123"\n\n\ndef q(k):\n    return "SELECT " + k\n',
            encoding="utf-8",
            newline="",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_base_text_reflects_committed_edits(self):
        s = PatchSession(self.tmp)
        self.assertIn('TOKEN = "abc123"', s.base_text("app.py") or "")

        s.commit("app.py", EditProposal("app.py", 'TOKEN = "abc123"', "TOKEN = load()"))
        self.assertIn("TOKEN = load()", s.base_text("app.py") or "")
        self.assertNotIn("abc123", s.base_text("app.py") or "")

    def test_second_patch_can_target_first_patch_output(self):
        """关键场景：第二条补丁的锚点只在第一条应用后才存在。"""
        s = PatchSession(self.tmp)
        first = EditProposal(
            "app.py",
            'TOKEN = "abc123"',
            'TOKEN = "placeholder"\nSECRET = "xyz"',
        )
        self.assertIsNotNone(replace_once(s.base_text("app.py") or "", first.old_string, first.new_string))
        s.commit("app.py", first)

        second = EditProposal("app.py", 'SECRET = "xyz"', "SECRET = env()")
        base = s.base_text("app.py") or ""
        self.assertIn('SECRET = "xyz"', base, "累积状态里应能看到第一条补丁引入的内容")

    def test_apply_session_writes_all_edits_in_order(self):
        s = PatchSession(self.tmp)
        s.commit("app.py", EditProposal("app.py", 'TOKEN = "abc123"', "TOKEN = load()"))
        s.commit("app.py", EditProposal("app.py", 'return "SELECT " + k', 'return "SELECT ?", (k,)'))

        written, errors = apply_session(self.tmp, s)
        self.assertEqual(written, 1)
        self.assertEqual(errors, [])

        text = self.file.read_text(encoding="utf-8")
        self.assertIn("TOKEN = load()", text)
        self.assertIn('"SELECT ?", (k,)', text)
        self.assertNotIn("abc123", text)

    def test_backup_created_once_per_file(self):
        s = PatchSession(self.tmp)
        s.commit("app.py", EditProposal("app.py", 'TOKEN = "abc123"', "TOKEN = load()"))
        apply_session(self.tmp, s)
        backups = list(self.tmp.glob("*.bee.bak"))
        self.assertEqual(len(backups), 1)
        self.assertIn("abc123", backups[0].read_text(encoding="utf-8"))

    def test_conflicting_edit_aborts_file_without_partial_write(self):
        s = PatchSession(self.tmp)
        s.commit("app.py", EditProposal("app.py", 'TOKEN = "abc123"', "TOKEN = load()"))
        s.commit("app.py", EditProposal("app.py", 'TOKEN = "abc123"', "TOKEN = other()"))

        before = self.file.read_text(encoding="utf-8")
        written, errors = apply_session(self.tmp, s)
        after = self.file.read_text(encoding="utf-8")

        self.assertEqual(written, 0)
        self.assertTrue(errors)
        self.assertEqual(before, after, "冲突时不应写出一半结果")


if __name__ == "__main__":
    unittest.main(verbosity=2)
