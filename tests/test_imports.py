"""缺失 import 检测的回归测试。

这个检查来自一次真实漏网：模型修 pickle 漏洞时写了 io.BytesIO，
但没在补丁里加 import io。py_compile 通过、测试没覆盖到，
NameError 一路躲过了全部四项信号。
"""

from __future__ import annotations

import unittest

from bee.verify import check_missing_imports


class TestMissingImports(unittest.TestCase):
    def test_detects_missing_io(self):
        text = (
            "import pickle\n\n\n"
            "def load(blob):\n    return pickle.Unpickler(io.BytesIO(blob)).load()\n"
        )
        self.assertIn("io", check_missing_imports(text))

    def test_detects_missing_subprocess(self):
        text = (
            "import os\n\n\n"
            "def run():\n    subprocess.run(['ls'], shell=False)\n"
        )
        self.assertIn("subprocess", check_missing_imports(text))

    def test_accepts_when_imported(self):
        text = (
            "import io\nimport pickle\n\n\n"
            "def load(blob):\n    return pickle.Unpickler(io.BytesIO(blob)).load()\n"
        )
        self.assertEqual(check_missing_imports(text), [])

    def test_accepts_from_import(self):
        text = "from os import path\n\n\ndef p():\n    return path.join('a', 'b')\n"
        self.assertEqual(check_missing_imports(text), [])

    def test_ignores_local_variable_shadowing(self):
        """局部变量名与标准库同名时不能误报。"""
        text = (
            "def f():\n"
            "    json = object()\n"
            "    return json.dumps\n"
        )
        self.assertEqual(check_missing_imports(text), [])

    def test_ignores_non_stdlib_attribute(self):
        text = (
            "class Repo:\n    def query(self):\n        return 1\n\n\n"
            "def f():\n    return repo.query()\n"
        )
        self.assertEqual(check_missing_imports(text), [])

    def test_syntax_error_returns_empty(self):
        self.assertEqual(check_missing_imports("def broken(:\n"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
