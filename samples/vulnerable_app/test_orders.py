"""订单查询的回归测试。

用途：验证 bee 生成的补丁不会破坏既有行为契约。
用标准库 unittest 编写，不依赖 pytest。
"""

import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import orders


class TestOrders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conn = sqlite3.connect(orders.DB_PATH)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS orders "
            "(id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, note TEXT)"
        )
        conn.execute("DELETE FROM orders")
        conn.executemany(
            "INSERT INTO orders (id, user_id, amount, note) VALUES (?, ?, ?, ?)",
            [
                (1, 10, 99.5, "urgent delivery"),
                (2, 11, 20.0, "gift wrap"),
                (3, 12, 5.0, "return"),
            ],
        )
        conn.commit()
        conn.close()

    def test_find_order_returns_matching_rows(self):
        rows = orders.find_order("urgent")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 1)

    def test_find_order_handles_no_match(self):
        self.assertEqual(orders.find_order("nonexistent"), [])

    def test_find_order_like_wildcard_still_works(self):
        """参数化改造后 LIKE 语义必须保持不变，否则是隐性功能破坏。"""
        rows = orders.find_order("urgent%delivery")
        self.assertEqual(len(rows), 1)

    def test_fingerprint_is_stable(self):
        self.assertEqual(orders.fingerprint("abc"), orders.fingerprint("abc"))
        self.assertEqual(len(orders.fingerprint("abc")), 32)

    def test_export_report_returns_path(self):
        path = orders.export_report(42, "ignored.txt")
        self.assertTrue(path.endswith("order_42.csv"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
