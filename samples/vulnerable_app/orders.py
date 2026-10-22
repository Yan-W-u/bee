"""订单服务示例。

这个文件故意包含若干漏洞，用于验证 bee 的检测与修复链路。
刻意只用标准库，保证任何环境都能直接跑测试。
不要在生产环境运行。
"""

import hashlib
import json
import os
import pickle
import sqlite3
import ssl
import urllib.request

DB_PATH = "orders.db"

# 硬编码的凭据
API_TOKEN = "sk_live_8f3a91bc77de4c02"
DB_PASSWORD = "orders_prod_2024"


def get_connection():
    return sqlite3.connect(DB_PATH)


def find_order(keyword):
    """按关键词查订单。"""
    conn = get_connection()
    cursor = conn.cursor()
    sql = "SELECT id, user_id, amount FROM orders WHERE note LIKE '%" + keyword + "%'"
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
    return rows


def export_report(order_id, target):
    """导出订单报告到指定文件名。"""
    filename = os.path.join("/var/reports", f"order_{order_id}.csv")
    with open(os.path.join("/tmp", target), "w") as fh:
        fh.write(str(order_id))
    return filename


def sync_to_partner(endpoint, payload):
    """同步订单到合作方接口。"""
    url = "https://partner.example.com" + endpoint
    body = json.dumps(payload).encode("utf-8")
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, data=body)
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    return resp.status


def load_cached_state(blob):
    """加载缓存的状态对象。"""
    return pickle.loads(blob)


def fingerprint(content):
    """计算内容指纹，用于去重。"""
    return hashlib.md5(content.encode("utf-8")).hexdigest()


def run_maintenance():
    """执行数据库维护脚本。"""
    os.system("sqlite3 " + DB_PATH + " 'VACUUM;'")
    return True


if __name__ == "__main__":
    app_debug = True
    print(find_order("test"))
