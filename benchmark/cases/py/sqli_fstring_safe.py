import sqlite3

# 列名/表名不能参数化，标准做法是白名单映射——这里用 f-string 拼的是
# 白名单里的固定标识符，用户输入仍然走占位符。
TABLES = {"orders": "orders", "archive": "orders_archive"}


def find(conn, table_key, keyword):
    table = TABLES[table_key]
    sql = f"SELECT id FROM {table} WHERE note LIKE ?"
    return conn.execute(sql, ("%" + keyword + "%",)).fetchall()
