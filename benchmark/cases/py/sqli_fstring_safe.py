import sqlite3


def find(keyword):
    conn = sqlite3.connect("app.db")
    sql = "SELECT id FROM orders WHERE note LIKE ?"
    return conn.execute(sql, ("%" + keyword + "%",)).fetchall()
