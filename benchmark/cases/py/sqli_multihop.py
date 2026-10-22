def search(q):
    conn = connect()
    part = "WHERE name LIKE '%" + q + "%'"
    sql = "SELECT id FROM users " + part
    return conn.execute(sql).fetchall()
