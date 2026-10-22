def list_users(sort_field):
    sql = "SELECT id FROM users ORDER BY " + sort_field + " ASC"
    return sql
