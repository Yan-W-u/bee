SAFE_COLUMNS = {"id": "id", "name": "name", "created": "created_at"}


def list_users(sort_field):
    column = SAFE_COLUMNS.get(sort_field, "id")
    sql = "SELECT id FROM users ORDER BY " + column + " ASC"
    return sql
