package main

import (
	"database/sql"
)

func Find(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT id FROM users WHERE name = '" + name + "'")
}
