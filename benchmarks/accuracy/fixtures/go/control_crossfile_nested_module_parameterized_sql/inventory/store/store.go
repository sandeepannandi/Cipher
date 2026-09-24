package store

import "database/sql"

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = ?", name)
}
