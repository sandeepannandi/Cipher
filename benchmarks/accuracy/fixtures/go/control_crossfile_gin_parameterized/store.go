package main

import "database/sql"

var db *sql.DB

func findUser(name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = $1", name)
}
