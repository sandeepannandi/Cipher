package main

import "database/sql"

func FindUser(db *sql.DB, name string) {
	db.Query("SELECT id FROM users WHERE name = '" + name + "'")
}
