package main

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func findUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
