package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
