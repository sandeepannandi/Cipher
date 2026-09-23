package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func findUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := fmt.Sprintf("SELECT id, email FROM users WHERE name = '%s'", name)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
