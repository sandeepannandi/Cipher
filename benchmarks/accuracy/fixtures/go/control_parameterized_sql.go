package main

import (
	"database/sql"
	"net/http"
)

func findUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query("SELECT id, email FROM users WHERE name = $1", name)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
