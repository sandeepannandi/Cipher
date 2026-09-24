package main

import (
	"net/http"

	"example.com/inventory/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.FindUser(name)
}
