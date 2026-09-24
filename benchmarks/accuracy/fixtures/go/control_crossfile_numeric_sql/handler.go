package main

import (
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	id, _ := strconv.Atoi(name)
	findUser(id)
}
