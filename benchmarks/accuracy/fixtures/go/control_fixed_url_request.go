package main

import (
	"io"
	"net/http"
	"strings"
)

func search(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	resp, err := http.Post("https://api.example.com/search", "text/plain", strings.NewReader(term))
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
