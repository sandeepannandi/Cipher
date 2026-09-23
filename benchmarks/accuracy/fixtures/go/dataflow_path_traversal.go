package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	requested := r.URL.Query().Get("file")
	target := filepath.Join("uploads", requested)
	data, err := os.ReadFile(target)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}
