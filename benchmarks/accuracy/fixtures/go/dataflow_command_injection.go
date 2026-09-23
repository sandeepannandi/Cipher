package main

import (
	"net/http"
	"os/exec"
)

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := "ping -c 1 " + host
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}
