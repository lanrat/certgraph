// Package web defines a minimal web server for serving the web UI
package web

import (
	"fmt"
	"net/http"
)

//go:generate ./generate.sh

// Serve starts a very basic webserver serving the embed web UI
func Serve(addr string) error {
	http.HandleFunc("/", indexHandler)
	return http.ListenAndServe(addr, nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s", indexSource)
}
