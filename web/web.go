// Package web defines a minimal web server for serving the web UI
package web

import (
	"io/fs"
	"log"
	"net/http"
)

// Serve starts a very basic webserver serving the embed web UI
func Serve(addr string, data fs.FS) error {
	data, err := fs.Sub(data, "docs")
	if err != nil {
		return err
	}
	http.Handle("/", http.FileServer(http.FS(data)))
	return http.ListenAndServe(addr, logRequest(http.DefaultServeMux))
}

// very minimal request logger
func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
