package main

import (
	"net/http"
)

func handlerHealthz(headerMap http.ResponseWriter, req *http.Request) {
	headerMap.Header().Set("Content-Type", "text/plain; charset=utf-8")
	headerMap.WriteHeader(http.StatusOK)
	headerMap.Write([]byte("OK"))
}

func main() {
	sMux := http.NewServeMux()

	server := http.Server{
		Handler: sMux,
		Addr:    ":8080",
	}
	sMux.Handle("/", http.FileServer(http.Dir(".")))
	sMux.Handle("/assets/logo.png", http.FileServer(http.Dir(".")))
	server.ListenAndServe()
}
