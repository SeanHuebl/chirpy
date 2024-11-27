package main

import "net/http"

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
