package main

import "net/http"

func main() {

	serverMux := http.NewServeMux()
	server := http.Server{
		Handler: serverMux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
