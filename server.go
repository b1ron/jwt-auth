package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

// server is a simple HTTP server that uses JWT for authentication.
// It has two endpoints:
// - /login: expects a POST request with a JSON body containing a "username" key.
// - /resource: expects a GET request with a "Authorization" header containing a JWT token.

var resources = map[string]string{
	"1234567890": "some resource",
	"0987654321": "another resource",
	"1122334455": "yet another resource",
	"5432167890": "one more resource",
	"1010101010": "cannot access this resource",
}

func main() {
	secret, err := os.ReadFile("secret.txt")
	if err != nil {
		log.Fatalf("could not read secret: %v", err)
	}
	_ = secret
	http.HandleFunc("/login", login)
	http.HandleFunc("/resource", resource)
	log.Fatal(http.ListenAndServe("localhost:8000", nil))
}

func login(w http.ResponseWriter, r *http.Request) {
	// TODO ...
	fmt.Fprintf(w, "URL.Path = %q\n", r.URL.Path)
}

func resource(w http.ResponseWriter, r *http.Request) {
	// TODO ...
	fmt.Fprintf(w, "URL.Path = %q\n", r.URL.Path)
}
