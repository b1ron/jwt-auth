package main

import (
	"jwt/jwt"
	"log"
	"net/http"
	"os"
)

// server is a simple HTTP server that uses JWT for authentication. It also acts as a session manager.
// It has two endpoints:
// - /login: expects a POST request with a JSON body containing a "username" and password.
//  If the credentials are valid, it responds with a JWT token. The secret used to sign the token. A refresh token is set as a cookie.
// - /resource: expects a GET request with a "Authorization" header containing a JWT token.
// If the token is valid, it responds with a JSON object containing the requested resource.

func main() {
	token, err := jwt.Encode(map[string]interface{}{
		"iat":  1516239022,
		"name": "John Doe",
	}, "secret", "HS256")
	if err != nil {
		log.Fatalf("could not encode token: %v", err)
	}
	_ = token
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
}

func resource(w http.ResponseWriter, r *http.Request) {
	// TODO ...
}
