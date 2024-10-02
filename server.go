package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/b1ron/jwt-auth/jwt"
)

// server is a simple HTTP server that uses JWT for authentication. It also acts as a session manager.
// It has two endpoints:
// - /login: expects a POST request with a JSON body containing a "username" and "password".
//  If the credentials are valid, it responds with a JWT token. The secret is used to sign the token. A refresh token is set as a cookie.
// - /resource: expects a GET request with a "Authorization" header containing a JWT token.
//  If the token is valid, it responds with a JSON object containing the requested resource.

type session struct {
	token  string
	secret string
}

var store = make(map[string]*session)

func init() {
	secret, err := os.ReadFile("secret.txt")
	if err != nil {
		log.Fatalf("could not read secret: %v", err)
	}
	store["init"] = &session{
		secret: string(secret),
	}
}

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/resource", resource)
	log.Fatal(http.ListenAndServe("localhost:8000", nil))
}

func login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	token, err := jwt.Encode(map[string]interface{}{
		"iat":  time.Now().Unix(),
		"name": r.Form.Get("username"),
	}, string(store["init"].secret), "HS256")
	if err != nil {
		fmt.Fprintf(w, "could not encode token: %v", err)
	}
	store[r.Form.Get("username")] = &session{
		token: token,
	}
	http.SetCookie(w, &http.Cookie{Name: "refreshToken", Value: token})
	w.Header().Set("Authorization", token)
	w.WriteHeader(http.StatusOK)
}

func resource(w http.ResponseWriter, r *http.Request) {
	// TODO ...
}
