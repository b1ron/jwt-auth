package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"jwt-auth/jwt"
)

// NOTE the server is not working as described in the below comments because it's a WIP.
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

// store is a simple in-memory session store where the key is the username and the value is a session.
var store = make(map[string]*session)

func init() {
	secret, err := os.ReadFile("secret.txt")
	if err != nil {
		log.Fatalf("could not read secret: %v", err)
	}
	// remove newline character
	secret = secret[:len(secret)-1]
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
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	claims, err := jwt.Decode(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	claimsM := claims.Map()
	username := claimsM["name"].(string)
	if err := jwt.Validate(token, store[username].secret); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "claims: %s\n", claims)
}
