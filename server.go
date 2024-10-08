package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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
type store struct {
	sessions map[string]*session
}

func main() {
	// make the session store for the handlers
	store := &store{
		sessions: make(map[string]*session),
	}
	f, err := os.ReadFile("secret.txt")
	if err != nil {
		log.Fatalf("could not read secret: %v", err)
	}
	secret := strings.Trim(string(f), "\n")
	store.sessions["init"] = &session{
		secret: secret,
	}
	http.HandleFunc("/login", store.login)
	http.HandleFunc("/resource", store.resource)
	log.Fatal(http.ListenAndServe("localhost:8000", nil))
}

func (s *store) login(w http.ResponseWriter, r *http.Request) {
	token, err := jwt.Encode(map[string]interface{}{
		"iat":  time.Now().Unix(),
		"name": r.FormValue("username"),
	}, s.sessions["init"].secret, "HS256")
	if err != nil {
		fmt.Fprintf(w, "could not encode token: %v", err)
	}
	s.sessions[r.FormValue("username")] = &session{
		token:  token,
		secret: s.sessions["init"].secret,
	}
	http.SetCookie(w, &http.Cookie{Name: "refreshToken", Value: token})
	w.WriteHeader(http.StatusOK)
}

func (s *store) resource(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	token = strings.TrimPrefix(token, "Bearer ")
	claims, err := jwt.Decode(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	claimsM := claims.Map()
	username := claimsM["name"].(string)
	if err := jwt.Validate(token, s.sessions[username].secret); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	fmt.Fprint(w, claims, http.StatusOK)
}
