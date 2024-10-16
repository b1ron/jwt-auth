package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/b1ron/jwt-auth/internal/hashutil"
	"github.com/b1ron/jwt-auth/internal/jwt"
)

// NOTE the server is not working as described in the below comments because it's a WIP.
// server is a simple HTTP server that uses JWT for authentication. It also acts as a session manager.
// It has two endpoints:
// - /login: expects a POST request with a JSON body containing a "username" and "password".
//  If the credentials are valid, it responds with a JWT token. The secret is used to sign the token. A refresh token is set as a cookie.
// - /resource: expects a GET request with a "Authorization" header containing a JWT token.
//  If the token is valid, it responds with a JSON object containing the requested resource.

type session struct {
	username string
	secret   string
	hash     string // hash of the user credentials
	salt     string
}

// store is a simple in-memory session store where the key is the username and the value is a session.
type store struct {
	mu       sync.Mutex // guards sessions
	sessions map[string]*session
}

func (s *store) get(name string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[name]
}

func (s *store) set(name, secret, hash, salt string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[name] = &session{
		username: name,
		secret:   secret,
		hash:     hash,
		salt:     salt,
	}
}

func main() {
	// make the session store for the handlers first
	store := &store{
		sessions: make(map[string]*session),
	}
	f, err := os.ReadFile("secret.txt")
	if err != nil {
		log.Fatalf("could not read secret: %v", err)
	}
	secret := strings.Trim(string(f), "\n")
	salt := hashutil.GenerateNonce()
	hash := hashutil.GenerateHash("password", salt)

	// set the initial user
	store.set("init", secret, hash, salt)

	f, err = os.ReadFile("users.txt")
	if err != nil {
		log.Fatalf("could not read users: %v", err)
	}
	user := strings.Trim(string(f), "\n")
	username, password := strings.Split(user, ":")[0], strings.Split(user, ":")[1]
	salt = hashutil.GenerateNonce()
	hash = hashutil.GenerateHash(password, salt)

	// set the user from the users file
	store.set(username, secret, hash, salt)

	http.HandleFunc("/login", store.login)
	http.HandleFunc("/resource", store.resource)
	log.Fatal(http.ListenAndServe("localhost:8000", nil))
}

func (s *store) login(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("username")
	secret := s.get("init").secret
	token, err := jwt.Encode(map[string]interface{}{
		"iat":  time.Now().Unix(),
		"name": name,
		"exp":  time.Now().Add(time.Second * 5).Unix(),
	}, secret, "HS256")
	if err != nil {
		fmt.Fprintf(w, err.Error(), http.StatusUnauthorized)
	}

	if s.get(name) == nil {
		fmt.Fprintf(w, "could not find user %s %d", name, http.StatusUnauthorized)
		return
	}

	hash := s.get(name).hash
	salt := s.get(name).salt
	if !hashutil.IsValid(r.FormValue("password"), salt, hash) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "refresh-token", Value: token})
	w.WriteHeader(http.StatusOK)
}

func (s *store) resource(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	token = strings.TrimPrefix(token, "Bearer ")
	decodedClaims, err := jwt.Decode(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	claimsM := decodedClaims.Map()
	name := claimsM["name"].(string)
	secret := s.get(name).secret
	if err := jwt.Validate(token, secret); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	now := float64(time.Now().Unix())
	if now-claimsM["exp"].(float64) > 0 {
		http.Error(w, "token expired", http.StatusUnauthorized)
		return
	}

	claims, err := json.Marshal(claimsM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// write claims to the response for now
	fmt.Fprintf(w, "%s", claims)
}
