// package jwt implements the JSON Web Token (JWT) standard as per rfc7519

package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

type JOSEHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

type JWTClaimsSet struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
	Iat  int64  `json:"iat"`
}

type payload struct{}

var supportedAlgorithms = []string{"HS256", "HS512"}

func newJWT() string {
	buf := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(buf)
	h := JOSEHeader{}
	h.Typ = "JWT"
	h.Alg = "HS256"
	encoder.Encode(h)
	header := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	j := JWTClaimsSet{
		Sub:  "subject",
		Name: "Bob",
		Iat:  time.Now().Unix(),
	}
	encoder.Encode(j)
	claims := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	signedJWT := signJWT(header, claims)
	signature := base64.RawURLEncoding.EncodeToString(signedJWT)
	// concat each encoded part with a period '.' separator
	return header + "." + claims + "." + signature
}

func signJWT(parts ...string) []byte {
	secret := make([]byte, 64)
	rand.Read(secret)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(parts[0] + "." + parts[1]))
	return h.Sum(nil)
}
