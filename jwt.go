// package jwt implements the JSON Web Token (JWT) standard as per rfc7519

package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type JOSEHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

type JWTClaimsSet struct {
	Iss string `json:"iss"`
	Exp int64  `json:"exp"`
	URL bool   `json:"http://example.com/is_root"`
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
		Iss: "joe",
		Exp: 1300819380,
		URL: true,
	}
	encoder.Encode(j)
	claims := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	buf.Reset()

	signedJWT := signJWT(header, claims)
	signature := base64.RawURLEncoding.EncodeToString(signedJWT)
	// concat each encoded part with a period '.' separator
	return header + "." + claims + "." + signature
}

// TODO read https://www.rfc-editor.org/rfc/rfc7515.txt
func signJWT(parts ...string) []byte {
	secret := make([]byte, 64)
	rand.Read(secret)
	h := hmac.New(sha256.New, secret)
	for _, part := range parts {
		h.Write([]byte(part))
	}
	return h.Sum(nil)
}
