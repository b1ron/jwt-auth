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
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Aud   string   `json:"aud"`
	Exp   int64    `json:"exp"`
	Nbf   int64    `json:"nbf"`
	Iat   string   `json:"iat"`
	Jti   string   `json:"jti"`
	Roles []string `json:"roles"`
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
	n := buf.Len()

	j := JWTClaimsSet{
		Iss:   "issuer",
		Sub:   "subject",
		Roles: []string{"ROLE_USER"},
	}
	encoder.Encode(j)
	claims := base64.RawURLEncoding.EncodeToString(buf.Bytes()[n:]) // FIXME: access the offset of the buffer from the last write

	signedJWT := signJWT(buf.Bytes())
	signature := base64.RawURLEncoding.EncodeToString(signedJWT)
	// concat each encoded part with a period '.' separator
	return header + "." + claims + "." + signature
}

// FIXME: unsure if this is the correct way to sign a JWT
func signJWT(jwt []byte) []byte {
	secret := make([]byte, 64)
	rand.Read(secret)
	h := hmac.New(sha256.New, secret)
	parts := bytes.Split(jwt, []byte("."))
	for i, part := range parts {
		h.Write(part)
		if i == 0 {
			h.Write([]byte("."))
		}
	}
	return h.Sum(nil)
}
