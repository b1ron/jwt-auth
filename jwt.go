// package jwt implements the JSON Web Token (JWT) standard as per rfc7519

package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
)

type JOSEHeader struct {
	typ string
	alg string
}

type JWTClaimsSet struct {
	iss   string
	sub   string
	aud   string
	exp   int64
	nbf   int64
	iat   string
	jti   string
	roles []string
}

type payload struct{}

var supportedAlgorithms = []string{"HS256", "HS512"}

func newJWT() string {
	buf := bytes.NewBuffer(nil)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	h := JOSEHeader{}
	h.typ = "JWT"
	h.alg = "HS256"
	encoder.Write([]byte(h.typ))
	encoder.Write([]byte(h.alg))
	buf.WriteRune('.') // concat each encoded part with a period '.'
	j := JWTClaimsSet{
		iss:   "issuer",
		sub:   "subject",
		aud:   "audience",
		exp:   0,
		nbf:   0,
		iat:   "issuedAt",
		jti:   "jwtID",
		roles: []string{"ROLE_USER"},
	}
	encoder.Write([]byte(j.iss))
	encoder.Write([]byte(j.sub))
	encoder.Write([]byte(j.aud))
	encoder.Write([]byte(strconv.FormatInt(j.exp, 10)))
	encoder.Write([]byte(strconv.FormatInt(j.nbf, 10)))
	encoder.Write([]byte(j.iat))
	encoder.Write([]byte(j.jti))
	for _, role := range j.roles {
		encoder.Write([]byte(role))
	}
	buf.WriteRune('.')
	signedJWT := signJWT(buf.Bytes())
	encoder.Close()
	return signedJWT
}

func signJWT(jwt []byte) string {
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
	return string(h.Sum(nil))
}
