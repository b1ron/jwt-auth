// package jwt implements the JSON Web Token (JWT) standard as per rfc7519

package jwt

import (
	"bytes"
	"encoding/base64"
	"strconv"
)

type JOSEHeader struct {
	typ string
	alg string
}

type JWTClaimsSet struct {
	iss  string
	sub  string
	aud  string
	exp  int64
	nbf  int64
	iat  string
	jti  string
	role string
}

type payload struct {
}

var supportedAlgorithms = []string{"HS256", "HS512"}

func newJWT() string {
	buf := bytes.NewBuffer(nil)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	h := JOSEHeader{}
	h.typ = "JWS"
	h.alg = "HS256"
	encoder.Write([]byte(h.typ))
	encoder.Write([]byte(h.alg))
	j := JWTClaimsSet{
		iss:  "issuer",
		sub:  "subject",
		aud:  "audience",
		exp:  0,
		nbf:  0,
		iat:  "issuedAt",
		jti:  "jwtID",
		role: "READ",
	}
	encoder.Write([]byte(j.iss))
	encoder.Write([]byte(j.sub))
	encoder.Write([]byte(j.aud))
	encoder.Write([]byte(strconv.Itoa(int(j.exp))))
	encoder.Write([]byte(strconv.Itoa(int(j.nbf))))
	encoder.Write([]byte(j.iat))
	encoder.Write([]byte(j.jti))
	encoder.Write([]byte(j.role))
	encoder.Close()
	return buf.String()
}
