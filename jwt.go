// package jwt implements the JSON Web Token (JWT) standard as per rfc7519

package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type JOSEHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

type Claims struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
	Iat  int64  `json:"iat"`
}

type payload struct{}

var supportedAlgorithms = []string{"HS256", "HS512"}

func Encode(claims Claims, secret string, algorithm string) string {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	h := JOSEHeader{
		Typ: "JWT",
		Alg: algorithm,
	}
	encoder.Encode(h)
	header := base64.RawURLEncoding.EncodeToString(buf.Bytes()[0 : buf.Len()-1])
	buf.Reset()

	encoder.Encode(claims)
	cs := base64.RawURLEncoding.EncodeToString(buf.Bytes()[0 : buf.Len()-1])
	buf.Reset()

	signed := sign([]byte(secret), header, cs)
	signature := base64.RawURLEncoding.EncodeToString(signed)
	// concat each encoded part with a period '.' separator
	return header + "." + cs + "." + signature
}

func sign(key []byte, parts ...string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(parts[0] + "." + parts[1]))
	return h.Sum(nil)
}
