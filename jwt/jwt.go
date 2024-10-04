// package jwt implements the JSON Web Token (JWT) standard as per rfc7519
package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
)

// Claims represents the JWT claims.
type Claims struct {
	raw []byte
}

type headerJOSE struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

var supportedAlgorithms = map[string]struct{}{
	"HS256": {},
	// "HS384": {},
	// "HS512": {},
}

// Encode generates a JWT token with the given claims, secret and algorithm.
func Encode(claims map[string]any, secret, algorithm string) (string, error) {
	if _, ok := supportedAlgorithms[algorithm]; !ok {
		return "", fmt.Errorf("unsupported algorithm %s", algorithm)
	}
	header := headerJOSE{
		Typ: "JWT",
		Alg: algorithm,
	}
	buf, err := json.Marshal(&header)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(buf)
	// ensure claims are sorted for signature hash
	keys := maps.Keys(claims)
	sort.Strings(keys)
	m := make(map[string]any)
	for _, k := range keys {
		m[k] = claims[k]
	}
	buf, err = json.Marshal(m)
	if err != nil {
		return "", err
	}
	c := base64.RawURLEncoding.EncodeToString(buf)
	signed := sign(secret, h, c)
	signature := base64.RawURLEncoding.EncodeToString(signed)
	// concat each encoded part with a period '.' separator
	return h + "." + c + "." + signature, nil
}

// Decode decodes a JWT token and returns the claims.
func Decode(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token")
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	c := &Claims{}
	c.raw = claims
	return c, err
}

// Map returns the claims as a map.
func (c *Claims) Map() map[string]any {
	m := make(map[string]any)
	json.Unmarshal(c.raw, &m)
	return m
}

// IsValid validates the JWS signature against the given secret.
func IsValid(token string, secret string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var h headerJOSE
	if err := json.Unmarshal(header, &h); err != nil {
		return false
	}
	if h.Typ != "JWT" {
		return false
	}
	if _, ok := supportedAlgorithms[h.Alg]; !ok {
		return false
	}
	validSignature := sign(secret, parts[0], parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	// verify signature by byte comparison
	return bytes.Equal(signature, validSignature)
}

// sign computes the HMAC and returns the JWS signature.
func sign(key string, parts ...string) []byte {
	// TODO allow for other algorithms
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(parts[0] + "." + parts[1]))
	return h.Sum(nil)
}
