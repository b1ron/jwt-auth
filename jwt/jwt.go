// package jwt implements the JSON Web Token (JWT) standard as per rfc7519, sort of...
package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
)

// Claims represents the JWT claims set.
type Claims struct {
	raw []byte
}

// headerJOSE represents the JOSE (JSON Object Signing and Encryption) header.
type headerJOSE struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

// hashFunc is a factory function that returns a hash.Hash.
type hashFunc func() hash.Hash

var HS256 hashFunc = func() hash.Hash { return sha256.New() }

var HS512 hashFunc = func() hash.Hash { return sha512.New() }

var supportedAlgorithms = map[string]hashFunc{
	"HS256": HS256,
	"HS512": HS512,
}

// Encode generates a JWT token with the given claims, secret and algorithm.
func Encode(claims map[string]any, secret, algorithm string) (string, error) {
	var hashFunc hashFunc
	if v, ok := supportedAlgorithms[algorithm]; ok {
		hashFunc = v
	} else {
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
	signed := sign(secret, hashFunc, h, c)
	signature := base64.RawURLEncoding.EncodeToString(signed)
	// concat each encoded part with a period '.' separator
	return h + "." + c + "." + signature, nil
}

// Decode decodes the JWT token and returns the claims.
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

// Validate validates the JWS signature against the given secret.
func Validate(token string, secret string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var h headerJOSE
	if err := json.Unmarshal(header, &h); err != nil {
		return err
	}
	if h.Typ != "JWT" {
		return fmt.Errorf("invalid token type")
	}
	hashFunc := supportedAlgorithms[h.Alg]
	validSignature := sign(secret, hashFunc, parts[0], parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	// verify signature by byte comparison
	if !bytes.Equal(signature, validSignature) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// sign computes the HMAC using the given hashFunc type and returns the JWS signature.
func sign(key string, hashFunc hashFunc, parts ...string) []byte {
	h := hmac.New(hashFunc, []byte(key))
	h.Write([]byte(parts[0] + "." + parts[1]))
	return h.Sum(nil)
}
