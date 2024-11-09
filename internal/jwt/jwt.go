// package jwt implements the JSON Web Token (JWT) standard as per rfc7519, sort of...
package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/b1ron/jwt-auth/internal/hashutil"

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

var supportedAlgorithms = map[string]hashutil.HashFunc{
	"HS256": hashutil.HS256,
	"HS512": hashutil.HS512,
}

// Encode generates a JWT token with the given claims, secret and algorithm.
func Encode(claims map[string]any, secret, algorithm string) (string, error) {
	var hashFunc hashutil.HashFunc
	if v, ok := supportedAlgorithms[algorithm]; ok {
		hashFunc = v
	} else {
		return "", fmt.Errorf("unsupported algorithm %s", algorithm)
	}
	// encode header
	header := headerJOSE{
		Typ: "JWT",
		Alg: algorithm,
	}
	buf, err := json.Marshal(&header)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(buf)

	// ensure claims are sorted for signature hash
	keys := maps.Keys(claims)
	sort.Strings(keys)
	m := make(map[string]any)
	for _, k := range keys {
		m[k] = claims[k]
	}

	// encode payload
	buf, err = json.Marshal(m)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(buf)

	signature := hashutil.Sign(secret, hashFunc, encodedHeader, encodedPayload)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	// concat each encoded part with a period '.' separator
	return encodedHeader + "." + encodedPayload + "." + encodedSignature, nil
}

// Decode decodes the JWT token and returns the claims.
func Decode(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token")
	}

	payload := parts[1]
	decodedPayload, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	return &Claims{raw: decodedPayload}, nil
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
	header, payload, signature := parts[0], parts[1], parts[2]
	decodedHeader, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return err
	}
	var h headerJOSE
	if err := json.Unmarshal(decodedHeader, &h); err != nil {
		return err
	}
	if h.Typ != "JWT" {
		return fmt.Errorf("invalid token type")
	}
	hashFunc := supportedAlgorithms[h.Alg]

	validSignature := hashutil.Sign(secret, hashFunc, header, payload)

	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	// verify signature by byte comparison
	if !bytes.Equal(decodedSignature, validSignature) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}
