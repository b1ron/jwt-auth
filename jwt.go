// package jwt implements the JSON Web Token (JWT) standard as per rfc7519
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"golang.org/x/exp/maps"
)

type headerJOSE struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

var supportedAlgorithms = map[string]struct{}{
	"HS256": {},
	// "HS384": {},
	// "HS512": {},
}

func Encode(claims map[string]any, secret string, algorithm string) (string, error) {
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
	signed := sign([]byte(secret), h, c)
	signature := base64.RawURLEncoding.EncodeToString(signed)
	// concat each encoded part with a period '.' separator
	return h + "." + c + "." + signature, nil
}

func sign(key []byte, parts ...string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(parts[0] + "." + parts[1]))
	return h.Sum(nil)
}
