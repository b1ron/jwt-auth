// package util contains helper functions for generating and verifying hashes.
package util

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
)

// HashFunc is a factory function abstraction that returns a hash.Hash.
type HashFunc func() hash.Hash

var HS256 HashFunc = func() hash.Hash { return sha256.New() }

var HS512 HashFunc = func() hash.Hash { return sha512.New() }

// Sign computes the HMAC using the given HashFunc type and returns the JWS signature.
func Sign(key string, hashFunc HashFunc, parts ...string) []byte {
	h := hmac.New(hashFunc, []byte(key))
	header, payload := parts[0], parts[1]
	h.Write([]byte(header + "." + payload))
	return h.Sum(nil)
}

// GenerateHash returns a base64 encoded SHA-256 hash of the salted password.
func GenerateHash(password, salt string) string {
	h := sha256.New()
	h.Write([]byte(password + salt))
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil))
}

// VerifyHash returns true if the salted password matches the given hash.
func VerifyHash(password, salt, hash string) bool {
	// IDEA: because we don't use public-key encryption credentials are transmitted in plaintext
	// a naive attempt to further secure the password hash would be to force a user to strip out
	// the salt from the hash and then compare the salt in the session store
	return GenerateHash(password, salt) == hash
}

// GenerateNonce returns a random 16-byte nonce for the salt.
func GenerateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return string(b)
}
