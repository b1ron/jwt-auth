package jwt

import (
	"strings"
	"testing"
)

// from https://jwt.io/#debugger-io?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.wGeH-9KZwRmaddca1QmnSRZgJRt5AgGydEPFpLsZfpw
var expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.wGeH-9KZwRmaddca1QmnSRZgJRt5AgGydEPFpLsZfpw"

func TestEncode(t *testing.T) {
	claims := map[string]interface{}{
		"iat":  1516239022,
		"name": "John Doe",
		"sub":  "1234567890",
	}
	token, err := Encode(claims, "secret", "HS256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != expected {
		t.Errorf("expected %s, got %s", expected, token)
	}
}

func TestValidate(t *testing.T) {
	claims := map[string]interface{}{
		"iat":  1516239022,
		"name": "John Doe",
		"sub":  "1234567890",
	}
	token, err := Encode(claims, "secret", "HS256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// modify the token i.e. tamper with the payload to invalidate the signature
	parts := strings.Split(token, ".")
	verify := Validate(strings.Join([]string{parts[0], "xxxxxxxxxx", parts[2]}, "."), "secret")
	if verify {
		t.Error("expected token to be invalid")
	}
	verify = Validate(strings.Join([]string{parts[0], parts[1], parts[2]}, "."), "secret")
	if !verify {
		t.Error("expected token to be valid")
	}
}
