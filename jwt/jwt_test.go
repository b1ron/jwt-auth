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

func TestDecode(t *testing.T) {
	claims, err := Decode(expected)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(claims.raw) != `{"iat":1516239022,"name":"John Doe","sub":"1234567890"}` {
		t.Errorf("expected %s, got %s", `{"iat":1516239022,"name":"John Doe","sub":"1234567890"}`, string(claims.raw))
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
	parts := strings.Split(token, ".")
	// modify the token i.e. tamper with the payload to invalidate the signature
	invalidToken := strings.Join([]string{parts[0], "xxxxxxxxxx", parts[2]}, ".")
	err = Validate(invalidToken, "secret")
	if err == nil {
		t.Error("expected signature to be invalid")
	}
	validToken := strings.Join([]string{parts[0], parts[1], parts[2]}, ".")
	err = Validate(validToken, "secret")
	if err != nil {
		t.Error("expected signature to be valid")
	}
}
