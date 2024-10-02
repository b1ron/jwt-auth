package jwt

import (
	"testing"
)

func TestEncode(t *testing.T) {
	// from https://jwt.io/#debugger-io?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.wGeH-9KZwRmaddca1QmnSRZgJRt5AgGydEPFpLsZfpw
	expected := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.wGeH-9KZwRmaddca1QmnSRZgJRt5AgGydEPFpLsZfpw"
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
