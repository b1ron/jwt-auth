package jwt

import "testing"

func TestEncode(t *testing.T) {
	// from https://jwt.io/#debugger-io?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.7m6JhjDj0Blnye6rLAat5mX0BCivb9XXuEY15LprW8c
	expected := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.7m6JhjDj0Blnye6rLAat5mX0BCivb9XXuEY15LprW8c"
	claims := Claims{
		Sub:  "1234567890",
		Name: "John Doe",
		Iat:  1516239022,
	}
	token := Encode(claims, "secret", "HS256")
	if token != expected {
		t.Errorf("Expected %s, got %s", expected, token)
	}
}
