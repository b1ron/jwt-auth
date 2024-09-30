package jwt

import "testing"

// https://jwt.io/

// https://datatracker.ietf.org/doc/html/rfc7519#section-3.1

// {"typ":"JWT",
// "alg":"HS256"}

// {"iss":"joe",
// "exp":1300819380,
// "http://example.com/is_root":true}

func TestXxx(t *testing.T) {
	j := newJWT()
	t.Log(j)
}
