package middleware

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// BasicAuth is a simple auth middleware, pass handler and a string in the format of `user:password`
// it will short-circuit on unathorized
// based off: https://gist.github.com/sambengtson/bc9f76331065f09e953f
func BasicAuth(next http.Handler, authStr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		if len(auth) != 2 || auth[0] != "Basic" {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		payload, _ := base64.StdEncoding.DecodeString(auth[1])
		if string(payload) != authStr {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
