package authorization

import (
	"fmt"
	"net/http"

	"context"
)

// User is a parsed Authorization header
type User struct {
	// AuthorizationValue is the auth header value with which a user was created
	AuthorizationValue string
	IsDummy            bool
	Permissions        Permissions
}

// Parser creates a User from an authorization header
type Parser interface {
	Parse(authHeader string) (*User, error)
}

// Middleware creates a User from a Parser and puts it in the request context
// which can be later obtained by calling to UserFromContext()
// Errors returned from Parser are printed to the response body
func Middleware(p Parser) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			pt, err := p.Parse(authHeader)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), activeUser, pt)
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserFromContext returns the User stored in a context
func UserFromContext(ctx context.Context) (*User, bool) {
	val, ok := ctx.Value(activeUser).(*User)
	return val, ok
}

type contextKey struct{}

var activeUser = contextKey{}
