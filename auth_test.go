package authorization

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMiddleware_wrongHeader tests that the handler returns error when doesn't receive authorization header
func TestMiddleware_noAuthorizationHeader(t *testing.T) {
	mw := Middleware(nil)

	req, err := http.NewRequest("POST", "", nil)
	assert.NoError(t, err)
	rec := httptest.NewRecorder()

	nextHandler := &testNextHandler{}
	mw(nextHandler.Handler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, false, nextHandler.executed)
	assert.True(t, strings.Contains(rec.Body.String(), errMessageNoAuthorizationHeader))
}

func TestMiddleware_ParserError(t *testing.T) {
	parserErr := errors.New("parse err")
	parser := &MockParser{
		ParseFn: func(authHeader string) (*User, error) {
			return nil, parserErr
		},
	}

	mw := Middleware(parser)

	req, err := http.NewRequest("POST", "", nil)
	assert.NoError(t, err)
	req.Header.Add("Authorization", "bearer")

	rec := httptest.NewRecorder()

	nextHandler := &testNextHandler{}
	mw(nextHandler.Handler()).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, false, nextHandler.executed)
	assert.True(t, strings.Contains(rec.Body.String(), parserErr.Error()))
}

func TestMiddleware_success(t *testing.T) {
	newUser := func(authHeader string) *User {
		return &User{AuthorizationValue: authHeader}
	}

	parser := &MockParser{
		ParseFn: func(authHeader string) (*User, error) {
			return newUser(authHeader), nil
		},
	}

	mw := Middleware(parser)

	req, err := http.NewRequest("POST", "", nil)
	assert.NoError(t, err)
	authHeader := "bearer WAEDWe2m3wasdlol"
	req.Header.Add("Authorization", authHeader)

	rec := httptest.NewRecorder()

	nextHandler := &testNextHandler{}
	mw(nextHandler.Handler()).ServeHTTP(rec, req)

	contextUser, found := UserFromContext(nextHandler.req.Context())
	assert.True(t, found)
	assert.Equal(t, newUser(authHeader), contextUser)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, true, nextHandler.executed)
	assert.Equal(t, "", rec.Body.String())
}

type testNextHandler struct {
	executed bool
	req      *http.Request
}

func (h *testNextHandler) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.executed = true
		h.req = r
	})
}

func TestUserFromContext_Found(t *testing.T) {
	u := &User{AuthorizationValue: "lol"}

	ctx := context.Background()
	ctx = ContextWithUser(ctx, u)

	ctxUser, ok := UserFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, u, ctxUser)
}

func TestUserFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	ctxUser, ok := UserFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, ctxUser)
}

func TestContextCopyUser(t *testing.T) {
	user := &User{}
	parent := ContextWithUser(context.Background(), user)
	background := ContextCopyUser(parent, context.Background())

	bgUser, found := UserFromContext(background)
	assert.True(t, found)
	assert.Same(t, user, bgUser)
}
