package authorization

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestIsNotApiKey(t *testing.T) {
	newUser := func(authHeader string) *User {
		return &User{
			Permissions:        nil,
			AuthorizationValue: authHeader,
			UserID:             []string{"twinki@winki.com"},
			IsDummy:            false,
		}
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

	isApiKey := IsApikeyFromContext(nextHandler.req.Context())
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, false, isApiKey)
}

func TestIsTGXMember(t *testing.T) {
	newUser := func(authHeader string) *User {
		return &User{
			Permissions:        nil,
			AuthorizationValue: authHeader,
			UserID:             []string{"twinki-winki-com-truki"},
			IsDummy:            false,
			TgxMember:          true,
		}
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

	IsTGXMember := IsTGXMember(nextHandler.req.Context())
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, true, IsTGXMember)
}

func TestIsNOTTGXMember(t *testing.T) {
	newUser := func(authHeader string) *User {
		return &User{
			Permissions:        nil,
			AuthorizationValue: authHeader,
			UserID:             []string{"twinki-winki-com-truki"},
			IsDummy:            false,
			TgxMember:          false,
		}
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

	IsTGXMember := IsTGXMember(nextHandler.req.Context())
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, false, IsTGXMember)
}

func TestIsApiKey(t *testing.T) {
	newUser := func(authHeader string) *User {
		return &User{
			Permissions:        nil,
			AuthorizationValue: authHeader,
			UserID:             []string{"twinki-winki-com-truki"},
			IsDummy:            false,
		}
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

	isApiKey := IsApikeyFromContext(nextHandler.req.Context())
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, true, isApiKey)
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
	req      *http.Request
	executed bool
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

func TestTGXUser(t *testing.T) {

	entitiesService := ENTITIES

	tgx_admin_service_admin := User{
		TgxMember: true,
		Orgs: []interface{}{
			[]interface{}{
				map[string]interface{}{
					"o": "tgx",
					"r": "ADMIN",
					"s": []interface{}{map[string]interface{}{
						"c": "ENTITIES",
						"r": "ADMIN",
					}},
				},
			},
		},
	}

	tgx_viewer_service_admin := User{
		TgxMember: true,
		Orgs: []interface{}{
			[]interface{}{
				map[string]interface{}{
					"o": "tgx",
					"r": "VIEWER",
					"s": []interface{}{map[string]interface{}{
						"c": "ENTITIES",
						"r": "ADMIN",
					}},
				},
			},
		},
	}

	tgx_viewer_service_viewer := User{
		TgxMember: true,
		Orgs: []interface{}{
			[]interface{}{
				map[string]interface{}{
					"o": "tgx",
					"r": "VIEWER",
					"s": []interface{}{map[string]interface{}{
						"c": "ENTITIES",
						"r": "VIEWER",
					}},
				},
			},
		},
	}

	tgx_viewer := User{
		TgxMember: true,
		Orgs: []interface{}{
			[]interface{}{
				map[string]interface{}{
					"o": "tgx",
					"r": "VIEWER",
				},
			},
		},
	}

	tgx_admin := User{
		TgxMember: true,
		Orgs: []interface{}{
			[]interface{}{
				map[string]interface{}{
					"o": "tgx",
					"r": "ADMIN",
				},
			},
		},
	}

	no_tgx_admin := User{
		TgxMember: false,
		Orgs: []interface{}{
			[]interface{}{
				map[string]interface{}{
					"o": "org1",
					"r": "ADMIN",
				},
			},
		},
	}

	if no_tgx_admin.IsTGXMemberRole(ADMIN, &entitiesService) {
		t.Errorf("Test no_tgx_admin failed: expected no tgx member")
	}
	if !tgx_admin.IsTGXMemberRole(ADMIN, &entitiesService) {
		t.Errorf("Test tgx_admin failed: expected tgx member")
	}
	if tgx_viewer.IsTGXMemberRole(ADMIN, &entitiesService) {
		t.Errorf("Test tgx_viewer failed: expected no tgx member admin")
	}
	if tgx_viewer_service_viewer.IsTGXMemberRole(ADMIN, &entitiesService) {
		t.Errorf("tgx_viewer_service_viewer tgx_viewer failed: expected no tgx member admin")
	}
	if !tgx_viewer_service_admin.IsTGXMemberRole(ADMIN, &entitiesService) {
		t.Errorf("Test tgx_viewer_service_admin failed: expected tgx member admin")
	}
	if !tgx_admin_service_admin.IsTGXMemberRole(ADMIN, &entitiesService) {
		t.Errorf("Test tgx_admin_service_admin failed: expected tgx member admin")
	}

}
func TestGetOrgs(t *testing.T) {

	entitiesService := ENTITIES

	user := User{
		Orgs: []interface{}{
			[]interface{}{
				map[string]interface{}{
					"o": "org1",
					"r": "OWNER",
					"s": []interface{}{map[string]interface{}{
						"c": "ENTITIES",
						"r": "ADMIN",
					}},
				},
				map[string]interface{}{
					"o": "org2",
					"r": "ADMIN",
				},
				map[string]interface{}{
					"o": "org3",
					"r": "EDITOR",
				},
				map[string]interface{}{
					"o": "org4",
				},
				map[string]interface{}{
					"o": "org5",
					"r": "VIEWER",
					"s": []interface{}{map[string]interface{}{
						"c": "ENTITIES",
						"r": "ADMIN",
					}},
				},
				map[string]interface{}{
					"o": "org6",
					"r": "VIEWER",
					"s": []interface{}{map[string]interface{}{
						"c": "ENTITIES",
						"r": "EDITOR",
					}},
				},
			},
		},
	}

	tests := []struct {
		name     string
		role     Role
		service  *Service
		expected []string
	}{
		{
			name:     "Test OWNER role",
			role:     OWNER,
			service:  nil,
			expected: []string{"org1"},
		},
		{
			name:     "Test ADMIN role",
			role:     ADMIN,
			service:  &entitiesService,
			expected: []string{"org1", "org2", "org5"},
		},
		{
			name:     "Test EDITOR role",
			role:     EDITOR,
			service:  &entitiesService,
			expected: []string{"org1", "org2", "org3", "org5", "org6"},
		},
		{
			name:     "Test VIEWER role",
			role:     VIEWER,
			service:  nil,
			expected: []string{"org1", "org2", "org3", "org4", "org5", "org6"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := user.GetOrgsServiceFilter(tt.role, tt.service)
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("Test %q failed: expected %v, got %v", tt.name, tt.expected, actual)
			}
		})
	}
}
