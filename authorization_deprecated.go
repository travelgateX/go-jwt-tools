package authorization

import (
	"fmt"
	"net/http"
	"strings"

	"context"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/form3tech-oss/jwt-go"
)

type Config struct {
	PublicKeyStr     string   `json:"public_key_str"`
	AdminGroup       string   `json:"admin_group"`
	MemberIDClaim    []string `json:"member_id_claim"`
	GroupsClaim      []string `json:"groups_claim"`
	DummyToken       string   `json:"dummy_token"`
	IgnoreExpiration bool     `json:"ignore_expiration"`
}

// Define a type in order to make it unique and avoid conflicts
type key string

// ContextKey contains the key where the PermissionTree will be stored
const ContextKey = key("permission")
const AuthKey = key("authorization")

func Authorize(inner http.Handler, c Config) http.Handler {
	inner = preparePermissions(inner, c)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler := inner
		authorizePayload := strings.Split(r.Header.Get("Authorization"), " ")
		authorizeType := authorizePayload[0]
		r = r.WithContext(context.WithValue(r.Context(), AuthKey, authorizeType))
		switch authorizeType {
		case "Bearer":
			if authorizePayload[1] != c.DummyToken {
				handler = authorizationBearer(inner, c.PublicKeyStr)
			}
			handler.ServeHTTP(w, r)
		default:
			fmt.Fprintln(w, "Invalid authorization header.")
		}
	})
}

func authorizationBearer(inner http.Handler, publicKey string) http.Handler {
	jwt := jwtmiddleware.New(jwtmiddleware.Options{ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		var result interface{}
		result, _ = jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
		return result, nil
	}, SigningMethod: jwt.SigningMethodRS256})
	return jwt.Handler(inner)
}

func preparePermissions(inner http.Handler, c Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizePayload := r.Header.Get("Authorization")
		authorizeSplit := strings.Split(authorizePayload, " ")
		authorizeType := authorizeSplit[0]
		switch authorizeType {
		case "Bearer":
			if authorizeSplit[1] != c.DummyToken {
				claims := r.Context().Value("user").(*jwt.Token).Claims.(jwt.MapClaims)
				var groups []interface{}
				for _, g := range c.GroupsClaim {
					groups = append(groups, claims[g])
				}
				var memberId []string
				for _, m := range c.MemberIDClaim {
					if claims[m] != nil {
						memberId = append(memberId, claims[m].(string))
					}
				}
				if len(groups) > 0 {
					x := NewPermissionTable(groups, memberId, authorizePayload, c.AdminGroup)
					r = r.WithContext(context.WithValue(r.Context(), ContextKey, x))
					inner.ServeHTTP(w, r)
				} else {
					fmt.Fprintln(w, "Your token doesn't contain any group.")
				}
			} else {
				newctx := context.WithValue(r.Context(), "group", "TEST_GROUP")
				r = r.WithContext(newctx)
				inner.ServeHTTP(w, r)
			}
		default:
			fmt.Fprintln(w, "Invalid authorization header.")
		}
	})
}

// PermissionTableFromContext returns the permissionTable stored in a context
func PermissionTableFromContext(ctx context.Context) (*PermissionTable, bool) {
	val, ok := ctx.Value(ContextKey).(*PermissionTable)
	return val, ok
}
