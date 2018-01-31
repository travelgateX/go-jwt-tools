package authorization

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
)

type Config struct {
	PublicKeyStr     string `json:"publicKeyStr"`
	AdminGroup       string `json:"admin_group"`
	IgnoreExpiration bool   `json:"ignore_expiration"`
}

// Define a type in order to make it unique and avoid conflicts
type key string

// ContextKey contains the key where the PermissionTree will be stored
const ContextField = key("permission")

const tokenDummy = "XXX"

func Authorize(inner http.Handler, c Config) http.Handler {
	inner = preparePermissions(inner, c.AdminGroup)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler := inner
		authorizePayload := strings.Split(r.Header.Get("Authorization"), " ")
		authorizeType := authorizePayload[0]
		context.Set(r, "authorization", authorizeType)
		switch authorizeType {
		case "Bearer":
			if authorizePayload[1] != tokenDummy {
				handler = authorizationBearer(inner, c.AdminGroup)
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

func preparePermissions(inner http.Handler, adminGroup string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizePayload := strings.Split(r.Header.Get("Authorization"), " ")
		authorizeType := authorizePayload[0]
		switch authorizeType {
		case "Bearer":
			if authorizePayload[1] != tokenDummy {
				claims := r.Context().Value("user").(*jwt.Token).Claims.(jwt.MapClaims)
				aux_groups := claims["https://xtg.com/iam"]
				if aux_groups != nil {
					groups := claims["https://xtg.com/iam"].([]interface{})
					if len(groups) > 0 {
						x := NewPermissionTable(groups, adminGroup)
						context.Set(r, ContextField, x)
						inner.ServeHTTP(w, r)
					} else {
						fmt.Fprintln(w, "Your user hasn't got any company.")
					}
				} else {
					fmt.Fprintln(w, "Your token doesn't contain any company.")
				}
			} else {
				context.Set(r, "company", "TEST_COMPANY")
				inner.ServeHTTP(w, r)
			}
		default:
			fmt.Fprintln(w, "Invalid authorization header.")
		}
	})
}
