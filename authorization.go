package authorization

import (
	"fmt"
	"strings"
	"net/http"
    "go-jwt-tools/config"
	"github.com/gorilla/context"
	"github.com/dgrijalva/jwt-go"
	"github.com/auth0/go-jwt-middleware"
)

var tokenDummy = "XXX"

func Authorize(inner http.Handler, c config.AuthConfigData) http.Handler {
	config.LoadConfiguration(c)
	inner = preparePermissions(inner)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler := inner
		authorizePayload := strings.Split(r.Header.Get("Authorization"), " ")
		authorizeType := authorizePayload[0]
		context.Set(r, "authorization", authorizeType)
		switch authorizeType {
		case "Bearer":
			if authorizePayload[1] != tokenDummy {
				handler = authorizationBearer(inner)
			}
			handler.ServeHTTP(w, r)
		default:
			fmt.Fprintln(w, "Invalid authorization header.")
		}
	})
}

func authorizationBearer(inner http.Handler) http.Handler {
	jwt := jwtmiddleware.New(jwtmiddleware.Options{ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		var result interface{}
		result, _ = jwt.ParseRSAPublicKeyFromPEM([]byte(config.PublicKeyStr))
		return result, nil
	}, SigningMethod: jwt.SigningMethodRS256,})
	return jwt.Handler(inner)
}

func preparePermissions(inner http.Handler) http.Handler {
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
						x := NewPermissionTable()
						x.BuildPermissions(groups)
						context.Set(r, PERMISSIONS, x)
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
