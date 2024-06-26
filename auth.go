package authorization

import (
	"net/http"
	"regexp"

	"context"
)

// User is a parsed Authorization header
type User struct {
	Permissions        Permissions
	AuthorizationValue string
	UserID             []string
	Orgs               []interface{}
	Expiration         float64
	IsExpired          bool
	IsDummy            bool
	TgxMember          bool
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
				http.Error(w, errMessageNoAuthorizationHeader, http.StatusUnauthorized)
				return
			}

			u, err := p.Parse(authHeader)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			ctx := ContextWithUser(r.Context(), u)
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

const errMessageNoAuthorizationHeader string = "Authorization header required"

// UserFromContext returns the User stored in a context
func UserFromContext(ctx context.Context) (*User, bool) {
	val, ok := ctx.Value(activeUser).(*User)
	return val, ok
}

func IsApikeyFromContext(ctx context.Context) bool {
	val, _ := ctx.Value(activeUser).(*User)
	return !isValidEmail(val.UserID[0])
}

func IsTGXMember(ctx context.Context) bool {
	val, _ := ctx.Value(activeUser).(*User)
	return val.IsTGXMember()
}

func (u User) IsTGXMember() bool {
	return u.TgxMember
}
func GetOrgsServiceFilter(ctx context.Context, role Role, service Service) []string {
	user, _ := ctx.Value(activeUser).(*User)
	return user.GetOrgsServiceFilter(role, &service)
}

func HasRoleInOrg(ctx context.Context, org string, role Role, service *Service) bool {
	user, _ := ctx.Value(activeUser).(*User)
	orgsBearer := user.GetOrgsServiceFilter(role, service)

	return Contains(orgsBearer, org)

}

func GetOrgs(ctx context.Context, role Role) []string {
	user, _ := ctx.Value(activeUser).(*User)
	return user.GetOrgs(role)
}

func (u User) GetOrgs(role Role) []string {
	return u.GetOrgsServiceFilter(role, nil)
}

func (u User) GetOrgsServiceFilter(role Role, service *Service) []string {
	orgCodes := []string{}

	if len(u.Orgs) == 0 {
		return orgCodes
	}

	for _, org := range u.Orgs[0].([]interface{}) {
		orgRole, orgName := extractOrgInfo(org, service)

		if orgRole >= role {
			if orgName != "" {
				orgCodes = append(orgCodes, orgName)
			}
		}
	}
	return orgCodes
}

func IsTGXMemberRole(ctx context.Context, role Role, service *Service) bool {

	user, _ := ctx.Value(activeUser).(*User)
	return user.IsTGXMemberRole(role, service)

}
func (u User) IsTGXMemberRole(role Role, service *Service) bool {
	if !u.IsTGXMember() {
		return false
	}

	for _, org := range u.Orgs[0].([]interface{}) {
		orgRole, orgName := extractOrgInfo(org, service)

		if orgName == ORG_TGX && orgRole >= role {
			return true
		}
	}

	return false
}

func extractOrgInfo(org interface{}, service *Service) (Role, string) {
	if orgMap, ok := org.(map[string]interface{}); ok {
		orgRole := VIEWER
		if orgString, ok := orgMap["r"].(string); ok {
			orgRole = GetRoleFromString(orgString)
		}
		if service != nil {
			orgRole = getServiceRole(*service, orgMap, orgRole)
		}
		if orgName, ok := orgMap["o"].(string); ok {
			return orgRole, orgName
		}
	}
	return VIEWER, ""
}
func getServiceRole(inputService Service, orgMap map[string]interface{}, orgRole Role) Role {
	services, ok := orgMap["s"].([]interface{})
	if !ok {
		return orgRole
	}

	for _, serviceInt := range services {
		serviceMap, ok := serviceInt.(map[string]interface{})
		if !ok {
			continue
		}

		if service, ok := serviceMap["c"].(string); !ok || GetServiceFromString(service) != inputService {
			continue
		}

		serviceRoleStr, ok := serviceMap["r"].(string)
		if !ok {
			continue
		}

		serviceRole := GetRoleFromString(serviceRoleStr)
		if orgRole < serviceRole {
			return serviceRole
		}
	}

	return orgRole
}

func isValidEmail(email string) bool {
	regex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	pattern := regexp.MustCompile(regex)
	return pattern.MatchString(email)
}

// ContextWithUser returns a new `context.Context` that holds a reference to the user `u`
func ContextWithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, activeUser, u)
}

// ContextCopyUser lookups for a user in a parent context a copies it into another context. Useful
// when creating background context with the parent's values
func ContextCopyUser(parent, background context.Context) context.Context {
	if u, ok := UserFromContext(parent); ok {
		background = ContextWithUser(background, u)
	}
	return background
}

func Contains(a []string, e string) bool {
	for _, x := range a {
		if x == e {
			return true
		}
	}
	return false
}

type contextKey struct{}

var activeUser = contextKey{}
