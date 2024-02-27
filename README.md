# go-jwt-tools

Golang authorization http middleware for Authorization headers

These are the important features on this package:

- `User`: The object representation of who is doing the request and its permissions.

```go 
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

type Permissions interface {
	// CheckPermission returns the given Permissions for a given product and object. Returns the special Permissions applied on that object if any, and a boolean indicating if the user has the requested Permission. NOTE: Special Permissions returned can be filtered by the specials argument).
	CheckPermission(product string, object string, permission Permission, specials ...string) ([]string, bool)
	// ValidGroups returns all the groups and its Permissions that have any Permission for the given product and object.
	ValidGroups(product string, object string, permission Permission) map[string]struct{}
	// Returns all groups of a given type
	GetGroups(groupType string) []string
	// GetAllGroups returns the group hierarchy
	GetAllGroups() map[string]struct{}
	// GetGroupsByTypes returns a map indexed by group types, containing the list of groups of that type
	GetGroupsByTypes() map[string][]string
	// GetParents returns all the parent groups of a given group.
	GetParents(group string) map[string]interface{}
}

```

- `Parser`: Who knows how to transform an authorization header into an User, this is what the different authorization techniques should implement.

```go
type Parser interface {
	Parse(authHeader string) (*User, error)
}
```
- `Middleware`: A middleware is a wrap to a **http.Handler**

```go
func(h http.Handler) http.Handler
```

This concrete middleware requires a **Parser** that will be used to transform the Authorization header from **http.Request** into an **User**, and then put in the request context. To retrieve the **User** from the context, use the function:

```go
func UserFromContext(ctx context.Context) (*User, bool)
```

### Implementations

Implementation details can be found in these subpackages:

#### jwt

In this implementation, the Authorization headers must be **Bearers** (auth0 or other). 

The jwt parser can be instantiated from:

```go
type ParserConfig struct {
	ClientConfig       *ClientConfig `json:"client_config"`
	PublicKey          string        `json:"public_key_str"`
	AdminGroup         string        `json:"admin_group"`
	DummyToken         string        `json:"dummy_token"`
	Expiration         string        `json:"exp"`
	IsExpired          bool          `json:"is_expired"`
	MemberIDClaim      []string      `json:"member_id_claim"`
	GroupsClaim        []string      `json:"groups_claim"`
	FetchNeededClaim   []string      `json:"fetch_needed_claim"`
	TGXMemberClaim     []string      `json:"tgx_member_claim"`
	OrganizationsClaim []string      `json:"organizations_claim"`
	IgnoreExpiration   bool          `json:"ignore_expiration"`
	DisableFetchNeeded bool          `json:"disable_fetch_needed"`
}
```

#### cache

Has a Parser implementation that uses a [lru cache](https://github.com/travelgateX/go-cache) where the key is the Authorization header and the value is the User, it basically caches the Parsing process. Recommended when the parsing process is heavy.

### How to use

First instance the desired Parser implementation, for instance, if we want our endpoint to understand of jwt bearers:

```go
jwtParserConfig := jwt.ParserConfig{
		AdminGroup:       "admin",
		PublicKey:        "myKey",
		DummyToken:       "dummyToken",
		IgnoreExpiration: false,
		GroupsClaim:      []string{"https://xtg.com/iam", "https://travelgatex.com/iam"},
		MemberIDClaim:    []string{"https://xtg.com/member_id", "https://travelgatex.com/member_id"},
		IgnoreExpiration:   false,
		ClientConfig:       &jwt.ClientConfig{FetcherURL: string(authFetcherURL.Data)},
		FetchNeededClaim:   []string{"https://xtg.com/fetch_needed", "https://travelgatex.com/fetch_needed"},
		TGXMemberClaim:     []string{"https://xtg.com/is_tgx", "https://travelgatex.com/is_tgx"},
		OrganizationsClaim: []string{"https://xtg.com/org", "https://travelgatex.com/org"},
	}

jwtParser := jwt.NewParser(jwtParserConfig)
```

Then, if we want a cache layer to cache the jwt parsing process we can wrap the **jwtParser** with a cache parser:

```go
size := 100
ttl := time.Minute
c, _ := cache.New(size, ttl)
cacheParser := authcache.NewParser(jwtParser, c)
```

Now that we have built the desired parser **cacheParser**, instance the middleware and use it to wrap your service handler:

```go
middleware := authorization.Middleware(cacheParser)

var serviceHandler http.Handler // omitted code
serviceHandler = middleware(serviceHandler)

http.Handle("/foo", serviceHandler)
```

Remember that in order to obtain the **User**, you must retrieve it from the context.Context using the func **UserFromContext**
