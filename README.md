# go-jwt-tools

Golang authorization middleware for JWT tokens. JWT tools (auth0 or other)

There are two important features on this package:
- `authorization.go` contains a middleware that processes a token and checks its validity (authorizes).
- `permissions.go` handles the "PermissionsTable" struct which contains the information of the JWT token conveniently adapted, and a set of functions to use it.

## MiddleWare
### How to use

We just need to add a call to the function **`Authorize`** on all the calls that must be authorized (in this case, we use a **`Route`** struct that contains the `HandlerFunc` and a `bool` indicating if that `Route` must be authorized). `Authorize` expects the handler function to wrap and a configuration object of type **`Config`** (defined on `authorization.go` file).

**IMPORTANT**: The middleware stores the `PermissionTable` item on the [context](https://golang.org/pkg/context/), under the key defined on the `ContextKey` constant.

### Example of use

```golang
func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	// Prepare Authorization configuration
        c := authorization.Config{
		PublicKeyStr: "myKey",
		AdminGroup: "admin",
		IgnoreExpiration: false,
		TokenDummy: "TokenDummy",
	}

	for _, route := range routes {
		var handler http.Handler

		// Add Authorization or not
		if route.Authorization {
			handler = authorization.Authorize(route.HandlerFunc(), c)
		
		} else {
			handler = route.HandlerFunc()
		}

		handler = handlers.CompressHandler(util.CompressGzip(handler, route.GzipMandatory))

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	return router
}
```

After this, out `PermissionTable` will be stored on the `ContextKey` key of the context:

```golang
permissions := ctx.Value(authorization.ContextKey).(*authorization.PermissionTable)
``` 


## Permissions


```golang

type Permissions interface {
	// CheckPermission returns the given permissions for a given product and object. Returns the special permissions applied on that object if any, and a boolean indicating if the user has the requested permission. NOTE: Special permissions returned can be filtered by the specials argument).
	CheckPermission(product string, object string, per string, specials ...string) ([]string, bool)
	// ValidGroups returns all the groups and its permissions that have any permission for the given product and object.
	ValidGroups(product string, object string, per string) map[string]bool
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
