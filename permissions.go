package authorization

type Permission string

const (
	Create  Permission = "c"
	Update  Permission = "u"
	Delete  Permission = "d"
	Read    Permission = "r"
	Execute Permission = "x"
	Admin   Permission = "a"
)

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


var _ Permissions = (*MockPermission)(nil)

type MockPermission struct {
	CheckPermissionFn func(string, string, Permission, ...string) ([]string, bool)
	ValidGroupsFn func(string, string, Permission) map[string]struct{}
	GetGroupsFn func(string) []string
	GetAllGroupsFn func() map[string]struct{}
	GetGroupsByTypesFn func() map[string][]string
	GetParentsFn func(string) map[string]interface{}
}

func (m MockPermission) CheckPermission(product string, object string, permission Permission, specials ...string) ([]string, bool) {
	return m.CheckPermissionFn(product, object, permission, specials...)
}

func (m MockPermission) ValidGroups(product string, object string, permission Permission) map[string]struct{} {
	return m.ValidGroupsFn(product, object, permission)
}

func (m MockPermission) GetGroups(groupType string) []string {
	return m.GetGroupsFn(groupType)
}

func (m MockPermission) GetAllGroups() map[string]struct{} {
	return m.GetAllGroupsFn()
}

func (m MockPermission) GetGroupsByTypes() map[string][]string {
	return m.GetGroupsByTypesFn()
}

func (m MockPermission) GetParents(group string) map[string]interface{} {
	return m.GetParentsFn(group)
}
