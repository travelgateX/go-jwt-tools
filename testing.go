package authorization

var _ Parser = &MockParser{}

type MockParser struct {
	ParseFn func(authHeader string) (*User, error)
}

func (p *MockParser) Parse(authHeader string) (*User, error) {
	return p.ParseFn(authHeader)
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