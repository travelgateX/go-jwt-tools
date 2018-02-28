package authorization

const GROUP = "c"
const PRODUCTS = "p"
const GROUPS = "g"
const ADDITIONAL = "a"
const TYPE = "t"

type permission string

const (
	Create permission = "c"
	Update permission = "u"
	Delete permission = "d"
	Read   permission = "r"
	Execute permission = "x"
)

const GROUP_PERMISSION = "grp"

type GroupTree struct {
	Type   string               // Group type
	Groups map[string]GroupTree // Group hierarchy tree
}

type PermissionTable struct {
	Permissions           map[string]map[string]map[permission]map[string]bool //Product-->object-->Permission-->Groups
	IsAdmin               bool
	Bearer				  string
	Groups                map[string]GroupTree                      // Group hierarchy tree
	AdditionalPermissions map[string]map[string]map[string]struct{} // Structure contaiing the additional permissions indexed by group code
}

func NewPermissionTable(jwt interface{}, bearer, adminGroup string) *PermissionTable {
	pt := &PermissionTable{Permissions: make(map[string]map[string]map[permission]map[string]bool), IsAdmin: false, Bearer:bearer}
	buildPermissions(pt, jwt, &map[string]GroupTree{}, adminGroup)
	return pt
}

// Recursive call for the jwt traversal
func buildPermissions(t *PermissionTable, jwt interface{}, tree *map[string]GroupTree, adminGroup string) {
	ok := true
	var groups []interface{}

	// If jwt not in correct format, return null
	if groups, ok = jwt.([]interface{}); !ok {
		return
	}

	// Iterate through each group to gather its information
	for _, grp := range groups {
		var group string
		var typ string
		var x map[string]interface{}
		var objects map[string]interface{}

		//Check if the token is not null
		if x, ok = grp.(map[string]interface{}); !ok {
			return
		}

		//The group never should be null
		if group, ok = x[GROUP].(string); !ok {
			return
		}

		if typ, ok = x[TYPE].(string); !ok {
			return
		}

		(*tree)[group] = GroupTree{Groups: map[string]GroupTree{}, Type: typ}

		// Add Additional permissions
		if x[ADDITIONAL] != nil {
			if _, ok := t.AdditionalPermissions[group]; ok {
				t.AdditionalPermissions[group] = map[string]map[string]struct{}{}
			}
			for name, permissions := range x[ADDITIONAL].(map[string]string) {
				for _, permission := range extractPermissions(permissions) {
					t.AdditionalPermissions[group][name][string(permission)] = struct{}{}
				}
			}
		}

		//Check the products
		if apis, ok := x[PRODUCTS].(map[string]interface{}); ok {
			for prod, api := range apis {
				// Register permissions for this product
				if t.Permissions[prod] == nil {
					t.Permissions[prod] = make(map[string]map[permission]map[string]bool)
				}
				p := t.Permissions[prod]

				// Iterate through objects of the api
				if objects, ok = api.(map[string]interface{}); ok {
					for object, v := range objects {
						var isAdmin bool
						p[object], isAdmin = getObjects(v, group, p[object], adminGroup)
						if isAdmin {
							t.IsAdmin = true
						}
					}
				}
			}
		}

		// Set this group tree and pass it to the recursive call that will traverse child groups
		groupTree := (*tree)[group]
		buildPermissions(t, x[GROUPS], &groupTree.Groups, adminGroup)
	}

	t.Groups = *tree
	return
}

// Checks the user permissions for a specified product and object
// Returns: Special permissions that apply (can be filtered with "args" parameter)
func (t *PermissionTable) CheckPermission(product string, object string, per permission, specials ...string) ([]string, bool) {
	// If user is admin, return true
	if t.IsAdmin {
		return nil, true
	}

	// If user has permissions for the desired product and object return them
	if t.Permissions[product] != nil && t.Permissions[product][object] != nil && t.Permissions[product][object][per] != nil {
		l := make([]string, 0, len(specials))
		// If special permissions introduced, search and store them in a slice
		// Else, store all of them in a slice
		if specials != nil {
			for _, arg := range specials {
				if _, ok := t.Permissions[product][object][per][arg]; ok {
					l = append(l, arg)
				}
			}
		} else {
			for k, _ := range t.Permissions[product][object][per] {
				l = append(l, k)
			}
		}

		// If arguments found, return them
		if len(l) > 0 {
			return l, true
		}
	}

	// Return false as the user has no permissions
	return nil, false
}

func extractPermissions(p string) []permission {
	var out []permission

	//Permission flags
	update := false
	create := false
	delete := false
	read := false

	enabled := false
	other := []permission{}

	// Iterate through permission string.
	// It will be of the form [c][r][u][d](0|1)[(aA1-9)*]
	for _, s := range p {
		switch s {
		case 99: //c
			create = true
		case 114: //r
			read = true
		case 117: //u
			update = true
		case 100: //d
			delete = true
		case 48: //0
			enabled = false
		case 49: //1
			enabled = true
		default:
			other = append(out, permission(string(s)))
		}

	}

	// Append every charater
	if enabled {
		if create {
			out = append(out, Create)
		}
		if read {
			out = append(out, Read)
		}
		if update {
			out = append(out, Update)
		}
		if delete {
			out = append(out, Delete)
		}
	}

	//Append special permissions
	if len(other) > 0 {
		out = append(out, other...)
	}

	return out
}

func getObjects(v interface{}, group string, p map[permission]map[string]bool, adminGroup string) (map[permission]map[string]bool, bool) {
	isAdmin := false

	// Register objects of the api
	if p == nil {
		p = make(map[permission]map[string]bool)
	}
	o := p

	// Iterate through each role of the object
	if roles, ok := v.([]interface{}); ok {
		for _, rol := range roles {
			// Extract role permissions and store them
			for _, permissions := range extractPermissions(rol.(string)) {
				if o[permissions] == nil {
					o[permissions] = make(map[string]bool)
				}
				if _, ok := o[permissions][group]; !ok {
					o[permissions][group] = true
				}
			}
		}

		// If Admin group and all permissions on it => User is admin
		if group == adminGroup &&
			o["c"] != nil && o["c"][adminGroup] &&
			o["r"] != nil && o["r"][adminGroup] &&
			o["u"] != nil && o["u"][adminGroup] &&
			o["d"] != nil && o["d"][adminGroup] {
			isAdmin = true
		}
	}

	return p, isAdmin
}

// Return all the groups that have a permissions into an object
func (t *PermissionTable) ValidGroups(product string, object string, per permission) map[string]bool {
	if p, ok := t.Permissions[product]; ok {
		if o, ok := p[object]; ok {
			if perm, ok := o[per]; ok {
				return perm
			}
		}
	}

	return nil
}

// Return the list of group codes
func (t *PermissionTable) GetAllGroups() map[string]struct{} {
	ret := map[string]struct{}{}
	for _, product := range t.Permissions {
		for _, object := range product {
			for _, permission := range object {
				for group, valid := range permission {
					if valid {
						ret[group] = struct{}{}
					}
				}
			}
		}
	}
	return ret
}

// Returns all groups of a given type
func (t *PermissionTable) GetGroups(groupType string) []string {
	// Call to recursive traverse function
	var groups []string
	tree := getGroups(groupType, t.Groups, groups)
	return tree
}

func getGroups(groupType string, tree map[string]GroupTree, resultGroups []string) []string {
	// Iterate through all the groups on that node
	for groupName, childs := range tree {
		// If this is the type we are lokking for, save this group
		if childs.Type == groupType {
			resultGroups = append(resultGroups, groupName)
		}
		// If group has childs, analyze them
		if childs.Groups != nil {
			resultGroups = getGroups(groupType, childs.Groups, resultGroups)
		}
	}
	return resultGroups
}

// Returns all the parents of a given group
func (t *PermissionTable) GetParents(group string) map[string]interface{} {
	// Call to recursive traverse function
	tree, _ := getParents(group, t.Groups)
	return tree
}

func getParents(group string, tree map[string]GroupTree) (map[string]interface{}, bool) {
	foundOnChilds := false // If group found on childs, this branch is valid
	generationTree := map[string]interface{}{}

	// Iterate through all the groups on that node
	for groupName, childs := range tree {
		found := false
		childTree := map[string]interface{}{}

		// If group has childs, analyze them
		if childs.Groups != nil {
			childTree, found = getParents(group, childs.Groups)
		}

		// If this is the group that we are looking for, set found flag as true and return
		if groupName == group {
			return nil, true
		}

		// If flag is true save branch and mark it as valid
		if found {
			generationTree[groupName] = childTree
			foundOnChilds = true
		}
	}

	return generationTree, foundOnChilds
}

// Checks if the user is an admin of a group
func (t *PermissionTable) IsAdminFrom(group string) bool {
	if _, ok := t.AdditionalPermissions[group]; !ok {
		return false
	}

	groupPermission, ok := t.AdditionalPermissions[group][GROUP_PERMISSION]
	if !ok {
		return false
	}

	_, c := groupPermission["c"]
	_, r := groupPermission["r"]
	_, u := groupPermission["u"]
	_, d := groupPermission["d"]

	return c && r && u && d
}

// Checks group permissions
func (t *PermissionTable) CheckGroupPermissions(group string, per string, args ...string) ([]string, bool) {
	if _, ok := t.AdditionalPermissions[group]; !ok {
		return nil, false
	}

	permissions, ok := t.AdditionalPermissions[group][per]
	if !ok {
		return nil, false
	}

	// If special permissions introduced, search and store them in a slice
	// Else, store all of them in a slice
	l := make([]string, 0, len(args))
	if args != nil {
		for _, arg := range args {
			if _, ok := permissions[arg]; ok {
				l = append(l, arg)
			}
		}
	} else {
		for k, _ := range permissions {
			l = append(l, k)
		}
	}
	return l, true
}
