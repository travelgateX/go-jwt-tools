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
	Permissions           map[string]map[string]map[permission]map[string]struct{} //Product-->object-->Permission-->Groups
	IsAdmin               bool
	Bearer				  string
	Groups                map[string]GroupTree                                     // Group hierarchy tree
	MemberID              string                                                   // Member identifier
}

func NewPermissionTable(jwt interface{}, memberId string, bearer string, adminGroup string) *PermissionTable {
	pt := &PermissionTable{	Permissions: make(map[string]map[string]map[permission]map[string]struct{}), IsAdmin: false, Bearer: bearer, MemberID: memberId }
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
		if groups, ok := x[ADDITIONAL].(map[string]interface{}); ok {
			// Iterate through groups
			for aGroup, products := range groups {
				if prods, ok := products.(map[string]interface{}); ok {
					// Iterate through products of the group
					fillPermissionsfromProducts(prods, &t.Permissions, aGroup, adminGroup)
				}
			}
		}

		//Check the products
		if apis, ok := x[PRODUCTS].(map[string]interface{}); ok {
			isAdmin := fillPermissionsfromProducts(apis, &t.Permissions, group, adminGroup)
			if isAdmin { t.IsAdmin = true }
		}

		// Set this group tree and pass it to the recursive call that will traverse child groups
		groupTree := (*tree)[group]
		buildPermissions(t, x[GROUPS], &groupTree.Groups, adminGroup)
	}

	t.Groups = *tree
	return
}

// Checks the user permissions for a specified product and object
// Returns: Groups that have the requested permissions
func (t *PermissionTable) CheckPermission(product string, object string, per permission, groups ...string) ([]string, bool) {
	// If user is admin, return true
	if t.IsAdmin {
		return nil, true
	}

	// If user has permissions for the desired product and object return them
	if t.Permissions[product] != nil && t.Permissions[product][object] != nil && t.Permissions[product][object][per] != nil {
		l := make([]string, 0, len(groups))
		// If special permissions introduced, search and store them in a slice
		// Else, store all of them in a slice
		if groups != nil {
			for _, gp := range groups {
				if _, ok := t.Permissions[product][object][per][gp]; ok {
					l = append(l, gp)
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

// Return all the groups that have a permissions into an object
func (t *PermissionTable) ValidGroups(product string, object string, per permission) map[string]struct{} {
	if p, ok := t.Permissions[product]; ok {
		if o, ok := p[object]; ok {
			if perm, ok := o[per]; ok {
				return perm
			}
		}
	}

	return nil
}

// Return the group codes
func (t *PermissionTable) GetAllGroups() map[string]struct{} {
	ret := map[string]struct{}{}
	for _, product := range t.Permissions {
		for _, object := range product {
			for _, permission := range object {
				for group, _ := range permission {
					ret[group] = struct{}{}
				}
			}
		}
	}
	return ret
}

// Returns a map indexed by group types, containing the list of groups of that type
func (t *PermissionTable) GetGroupsByTypes() map[string][]string {
	ret := map[string][]string{}
	processingQueue := []map[string]GroupTree { t.Groups }
	for len(processingQueue) > 0 {
		gTree := processingQueue[0]
		processingQueue = processingQueue[1:]
		for group, gTree := range gTree {
			if _, ok := ret[gTree.Type]; ok {
				ret[gTree.Type] = []string{}
			}
			ret[gTree.Type] = append(ret[gTree.Type], group)
			processingQueue = append(processingQueue, gTree.Groups)
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

func getObjects(v interface{}, group string, p map[permission]map[string]struct{}, adminGroup string) (map[permission]map[string]struct{}, bool) {
	isAdmin := false

	// Register objects of the api
	if p == nil {
		p = make(map[permission]map[string]struct{})
	}
	o := p

	// Iterate through each role of the object
	if roles, ok := v.([]interface{}); ok {
		for _, rol := range roles {
			// Extract role permissions and store them
			for _, permissions := range extractPermissions(rol.(string)) {
				if o[permissions] == nil {
					o[permissions] = make(map[string]struct{})
				}
				if _, ok := o[permissions][group]; !ok {
					o[permissions][group] = struct{}{}
				}
			}
		}

		// If Admin group and all permissions on it => User is admin
		if group == adminGroup && o["c"] != nil && o["r"] != nil && o["u"] != nil && o["d"] != nil {
			_, c := o["c"][adminGroup]
			_, r := o["r"][adminGroup]
			_, u := o["u"][adminGroup]
			_, d := o["d"][adminGroup]
			if c && r && u && d {
				isAdmin = true
			}
		}
	}

	return p, isAdmin
}

func fillPermissionsfromProducts(products map[string]interface{}, permissions *map[string]map[string]map[permission]map[string]struct{}, group string, adminGroup string) (bool){
	ret := false
	for product, objects := range products {
		if (*permissions)[product] == nil {
			(*permissions)[product] = map[string]map[permission]map[string]struct{}{}
		}
		p := (*permissions)[product]
		if objs, ok := objects.(map[string]interface{}); ok {
			// Iterate through objects of the product
			for object, perms := range objs {
				isAdmin := false
				p[object], isAdmin = getObjects(perms, group, p[object], adminGroup) // Get permissions of the object
				if isAdmin { ret = true }
			}
		}
	}
	return ret
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