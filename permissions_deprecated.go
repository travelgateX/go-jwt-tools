package authorization

const GROUP = "c"
const PRODUCTS = "p"
const GROUPS = "g"
const ADDITIONAL = "a"
const TYPE = "t"


const GROUP_Permission = "grp"

type GroupTree struct {
	Type   string               // Group type
	Groups map[string]GroupTree // Group hierarchy tree
}

type PermissionTable struct {
	Permissions map[string]map[string]map[Permission]map[string]struct{} //Product-->object-->Permission-->Groups
	IsAdmin     bool
	Bearer      string
	Groups      []map[string]GroupTree // Group hierarchy tree
	MemberID    []string               // Member identifier
}

func NewPermissionTable(jwt interface{}, memberId []string, bearer string, adminGroup string) *PermissionTable {
	pt := &PermissionTable{Permissions: make(map[string]map[string]map[Permission]map[string]struct{}), IsAdmin: false, Bearer: bearer, MemberID: memberId}
	buildPermissions(pt, jwt, &map[string]GroupTree{}, adminGroup)
	return pt
}

// Recursive call for the jwt traversal
func buildPermissions(t *PermissionTable, jwt interface{}, tree *map[string]GroupTree, adminGroup string) {
	ok := true
	var Permission []interface{}

	// If jwt not in correct format, return null
	if Permission, ok = jwt.([]interface{}); !ok {
		return
	}
	// Iterate through each group to gather its information
	for _, p := range Permission {
		var groups []interface{}
		if groups, ok = p.([]interface{}); ok {
			for _, g := range groups {
				var group string
				var typ string
				var x map[string]interface{}

				//Check if the token is not null
				if x, ok = g.(map[string]interface{}); !ok {
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

				// Add Additional Permissions
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
					if isAdmin {
						t.IsAdmin = true
					}
				}

				// Set this group tree and pass it to the recursive call that will traverse child groups
				groupTree := (*tree)[group]
				var aux []interface{}
				aux = append(aux, x[GROUPS])
				buildPermissions(t, aux, &groupTree.Groups, adminGroup)
			}
		}
	}

	t.Groups = append(t.Groups, *tree)
	return
}

// Checks the user Permissions for a specified product and object
// Returns: Groups that have the requested Permissions
func (t *PermissionTable) CheckPermission(product string, object string, per Permission, groups ...string) ([]string, bool) {
	// If user is admin, return true
	// Admin concept deprecated
	// if t.IsAdmin {
	// 	return nil, true
	// }

	// If user has Permissions for the desired product and object return them
	if t.Permissions[product] != nil && t.Permissions[product][object] != nil && t.Permissions[product][object][per] != nil {
		l := make([]string, 0, len(groups))
		// If special Permissions introduced, search and store them in a slice
		// Else, store all of them in a slice
		if groups != nil {
			for _, gp := range groups {
				if _, ok := t.Permissions[product][object][per][gp]; ok {
					l = append(l, gp)
				} else if _, ok := t.Permissions[product][object][per]["all"]; ok {
					l = append(l, "all")
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

	// Return false as the user has no Permissions
	return nil, false
}

func extractPermissions(p string) []Permission {
	var out []Permission

	//Permission flags
	update := false
	create := false
	delete := false
	read := false

	enabled := false
	other := []Permission{}

	// Iterate through Permission string.
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
			other = append(other, Permission(string(s)))
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

	//Append special Permissions
	if len(other) > 0 {
		out = append(out, other...)
	}

	return out
}

// Return all the groups that have a Permissions into an object
func (t *PermissionTable) ValidGroups(product string, object string, per Permission) map[string]struct{} {
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
			for _, Permission := range object {
				for group, _ := range Permission {
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
	for _, g := range t.Groups {
		processingQueue := []map[string]GroupTree{g}
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
	}
	return ret
}

// Returns all groups of a given type
func (t *PermissionTable) GetGroups(groupType string) []string {
	// Call to recursive traverse function
	var groups []string
	var tree []string
	for _, g := range t.Groups {
		tree = getGroups(groupType, g, groups)
	}
	return tree
}

func getObjects(v interface{}, group string, p map[Permission]map[string]struct{}, adminGroup string) (map[Permission]map[string]struct{}, bool) {
	isAdmin := false

	// Register objects of the api
	if p == nil {
		p = make(map[Permission]map[string]struct{})
	}
	o := p

	// Iterate through each role of the object
	if roles, ok := v.([]interface{}); ok {
		for _, rol := range roles {
			// Extract role Permissions and store them
			for _, Permissions := range extractPermissions(rol.(string)) {
				if o[Permissions] == nil {
					o[Permissions] = make(map[string]struct{})
				}
				if _, ok := o[Permissions][group]; !ok {
					o[Permissions][group] = struct{}{}
				}
			}
		}

		// If Admin group and all Permissions on it => User is admin
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

func fillPermissionsfromProducts(products map[string]interface{}, Permissions *map[string]map[string]map[Permission]map[string]struct{}, group string, adminGroup string) bool {
	ret := false
	for product, objects := range products {
		if (*Permissions)[product] == nil {
			(*Permissions)[product] = map[string]map[Permission]map[string]struct{}{}
		}
		p := (*Permissions)[product]
		if objs, ok := objects.(map[string]interface{}); ok {
			// Iterate through objects of the product
			for object, perms := range objs {
				isAdmin := false
				p[object], isAdmin = getObjects(perms, group, p[object], adminGroup) // Get Permissions of the object
				if isAdmin {
					ret = true
				}
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
	var tree map[string]interface{}
	for _, g := range t.Groups {
		tree, _ = getParents(group, g)
	}
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
