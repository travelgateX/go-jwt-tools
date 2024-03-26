package jwt

import (
	authorization "go-jwt-tools"
)

const (
	claimGroup      = "c"
	claimProducts   = "p"
	claimGroups     = "g"
	claimAdditional = "a"
	claimType       = "t"
)

type GroupTree struct {
	Groups map[string]GroupTree
	Type   string
}

var _ authorization.Permissions = (*Permissions)(nil)

type Permissions struct {
	Permissions map[string]map[string]map[authorization.Permission]map[string]struct{} //Product-->object-->Permission-->Groups
	Groups      []map[string]GroupTree                                                 // Group hierarchy tree
	MemberID    []string                                                               // Member identifier
}

func NewPermissions(jwt interface{}, memberId []string, adminGroup string) *Permissions {
	pt := &Permissions{Permissions: make(map[string]map[string]map[authorization.Permission]map[string]struct{}), MemberID: memberId}
	buildPermissions(pt, jwt, &map[string]GroupTree{}, adminGroup)
	return pt
}

// Recursive call for the jwt traversal
func buildPermissions(t *Permissions, jwt interface{}, tree *map[string]GroupTree, adminGroup string) {
	ok := true
	var permission []interface{}

	// If jwt not in correct format, return null
	if permission, ok = jwt.([]interface{}); !ok {
		return
	}
	// Iterate through each group to gather its information
	for _, p := range permission {
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
				if group, ok = x[claimGroup].(string); !ok {
					return
				}

				if typ, ok = x[claimType].(string); !ok {
					return
				}

				(*tree)[group] = GroupTree{Groups: map[string]GroupTree{}, Type: typ}

				// Add Additional permissions
				if groups, ok := x[claimAdditional].(map[string]interface{}); ok {
					// Iterate through groups
					for aGroup, products := range groups {
						if prods, ok := products.(map[string]interface{}); ok {
							// Iterate through products of the group
							fillPermissionsfromProducts(prods, &t.Permissions, aGroup, adminGroup)
						}
					}
				}

				//Check the products
				if apis, ok := x[claimProducts].(map[string]interface{}); ok {
					fillPermissionsfromProducts(apis, &t.Permissions, group, adminGroup)
				}

				// Set this group tree and pass it to the recursive call that will traverse child groups
				groupTree := (*tree)[group]
				var aux []interface{}
				aux = append(aux, x[claimGroups])
				buildPermissions(t, aux, &groupTree.Groups, adminGroup)
			}
		}
	}

	t.Groups = append(t.Groups, *tree)
	return
}

// Checks the user permissions for a specified product and object
// Returns: Groups that have the requested permissions
func (t *Permissions) CheckPermission(product string, object string, per authorization.Permission, groups ...string) ([]string, bool) {
	// If user has permissions for the desired product and object return them
	if t.Permissions[product] != nil && t.Permissions[product][object] != nil && t.Permissions[product][object][per] != nil {
		l := make([]string, 0, len(groups))
		// If special permissions introduced, search and store them in a slice
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
			for k := range t.Permissions[product][object][per] {
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

func extractPermissions(p string) []authorization.Permission {
	var out []authorization.Permission

	//Permission flags
	update := false
	create := false
	delete := false
	read := false

	enabled := false
	other := []authorization.Permission{}

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
			other = append(other, authorization.Permission(string(s)))
		}

	}

	// Append every charater
	if enabled {
		if create {
			out = append(out, authorization.Create)
		}
		if read {
			out = append(out, authorization.Read)
		}
		if update {
			out = append(out, authorization.Update)
		}
		if delete {
			out = append(out, authorization.Delete)
		}
	}

	//Append special permissions
	if len(other) > 0 {
		out = append(out, other...)
	}

	return out
}

// Return all the groups that have a permissions into an object
func (t *Permissions) ValidGroups(product string, object string, per authorization.Permission) map[string]struct{} {
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
func (t *Permissions) GetAllGroups() map[string]struct{} {
	ret := map[string]struct{}{}
	for _, product := range t.Permissions {
		for _, object := range product {
			for _, permission := range object {
				for group := range permission {
					ret[group] = struct{}{}
				}
			}
		}
	}
	return ret
}

// Returns a map indexed by group types, containing the list of groups of that type
func (t *Permissions) GetGroupsByTypes() map[string][]string {
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
func (t *Permissions) GetGroups(groupType string) []string {
	// Call to recursive traverse function
	var groups []string
	var tree []string
	for _, g := range t.Groups {
		tree = getGroups(groupType, g, groups)
	}
	return tree
}

func getObjects(v interface{}, group string, p map[authorization.Permission]map[string]struct{}, adminGroup string) map[authorization.Permission]map[string]struct{} {
	// Register objects of the api
	if p == nil {
		p = make(map[authorization.Permission]map[string]struct{})
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
	}

	return p
}

func fillPermissionsfromProducts(products map[string]interface{}, permissions *map[string]map[string]map[authorization.Permission]map[string]struct{}, group string, adminGroup string) {
	for product, objects := range products {
		if (*permissions)[product] == nil {
			(*permissions)[product] = map[string]map[authorization.Permission]map[string]struct{}{}
		}
		p := (*permissions)[product]
		if objs, ok := objects.(map[string]interface{}); ok {
			// Iterate through objects of the product
			for object, perms := range objs {
				p[object] = getObjects(perms, group, p[object], adminGroup) // Get permissions of the object
			}
		}
	}
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
func (t *Permissions) GetParents(group string) map[string]interface{} {
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
