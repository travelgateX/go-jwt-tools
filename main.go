package main

import (
	"go-jwt-tools/authorization"

	"github.com/gopherjs/gopherjs/js"
)

func main() {
	js.Module.Get("exports").Set("authorization", map[string]interface{}{
		"Authorize":                  authorization.Authorize,
		"PermissionTableFromContext": authorization.PermissionTableFromContext,
		"NewPermissionTable":         authorization.NewPermissionTable,
	})
}
