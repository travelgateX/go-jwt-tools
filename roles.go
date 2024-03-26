package authorization

type Role int

const (
	VIEWER Role = 0
	EDITOR Role = 1
	ADMIN  Role = 2
	OWNER  Role = 3
)

func GetRoleFromString(role string) Role {
	switch role {
	case "OWNER":
		return OWNER
	case "ADMIN":
		return ADMIN
	case "EDITOR":
		return EDITOR
	default:
		return VIEWER
	}
}
