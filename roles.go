package authorization

type Role int

const (
	VIEWER Role = 0
	EDITOR Role = 1
	ADMIN  Role = 2
	OWNER  Role = 3
)

type Service string

const (
	ENTITIES Service = "ENTITIES"
	BILLING  Service = "BILLING"
	HOTELX   Service = "HOTELX"
	UNKNOWN  Service = "UNKNOWN"
)

const ORG_TGX = "tgx"

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

func GetServiceFromString(service string) Service {
	switch service {
	case "ENTITIES":
		return ENTITIES
	case "BILLING":
		return BILLING
	case "HOTELX":
		return HOTELX
	default:
		return UNKNOWN
	}
}
