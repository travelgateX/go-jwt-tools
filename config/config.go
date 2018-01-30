package config

type AuthConfigData struct {
	PublicKeyStr string `json:"publicKeyStr"`
	AdminGroup string `json:"admin_group"`
	IgnoreExpiration bool `json:"ignore_expiration"`
}

var (
	PublicKeyStr string 
	AdminGroup string
	IgnoreExpiration bool
)

func LoadConfiguration(config AuthConfigData) {
	PublicKeyStr = config.PublicKeyStr
	AdminGroup = config.AdminGroup
	IgnoreExpiration = config.IgnoreExpiration
}