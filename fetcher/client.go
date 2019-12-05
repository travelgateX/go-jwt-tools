package fetcher

import (
	"sync"
)

// fetcher interface
type Client interface {
	GetBearer(userID, authHeader string) (string, error)
}

// Global API instance
var f Client
var once sync.Once

// Get cached fetcher
func GetClient(url string) Client {
	once.Do(func() {
		f = NewCachedClient(NewClient(url))
	})

	return f
}

// GetBearerResponseStruct api graphql response
type GetBearerResponseStruct struct {
	Admin struct {
		GetBearer struct {
			Token         string `json:"token"`
			AdviseMessage []struct {
				Code        string `json:"code"`
				Description string `json:"description"`
				Level       string `json:"level"`
			} `json:"adviseMessage"`
		} `json:"getBearer"`
	} `json:"admin"`
}
