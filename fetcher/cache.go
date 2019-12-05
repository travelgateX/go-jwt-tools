package fetcher

import (
	"time"

	cache "github.com/patrickmn/go-cache"
)

type cachedClient struct {
	client Client
	cache  *cache.Cache
}

// NewCachedClient
func NewCachedClient(client Client) Client {
	c := cache.New(5*time.Minute, 10*time.Minute)
	return cachedClient{
		client: client,
		cache:  c,
	}
}

// GetBearer returns cached user bearer
func (a cachedClient) GetBearer(userID, authHeader string) (string, error) {
	key := "bearer#" + userID
	cached, found := a.cache.Get(key)
	if found {
		return cached.(string), nil
	}

	gr, err := a.client.GetBearer(userID, authHeader)
	if err != nil {
		return "", err
	}

	a.cache.Set(key, gr, cache.DefaultExpiration)
	return gr, nil
}
