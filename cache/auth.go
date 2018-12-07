package cache

import (
	"github.com/travelgateX/go-cache/cache"
	"github.com/travelgateX/go-jwt-tools"
)

type Parser struct {
	p auth.Parser
	c *cache.FetcherLRU
}

func NewParser(p auth.Parser, c *cache.FetcherLRU) auth.Parser {
	return &Parser{p, c}
}

func (p *Parser) Parse(authHeader string) (*auth.User, error) {
	onFetch := func() (interface{}, error) {
		user, err := p.p.Parse(authHeader)
		if err != nil {
			if err == auth.ErrInvalidUser {
				p.c.Remove(authHeader)
			}
			return nil, err
		}
		return user, nil
	}
	v, err := p.c.GetOrFetch(authHeader, onFetch)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	return v.(*auth.User), nil
}
