package cache

import (
	"github.com/travelgateX/go-jwt-tools"
	"github.com/travelgateX/go-cache/cache"
)

type Parser struct {
	p authorization.Parser
	c *cache.FetcherLRU
}

func NewParser(p authorization.Parser, c *cache.FetcherLRU) authorization.Parser {
	return &Parser{p, c}
}

func (p *Parser) Parse(authorizationHeader string) (*authorization.User, error) {
	onFetch := func() (interface{}, error) {
		user, err := p.p.Parse(authorizationHeader)
		if err != nil {
			if err == authorization.ErrInvalidUser {
				p.c.Remove(authorizationHeader)
			}
			return nil, err
		}
		return user, nil
	}
	v, err := p.c.GetOrFetch(authorizationHeader, onFetch)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	return v.(*authorization.User), nil
}
