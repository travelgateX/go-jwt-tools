package authorization

var _ Parser = &MockParser{}

type MockParser struct {
	ParseFn func(authHeader string) (*User, error)
}

func (p *MockParser) Parse(authHeader string) (*User, error) {
	return p.ParseFn(authHeader)
}
