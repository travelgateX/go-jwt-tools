package jwt

import (
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/travelgateX/go-jwt-tools"
)

var _ authorization.Parser = (*Parser)(nil)

type Parser struct {
	ParserConfig
	KeyFunc func(token *jwt.Token) (interface{}, error)
}

// ParserConfig is the data required to instance a Parser
type ParserConfig struct {
	PublicKey        string   `json:"public_key_str"`
	AdminGroup       string   `json:"admin_group"`
	DummyToken       string   `json:"dummy_token"`
	IgnoreExpiration bool     `json:"ignore_expiration"`
	MemberIDClaim    []string `json:"member_id_claim"`
	GroupsClaim      []string `json:"groups_claim"`
}

// NewParser returns an instance of Parser which parses bearers from a publicKey
func NewParser(p ParserConfig) *Parser {
	jkf := func(token *jwt.Token) (interface{}, error) {
		var result interface{}
		result, _ = jwt.ParseRSAPublicKeyFromPEM([]byte(p.PublicKey))
		return result, nil
	}
	return &Parser{
		KeyFunc:      jkf,
		ParserConfig: p,
	}
}

func (p *Parser) Parse(authorizationHeader string) (*authorization.User, error) {
	// validate bearer
	authorizationHeaderParts := strings.SplitN(authorizationHeader, " ", 2)
	if len(authorizationHeaderParts) != 2 || authorizationHeaderParts[0] != "Bearer" {
		return nil, fmt.Errorf("authorizationorization header format must be Bearer {token}")
	}
	// dummy treatment
	if p.DummyToken != "" && authorizationHeaderParts[1] == p.DummyToken {
		return &authorization.User{
			AuthorizationValue: authorizationHeader,
			IsDummy:            true,
			Permissions:        nil, // TODO: NoopImpl?
		}, nil
	}
	// parse token
	jwtp := &jwt.Parser{SkipClaimsValidation: p.IgnoreExpiration}
	token, err := jwtp.Parse(authorizationHeaderParts[1], p.KeyFunc)
	if err != nil {
		return nil, fmt.Errorf("error parsing bearer: %v", err)
	}
	if jwt.SigningMethodRS256.Alg() != token.Header["alg"] {
		message := fmt.Sprintf("Expected %s signing method but token specified %s",
			jwt.SigningMethodRS256.Alg(),
			token.Header["alg"])
		return nil, fmt.Errorf("Error validating token algorithm: %s", message)
	}
	// check if the parsed token is valid...
	if !token.Valid {
		return nil, authorization.ErrInvalidUser
	}
	return p.createUser(token)
}

func (p *Parser) createUser(token *jwt.Token) (*authorization.User, error) {
	claimsMap := token.Claims.(jwt.MapClaims)
	// TODO: remove when migration finishes
	groups := make([]interface{}, 0, len(p.GroupsClaim))
	for _, g := range p.GroupsClaim {
		if c, ok := claimsMap[g]; ok {
			groups = append(groups, c)
		}
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("Your token doesn't contain any group")
	}
	memberIDs := make([]string, 0, len(p.MemberIDClaim))
	for _, m := range p.MemberIDClaim {
		if c, ok := claimsMap[m]; ok {
			if mID, ok := c.(string); ok {
				memberIDs = append(memberIDs, mID)
			}
		}
	}
	return &authorization.User{
		AuthorizationValue: "Bearer " + token.Raw,
		IsDummy:            false,
		Permissions:        NewPermissions(groups, memberIDs, p.AdminGroup),
		UserID:             memberIDs,
	}, nil
}
