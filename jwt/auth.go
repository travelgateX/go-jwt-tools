package jwt

import (
	"fmt"
	"strings"

	authorization "github.com/travelgateX/go-jwt-tools"

	"github.com/form3tech-oss/jwt-go"
)

var _ authorization.Parser = (*Parser)(nil)

type Parser struct {
	client  client
	KeyFunc func(token *jwt.Token) (interface{}, error)
	ParserConfig
}

// ParserConfig is the data required to instance a Parser
type ParserConfig struct {
	ClientConfig     *ClientConfig `json:"client_config"`
	PublicKey        string        `json:"public_key_str"`
	AdminGroup       string        `json:"admin_group"`
	DummyToken       string        `json:"dummy_token"`
	MemberIDClaim    []string      `json:"member_id_claim"`
	GroupsClaim      []string      `json:"groups_claim"`
	FetchNeededClaim []string      `json:"fetch_needed_claim"`
	TGXMemberClaim   []string      `json:"tgx_member_claim"`
	IgnoreExpiration bool          `json:"ignore_expiration"`
}

type ClientConfig struct {
	FetcherURL string `json:"fetcher_url"`
}

func (c ClientConfig) buildClient() client {
	return newClient(c.FetcherURL)
}

// NewParser returns an instance of Parser which parses bearers from a publicKey
func NewParser(p ParserConfig) *Parser {
	var client client
	if p.ClientConfig != nil {
		client = p.ClientConfig.buildClient()
	}

	jkf := func(token *jwt.Token) (interface{}, error) {
		var result interface{}
		result, err := jwt.ParseRSAPublicKeyFromPEM([]byte(p.PublicKey))
		return result, err
	}
	return &Parser{
		KeyFunc:      jkf,
		ParserConfig: p,
		client:       client,
	}
}

func (p *Parser) Parse(authorizationHeader string) (*authorization.User, error) {
	// validate bearer
	authorizationHeaderParts := strings.SplitN(authorizationHeader, " ", 2)
	if len(authorizationHeaderParts) != 2 || authorizationHeaderParts[0] != "Bearer" {
		return nil, fmt.Errorf("authorization header format must be Bearer {token}")
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

	isTgxMember := false
	for _, f := range p.TGXMemberClaim {
		if c, ok := claimsMap[f]; ok {
			if c.(bool) {
				isTgxMember = true
			}
		}
	}

	// First of all is checked if the token received in a "fullToken"
	for _, f := range p.FetchNeededClaim {
		if c, ok := claimsMap[f]; ok {
			if c.(bool) {
				if p.client != nil {
					// Get the client's "fullToken"
					shortToken := "Bearer " + token.Raw
					fullBearer, err := p.client.GetBearer("", shortToken)
					if err != nil {
						return nil, err
					}

					// Do Parse(), recursive call with the new authorization token
					user, err := p.Parse("Bearer " + fullBearer)
					if err != nil {
						return nil, err
					}

					// Set the reduced token in the response object
					user.AuthorizationValue = shortToken
					user.TgxMember = isTgxMember
					return user, nil
				}
			}
		}
	}

	// This way is done when the token received is a "fullToken"
	// TODO: remove when migration finishes
	groups := make([]interface{}, 0, len(p.GroupsClaim))
	for _, g := range p.GroupsClaim {
		if c, ok := claimsMap[g]; ok {
			groups = append(groups, c)
		}
	}
	//if len(groups) == 0 {
	//	return nil, fmt.Errorf("Your token doesn't contain any group")
	//}

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
		TgxMember:          isTgxMember,
	}, nil
}
