package jwt

import (
	"context"
	"fmt"

	"github.com/machinebox/graphql"
)

type client interface {
	GetBearer(userID, authHeader string) (string, error)
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

type fetcherClient struct {
	cli *graphql.Client
}

func newClient(url string) client {
	cli := graphql.NewClient(url)
	// cli.Log = func(s string) { log.Println(s) }
	return &fetcherClient{cli}
}

// GetBearer returns user bearer
func (a *fetcherClient) GetBearer(userID, authHeader string) (string, error) {
	req := graphql.NewRequest(`
		query{
			admin{
				getBearer{
					token
					adviseMessage{
						code
						description
						level
					}
				}
			}
		}
	`)

	res := GetBearerResponseStruct{}
	req.Header.Add("Authorization", authHeader)

	ctx := context.Background()
	if err := a.cli.Run(ctx, req, &res); err != nil {
		return "", err
	}
	if res.Admin.GetBearer.AdviseMessage != nil && len(res.Admin.GetBearer.AdviseMessage) > 0 {
		return "", fmt.Errorf("error fetching permissions data: %v", res.Admin.GetBearer.AdviseMessage[0].Description)
	}
	return res.Admin.GetBearer.Token, nil
}
