package jwt

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type client interface {
	GetBearer(userID, authHeader string) (string, error)
}

type GetBearerResponseStruct struct {
	Email				string `json:"email,omitempty"`
	Token 				string `json:"token,omitempty"`
	Status 				int 	`json:"status,omitempty"`
	ErrorDescription 	string `json:"errorDescription,omitempty"`
}

type fetcherClient struct {
	cli http.Client
	url string
}

func newClient(url string) client {
	cli := http.Client{}
	return &fetcherClient{cli, url}
}

// GetBearer returns user bearer
func (a *fetcherClient) GetBearer(userID, authHeader string) (string, error) {
	req, err := http.NewRequest("GET", a.url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", authHeader)
	res, err := a.cli.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	resJSON := GetBearerResponseStruct{}
	err = json.Unmarshal(body, &resJSON)
	if err != nil {
		return "", err
	}

	if resJSON.ErrorDescription != ""  {
		return "", fmt.Errorf("error fetching permissions data: %v", resJSON.ErrorDescription)
	}
	return resJSON.Token, nil
}
