package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type client interface {
	GetBearer(userID, authHeader string) (string, error)
}

type GetBearerResponseStruct struct {
	Email            string `json:"email,omitempty"`
	Token            string `json:"token,omitempty"`
	ErrorDescription string `json:"errorDescription,omitempty"`
	Status           int    `json:"status,omitempty"`
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

	query := `{"query": "{ admin { jwt } }"}`

	req, err := http.NewRequest("POST", a.url, bytes.NewBuffer([]byte(query)))
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", authHeader)
	req.Header.Add("Content-Type", "application/json")

	res, err := a.cli.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var response struct {
		Data   map[string]map[string]string `json:"data"`
		Errors []map[string]interface{}     `json:"errors,omitempty"`
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return "", err
	}

	if len(response.Errors) > 0 {
		return "", fmt.Errorf("error fetching permissions data: %v", response.Errors)
	}

	return response.Data["admin"]["jwt"], nil
}
