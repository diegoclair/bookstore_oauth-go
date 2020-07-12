package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/diegoclair/go_utils-lib/resterrors"
	"github.com/federicoleon/golang-restclient/rest"
	//"github.com/mercadolibre/golang-restclient/rest" this version doesn't work with golang >= 1.13, so we are use the federicoleon while wait for approve the federicoleon PR
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-ID"
	headerXCallerID = "X-Caller-ID"

	paramAccessToken = "access_token"
)

var oauthRestClient = rest.RequestBuilder{
	BaseURL: "http://micro_oauth:3001",
	Timeout: 200 * time.Millisecond,
}

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

//IsPublic chek if the request is public
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

// GetCallerID returns a requet's callerID
func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

// GetClientID returns a requet's clientID
func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

//AuthenticateRequest authenticates the request
func AuthenticateRequest(request *http.Request) resterrors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenID := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenID == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenID)
	if err != nil {
		if err.StatusCode() == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))
	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, resterrors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/accesstoken/%s", accessTokenID))
	if response == nil || response.Response == nil {
		return nil, resterrors.NewInternalServerError("Invalid restclient response when trying to get access token")
	}

	if response.StatusCode > 299 {
		var restErr resterrors.RestErr

		err := json.Unmarshal(response.Bytes(), restErr)
		if err != nil {
			return nil, resterrors.NewInternalServerError("Error when trying to unmarshal the get access token response")
		}
		return nil, restErr
	}
	var accessToken accessToken
	if err := json.Unmarshal(response.Bytes(), &accessToken); err != nil {
		return nil, resterrors.NewInternalServerError("Error when trying to unmarshal then access token response to accessToken struct")
	}
	return &accessToken, nil
}
