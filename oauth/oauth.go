package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DeKal/bookstore_utils-go/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:9002",
		Timeout: 100 * time.Millisecond,
	}
)

// AccessToken to verify user
type accessToken struct {
	ID       string `json:"access_token"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

// IsPublic check if request is public or not
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

// GetCallerID get caller id from header
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

// GetClientID get client id from header
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

// AuthenticateRequest make sure request has valid accesstoken
func AuthenticateRequest(request *http.Request) *errors.RestError {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenID := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenID == "" {
		return nil
	}
	fmt.Println(accessTokenID)
	accessToken, err := getAccessToken(accessTokenID)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", accessToken.UserID))
	request.Header.Add(headerXClientID, fmt.Sprintf("%v", accessToken.ClientID))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, *errors.RestError) {
	endPoint := fmt.Sprintf("/oauth/access_token/%s", accessTokenID)
	response := oauthRestClient.Get(endPoint)
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("Invalid rest client response when trying to get user")
	}
	if response.StatusCode > 299 {
		restError := errors.RestError{}
		if err := json.Unmarshal(response.Bytes(), &restError); err != nil {
			return nil, errors.NewInternalServerError("Invalid error interface return when trying to login user")
		}
		return nil, &restError
	}

	accessToken := &accessToken{}
	if err := json.Unmarshal(response.Bytes(), accessToken); err != nil {
		return nil, errors.NewInternalServerError("Error while trying to unmarshal user response")
	}
	return accessToken, nil
}
