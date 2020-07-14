package oauth

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/federicoleon/golang-restclient/rest"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	fmt.Println("About to start oauth tests")

	rest.StartMockupServer()
	os.Exit(m.Run())
}

func TestOauthConstants(t *testing.T) {
	//Is important test this constants because the microservices
	//are always using this value to authenticate the requests
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-ID", headerXClientID)
	assert.EqualValues(t, "X-Caller-ID", headerXCallerID)
	assert.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}

func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPublic(&request))

	request.Header.Add("X-Public", "true")
}

func TestGetCallerIDNilRequest(t *testing.T) {
	assert.EqualValues(t, 0, GetCallerID(nil))
}

func TestGetCallerIDInvalidCallerFormat(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Caller-ID", "Invalid")
	assert.EqualValues(t, 0, GetCallerID(&request))
}

func TestGetCallerIDNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Caller-ID", "1234")
	assert.EqualValues(t, 1234, GetCallerID(&request))
}
