package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/thanhpk/randstr"
)

var (
	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	state        = randstr.Hex(16)
	nonce        = "NonceNotSetYet"
)

// IndexHandler serves the index.html page
func IndexHandler(c *gin.Context) {
	log.Println("Loading main page")

	errorMsg := ""

	profile, err := getProfileData(c.Request)

	if err != nil {
		errorMsg = err.Error()
	}

	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the index.gohtml template
		"index.gohtml",
		// Pass the data that the page uses
		gin.H{
			"Profile":         profile,
			"IsAuthenticated": isAuthenticated(c.Request),
			"Error":           errorMsg,
		},
	)

}

func LoginHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	nonce = base64.URLEncoding.EncodeToString(randstr.Bytes(32))

	q := url.Values{}
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")
	q.Add("state", state)
	q.Add("nonce", nonce)

	location := url.URL{Path: os.Getenv("ISSUER") + "/v1/authorize", RawQuery: q.Encode()}
	c.Redirect(http.StatusFound, location.RequestURI())
}

func LogoutHandler(c *gin.Context) {
	session, err := sessionStore.Get(c.Request, "okta-hosted-login-session-store")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("The state was not as expected"))
		return
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")

	session.Save(c.Request, c.Writer)

	c.Redirect(http.StatusFound, "/")
}

func ProfileHandler(c *gin.Context) {
	errorMsg := ""

	profile, err := getProfileData(c.Request)

	if err != nil {
		errorMsg = err.Error()
	}
	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the index.gohtml template
		"profile.gohtml",
		// Pass the data that the page uses
		gin.H{
			"Profile":         profile,
			"IsAuthenticated": isAuthenticated(c.Request),
			"Error":           errorMsg,
		},
	)
}

func AuthCodeCallbackHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	// Check the state that was returned in the query string is the same as the above state
	if c.Query("state") != state {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("The state was not as expected"))
		return
	}
	// Make sure the code was provided
	if c.Query("code") == "" {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("The code was not returned or is not accessible"))
		return
	}

	exchange, err := exchangeCode(c.Query("code"))
	if err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}
	if exchange.Error != "" {
		c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("%s:%s", exchange.Error, exchange.ErrorDescription))
		return
	}

	session, err := sessionStore.Get(c.Request, "okta-hosted-login-session-store")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	_, err = verifyToken(exchange.IdToken)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	} else {
		session.Values["id_token"] = exchange.IdToken
		session.Values["access_token"] = exchange.AccessToken

		session.Save(c.Request, c.Writer)
	}

	c.Redirect(http.StatusFound, "/")
}

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func getProfileData(r *http.Request) (map[string]string, error) {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m, nil
	}

	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"

	req, err := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	if err != nil {
		return m, err
	}

	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return m, err
	}

	json.Unmarshal(body, &m)

	return m, nil
}

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

func exchangeCode(code string) (Exchange, error) {
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	q := url.Values{}
	q.Add("grant_type", "authorization_code")
	q.Set("code", code)
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")

	url := os.Getenv("ISSUER") + "/v1/token?" + q.Encode()

	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	if err != nil {
		return Exchange{}, err
	}

	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Exchange{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Exchange{}, err
	}

	var exchange Exchange
	json.Unmarshal(body, &exchange)

	return exchange, nil
}

func verifyToken(t string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["nonce"] = nonce
	tv["aud"] = os.Getenv("CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("ISSUER"),
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}
