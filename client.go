package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/net/context"
	oauth2 "golang.org/x/oauth2"
)

var (
	clientID                           = os.Getenv("GO_CLIENT_ID")
	clientSecret                       = os.Getenv("GO_CLIENT_SECRET")
	issuerURL                          = os.Getenv("GO_ISSUER_URL")
	audience                           = os.Getenv("GO_AUDIENCE")
	audienceOpt  oauth2.AuthCodeOption = oauth2.SetAuthURLParam("audience", audience)
)

func sanityChecks() {

	if len(strings.TrimSpace(clientID)) == 0 || len(strings.TrimSpace(clientSecret)) == 0 {
		panic("Please set the client credentials using the GO_CLIENT_ID and GO_CLIENT_SECRET env variables")
	}

	if len(strings.TrimSpace(issuerURL)) == 0 {
		issuerURL = "https://wlcg.cloud.cnaf.infn.it/"
	}

	if len(strings.TrimSpace(audience)) == 0 {
		audienceOpt = oauth2.SetAuthURLParam("audience", "example-audience")
	}

}
func main() {
	ctx := context.Background()

	sanityChecks()

	provider, err := oidc.NewProvider(ctx, issuerURL)

	if err != nil {
		log.Fatal(err)
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:5556/go-oidc-client/callback",
		Scopes:       []string{oidc.ScopeOpenID},
	}

	state := "foobar" // Don't do this in production.

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		// Here is where you can easily add parameters to the URL
		// used for the authorization request via the
		// oauth2.AuthCodeOption mechanism
		http.Redirect(w, r, config.AuthCodeURL(state, audienceOpt), http.StatusFound)
	})

	http.HandleFunc("/go-oidc-client/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		// Here is where you can easily add parameters to the URL
		// used for the token request via the oauth2.AuthCodeOption mechanism
		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
