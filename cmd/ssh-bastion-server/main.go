package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/lstoll/nassh-relay"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	issuer        = kingpin.Flag("issuer", "OIDC Issuer").Required().String()
	clientID      = kingpin.Flag("client-id", "OIDC Client ID").Required().String()
	clientSecret  = kingpin.Flag("client-secret", "OIDC Client Secret").Required().String()
	addr          = kingpin.Flag("addr", "Address to listen on").Default("127.0.0.1:8080").String()
	baseURL       = kingpin.Flag("base-url", "URL where this service is served").Default("http://127.0.0.1:8080").String()
	sessionSecret = kingpin.Flag("session-secret", "Secret for cookie session store").Default(string(securecookie.GenerateRandomKey(64))).String()
	sshPrivKey    = kingpin.Flag("ssh-private-key", "Private SSH key for connecting to backends. If set, will proxy conns").File()
	sshHostKey    = kingpin.Flag("ssh-host-key", "Host key for ssh sessions").File()
	sshUser       = kingpin.Flag("ssh-user", "Username to connect to backends").String()
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := logrus.New()
	kingpin.Parse()

	cookieStore := sessions.NewCookieStore([]byte(*sessionSecret))

	provider, err := oidc.NewProvider(ctx, *issuer)
	if err != nil {
		log.Fatalf("Error creating OIDC provider [%+v]", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		RedirectURL:  *baseURL + "/callback",

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: *clientID})

	relay := nassh.Relay{
		Logger:      log,
		HTTPSession: cookieStore,
	}
	if *sshPrivKey != nil {
		sp, err := newSSHProxy(log)
		if err != nil {
			log.WithError(err).Fatal("Could't init ssh proxy")
		}
		relay.Dialer = sp.Dial
	}

	m := http.NewServeMux()

	// Init the auth flow in the cookie handler
	m.HandleFunc("/cookie", func(w http.ResponseWriter, r *http.Request) {
		sessionID := uuid.New().String()
		sess, err := cookieStore.New(r, sessionID)
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
		sess.Options.MaxAge = 10 * 60 // 10 minutes
		sess.Values["ext"] = r.URL.Query().Get("ext")
		sess.Values["path"] = r.URL.Query().Get("path")
		sess.Values["version"] = r.URL.Query().Get("version")
		sess.Values["method"] = r.URL.Query().Get("method")
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, oauth2Config.AuthCodeURL(sessionID), http.StatusFound)
	})

	m.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		sess, err := cookieStore.Get(r, r.FormValue("state"))
		if err != nil {
			http.Error(w, "Invalid oauth state", http.StatusBadRequest)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exhange oauth2 token", http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "ID Token missing", http.StatusBadRequest)
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Token failed verification", http.StatusForbidden)
			return
		}

		var claims struct {
			Email    string   `json:"email"`
			Verified bool     `json:"email_verified"`
			Groups   []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to process token claims", http.StatusForbidden)
			return
		}

		log.Printf("Starting session for %s", claims.Email)

		ext, eok := sess.Values["ext"]
		path, pok := sess.Values["path"]
		version, vok := sess.Values["version"]
		method, mok := sess.Values["method"]
		if !eok || !pok || !vok || !mok {
			http.Error(w, "Session missing information", http.StatusBadRequest)
			return
		}

		relay.StartSession(w, r, claims.Email, r.FormValue("state"), ext.(string), path.(string), version.(string), method.(string))
	})

	m.HandleFunc("/proxy", relay.ProxyHandler)
	m.HandleFunc("/connect", relay.ConnectHandler)

	log.Printf("Listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, logRequest(m)))
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func newSSHProxy(l logrus.FieldLogger) (*sshProxy, error) {
	hb, err := ioutil.ReadAll(*sshHostKey)
	if err != nil {
		return nil, err
	}
	hostKey, err := ssh.ParsePrivateKey(hb)
	if err != nil {
		return nil, err
	}
	cb, err := ioutil.ReadAll(*sshPrivKey)
	if err != nil {
		return nil, err
	}
	clientKey, err := ssh.ParsePrivateKey(cb)
	if err != nil {
		return nil, err
	}
	return &sshProxy{
		l:              l,
		hostKey:        hostKey,
		clientKey:      clientKey,
		clientUsername: *sshUser,
	}, nil
}
