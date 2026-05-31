// Copyright 2025 StrongDM Inc
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// OIDCAuth wires a generic OpenID Connect provider with the browser session store.
type OIDCAuth struct {
	cfg           *oauth2.Config
	stateMaxAge   time.Duration
	userinfoURL   string
	allowedDomain string
	allowedEmails map[string]bool
	allowedHosts  map[string]bool
	sessions      *SessionStore
	providerName  string
}

type OIDCOptions struct {
	PublicBaseURL string
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	Scopes        []string
	AllowedDomain string
	AllowedEmails []string
	AllowedHosts  []string
	ProviderName  string
}

func NewOIDCAuth(ctx context.Context, opts OIDCOptions, sessions *SessionStore) (*OIDCAuth, error) {
	issuer := strings.TrimRight(strings.TrimSpace(opts.IssuerURL), "/")
	discovery, err := fetchOIDCDiscovery(ctx, issuer)
	if err != nil {
		return nil, err
	}

	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	hostMap := make(map[string]bool, len(opts.AllowedHosts))
	for _, h := range opts.AllowedHosts {
		if v := strings.ToLower(strings.TrimSpace(h)); v != "" {
			hostMap[v] = true
		}
	}

	emailMap := make(map[string]bool, len(opts.AllowedEmails))
	for _, email := range opts.AllowedEmails {
		if v := strings.ToLower(strings.TrimSpace(email)); v != "" {
			emailMap[v] = true
		}
	}

	name := strings.TrimSpace(opts.ProviderName)
	if name == "" {
		name = "OIDC"
	}

	return &OIDCAuth{
		cfg: &oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			RedirectURL:  strings.TrimSuffix(opts.PublicBaseURL, "/") + "/auth/oidc/callback",
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  discovery.AuthorizationEndpoint,
				TokenURL: discovery.TokenEndpoint,
			},
		},
		stateMaxAge:   10 * time.Minute,
		userinfoURL:   discovery.UserinfoEndpoint,
		allowedDomain: strings.ToLower(strings.TrimSpace(opts.AllowedDomain)),
		allowedEmails: emailMap,
		allowedHosts:  hostMap,
		sessions:      sessions,
		providerName:  name,
	}, nil
}

func (o *OIDCAuth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randomState()
	if err != nil {
		http.Error(w, "unable to create state", http.StatusInternalServerError)
		return
	}
	o.setPostAuthRedirectCookie(w, r)
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Domain:   o.sessions.Domain(),
		Path:     "/",
		MaxAge:   int(o.stateMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   o.sessions.Secure(),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, o.cfg.AuthCodeURL(state, oauth2.AccessTypeOnline), http.StatusFound)
}

func (o *OIDCAuth) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		http.Redirect(w, r, "/login?error=access_denied", http.StatusFound)
		return
	}
	if !o.validState(r, state) {
		http.Redirect(w, r, "/login?error=state", http.StatusFound)
		return
	}
	token, err := o.cfg.Exchange(ctx, code)
	if err != nil {
		if o.sessions.Debug() {
			log.Printf("[oidc] exchange error: %v", err)
		}
		http.Redirect(w, r, "/login?error=exchange", http.StatusFound)
		return
	}
	user, err := o.fetchUser(ctx, token)
	if err != nil {
		if o.sessions.Debug() {
			log.Printf("[oidc] userinfo error: %v", err)
		}
		http.Redirect(w, r, "/login?error=profile", http.StatusFound)
		return
	}
	email := strings.ToLower(strings.TrimSpace(user.Email))
	if email == "" {
		http.Redirect(w, r, "/login?error=profile", http.StatusFound)
		return
	}
	if !o.allowed(email) {
		if o.sessions.Debug() {
			log.Printf("[oidc] unauthorized email %s", email)
		}
		http.Redirect(w, r, "/login?error=unauthorized", http.StatusFound)
		return
	}
	name := strings.TrimSpace(user.Name)
	if name == "" {
		name = email
	}
	sessionID, err := o.sessions.Create(ctx, email, name, user.Picture)
	if err != nil {
		if o.sessions.Debug() {
			log.Printf("[oidc] create session error: %v", err)
		}
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}
	o.sessions.SetCookie(w, sessionID)
	o.clearStateCookie(w)
	if dest := o.postAuthRedirect(w, r); dest != "" {
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (o *OIDCAuth) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if sess, _ := o.sessions.SessionFromRequest(ctx, r); sess != nil {
		_ = o.sessions.Delete(ctx, sess.ID)
	}
	o.sessions.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (o *OIDCAuth) ProviderName() string {
	return o.providerName
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

func fetchOIDCDiscovery(ctx context.Context, issuer string) (oidcDiscovery, error) {
	if issuer == "" {
		return oidcDiscovery{}, errors.New("oidc issuer is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oidcDiscovery{}, fmt.Errorf("build oidc discovery request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oidcDiscovery{}, fmt.Errorf("fetch oidc discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return oidcDiscovery{}, fmt.Errorf("oidc discovery status: %d", resp.StatusCode)
	}
	var discovery oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return oidcDiscovery{}, fmt.Errorf("decode oidc discovery: %w", err)
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return oidcDiscovery{}, errors.New("oidc discovery missing authorization or token endpoint")
	}
	return discovery, nil
}

type oidcUser struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func (o *OIDCAuth) fetchUser(ctx context.Context, token *oauth2.Token) (oidcUser, error) {
	if o.userinfoURL != "" {
		client := o.cfg.Client(ctx, token)
		resp, err := client.Get(o.userinfoURL)
		if err != nil {
			return oidcUser{}, fmt.Errorf("userinfo request: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			var u oidcUser
			if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
				return oidcUser{}, fmt.Errorf("decode userinfo: %w", err)
			}
			if u.Email != "" {
				return u, nil
			}
		}
	}
	return userFromIDToken(token)
}

func userFromIDToken(token *oauth2.Token) (oidcUser, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return oidcUser{}, errors.New("email missing in userinfo and id_token unavailable")
	}
	parts := strings.Split(rawIDToken, ".")
	if len(parts) < 2 {
		return oidcUser{}, errors.New("invalid id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oidcUser{}, fmt.Errorf("decode id_token payload: %w", err)
	}
	var claims struct {
		Email         string `json:"email"`
		Name          string `json:"name"`
		PreferredName string `json:"preferred_username"`
		Picture       string `json:"picture"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return oidcUser{}, fmt.Errorf("decode id_token claims: %w", err)
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredName
	}
	if claims.Email == "" {
		return oidcUser{}, errors.New("email missing in id_token")
	}
	return oidcUser{Email: claims.Email, Name: name, Picture: claims.Picture}, nil
}

func (o *OIDCAuth) allowed(email string) bool {
	if len(o.allowedEmails) == 0 && o.allowedDomain == "" {
		return true
	}
	if o.allowedEmails[email] {
		return true
	}
	return o.allowedDomain != "" && strings.HasSuffix(email, "@"+o.allowedDomain)
}

func (o *OIDCAuth) validState(r *http.Request, state string) bool {
	if state == "" {
		return false
	}
	c, err := r.Cookie("oidc_state")
	if err != nil {
		return false
	}
	return subtleEqual(state, c.Value)
}

func (o *OIDCAuth) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    "",
		Domain:   o.sessions.Domain(),
		Path:     "/",
		HttpOnly: true,
		Secure:   o.sessions.Secure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (o *OIDCAuth) setPostAuthRedirectCookie(w http.ResponseWriter, r *http.Request) {
	host := canonicalAuthority(r)
	if host == "" {
		return
	}
	scheme := "https"
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.ToLower(forwarded)
	} else if r.TLS == nil {
		scheme = "http"
	}
	if scheme != "https" && scheme != "http" {
		return
	}
	base := scheme + "://" + host
	if !o.isAllowedRedirectBase(base) {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "post_auth_redirect",
		Value:    base,
		Domain:   o.sessions.Domain(),
		Path:     "/",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   o.sessions.Secure(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (o *OIDCAuth) postAuthRedirect(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie("post_auth_redirect")
	if err != nil {
		return ""
	}
	o.clearPostAuthRedirectCookie(w)
	base := strings.TrimSpace(c.Value)
	if base == "" || !o.isAllowedRedirectBase(base) {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	u.Path = "/"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (o *OIDCAuth) clearPostAuthRedirectCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "post_auth_redirect",
		Value:    "",
		Domain:   o.sessions.Domain(),
		Path:     "/",
		HttpOnly: true,
		Secure:   o.sessions.Secure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (o *OIDCAuth) isAllowedRedirectBase(rawBaseURL string) bool {
	u, err := url.Parse(rawBaseURL)
	if err != nil {
		return false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return false
	}
	if u.User != nil {
		return false
	}
	if u.Path != "" && u.Path != "/" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	if len(o.allowedHosts) > 0 {
		return o.allowedHosts[host]
	}
	domain := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(o.sessions.Domain(), ".")))
	return domain != "" && (host == domain || strings.HasSuffix(host, "."+domain))
}
