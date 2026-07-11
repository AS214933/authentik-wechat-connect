package main

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) handleOpenIDConfiguration(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.OIDCIssuer,
		"authorization_endpoint":                absoluteURL(s.cfg.PublicURL, "/oauth/authorize"),
		"token_endpoint":                        absoluteURL(s.cfg.PublicURL, "/oauth/token"),
		"userinfo_endpoint":                     absoluteURL(s.cfg.PublicURL, "/oauth/userinfo"),
		"jwks_uri":                              absoluteURL(s.cfg.PublicURL, "/oauth/jwks"),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"openid", "profile"},
		"claims_supported": []string{
			"sub", "name", "nickname", "preferred_username", "picture", "gender", "wechat_openid", "wechat_unionid",
		},
		"code_challenge_methods_supported": []string{"plain", "S256"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{s.signer.JWK()}})
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	state := query.Get("state")

	if redirectURI == "" || !s.redirectAllowed(redirectURI) {
		logOAuthWarning(r, "authorize rejected: redirect_uri is not allowed client_id=%q redirect_uri=%q", clientID, redirectURI)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not allowed")
		return
	}
	if query.Get("response_type") != "code" {
		logOAuthWarning(r, "authorize rejected: unsupported response_type=%q client_id=%q redirect_uri=%q", query.Get("response_type"), clientID, redirectURI)
		redirectOAuthError(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if clientID != s.cfg.OIDCClientID {
		logOAuthWarning(r, "authorize rejected: unknown client_id=%q redirect_uri=%q", clientID, redirectURI)
		redirectOAuthError(w, r, redirectURI, state, "unauthorized_client", "unknown client_id")
		return
	}
	if err := s.ensureWeChatConfigured(); err != nil {
		logOAuthWarning(r, "authorize rejected: %v", err)
		redirectOAuthError(w, r, redirectURI, state, "server_error", err.Error())
		return
	}

	req := oidcAuthRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               query.Get("nonce"),
		Scope:               normalizeScope(query.Get("scope")),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
	}
	if req.Scope == "" {
		req.Scope = "openid profile"
	}

	scan, err := s.createScanSession(r.Context(), scanKindOIDC, req, "")
	if err != nil {
		logOAuthWarning(r, "authorize failed: create WeChat scan session client_id=%q redirect_uri=%q state_fp=%s: %v", clientID, redirectURI, tokenFingerprint(state), err)
		redirectOAuthError(w, r, redirectURI, state, "server_error", "failed to create WeChat login QR code")
		return
	}
	logOAuthInfo(r, "authorize accepted: client_id=%q redirect_uri=%q state_fp=%s scan_id_fp=%s", clientID, redirectURI, tokenFingerprint(state), tokenFingerprint(scan.ID))
	http.Redirect(w, r, "/scan/"+url.PathEscape(scan.ID), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		logOAuthWarning(r, "token rejected: parse form: %v", err)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	clientID, clientSecret, ok := decodeBasicAuth(r)
	if !ok {
		clientID = formValue(r, "client_id")
		clientSecret = formValue(r, "client_secret")
	}
	if clientID != s.cfg.OIDCClientID || !s.clientSecretMatches(clientSecret) {
		logOAuthWarning(r, "token rejected: invalid client credentials client_id=%q", clientID)
		w.Header().Set("WWW-Authenticate", `Basic realm="wechat-connect"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}
	if formValue(r, "grant_type") != "authorization_code" {
		logOAuthWarning(r, "token rejected: unsupported grant_type=%q client_id=%q", formValue(r, "grant_type"), clientID)
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	code := formValue(r, "code")
	record, reason, ok := s.popAuthCodeWithReason(code)
	if !ok {
		logOAuthWarning(r, "token rejected: authorization code invalid or expired client_id=%q code_fp=%s reason=%q", clientID, tokenFingerprint(code), reason)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}
	if record.ClientID != clientID {
		logOAuthWarning(r, "token rejected: code client mismatch client_id=%q code_client_id=%q code_fp=%s", clientID, record.ClientID, tokenFingerprint(code))
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code was issued to a different client")
		return
	}
	if formValue(r, "redirect_uri") != record.RedirectURI {
		logOAuthWarning(r, "token rejected: redirect_uri mismatch client_id=%q got=%q want=%q code_fp=%s", clientID, formValue(r, "redirect_uri"), record.RedirectURI, tokenFingerprint(code))
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match authorization request")
		return
	}
	if !verifyPKCE(record.CodeChallenge, record.CodeChallengeMethod, formValue(r, "code_verifier")) {
		logOAuthWarning(r, "token rejected: PKCE verification failed client_id=%q code_fp=%s method=%q", clientID, tokenFingerprint(code), record.CodeChallengeMethod)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	accessToken, accessSession, err := s.createAccessSession(clientID, record.Scope, record.User)
	if err != nil {
		logOAuthWarning(r, "token failed: create access session client_id=%q user_fp=%s: %v", clientID, tokenFingerprint(record.User.OpenID), err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue access token")
		return
	}
	idToken, err := s.signer.SignIDToken(clientID, record.Nonce, record.User, accessSession.ExpiresAt)
	if err != nil {
		logOAuthWarning(r, "token failed: sign id token client_id=%q user_fp=%s: %v", clientID, tokenFingerprint(record.User.OpenID), err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign id token")
		return
	}
	logOAuthInfo(r, "token issued: client_id=%q user_fp=%s code_fp=%s access_token_fp=%s", clientID, tokenFingerprint(record.User.OpenID), tokenFingerprint(code), tokenFingerprint(accessToken))

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(accessSession.ExpiresAt).Seconds()),
		"id_token":     idToken,
		"scope":        record.Scope,
	})
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		logOAuthWarning(r, "userinfo rejected: missing bearer token")
		writeOAuthError(w, http.StatusUnauthorized, "invalid_request", "missing bearer token")
		return
	}
	session, reason, ok := s.getAccessSessionWithReason(token)
	if !ok {
		logOAuthWarning(r, "userinfo rejected: access token invalid or expired token_fp=%s reason=%q", tokenFingerprint(token), reason)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "access token is invalid or expired")
		return
	}
	writeJSON(w, http.StatusOK, session.User.oidcClaims())
}

func (s *Server) authentikRedirectURL(req oidcAuthRequest, code string) (string, error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Server) redirectBackToAuthentik(w http.ResponseWriter, r *http.Request, req oidcAuthRequest, code string) {
	redirectURL, err := s.authentikRedirectURL(req, code)
	if err != nil {
		logOAuthWarning(r, "callback failed: stored redirect_uri is invalid redirect_uri=%q code_fp=%s", req.RedirectURI, tokenFingerprint(code))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "stored redirect_uri is invalid")
		return
	}
	logOAuthInfo(r, "redirecting back to authentik redirect_uri=%q state_fp=%s code_fp=%s", req.RedirectURI, tokenFingerprint(req.State), tokenFingerprint(code))
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func normalizeScope(scope string) string {
	parts := strings.Fields(strings.ReplaceAll(scope, ",", " "))
	if len(parts) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if _, ok := seen[part]; !ok {
			seen[part] = struct{}{}
			out = append(out, part)
		}
	}
	return strings.Join(out, " ")
}
