package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfg        Config
	wx         wechatService
	wxMenu     wechatMenuService
	signer     *JWTSigner
	management *wechatManagementStore
	wxCryptor  *wechatCryptor

	mu                    sync.Mutex
	scans                 map[string]*scanSession
	authCodes             map[string]authCode
	accessTokens          map[string]accessSession
	webSessions           map[string]webSession
	usedTokens            map[string]time.Time
	wechatResponses       map[string]wechatCachedResponse
	wechatInFlight        map[string]chan struct{}
	wechatPlainSignatures map[string]wechatPlainSignatureRecord
	wechatLoginAttempts   map[string]wechatLoginAttempt
	wechatGlobalAttempts  wechatLoginAttempt
	loginCodes            map[string]string
	qrUnauthorized        bool
}

type scanSession struct {
	ID            string
	Kind          string
	OIDC          oidcAuthRequest
	ReturnTo      string
	QRImageURL    string
	Ticket        string
	LoginMode     string
	LoginCode     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	CompletedAt   time.Time
	User          User
	AuthCode      string
	RedirectURL   string
	Error         string
	Completing    bool
	ClaimedOpenID string
	LocalConsumed bool
}

type oidcAuthRequest struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	Scope               string `json:"scope,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

type authCode struct {
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Nonce               string    `json:"nonce,omitempty"`
	Scope               string    `json:"scope,omitempty"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	User                User      `json:"user"`
	ExpiresAt           time.Time `json:"-"`
}

type accessSession struct {
	ClientID  string    `json:"client_id"`
	Scope     string    `json:"scope,omitempty"`
	User      User      `json:"user"`
	ExpiresAt time.Time `json:"-"`
}

type webSession struct {
	User      User
	ExpiresAt time.Time
}

type sealedTokenEnvelope struct {
	Type      string          `json:"typ"`
	IssuedAt  int64           `json:"iat"`
	ExpiresAt int64           `json:"exp"`
	Payload   json.RawMessage `json:"pld"`
}

const (
	scanKindOIDC  = "oidc"
	scanKindLocal = "local"

	sealedTokenVersion     = "wxc1"
	sealedTokenTypeCode    = "auth_code"
	sealedTokenTypeAccess  = "access_token"
	scanSessionIDBytes     = 18
	maxScanSessionIDLength = 64
)

type User struct {
	OpenID   string `json:"openid"`
	UnionID  string `json:"unionid,omitempty"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Gender   string `json:"gender,omitempty"`
	City     string `json:"city,omitempty"`
	Province string `json:"province,omitempty"`
	Country  string `json:"country,omitempty"`
}

func (u User) Subject() string {
	return "wechat:" + u.OpenID
}

func (u User) DisplayName() string {
	if u.Nickname != "" {
		return u.Nickname
	}
	if u.OpenID != "" {
		return "WeChat " + shortID(u.OpenID)
	}
	return "WeChat User"
}

func NewServer(cfg Config) (*Server, error) {
	signer, err := NewJWTSigner(cfg)
	if err != nil {
		return nil, err
	}
	management, err := newWeChatManagementStore(cfg.WeChatManagementDataFile)
	if err != nil {
		return nil, fmt.Errorf("load WeChat management data: %w", err)
	}
	var cryptor *wechatCryptor
	if cfg.WeChatEncodingAESKey != "" {
		cryptor, err = newWeChatCryptor(cfg.WeChatAppID, cfg.WeChatEncodingAESKey)
		if err != nil {
			return nil, fmt.Errorf("configure WeChat callback encryption: %w", err)
		}
	}
	client := NewWeChatClient(cfg)
	s := &Server{
		cfg:                   cfg,
		wx:                    client,
		wxMenu:                client,
		signer:                signer,
		management:            management,
		wxCryptor:             cryptor,
		scans:                 make(map[string]*scanSession),
		authCodes:             make(map[string]authCode),
		accessTokens:          make(map[string]accessSession),
		webSessions:           make(map[string]webSession),
		usedTokens:            make(map[string]time.Time),
		wechatResponses:       make(map[string]wechatCachedResponse),
		wechatInFlight:        make(map[string]chan struct{}),
		wechatPlainSignatures: make(map[string]wechatPlainSignatureRecord),
		wechatLoginAttempts:   make(map[string]wechatLoginAttempt),
		loginCodes:            make(map[string]string),
	}
	go s.cleanupLoop()
	return s, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleOpenIDConfiguration)
	mux.HandleFunc("GET /oauth/jwks", s.handleJWKS)
	mux.HandleFunc("GET /oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("GET /oauth/userinfo", s.handleUserInfo)
	mux.HandleFunc("POST /oauth/userinfo", s.handleUserInfo)
	mux.HandleFunc("GET /login/wechat", s.handleLocalWeChatLogin)
	mux.HandleFunc("GET /scan/{id}", s.handleScanPage)
	mux.HandleFunc("GET /scan/{id}/complete", s.handleLocalScanComplete)
	mux.HandleFunc("GET /api/scan/{id}", s.handleScanStatus)
	mux.HandleFunc("GET /wechat/callback", s.handleWeChatCallback)
	mux.HandleFunc("POST /wechat/callback", s.handleWeChatCallback)
	mux.HandleFunc("GET /admin/wechat", s.handleWeChatAdminPage)
	mux.HandleFunc("GET /api/admin/wechat/state", s.handleWeChatAdminState)
	mux.HandleFunc("PUT /api/admin/wechat/replies", s.handleWeChatAdminReplies)
	mux.HandleFunc("PUT /api/admin/wechat/menu", s.handleWeChatAdminMenu)
	mux.HandleFunc("POST /api/admin/wechat/menu/publish", s.handleWeChatAdminMenuPublish)
	mux.HandleFunc("GET /api/admin/wechat/menu/remote", s.handleWeChatAdminMenuRemote)
	mux.HandleFunc("POST /api/admin/wechat/menu/remote/import-text-replies", s.handleWeChatAdminMenuKeywordImport)
	mux.HandleFunc("DELETE /api/admin/wechat/menu/remote", s.handleWeChatAdminMenuDelete)
	mux.HandleFunc("GET /api/me", s.handleAPIMe)
	mux.HandleFunc("POST /api/logout", s.handleAPILogout)
	mux.HandleFunc("/", s.handleHome)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "build_commit": buildCommit})
}

func (s *Server) createAuthCode(req oidcAuthRequest, user User) (string, error) {
	record := authCode{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Nonce:               req.Nonce,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		User:                user,
	}
	code, expiresAt, err := s.sealToken(sealedTokenTypeCode, s.cfg.AuthCodeTTL, record)
	if err != nil {
		return "", err
	}
	record.ExpiresAt = expiresAt
	s.mu.Lock()
	s.authCodes[code] = record
	s.mu.Unlock()
	return code, nil
}

func (s *Server) popAuthCode(code string) (authCode, bool) {
	record, _, ok := s.popAuthCodeWithReason(code)
	return record, ok
}

func (s *Server) popAuthCodeWithReason(code string) (authCode, string, bool) {
	if code == "" {
		return authCode{}, "missing authorization code", false
	}
	s.mu.Lock()
	record, ok := s.authCodes[code]
	if ok {
		delete(s.authCodes, code)
	}
	s.mu.Unlock()
	if ok {
		if time.Now().After(record.ExpiresAt) {
			return authCode{}, "authorization code expired", false
		}
		if marked, reason := s.markTokenUsed(sealedTokenTypeCode, code, record.ExpiresAt); !marked {
			return authCode{}, reason, false
		}
		return record, "", true
	}
	expiresAt, err := s.openToken(sealedTokenTypeCode, code, &record)
	if err != nil {
		return authCode{}, err.Error(), false
	}
	record.ExpiresAt = expiresAt
	if marked, reason := s.markTokenUsed(sealedTokenTypeCode, code, expiresAt); !marked {
		return authCode{}, reason, false
	}
	return record, "", true
}

func (s *Server) createAccessSession(clientID, scope string, user User) (string, accessSession, error) {
	session := accessSession{
		ClientID: clientID,
		Scope:    scope,
		User:     user,
	}
	token, expiresAt, err := s.sealToken(sealedTokenTypeAccess, s.cfg.AccessTokenTTL, session)
	if err != nil {
		return "", accessSession{}, err
	}
	session.ExpiresAt = expiresAt
	s.mu.Lock()
	s.accessTokens[token] = session
	s.mu.Unlock()
	return token, session, nil
}

func (s *Server) getAccessSession(token string) (accessSession, bool) {
	session, _, ok := s.getAccessSessionWithReason(token)
	return session, ok
}

func (s *Server) getAccessSessionWithReason(token string) (accessSession, string, bool) {
	if token == "" {
		return accessSession{}, "missing access token", false
	}
	s.mu.Lock()
	session, ok := s.accessTokens[token]
	if ok && time.Now().After(session.ExpiresAt) {
		delete(s.accessTokens, token)
		s.mu.Unlock()
		return accessSession{}, "access token expired in memory", false
	}
	s.mu.Unlock()
	if ok {
		return session, "", true
	}
	expiresAt, err := s.openToken(sealedTokenTypeAccess, token, &session)
	if err != nil {
		return accessSession{}, err.Error(), false
	}
	session.ExpiresAt = expiresAt
	return session, "", true
}

func (s *Server) createWebSession(w http.ResponseWriter, user User) error {
	token, err := randomToken(32)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.webSessions[token] = webSession{User: user, ExpiresAt: time.Now().Add(s.cfg.SessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionCookieName,
		Value:    s.signCookieValue(token),
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	})
	return nil
}

func (s *Server) clearWebSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.cfg.SessionCookieName); err == nil {
		if token, ok := s.verifyCookieValue(cookie.Value); ok {
			s.mu.Lock()
			delete(s.webSessions, token)
			s.mu.Unlock()
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Server) currentWebSession(r *http.Request) (webSession, bool) {
	cookie, err := r.Cookie(s.cfg.SessionCookieName)
	if err != nil {
		return webSession{}, false
	}
	token, ok := s.verifyCookieValue(cookie.Value)
	if !ok {
		return webSession{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.webSessions[token]
	if !ok || time.Now().After(session.ExpiresAt) {
		if ok {
			delete(s.webSessions, token)
		}
		return webSession{}, false
	}
	return session, true
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.cleanupExpired()
	}
}

func (s *Server) cleanupExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, value := range s.scans {
		if now.After(value.ExpiresAt.Add(time.Minute)) {
			if value.LoginCode != "" {
				delete(s.loginCodes, normalizeLoginCode(value.LoginCode))
			}
			delete(s.scans, key)
		}
	}
	for key, value := range s.authCodes {
		if now.After(value.ExpiresAt) {
			delete(s.authCodes, key)
		}
	}
	for key, value := range s.accessTokens {
		if now.After(value.ExpiresAt) {
			delete(s.accessTokens, key)
		}
	}
	for key, value := range s.webSessions {
		if now.After(value.ExpiresAt) {
			delete(s.webSessions, key)
		}
	}
	for key, expiresAt := range s.usedTokens {
		if now.After(expiresAt) {
			delete(s.usedTokens, key)
		}
	}
	for key, response := range s.wechatResponses {
		if now.After(response.ExpiresAt) {
			delete(s.wechatResponses, key)
		}
	}
	for key, record := range s.wechatPlainSignatures {
		if now.After(record.ExpiresAt) {
			delete(s.wechatPlainSignatures, key)
		}
	}
	for openID, attempt := range s.wechatLoginAttempts {
		if now.After(attempt.WindowStart.Add(wechatLoginAttemptWindow)) {
			delete(s.wechatLoginAttempts, openID)
		}
	}
}

func randomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomLoginCode() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return "", err
	}
	return formatLoginCode(value.Int64()), nil
}

func formatLoginCode(value int64) string {
	return fmt.Sprintf("%08d", value)
}

func normalizeLoginCode(value string) string {
	if len(value) != 8 {
		return ""
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return ""
		}
	}
	return value
}

func (s *Server) sealToken(tokenType string, ttl time.Duration, payload any) (string, time.Time, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt := time.Unix(now.Add(ttl).Unix(), 0).UTC()
	envelope := sealedTokenEnvelope{
		Type:      tokenType,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
		Payload:   payloadJSON,
	}
	plaintext, err := json.Marshal(envelope)
	if err != nil {
		return "", time.Time{}, err
	}
	aead, err := s.tokenAEAD()
	if err != nil {
		return "", time.Time{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, err
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, tokenAAD(tokenType))
	return sealedTokenVersion + "." + base64.RawURLEncoding.EncodeToString(ciphertext), expiresAt, nil
}

func (s *Server) openToken(tokenType, token string, payload any) (time.Time, error) {
	encoded, ok := strings.CutPrefix(token, sealedTokenVersion+".")
	if !ok {
		return time.Time{}, fmt.Errorf("unsupported token version")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode token: %w", err)
	}
	aead, err := s.tokenAEAD()
	if err != nil {
		return time.Time{}, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return time.Time{}, fmt.Errorf("token is too short")
	}
	nonce, sealed := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, tokenAAD(tokenType))
	if err != nil {
		return time.Time{}, fmt.Errorf("open token: %w", err)
	}
	var envelope sealedTokenEnvelope
	if err := json.Unmarshal(plaintext, &envelope); err != nil {
		return time.Time{}, fmt.Errorf("decode token envelope: %w", err)
	}
	if envelope.Type != tokenType {
		return time.Time{}, fmt.Errorf("token type %q does not match %q", envelope.Type, tokenType)
	}
	expiresAt := time.Unix(envelope.ExpiresAt, 0).UTC()
	if !time.Now().Before(expiresAt) {
		return time.Time{}, fmt.Errorf("token is expired")
	}
	if err := json.Unmarshal(envelope.Payload, payload); err != nil {
		return time.Time{}, fmt.Errorf("decode token payload: %w", err)
	}
	return expiresAt, nil
}

func (s *Server) tokenAEAD() (cipher.AEAD, error) {
	keyMaterial := append([]byte("wechat-connect sealed token v1\x00"), s.cfg.SessionSecret...)
	key := sha256.Sum256(keyMaterial)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func tokenAAD(tokenType string) []byte {
	return []byte(sealedTokenVersion + ":" + tokenType)
}

func (s *Server) markTokenUsed(tokenType, token string, expiresAt time.Time) (bool, string) {
	now := time.Now()
	if expiresAt.IsZero() || !now.Before(expiresAt) {
		return false, "token expired"
	}
	key := usedTokenKey(tokenType, token)
	s.mu.Lock()
	defer s.mu.Unlock()
	if previousExpiry, ok := s.usedTokens[key]; ok && now.Before(previousExpiry) {
		return false, "token already used in this process"
	}
	s.usedTokens[key] = expiresAt
	return true, ""
}

func usedTokenKey(tokenType, token string) string {
	sum := sha256.Sum256([]byte(tokenType + "\x00" + token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write json response: %v", err)
	}
}

func logOAuthInfo(r *http.Request, format string, args ...any) {
	logOAuth(r, "INFO", format, args...)
}

func logOAuthWarning(r *http.Request, format string, args ...any) {
	logOAuth(r, "WARN", format, args...)
}

func logOAuth(r *http.Request, level, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	log.Printf("oauth level=%s method=%s path=%s remote=%s %s", level, r.Method, r.URL.Path, r.RemoteAddr, message)
}

func tokenFingerprint(value string) string {
	if value == "" {
		return "empty"
	}
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil || !u.IsAbs() {
		writeOAuthError(w, http.StatusBadRequest, code, description)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func verifyPKCE(challenge, method, verifier string) bool {
	if challenge == "" {
		return true
	}
	if verifier == "" {
		return false
	}
	switch strings.ToUpper(method) {
	case "", "PLAIN":
		return hmac.Equal([]byte(challenge), []byte(verifier))
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		encoded := base64.RawURLEncoding.EncodeToString(sum[:])
		return hmac.Equal([]byte(challenge), []byte(encoded))
	default:
		return false
	}
}

func (s *Server) signCookieValue(token string) string {
	mac := hmac.New(sha256.New, s.cfg.SessionSecret)
	mac.Write([]byte(token))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return token + "." + signature
}

func (s *Server) verifyCookieValue(value string) (string, bool) {
	token, signature, ok := strings.Cut(value, ".")
	if !ok || token == "" || signature == "" {
		return "", false
	}
	expected := s.signCookieValue(token)
	_, expectedSignature, _ := strings.Cut(expected, ".")
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return "", false
	}
	return token, true
}

func validateRelativeReturnTo(value string) string {
	if value == "" {
		return "/"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || strings.HasPrefix(value, "//") {
		return "/"
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return "/"
	}
	return parsed.String()
}

func (s *Server) ensureWeChatConfigured() error {
	var missing []string
	if s.cfg.WeChatAppID == "" {
		missing = append(missing, "WECHAT_APP_ID")
	}
	if s.cfg.WeChatAppSecret == "" {
		missing = append(missing, "WECHAT_APP_SECRET")
	}
	if s.cfg.WeChatCallbackToken == "" {
		missing = append(missing, "WECHAT_CALLBACK_TOKEN")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s must be configured", strings.Join(missing, ", "))
	}
	return nil
}

func (u User) oidcClaims() map[string]any {
	name := u.DisplayName()
	claims := map[string]any{
		"sub":                u.Subject(),
		"name":               name,
		"nickname":           name,
		"preferred_username": "wechat_" + shortID(u.OpenID),
		"wechat_openid":      u.OpenID,
	}
	if u.UnionID != "" {
		claims["wechat_unionid"] = u.UnionID
	}
	if u.Picture != "" {
		claims["picture"] = u.Picture
	}
	if u.Gender != "" {
		claims["gender"] = u.Gender
	}
	if u.City != "" {
		claims["locale"] = strings.Trim(strings.Join([]string{u.Country, u.Province, u.City}, " "), " ")
	}
	return claims
}

func shortID(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}

func absoluteURL(base, path string) string {
	return strings.TrimRight(base, "/") + path
}

func formValue(r *http.Request, key string) string {
	return strings.TrimSpace(r.FormValue(key))
}

func decodeBasicAuth(r *http.Request) (string, string, bool) {
	clientID, clientSecret, ok := r.BasicAuth()
	return clientID, clientSecret, ok
}

func (s *Server) clientSecretMatches(actual string) bool {
	return hmac.Equal([]byte(s.cfg.OIDCClientSecret), []byte(actual))
}

func (s *Server) redirectAllowed(redirectURI string) bool {
	parsed, err := url.ParseRequestURI(redirectURI)
	if err != nil || !parsed.IsAbs() || isAuthentikFlowURL(parsed) {
		return false
	}
	if s.cfg.OIDCInsecureAllowAllRedirects {
		return true
	}
	_, ok := s.cfg.OIDCAllowedRedirectURIs[redirectURI]
	return ok
}

func publicError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprint(err)})
}

func publicMessage(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"message": message})
}

var errScanNotFound = errors.New("scan session not found")
