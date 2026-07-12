package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeWeChatService struct {
	user User
}

func (f fakeWeChatService) CreateLoginQRCode(_ context.Context, scene string, ttl time.Duration) (WeChatQRCode, error) {
	return WeChatQRCode{
		Ticket:      "ticket-" + scene,
		ImageURL:    "https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=ticket-" + url.QueryEscape(scene),
		ExpireAfter: ttl,
		URL:         "http://weixin.qq.com/q/" + scene,
	}, nil
}

func (f fakeWeChatService) FetchUser(_ context.Context, openID string) (User, error) {
	if f.user.OpenID != "" {
		return f.user, nil
	}
	return User{OpenID: openID}, nil
}

func testServer(t *testing.T) *Server {
	t.Helper()
	server, err := NewServer(testConfig())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	server.wx = fakeWeChatService{user: User{
		OpenID:   "openid-123",
		UnionID:  "union-123",
		Nickname: "微信用户",
		Picture:  "https://wx.example/avatar.jpg",
		Gender:   "male",
	}}
	return server
}

func testConfig() Config {
	return Config{
		ListenAddr:              ":0",
		PublicURL:               "https://wechat-connect.example.com",
		WeChatAppID:             "wx-app",
		WeChatAppSecret:         "wx-secret",
		WeChatCallbackToken:     "callback-token",
		WeChatQRCodeTTL:         5 * time.Minute,
		WeChatUserInfoLang:      "zh_CN",
		OIDCIssuer:              "https://wechat-connect.example.com",
		OIDCClientID:            "authentik",
		OIDCClientSecret:        "oidc-secret",
		OIDCAllowedRedirectURIs: map[string]struct{}{"https://authentik.example.com/source/oauth/callback/wechat-connect/": {}},
		SessionSecret:           []byte("0123456789abcdef0123456789abcdef"),
		SessionCookieName:       "wechat_connect_session",
		AuthCodeTTL:             10 * time.Minute,
		AccessTokenTTL:          time.Hour,
		SessionTTL:              24 * time.Hour,
	}
}

func TestOpenIDConfiguration(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if doc["issuer"] != server.cfg.OIDCIssuer {
		t.Fatalf("issuer=%v", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "https://wechat-connect.example.com/oauth/authorize" {
		t.Fatalf("authorization_endpoint=%v", doc["authorization_endpoint"])
	}
}

func TestAuthorizeRedirectsToScanPage(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodGet, authorizePath(), nil)
	rec := httptest.NewRecorder()

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "/scan/") {
		t.Fatalf("expected scan redirect, got %s", location)
	}
	scanID := strings.TrimPrefix(location, "/scan/")
	if scanID == "" {
		t.Fatalf("missing scan id in location: %s", location)
	}
	scan, ok := server.scanSnapshot(scanID)
	if !ok {
		t.Fatal("scan session was not stored")
	}
	if scan.OIDC.State != "ak-state" || scan.OIDC.Nonce != "nonce" {
		t.Fatalf("unexpected OIDC request: %#v", scan.OIDC)
	}
}

func TestWeChatCallbackGETEcho(t *testing.T) {
	server := testServer(t)
	timestamp := "1720000000"
	nonce := "nonce"
	signature := testWeChatSignature(server.cfg.WeChatCallbackToken, timestamp, nonce)
	req := httptest.NewRequest(http.MethodGet, "/wechat/callback?signature="+signature+"&timestamp="+timestamp+"&nonce="+nonce+"&echostr=hello", nil)
	rec := httptest.NewRecorder()

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "hello" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestFullOIDCFlowThroughWeChatEventCallback(t *testing.T) {
	server := testServer(t)

	authorizeRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(authorizeRec, httptest.NewRequest(http.MethodGet, authorizePath(), nil))
	if authorizeRec.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", authorizeRec.Code, authorizeRec.Body.String())
	}
	scanID := strings.TrimPrefix(authorizeRec.Header().Get("Location"), "/scan/")
	if scanID == "" {
		t.Fatalf("scan id missing: %s", authorizeRec.Header().Get("Location"))
	}

	callbackBody := fmt.Sprintf(`<xml>
	<ToUserName><![CDATA[gh_test]]></ToUserName>
	<FromUserName><![CDATA[openid-123]]></FromUserName>
	<CreateTime>1720000000</CreateTime>
	<MsgType><![CDATA[event]]></MsgType>
	<Event><![CDATA[SCAN]]></Event>
	<EventKey><![CDATA[%s]]></EventKey>
	<Ticket><![CDATA[ticket-%s]]></Ticket>
	</xml>`, wechatLoginScenePrefix+scanID, scanID)
	callbackReq := signedWeChatRequest(server, http.MethodPost, "/wechat/callback", strings.NewReader(callbackBody))
	callbackRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusOK || callbackRec.Body.String() != "success" {
		t.Fatalf("callback status=%d body=%s", callbackRec.Code, callbackRec.Body.String())
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/scan/"+scanID, nil)
	statusRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("scan status=%d body=%s", statusRec.Code, statusRec.Body.String())
	}
	var status map[string]any
	if err := json.Unmarshal(statusRec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status["status"] != "confirmed" {
		t.Fatalf("unexpected scan status: %#v", status)
	}
	authentikURL, err := url.Parse(status["redirect_url"].(string))
	if err != nil {
		t.Fatalf("parse redirect_url: %v", err)
	}
	if authentikURL.Path != "/source/oauth/callback/wechat-connect/" {
		t.Fatalf("unexpected callback URL: %s", authentikURL.String())
	}
	if authentikURL.Query().Get("state") != "ak-state" {
		t.Fatalf("state=%q want ak-state", authentikURL.Query().Get("state"))
	}
	authCode := authentikURL.Query().Get("code")
	if authCode == "" {
		t.Fatalf("auth code missing: %s", authentikURL.String())
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", authCode)
	form.Set("redirect_uri", "https://authentik.example.com/source/oauth/callback/wechat-connect/")
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("authentik:oidc-secret")))
	tokenRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokenResponse map[string]any
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	accessToken, ok := tokenResponse["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("missing access token: %#v", tokenResponse)
	}

	userInfoReq := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+accessToken)
	userInfoRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(userInfoRec, userInfoReq)
	if userInfoRec.Code != http.StatusOK {
		t.Fatalf("userinfo status=%d body=%s", userInfoRec.Code, userInfoRec.Body.String())
	}
	var claims map[string]any
	if err := json.Unmarshal(userInfoRec.Body.Bytes(), &claims); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if claims["sub"] != "wechat:openid-123" || claims["nickname"] != "微信用户" || claims["wechat_openid"] != "openid-123" || claims["wechat_unionid"] != "union-123" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestWeChatCallbackRejectsInvalidSignature(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/wechat/callback?signature=bad&timestamp=1720000000&nonce=nonce", strings.NewReader("<xml></xml>"))
	rec := httptest.NewRecorder()

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func authorizePath() string {
	return "/oauth/authorize?response_type=code&client_id=authentik&redirect_uri=https%3A%2F%2Fauthentik.example.com%2Fsource%2Foauth%2Fcallback%2Fwechat-connect%2F&scope=openid+profile&state=ak-state&nonce=nonce"
}

func signedWeChatRequest(server *Server, method, target string, body *strings.Reader) *http.Request {
	timestamp := "1720000000"
	nonce := "nonce"
	signature := testWeChatSignature(server.cfg.WeChatCallbackToken, timestamp, nonce)
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	return httptest.NewRequest(method, target+separator+"signature="+signature+"&timestamp="+timestamp+"&nonce="+nonce, body)
}
