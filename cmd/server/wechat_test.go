package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestVerifyWeChatSignature(t *testing.T) {
	token := "callback-token"
	timestamp := "1720000000"
	nonce := "nonce"
	signature := testWeChatSignature(token, timestamp, nonce)

	if !verifyWeChatSignature(token, timestamp, nonce, signature) {
		t.Fatal("expected signature to verify")
	}
	if verifyWeChatSignature(token, timestamp, nonce, "bad") {
		t.Fatal("expected bad signature to be rejected")
	}
}

func TestSceneFromWeChatEvent(t *testing.T) {
	scene, ok := sceneFromWeChatEvent(wechatEventMessage{MsgType: "event", Event: "SCAN", EventKey: "login-123"})
	if !ok || scene != "login-123" {
		t.Fatalf("SCAN scene=%q ok=%t", scene, ok)
	}
	scene, ok = sceneFromWeChatEvent(wechatEventMessage{MsgType: "event", Event: "subscribe", EventKey: "qrscene_login-456"})
	if !ok || scene != "login-456" {
		t.Fatalf("subscribe scene=%q ok=%t", scene, ok)
	}
	if _, ok := sceneFromWeChatEvent(wechatEventMessage{MsgType: "text", EventKey: "login"}); ok {
		t.Fatal("expected non-event message to be ignored")
	}
	if _, ok := sceneFromWeChatEvent(wechatEventMessage{MsgType: "event", Event: "subscribe", EventKey: "login-456"}); ok {
		t.Fatal("expected subscribe without qrscene_ prefix not to be treated as a parameterized QR scan")
	}
}

func TestWeChatClientCreatesQRCodeAndFetchesUser(t *testing.T) {
	client := NewWeChatClient(testConfig())
	client.tokenEndpoint = "https://wechat.test/token"
	client.qrCodeEndpoint = "https://wechat.test/qrcode"
	client.userInfoEndpoint = "https://wechat.test/user"
	client.httpClient = &http.Client{Transport: wechatRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/token":
			if r.URL.Query().Get("appid") != "wx-app" || r.URL.Query().Get("secret") != "wx-secret" {
				t.Fatalf("unexpected token query: %s", r.URL.RawQuery)
			}
			return wechatJSONResponse(`{"access_token":"wx-token","expires_in":7200}`), nil
		case "/qrcode":
			if r.URL.Query().Get("access_token") != "wx-token" {
				t.Fatalf("unexpected QR token: %s", r.URL.RawQuery)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode QR request: %v", err)
			}
			if payload["action_name"] != "QR_STR_SCENE" {
				t.Fatalf("unexpected action_name: %#v", payload)
			}
			actionInfo := payload["action_info"].(map[string]any)
			scene := actionInfo["scene"].(map[string]any)
			if scene["scene_str"] != "scan-123" {
				t.Fatalf("unexpected scene: %#v", payload)
			}
			return wechatJSONResponse(`{"ticket":"ticket-123","expire_seconds":300,"url":"http://weixin.qq.com/q/test"}`), nil
		case "/user":
			if r.URL.Query().Get("access_token") != "wx-token" || r.URL.Query().Get("openid") != "openid-123" {
				t.Fatalf("unexpected user query: %s", r.URL.RawQuery)
			}
			return wechatJSONResponse(`{"openid":"openid-123","unionid":"union-123","nickname":"微信用户","sex":1,"headimgurl":"https://wx.example/avatar.jpg"}`), nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", r.URL.Path)
		}
	})}

	qr, err := client.CreateLoginQRCode(context.Background(), "scan-123", 5*time.Minute)
	if err != nil {
		t.Fatalf("create QR: %v", err)
	}
	if qr.Ticket != "ticket-123" || !strings.Contains(qr.ImageURL, "ticket=ticket-123") {
		t.Fatalf("unexpected QR response: %#v", qr)
	}

	user, err := client.FetchUser(context.Background(), "openid-123")
	if err != nil {
		t.Fatalf("fetch user: %v", err)
	}
	if user.OpenID != "openid-123" || user.UnionID != "union-123" || user.Gender != "male" {
		t.Fatalf("unexpected user: %#v", user)
	}
}

type wechatRoundTripFunc func(*http.Request) (*http.Response, error)

func (f wechatRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func wechatJSONResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestWeChatAccessTokenWaitHonorsContextDeadline(t *testing.T) {
	client := NewWeChatClient(testConfig())
	client.tokenRefresh = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := client.getAccessToken(ctx)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("get access token error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("context-aware token wait took %s", elapsed)
	}
}

func testWeChatSignature(token, timestamp, nonce string) string {
	parts := []string{token, timestamp, nonce}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	return hex.EncodeToString(sum[:])
}
