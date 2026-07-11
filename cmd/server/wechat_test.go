package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
}

func TestWeChatClientCreatesQRCodeAndFetchesUser(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("appid") != "wx-app" || r.URL.Query().Get("secret") != "wx-secret" {
			t.Fatalf("unexpected token query: %s", r.URL.RawQuery)
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "wx-token", "expires_in": 7200})
	})
	mux.HandleFunc("/qrcode", func(w http.ResponseWriter, r *http.Request) {
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
		writeJSON(w, http.StatusOK, map[string]any{"ticket": "ticket-123", "expire_seconds": 300, "url": "http://weixin.qq.com/q/test"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("access_token") != "wx-token" || r.URL.Query().Get("openid") != "openid-123" {
			t.Fatalf("unexpected user query: %s", r.URL.RawQuery)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"openid":     "openid-123",
			"unionid":    "union-123",
			"nickname":   "微信用户",
			"sex":        1,
			"headimgurl": "https://wx.example/avatar.jpg",
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	client := NewWeChatClient(testConfig())
	client.tokenEndpoint = api.URL + "/token"
	client.qrCodeEndpoint = api.URL + "/qrcode"
	client.userInfoEndpoint = api.URL + "/user"

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

func testWeChatSignature(token, timestamp, nonce string) string {
	parts := []string{token, timestamp, nonce}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	return hex.EncodeToString(sum[:])
}
