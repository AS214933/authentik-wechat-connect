package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const wechatAdminTestToken = "admin-test-token"

type wechatAdminTestMenuService struct {
	publishCalls    int
	getMenuCalls    int
	getCurrentCalls int
	deleteCalls     int
	published       WeChatMenu
	current         json.RawMessage
	publishErr      error
	currentErr      error
	deleteErr       error
}

func (f *wechatAdminTestMenuService) PublishMenu(_ context.Context, menu WeChatMenu) error {
	f.publishCalls++
	f.published = cloneWeChatMenu(menu)
	return f.publishErr
}

func (f *wechatAdminTestMenuService) GetMenu(context.Context) (json.RawMessage, error) {
	f.getMenuCalls++
	return append(json.RawMessage(nil), f.current...), nil
}

func (f *wechatAdminTestMenuService) GetCurrentMenu(context.Context) (json.RawMessage, error) {
	f.getCurrentCalls++
	return append(json.RawMessage(nil), f.current...), f.currentErr
}

func (f *wechatAdminTestMenuService) DeleteMenu(context.Context) error {
	f.deleteCalls++
	return f.deleteErr
}

func TestWeChatAdminPageIsPublicAndCSPProtected(t *testing.T) {
	server, _ := newWeChatAdminTestServer(t, wechatAdminTestToken)
	recorder := performWeChatAdminTestRequest(server, http.MethodGet, "/admin/wechat", "", "", "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	csp := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(csp, "style-src 'nonce-") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("unexpected CSP=%q", csp)
	}
	body := recorder.Body.String()
	for _, required := range []string{"sessionStorage", "If-Match", "window.confirm", "/api/admin/wechat/menu/remote", "defaultReplyType", "addRuleButton"} {
		if !strings.Contains(body, required) {
			t.Errorf("admin page missing %q", required)
		}
	}
	for _, forbidden := range []string{"innerHTML", "localStorage", wechatAdminTestToken} {
		if strings.Contains(body, forbidden) {
			t.Errorf("admin page contains forbidden value %q", forbidden)
		}
	}
}

func TestWeChatAdminStateAuthenticationAndMetadata(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		server, _ := newWeChatAdminTestServer(t, "")
		recorder := performWeChatAdminTestRequest(server, http.MethodGet, "/api/admin/wechat/state", "", "", "")
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		assertWeChatAdminNoStore(t, recorder)
	})

	server, _ := newWeChatAdminTestServer(t, wechatAdminTestToken)
	server.cfg.WeChatAppSecret = "must-not-be-returned"
	server.wxCryptor = &wechatCryptor{}

	for _, tt := range []struct {
		name  string
		token string
	}{
		{name: "missing"},
		{name: "wrong", token: "wrong-token"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := performWeChatAdminTestRequest(server, http.MethodGet, "/api/admin/wechat/state", "", tt.token, "")
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if !strings.HasPrefix(recorder.Header().Get("WWW-Authenticate"), "Bearer ") {
				t.Fatalf("WWW-Authenticate=%q", recorder.Header().Get("WWW-Authenticate"))
			}
			assertWeChatAdminNoStore(t, recorder)
		})
	}

	recorder := performWeChatAdminTestRequest(server, http.MethodGet, "/api/admin/wechat/state", "", wechatAdminTestToken, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("ETag") != `"0"` {
		t.Fatalf("ETag=%q", recorder.Header().Get("ETag"))
	}
	assertWeChatAdminNoStore(t, recorder)
	var state struct {
		SchemaVersion int                 `json:"schema_version"`
		Revision      uint64              `json:"revision"`
		Replies       WeChatReplySettings `json:"replies"`
		Menu          WeChatMenu          `json:"menu"`
		CallbackURL   string              `json:"callback_url"`
		AESEnabled    bool                `json:"aes_enabled"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if state.SchemaVersion != wechatManagementSchemaVersion || state.Revision != 0 {
		t.Fatalf("state version=%d revision=%d", state.SchemaVersion, state.Revision)
	}
	if state.CallbackURL != "https://wechat.example/wechat/callback" || !state.AESEnabled {
		t.Fatalf("callback_url=%q aes_enabled=%t", state.CallbackURL, state.AESEnabled)
	}
	if strings.Contains(recorder.Body.String(), wechatAdminTestToken) || strings.Contains(recorder.Body.String(), server.cfg.WeChatAppSecret) {
		t.Fatalf("state leaked a secret: %s", recorder.Body.String())
	}
}

func TestEveryWeChatAdminAPIRequiresBearerToken(t *testing.T) {
	server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
	requests := []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodGet, path: "/api/admin/wechat/state"},
		{method: http.MethodPut, path: "/api/admin/wechat/replies", body: `{}`},
		{method: http.MethodPut, path: "/api/admin/wechat/menu", body: `{}`},
		{method: http.MethodPost, path: "/api/admin/wechat/menu/publish"},
		{method: http.MethodGet, path: "/api/admin/wechat/menu/remote"},
		{method: http.MethodDelete, path: "/api/admin/wechat/menu/remote"},
	}
	for _, request := range requests {
		t.Run(request.method+" "+request.path, func(t *testing.T) {
			recorder := performWeChatAdminTestRequest(server, request.method, request.path, request.body, "", `"0"`)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			assertWeChatAdminNoStore(t, recorder)
		})
	}
	if fake.publishCalls != 0 || fake.getCurrentCalls != 0 || fake.deleteCalls != 0 {
		t.Fatalf("unauthorized requests reached menu service: %#v", fake)
	}
}

func TestWeChatAdminRepliesETagSaveAndConflict(t *testing.T) {
	server, _ := newWeChatAdminTestServer(t, wechatAdminTestToken)
	body := `{"enabled":true,"rules":[],"default_reply":{"type":"text","content":"欢迎关注"}}`

	missing := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/replies", body, wechatAdminTestToken, "")
	if missing.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match status=%d body=%s", missing.Code, missing.Body.String())
	}
	weak := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/replies", body, wechatAdminTestToken, `W/"0"`)
	if weak.Code != http.StatusBadRequest {
		t.Fatalf("weak If-Match status=%d body=%s", weak.Code, weak.Body.String())
	}

	saved := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/replies", body, wechatAdminTestToken, `"0"`)
	if saved.Code != http.StatusOK {
		t.Fatalf("save status=%d body=%s", saved.Code, saved.Body.String())
	}
	if saved.Header().Get("ETag") != `"1"` {
		t.Fatalf("save ETag=%q", saved.Header().Get("ETag"))
	}
	snapshot := server.management.Snapshot()
	if snapshot.Revision != 1 || !snapshot.Replies.Enabled || snapshot.Replies.DefaultReply == nil || snapshot.Replies.DefaultReply.Content != "欢迎关注" {
		t.Fatalf("saved state=%#v", snapshot)
	}

	staleBody := `{"enabled":false,"rules":[]}`
	conflict := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/replies", staleBody, wechatAdminTestToken, `"0"`)
	if conflict.Code != http.StatusPreconditionFailed {
		t.Fatalf("conflict status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	if conflict.Header().Get("ETag") != `"1"` {
		t.Fatalf("conflict ETag=%q", conflict.Header().Get("ETag"))
	}
	if !server.management.Snapshot().Replies.Enabled {
		t.Fatal("stale update changed reply settings")
	}
}

func TestWeChatAdminRejectsInvalidAndOversizeJSON(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed", body: `{"enabled":`},
		{name: "unknown field", body: `{"enabled":false,"rules":[],"unknown":true}`},
		{name: "multiple values", body: `{"enabled":false,"rules":[]} {"enabled":true,"rules":[]}`},
		{name: "invalid settings", body: `{"enabled":true,"rules":[],"default_reply":{"type":"text"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, _ := newWeChatAdminTestServer(t, wechatAdminTestToken)
			recorder := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/replies", tt.body, wechatAdminTestToken, `"0"`)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if server.management.Snapshot().Revision != 0 {
				t.Fatal("invalid request changed management state")
			}
		})
	}

	server, _ := newWeChatAdminTestServer(t, wechatAdminTestToken)
	oversize := strings.Repeat(" ", maxWeChatAdminRequestBody+1)
	recorder := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/replies", oversize, wechatAdminTestToken, `"0"`)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestWeChatAdminStorageFailureReturnsGeneric500(t *testing.T) {
	server, _ := newWeChatAdminTestServer(t, wechatAdminTestToken)
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("create blocker: %v", err)
	}
	server.management.path = filepath.Join(blocker, "state.json")
	body := `{"enabled":false,"rules":[]}`
	recorder := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/replies", body, wechatAdminTestToken, `"0"`)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), blocker) {
		t.Fatalf("response leaked storage path: %s", recorder.Body.String())
	}
	if server.management.Snapshot().Revision != 0 {
		t.Fatal("failed persistence changed in-memory state")
	}
}

func TestWeChatAdminMenuSavePublishRemoteAndDelete(t *testing.T) {
	server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
	menu := validWeChatAdminTestMenu()
	menuJSON, err := json.Marshal(menu)
	if err != nil {
		t.Fatalf("encode menu: %v", err)
	}

	saved := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/menu", string(menuJSON), wechatAdminTestToken, `"0"`)
	if saved.Code != http.StatusOK || saved.Header().Get("ETag") != `"1"` {
		t.Fatalf("save status=%d ETag=%q body=%s", saved.Code, saved.Header().Get("ETag"), saved.Body.String())
	}
	if !reflect.DeepEqual(server.management.Snapshot().Menu, menu) {
		t.Fatalf("saved menu=%#v want %#v", server.management.Snapshot().Menu, menu)
	}

	published := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/publish", "", wechatAdminTestToken, `"1"`)
	if published.Code != http.StatusOK {
		t.Fatalf("publish status=%d body=%s", published.Code, published.Body.String())
	}
	if fake.publishCalls != 1 || !reflect.DeepEqual(fake.published, menu) {
		t.Fatalf("publish calls=%d menu=%#v", fake.publishCalls, fake.published)
	}

	fake.current = json.RawMessage(`{"is_menu_open":1,"selfmenu_info":{"button":[]}}`)
	remote := performWeChatAdminTestRequest(server, http.MethodGet, "/api/admin/wechat/menu/remote", "", wechatAdminTestToken, "")
	if remote.Code != http.StatusOK || remote.Body.String() != string(fake.current) {
		t.Fatalf("remote status=%d body=%q", remote.Code, remote.Body.String())
	}
	if fake.getCurrentCalls != 1 || fake.getMenuCalls != 0 {
		t.Fatalf("remote calls current=%d legacy=%d", fake.getCurrentCalls, fake.getMenuCalls)
	}

	deleted := performWeChatAdminTestRequest(server, http.MethodDelete, "/api/admin/wechat/menu/remote", "", wechatAdminTestToken, "")
	if deleted.Code != http.StatusOK || fake.deleteCalls != 1 || !strings.Contains(deleted.Body.String(), "message") {
		t.Fatalf("delete status=%d calls=%d body=%s", deleted.Code, fake.deleteCalls, deleted.Body.String())
	}
}

func TestWeChatAdminMenuPublishRequiresCurrentRevision(t *testing.T) {
	server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
	if _, err := server.management.UpdateMenu(0, validWeChatAdminTestMenu()); err != nil {
		t.Fatalf("seed menu: %v", err)
	}
	missing := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/publish", "", wechatAdminTestToken, "")
	if missing.Code != http.StatusPreconditionRequired || fake.publishCalls != 0 {
		t.Fatalf("missing If-Match status=%d calls=%d body=%s", missing.Code, fake.publishCalls, missing.Body.String())
	}
	if _, err := server.management.UpdateReplies(1, WeChatReplySettings{}); err != nil {
		t.Fatalf("advance management revision: %v", err)
	}
	stale := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/publish", "", wechatAdminTestToken, `"1"`)
	if stale.Code != http.StatusPreconditionFailed || stale.Header().Get("ETag") != `"2"` || fake.publishCalls != 0 {
		t.Fatalf("stale publish status=%d ETag=%q calls=%d body=%s", stale.Code, stale.Header().Get("ETag"), fake.publishCalls, stale.Body.String())
	}
}

func TestWeChatAdminMenuFailuresAreSafe(t *testing.T) {
	t.Run("empty publish", func(t *testing.T) {
		server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
		recorder := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/publish", "", wechatAdminTestToken, `"0"`)
		if recorder.Code != http.StatusBadRequest || fake.publishCalls != 0 {
			t.Fatalf("status=%d publish calls=%d body=%s", recorder.Code, fake.publishCalls, recorder.Body.String())
		}
	})

	const upstreamSecret = "upstream-access-token"
	tests := []struct {
		name   string
		method string
		path   string
		setup  func(*wechatAdminTestMenuService)
	}{
		{
			name: "publish", method: http.MethodPost, path: "/api/admin/wechat/menu/publish",
			setup: func(fake *wechatAdminTestMenuService) {
				fake.publishErr = errors.New(upstreamSecret + " " + wechatAdminTestToken)
			},
		},
		{
			name: "remote", method: http.MethodGet, path: "/api/admin/wechat/menu/remote",
			setup: func(fake *wechatAdminTestMenuService) {
				fake.currentErr = errors.New(upstreamSecret + " " + wechatAdminTestToken)
			},
		},
		{
			name: "delete", method: http.MethodDelete, path: "/api/admin/wechat/menu/remote",
			setup: func(fake *wechatAdminTestMenuService) {
				fake.deleteErr = errors.New(upstreamSecret + " " + wechatAdminTestToken)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
			if _, err := server.management.UpdateMenu(0, validWeChatAdminTestMenu()); err != nil {
				t.Fatalf("seed menu: %v", err)
			}
			tt.setup(fake)
			ifMatch := ""
			if tt.path == "/api/admin/wechat/menu/publish" {
				ifMatch = `"1"`
			}
			recorder := performWeChatAdminTestRequest(server, tt.method, tt.path, "", wechatAdminTestToken, ifMatch)
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), upstreamSecret) || strings.Contains(recorder.Body.String(), wechatAdminTestToken) {
				t.Fatalf("response leaked a token: %s", recorder.Body.String())
			}
		})
	}

	t.Run("invalid remote JSON", func(t *testing.T) {
		server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
		fake.current = json.RawMessage(`not-json`)
		recorder := performWeChatAdminTestRequest(server, http.MethodGet, "/api/admin/wechat/menu/remote", "", wechatAdminTestToken, "")
		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("typed WeChat error is actionable", func(t *testing.T) {
		server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
		if _, err := server.management.UpdateMenu(0, validWeChatAdminTestMenu()); err != nil {
			t.Fatalf("seed menu: %v", err)
		}
		fake.publishErr = &wechatMenuAPIError{Operation: "publish", Code: 40018, Message: "invalid button name size"}
		recorder := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/publish", "", wechatAdminTestToken, `"1"`)
		if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "40018") || !strings.Contains(recorder.Body.String(), "invalid button name size") {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})
}

func newWeChatAdminTestServer(t *testing.T, token string) (*Server, *wechatAdminTestMenuService) {
	t.Helper()
	store, err := newWeChatManagementStore("")
	if err != nil {
		t.Fatalf("create management store: %v", err)
	}
	fake := &wechatAdminTestMenuService{current: json.RawMessage(`{"is_menu_open":0}`)}
	return &Server{
		cfg: Config{
			PublicURL:        "https://wechat.example",
			WeChatAdminToken: token,
		},
		management: store,
		wxMenu:     fake,
	}, fake
}

func validWeChatAdminTestMenu() WeChatMenu {
	return WeChatMenu{Button: []WeChatMenuButton{
		{Type: "click", Name: "帮助", Key: "help"},
		{Name: "更多", SubButton: []WeChatMenuButton{{Type: "view", Name: "网站", URL: "https://example.com/"}}},
	}}
}

func performWeChatAdminTestRequest(server *Server, method, path, body, token, ifMatch string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func assertWeChatAdminNoStore(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q", recorder.Header().Get("Cache-Control"))
	}
}

var _ wechatMenuService = (*wechatAdminTestMenuService)(nil)
