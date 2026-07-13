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
	"strconv"
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
	getCurrentHook  func()
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
	if f.getCurrentHook != nil {
		f.getCurrentHook()
	}
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
	for _, required := range []string{
		"sessionStorage", "If-Match", "window.confirm", "/api/admin/wechat/menu/remote/import-text-replies",
		"importKeywordRepliesButton", "importRemoteDraftButton", "menuPlatformNotice", "menuPermissionStatus",
		"读取成功不代表账号拥有发布权限", "直接发送完整按钮名称", "点击不会产生本服务可处理的 CLICK 事件",
		"丢弃尚未保存的回复编辑", "applyReplyState(saved.payload.replies)",
		"defaultReplyType", "addRuleButton",
	} {
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
		{method: http.MethodPost, path: "/api/admin/wechat/menu/remote/import-text-replies"},
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

func TestWeChatAdminImportsWebsiteTextMenuAsKeywordReplies(t *testing.T) {
	server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
	draft := validWeChatAdminTestMenu()
	if _, err := server.management.UpdateMenu(0, draft); err != nil {
		t.Fatalf("seed menu: %v", err)
	}
	manualRule := WeChatReplyRule{ID: "manual", Name: "manual", Enabled: true, Trigger: "text", Match: "exact", Pattern: "hello", Reply: WeChatReply{Type: "text", Content: "world"}}
	legacyRule := WeChatReplyRule{ID: legacyImportedMenuClickRulePrefix + "0123456789abcdef01234567", Name: "legacy API menu reply", Enabled: true, Trigger: "click", Match: "exact", Pattern: "help", Reply: WeChatReply{Type: "text", Content: "legacy help"}}
	if _, err := server.management.UpdateReplies(1, WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{manualRule, legacyRule}}); err != nil {
		t.Fatalf("seed replies: %v", err)
	}
	fake.current = json.RawMessage(currentWebsiteTextMenuFixture)
	imported := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/remote/import-text-replies", "", wechatAdminTestToken, `"2"`)
	if imported.Code != http.StatusOK || imported.Header().Get("ETag") != `"3"` {
		t.Fatalf("import status=%d ETag=%q body=%s", imported.Code, imported.Header().Get("ETag"), imported.Body.String())
	}
	state := server.management.Snapshot()
	if fake.getCurrentCalls != 1 || state.Revision != 3 || !reflect.DeepEqual(state.Menu, draft) || !state.Replies.Enabled || len(state.Replies.Rules) != 5 {
		t.Fatalf("current calls=%d imported state=%#v", fake.getCurrentCalls, state)
	}
	if !reflect.DeepEqual(state.Replies.Rules[0], manualRule) {
		t.Fatalf("manual rule was not preserved first: %#v", state.Replies.Rules)
	}
	legacyReply, legacyRuleID := state.Replies.SelectReply(WeChatInboundMessage{MsgType: "event", Event: "CLICK", EventKey: "help"})
	if legacyReply == nil || legacyReply.Content != "legacy help" || legacyRuleID != legacyRule.ID {
		t.Fatalf("legacy API menu reply was not preserved: reply=%#v rule=%q", legacyReply, legacyRuleID)
	}
	reply, ruleID := state.Replies.SelectReply(WeChatInboundMessage{MsgType: "text", Content: "关于此公众号"})
	if reply == nil || reply.Content != "你好，感谢关注！\n这里是公众号介绍。" || !strings.HasPrefix(ruleID, importedMenuKeywordRulePrefix) {
		t.Fatalf("keyword reply=%#v rule=%q", reply, ruleID)
	}
	if reply, _ := state.Replies.SelectReply(WeChatInboundMessage{MsgType: "event", Event: "CLICK", EventKey: "关于此公众号"}); reply != nil {
		t.Fatalf("keyword import unexpectedly created a CLICK reply: %#v", reply)
	}
}

func TestWeChatAdminKeywordImportFailureIsAtomic(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "duplicate", raw: `{"is_menu_open":0,"selfmenu_info":{"button":[{"type":"text","name":"帮助","value":"one"},{"type":"text","name":"帮助","value":"two"}]}}`, want: "duplicates"},
		{name: "login code", raw: `{"is_menu_open":0,"selfmenu_info":{"button":[{"type":"text","name":"12345678","value":"reserved"}]}}`, want: "reserved"},
		{name: "mixed action", raw: `{"is_menu_open":0,"selfmenu_info":{"button":[{"type":"text","name":"帮助","value":"reply"},{"type":"view","name":"网站","url":"https://example.com/"}]}}`, want: "cannot be imported"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
			original := WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{{ID: "manual", Name: "manual", Enabled: true, Trigger: "text", Match: "exact", Pattern: "hello", Reply: WeChatReply{Type: "text", Content: "world"}}}}
			if _, err := server.management.UpdateReplies(0, original); err != nil {
				t.Fatal(err)
			}
			fake.current = json.RawMessage(test.raw)
			recorder := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/remote/import-text-replies", "", wechatAdminTestToken, `"1"`)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), test.want) {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			state := server.management.Snapshot()
			if state.Revision != 1 || !reflect.DeepEqual(state.Replies, original) {
				t.Fatalf("failed import changed state=%#v", state)
			}
		})
	}
}

func TestWeChatAdminKeywordImportRejectsShadowedRulesAtomically(t *testing.T) {
	server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
	original := WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{{ID: "catch-all", Name: "catch all", Enabled: true, Trigger: "any_message", Match: "any", Reply: WeChatReply{Type: "text", Content: "default-like"}}}}
	if _, err := server.management.UpdateReplies(0, original); err != nil {
		t.Fatal(err)
	}
	fake.current = json.RawMessage(currentWebsiteTextMenuFixture)
	recorder := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/remote/import-text-replies", "", wechatAdminTestToken, `"1"`)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "catch-all") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	state := server.management.Snapshot()
	if state.Revision != 1 || !reflect.DeepEqual(state.Replies, original) {
		t.Fatalf("shadowed import changed state=%#v", state)
	}
}

func TestWeChatAdminKeywordImportIsRepeatableAndRevisionChecked(t *testing.T) {
	server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
	menu := validWeChatAdminTestMenu()
	if _, err := server.management.UpdateMenu(0, menu); err != nil {
		t.Fatal(err)
	}
	defaultReply := &WeChatReply{Type: "text", Content: "default"}
	manual := WeChatReplyRule{ID: "manual", Name: "manual", Enabled: true, Trigger: "text", Match: "exact", Pattern: "hello", Reply: WeChatReply{Type: "text", Content: "world"}}
	if _, err := server.management.UpdateReplies(1, WeChatReplySettings{Rules: []WeChatReplyRule{manual}, DefaultReply: defaultReply}); err != nil {
		t.Fatal(err)
	}
	fake.current = json.RawMessage(currentWebsiteTextMenuFixture)

	first := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/remote/import-text-replies", "", wechatAdminTestToken, `"2"`)
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	firstState := server.management.Snapshot()
	firstRules := cloneWeChatReplySettings(firstState.Replies).Rules

	staleReads := fake.getCurrentCalls
	stale := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/remote/import-text-replies", "", wechatAdminTestToken, `"2"`)
	if stale.Code != http.StatusPreconditionFailed || stale.Header().Get("ETag") != `"3"` || fake.getCurrentCalls != staleReads {
		t.Fatalf("stale status=%d ETag=%q reads=%d body=%s", stale.Code, stale.Header().Get("ETag"), fake.getCurrentCalls, stale.Body.String())
	}
	if !reflect.DeepEqual(server.management.Snapshot(), firstState) {
		t.Fatal("stale import changed state")
	}

	second := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/remote/import-text-replies", "", wechatAdminTestToken, `"3"`)
	if second.Code != http.StatusOK || second.Header().Get("ETag") != `"4"` {
		t.Fatalf("second status=%d ETag=%q body=%s", second.Code, second.Header().Get("ETag"), second.Body.String())
	}
	secondState := server.management.Snapshot()
	if !reflect.DeepEqual(secondState.Menu, menu) || !reflect.DeepEqual(secondState.Replies.Rules, firstRules) || !reflect.DeepEqual(secondState.Replies.DefaultReply, defaultReply) {
		t.Fatalf("repeat import changed data: first=%#v second=%#v", firstState, secondState)
	}
}

func TestWeChatAdminAPICurrentMenuImportDoesNotTouchReplies(t *testing.T) {
	server, _ := newWeChatAdminTestServer(t, wechatAdminTestToken)
	replies := WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{
		{ID: "manual-click", Name: "manual click", Enabled: true, Trigger: "click", Match: "exact", Pattern: "help", Reply: WeChatReply{Type: "text", Content: "help reply"}},
		{ID: importedMenuKeywordRulePrefix + "0123456789abcdef01234567", Name: "menu keyword", Enabled: true, Trigger: "text", Match: "exact", Pattern: "关于", Reply: WeChatReply{Type: "text", Content: "about"}},
	}}
	if _, err := server.management.UpdateReplies(0, replies); err != nil {
		t.Fatal(err)
	}
	raw := `{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"click","name":"帮助","key":"help"}]}}`
	first := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/menu", raw, wechatAdminTestToken, `"1"`)
	second := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/menu", raw, wechatAdminTestToken, `"2"`)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("first=%d %s second=%d %s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	if !reflect.DeepEqual(server.management.Snapshot().Replies, replies) {
		t.Fatalf("API menu import changed replies: %#v", server.management.Snapshot().Replies)
	}
}

func TestWeChatAdminKeywordImportGatewayAndCapacityFailuresAreAtomic(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*wechatAdminTestMenuService, *Server)
		want  int
	}{
		{name: "upstream failure", want: http.StatusBadGateway, setup: func(fake *wechatAdminTestMenuService, _ *Server) {
			fake.currentErr = errors.New("unavailable")
		}},
		{name: "invalid JSON", want: http.StatusBadGateway, setup: func(fake *wechatAdminTestMenuService, _ *Server) {
			fake.current = json.RawMessage(`not-json`)
		}},
		{name: "too many rules", want: http.StatusBadRequest, setup: func(fake *wechatAdminTestMenuService, server *Server) {
			rules := make([]WeChatReplyRule, maxWeChatReplyRules-2)
			for i := range rules {
				rules[i] = WeChatReplyRule{ID: "rule-" + strconv.Itoa(i), Name: "rule", Enabled: true, Trigger: "text", Match: "exact", Pattern: "value-" + strconv.Itoa(i), Reply: WeChatReply{Type: "text", Content: "reply"}}
			}
			if _, err := server.management.UpdateReplies(0, WeChatReplySettings{Enabled: true, Rules: rules}); err != nil {
				t.Fatalf("seed rules: %v", err)
			}
			fake.current = json.RawMessage(currentWebsiteTextMenuFixture)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
			test.setup(fake, server)
			before := server.management.Snapshot()
			recorder := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/remote/import-text-replies", "", wechatAdminTestToken, wechatManagementETag(before.Revision))
			if recorder.Code != test.want {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if !reflect.DeepEqual(server.management.Snapshot(), before) {
				t.Fatal("failed import changed state")
			}
		})
	}
}

func TestWeChatAdminKeywordImportPreservesConcurrentReplyUpdate(t *testing.T) {
	server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
	fake.current = json.RawMessage(currentWebsiteTextMenuFixture)
	concurrent := WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{{ID: "concurrent", Name: "concurrent", Enabled: true, Trigger: "text", Match: "exact", Pattern: "hello", Reply: WeChatReply{Type: "text", Content: "world"}}}}
	fake.getCurrentHook = func() {
		fake.getCurrentHook = nil
		if _, err := server.management.UpdateReplies(0, concurrent); err != nil {
			t.Fatalf("concurrent update: %v", err)
		}
	}
	recorder := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/remote/import-text-replies", "", wechatAdminTestToken, `"0"`)
	if recorder.Code != http.StatusPreconditionFailed || recorder.Header().Get("ETag") != `"1"` {
		t.Fatalf("status=%d ETag=%q body=%s", recorder.Code, recorder.Header().Get("ETag"), recorder.Body.String())
	}
	state := server.management.Snapshot()
	if state.Revision != 1 || !reflect.DeepEqual(state.Replies, concurrent) {
		t.Fatalf("concurrent state was overwritten: %#v", state)
	}
}

func TestWeChatAdminRejectedMenuImportDoesNotChangeState(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "inactive website menu", raw: currentWebsiteTextMenuFixture, want: "is_menu_open=0"},
		{name: "website media", raw: `{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"video","name":"视频","value":"https://example.com/video.mp4"}]}}`, want: "button[0]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := newWeChatAdminTestServer(t, wechatAdminTestToken)
			recorder := performWeChatAdminTestRequest(server, http.MethodPut, "/api/admin/wechat/menu", test.raw, wechatAdminTestToken, `"0"`)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), test.want) {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			state := server.management.Snapshot()
			if state.Revision != 0 || len(state.Menu.Button) != 0 || len(state.Replies.Rules) != 0 {
				t.Fatalf("rejected import changed state=%#v", state)
			}
		})
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

	t.Run("menu permission error explains read versus publish", func(t *testing.T) {
		server, fake := newWeChatAdminTestServer(t, wechatAdminTestToken)
		if _, err := server.management.UpdateMenu(0, validWeChatAdminTestMenu()); err != nil {
			t.Fatalf("seed menu: %v", err)
		}
		fake.publishErr = &wechatMenuAPIError{Operation: "publish", Code: 48001, Message: "api unauthorized"}
		before := server.management.Snapshot()
		recorder := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/publish", "", wechatAdminTestToken, `"1"`)
		var payload struct {
			Error           string `json:"error"`
			WeChatErrorCode int    `json:"wechat_error_code"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if recorder.Code != http.StatusBadGateway || payload.WeChatErrorCode != 48001 || !strings.Contains(payload.Error, "读取当前菜单的权限不代表可以发布") || !reflect.DeepEqual(server.management.Snapshot(), before) {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		retried := performWeChatAdminTestRequest(server, http.MethodPost, "/api/admin/wechat/menu/publish", "", wechatAdminTestToken, `"1"`)
		if retried.Code != http.StatusBadGateway || fake.publishCalls != 2 || !reflect.DeepEqual(server.management.Snapshot(), before) {
			t.Fatalf("retry status=%d calls=%d body=%s", retried.Code, fake.publishCalls, retried.Body.String())
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
