package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewWeChatClientHasOfficialMenuEndpoints(t *testing.T) {
	client := NewWeChatClient(testConfig())
	if client.menuCreateEndpoint != "https://api.weixin.qq.com/cgi-bin/menu/create" {
		t.Fatalf("create endpoint=%q", client.menuCreateEndpoint)
	}
	if client.menuGetEndpoint != "https://api.weixin.qq.com/cgi-bin/menu/get" {
		t.Fatalf("get endpoint=%q", client.menuGetEndpoint)
	}
	if client.menuCurrentEndpoint != "https://api.weixin.qq.com/cgi-bin/get_current_selfmenu_info" {
		t.Fatalf("current endpoint=%q", client.menuCurrentEndpoint)
	}
	if client.menuDeleteEndpoint != "https://api.weixin.qq.com/cgi-bin/menu/delete" {
		t.Fatalf("delete endpoint=%q", client.menuDeleteEndpoint)
	}
}

func TestWeChatMenuClientUsesOfficialMethodsPathsAndPayloads(t *testing.T) {
	menu := validTestWeChatMenu()
	const menuJSON = `{"menu":{"button":[{"type":"click","name":"Help","key":"help"}]}}`
	const currentJSON = `{"is_menu_open":1,"selfmenu_info":{"button":[]}}`

	var tokenRequests atomic.Int32
	var createRequests atomic.Int32
	var getRequests atomic.Int32
	var currentRequests atomic.Int32
	var deleteRequests atomic.Int32
	client := newMenuTestClient(menuRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/token":
			tokenRequests.Add(1)
			if r.Method != http.MethodGet {
				t.Errorf("token request method=%s", r.Method)
			}
			if got := r.URL.Query().Get("grant_type"); got != "client_credential" {
				t.Errorf("grant_type=%q", got)
			}
			if got := r.URL.Query().Get("appid"); got != "wx-app" {
				t.Errorf("appid=%q", got)
			}
			if got := r.URL.Query().Get("secret"); got != "wx-secret" {
				t.Errorf("secret=%q", got)
			}
			return menuJSONResponse(`{"access_token":"menu-token","expires_in":7200}`), nil
		case "/cgi-bin/menu/create":
			createRequests.Add(1)
			assertMenuAPIRequest(t, r, http.MethodPost, "/cgi-bin/menu/create", "menu-token")
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("create Content-Type=%q", got)
			}
			var got WeChatMenu
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decode create menu: %v", err)
			} else if !reflect.DeepEqual(got, menu) {
				t.Errorf("create menu=%#v want %#v", got, menu)
			}
			return menuJSONResponse(`{"errcode":0,"errmsg":"ok"}`), nil
		case "/cgi-bin/menu/get":
			getRequests.Add(1)
			assertMenuAPIRequest(t, r, http.MethodGet, "/cgi-bin/menu/get", "menu-token")
			assertEmptyRequestBody(t, r)
			return menuJSONResponse(menuJSON), nil
		case "/cgi-bin/get_current_selfmenu_info":
			currentRequests.Add(1)
			assertMenuAPIRequest(t, r, http.MethodGet, "/cgi-bin/get_current_selfmenu_info", "menu-token")
			assertEmptyRequestBody(t, r)
			return menuJSONResponse(currentJSON), nil
		case "/cgi-bin/menu/delete":
			deleteRequests.Add(1)
			assertMenuAPIRequest(t, r, http.MethodGet, "/cgi-bin/menu/delete", "menu-token")
			assertEmptyRequestBody(t, r)
			return menuJSONResponse(`{"errcode":0,"errmsg":"ok"}`), nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))

	if err := client.PublishMenu(context.Background(), menu); err != nil {
		t.Fatalf("publish menu: %v", err)
	}
	gotMenu, err := client.GetMenu(context.Background())
	if err != nil {
		t.Fatalf("get menu: %v", err)
	}
	if string(gotMenu) != menuJSON {
		t.Fatalf("get menu=%s want %s", gotMenu, menuJSON)
	}
	gotCurrent, err := client.GetCurrentMenu(context.Background())
	if err != nil {
		t.Fatalf("get current menu: %v", err)
	}
	if string(gotCurrent) != currentJSON {
		t.Fatalf("current menu=%s want %s", gotCurrent, currentJSON)
	}
	if err := client.DeleteMenu(context.Background()); err != nil {
		t.Fatalf("delete menu: %v", err)
	}

	if got := tokenRequests.Load(); got != 1 {
		t.Fatalf("token requests=%d want 1", got)
	}
	if createRequests.Load() != 1 || getRequests.Load() != 1 || currentRequests.Load() != 1 || deleteRequests.Load() != 1 {
		t.Fatalf("menu request counts create=%d get=%d current=%d delete=%d", createRequests.Load(), getRequests.Load(), currentRequests.Load(), deleteRequests.Load())
	}
}

func TestWeChatMenuClientValidatesBeforeRequest(t *testing.T) {
	var requests atomic.Int32
	client := newMenuTestClient(menuRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return menuJSONResponse(`{"access_token":"unexpected","expires_in":7200}`), nil
	}))
	invalid := WeChatMenu{Button: []WeChatMenuButton{{Type: "click", Name: "Missing key"}}}
	if err := client.PublishMenu(context.Background(), invalid); err == nil || !strings.Contains(err.Error(), "key is required") {
		t.Fatalf("publish invalid menu error=%v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests=%d want 0", got)
	}
}

func TestWeChatMenuClientReturnsBusinessErrorWithoutToken(t *testing.T) {
	const sensitiveToken = "sensitive-menu-token"
	client := newMenuTestClient(menuRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/token":
			return menuJSONResponse(`{"access_token":"` + sensitiveToken + `","expires_in":7200}`), nil
		case "/cgi-bin/menu/create":
			return menuJSONResponse(`{"errcode":40018,"errmsg":"invalid button name size"}`), nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	err := client.PublishMenu(context.Background(), validTestWeChatMenu())
	if err == nil || !strings.Contains(err.Error(), "40018") || !strings.Contains(err.Error(), "invalid button name size") {
		t.Fatalf("business error=%v", err)
	}
	if strings.Contains(err.Error(), sensitiveToken) {
		t.Fatalf("business error leaked access token: %v", err)
	}
}

func TestWeChatMenuClientRequiresExplicitMutationErrCode(t *testing.T) {
	for _, operation := range []string{"publish", "delete"} {
		t.Run(operation, func(t *testing.T) {
			client := newMenuTestClient(menuRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/token":
					return menuJSONResponse(`{"access_token":"menu-token","expires_in":7200}`), nil
				case "/cgi-bin/menu/create", "/cgi-bin/menu/delete":
					return menuJSONResponse(`{}`), nil
				default:
					return nil, fmt.Errorf("unexpected request path %q", r.URL.Path)
				}
			}))
			var err error
			if operation == "publish" {
				err = client.PublishMenu(context.Background(), validTestWeChatMenu())
			} else {
				err = client.DeleteMenu(context.Background())
			}
			if err == nil || !strings.Contains(err.Error(), "errcode is required") {
				t.Fatalf("operation error=%v", err)
			}
		})
	}
}

func TestWeChatMenuClientRefreshesInvalidTokenOnce(t *testing.T) {
	for _, code := range []int{40001, 40014, 42001} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var tokenRequests atomic.Int32
			var menuRequests atomic.Int32
			client := newMenuTestClient(menuRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/token":
					requestNumber := tokenRequests.Add(1)
					return menuJSONResponse(fmt.Sprintf(`{"access_token":"token-%d","expires_in":7200}`, requestNumber)), nil
				case "/cgi-bin/menu/get":
					requestNumber := menuRequests.Add(1)
					if requestNumber == 1 {
						if got := r.URL.Query().Get("access_token"); got != "token-1" {
							t.Errorf("first access_token=%q", got)
						}
						return menuJSONResponse(fmt.Sprintf(`{"errcode":%d,"errmsg":"invalid credential"}`, code)), nil
					}
					if got := r.URL.Query().Get("access_token"); got != "token-2" {
						t.Errorf("retry access_token=%q", got)
					}
					return menuJSONResponse(`{"menu":{"button":[]}}`), nil
				default:
					return nil, fmt.Errorf("unexpected request path %q", r.URL.Path)
				}
			}))

			raw, err := client.GetMenu(context.Background())
			if err != nil {
				t.Fatalf("get menu after refresh: %v", err)
			}
			if string(raw) != `{"menu":{"button":[]}}` {
				t.Fatalf("menu response=%s", raw)
			}
			if tokenRequests.Load() != 2 || menuRequests.Load() != 2 {
				t.Fatalf("requests token=%d menu=%d want 2 each", tokenRequests.Load(), menuRequests.Load())
			}
		})
	}
}

func TestWeChatMenuClientDoesNotRetryInvalidTokenMoreThanOnce(t *testing.T) {
	var tokenRequests atomic.Int32
	var menuRequests atomic.Int32
	client := newMenuTestClient(menuRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/token":
			requestNumber := tokenRequests.Add(1)
			return menuJSONResponse(fmt.Sprintf(`{"access_token":"expired-token-%d","expires_in":7200}`, requestNumber)), nil
		case "/cgi-bin/menu/get":
			menuRequests.Add(1)
			return menuJSONResponse(`{"errcode":42001,"errmsg":"access token expired"}`), nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	_, err := client.GetMenu(context.Background())
	if err == nil || !strings.Contains(err.Error(), "42001") {
		t.Fatalf("get menu error=%v", err)
	}
	if tokenRequests.Load() != 2 || menuRequests.Load() != 2 {
		t.Fatalf("requests token=%d menu=%d want 2 each", tokenRequests.Load(), menuRequests.Load())
	}
	client.mu.Lock()
	cachedToken := client.accessToken
	client.mu.Unlock()
	if cachedToken != "" {
		t.Fatalf("known invalid token remained cached: %q", cachedToken)
	}
}

func TestWeChatClientConcurrentMenuRequestsFetchTokenOnce(t *testing.T) {
	var tokenRequests atomic.Int32
	client := newMenuTestClient(menuRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/token":
			tokenRequests.Add(1)
			time.Sleep(25 * time.Millisecond)
			return menuJSONResponse(`{"access_token":"shared-token","expires_in":7200}`), nil
		case "/cgi-bin/menu/get":
			if got := r.URL.Query().Get("access_token"); got != "shared-token" {
				t.Errorf("access_token=%q", got)
			}
			return menuJSONResponse(`{"menu":{"button":[]}}`), nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))

	const workers = 24
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := client.GetMenu(context.Background())
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent get menu: %v", err)
		}
	}
	if got := tokenRequests.Load(); got != 1 {
		t.Fatalf("token requests=%d want 1", got)
	}
}

func TestInvalidateWeChatAccessTokenOnlyClearsMatchingValue(t *testing.T) {
	client := NewWeChatClient(testConfig())
	client.accessToken = "new-token"
	client.tokenExpiry = time.Now().Add(time.Hour)

	client.invalidateAccessToken("old-token")
	if client.accessToken != "new-token" {
		t.Fatalf("non-matching invalidation cleared token: %q", client.accessToken)
	}
	client.invalidateAccessToken("new-token")
	if client.accessToken != "" || !client.tokenExpiry.IsZero() {
		t.Fatalf("matching invalidation left token=%q expiry=%v", client.accessToken, client.tokenExpiry)
	}
}

func validTestWeChatMenu() WeChatMenu {
	return WeChatMenu{Button: []WeChatMenuButton{
		{Type: "click", Name: "Help", Key: "help"},
		{
			Name: "More",
			SubButton: []WeChatMenuButton{
				{Type: "view", Name: "Website", URL: "https://example.com/"},
			},
		},
	}}
}

func newMenuTestClient(transport http.RoundTripper) *WeChatClient {
	client := NewWeChatClient(testConfig())
	client.tokenEndpoint = "https://wechat.test/token"
	client.menuCreateEndpoint = "https://wechat.test/cgi-bin/menu/create"
	client.menuGetEndpoint = "https://wechat.test/cgi-bin/menu/get"
	client.menuCurrentEndpoint = "https://wechat.test/cgi-bin/get_current_selfmenu_info"
	client.menuDeleteEndpoint = "https://wechat.test/cgi-bin/menu/delete"
	client.httpClient = &http.Client{Transport: transport, Timeout: 2 * time.Second}
	return client
}

type menuRoundTripFunc func(*http.Request) (*http.Response, error)

func (f menuRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func menuJSONResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func assertMenuAPIRequest(t *testing.T, r *http.Request, method, path, token string) {
	t.Helper()
	if r.Method != method || r.URL.Path != path {
		t.Errorf("menu request method=%s path=%s, want %s %s", r.Method, r.URL.Path, method, path)
	}
	query := r.URL.Query()
	if got := query.Get("access_token"); got != token {
		t.Errorf("access_token=%q want %q", got, token)
	}
	if len(query) != 1 {
		t.Errorf("menu request query=%v, want only access_token", query)
	}
}

func assertEmptyRequestBody(t *testing.T, r *http.Request) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read request body: %v", err)
		return
	}
	if len(body) != 0 {
		t.Errorf("request body=%q want empty", body)
	}
}
