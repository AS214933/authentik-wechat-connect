package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

const maxWeChatAdminRequestBody = 1 << 20

var wechatAdminPageTemplate = template.Must(template.New("wechat-admin").Parse(wechatAdminPageHTML))

type wechatAdminPageData struct {
	Nonce string
}

func (s *Server) handleWeChatAdminPage(w http.ResponseWriter, _ *http.Request) {
	nonceBytes := make([]byte, 18)
	if _, err := cryptorand.Read(nonceBytes); err != nil {
		log.Printf("generate WeChat admin CSP nonce: %v", err)
		http.Error(w, "unable to render admin page", http.StatusInternalServerError)
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)
	var page bytes.Buffer
	if err := wechatAdminPageTemplate.Execute(&page, wechatAdminPageData{Nonce: nonce}); err != nil {
		log.Printf("render WeChat admin page: %v", err)
		http.Error(w, "unable to render admin page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", nonce, nonce))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page.Bytes())
}

func (s *Server) handleWeChatAdminState(w http.ResponseWriter, r *http.Request) {
	if !s.requireWeChatAdmin(w, r) {
		return
	}
	if s.management == nil {
		publicError(w, http.StatusInternalServerError, errors.New("WeChat management store is unavailable"))
		return
	}
	s.writeWeChatAdminState(w, http.StatusOK, s.management.Snapshot())
}

func (s *Server) handleWeChatAdminReplies(w http.ResponseWriter, r *http.Request) {
	if !s.requireWeChatAdmin(w, r) {
		return
	}
	expectedRevision, ok := readWeChatAdminRevision(w, r)
	if !ok {
		return
	}
	var replies WeChatReplySettings
	if !decodeWeChatAdminRequest(w, r, &replies) {
		return
	}
	if err := replies.Validate(); err != nil {
		publicError(w, http.StatusBadRequest, fmt.Errorf("invalid reply settings: %w", err))
		return
	}
	if s.management == nil {
		publicError(w, http.StatusInternalServerError, errors.New("WeChat management store is unavailable"))
		return
	}

	state, err := s.management.UpdateReplies(expectedRevision, replies)
	if err != nil {
		s.handleWeChatManagementUpdateError(w, err)
		return
	}
	s.writeWeChatAdminState(w, http.StatusOK, state)
}

func (s *Server) handleWeChatAdminMenu(w http.ResponseWriter, r *http.Request) {
	if !s.requireWeChatAdmin(w, r) {
		return
	}
	expectedRevision, ok := readWeChatAdminRevision(w, r)
	if !ok {
		return
	}
	var menu WeChatMenu
	if !decodeWeChatAdminRequest(w, r, &menu) {
		return
	}
	if err := menu.Validate(); err != nil {
		publicError(w, http.StatusBadRequest, fmt.Errorf("invalid menu: %w", err))
		return
	}
	if s.management == nil {
		publicError(w, http.StatusInternalServerError, errors.New("WeChat management store is unavailable"))
		return
	}

	state, err := s.management.UpdateMenu(expectedRevision, menu)
	if err != nil {
		s.handleWeChatManagementUpdateError(w, err)
		return
	}
	s.writeWeChatAdminState(w, http.StatusOK, state)
}

func (s *Server) handleWeChatAdminMenuPublish(w http.ResponseWriter, r *http.Request) {
	if !s.requireWeChatAdmin(w, r) {
		return
	}
	expectedRevision, ok := readWeChatAdminRevision(w, r)
	if !ok {
		return
	}
	if s.management == nil {
		publicError(w, http.StatusInternalServerError, errors.New("WeChat management store is unavailable"))
		return
	}
	state := s.management.Snapshot()
	if expectedRevision != state.Revision {
		s.handleWeChatManagementUpdateError(w, fmt.Errorf("%w: expected %d, current %d", errManagementRevisionConflict, expectedRevision, state.Revision))
		return
	}
	if len(state.Menu.Button) == 0 {
		publicError(w, http.StatusBadRequest, errors.New("the saved menu draft is empty"))
		return
	}
	if err := state.Menu.Validate(); err != nil {
		publicError(w, http.StatusBadRequest, fmt.Errorf("invalid saved menu draft: %w", err))
		return
	}
	if s.wxMenu == nil {
		publicError(w, http.StatusBadGateway, errors.New("WeChat menu service is unavailable"))
		return
	}
	if err := s.wxMenu.PublishMenu(r.Context(), state.Menu); err != nil {
		s.writeWeChatMenuGatewayError(w, "publish", err)
		return
	}
	publicMessage(w, http.StatusOK, "saved menu draft published")
}

func (s *Server) handleWeChatAdminMenuRemote(w http.ResponseWriter, r *http.Request) {
	if !s.requireWeChatAdmin(w, r) {
		return
	}
	if s.wxMenu == nil {
		publicError(w, http.StatusBadGateway, errors.New("WeChat menu service is unavailable"))
		return
	}
	raw, err := s.wxMenu.GetCurrentMenu(r.Context())
	if err != nil {
		s.writeWeChatMenuGatewayError(w, "read current menu", err)
		return
	}
	if !json.Valid(raw) {
		log.Printf("read current WeChat menu: upstream returned invalid JSON")
		publicError(w, http.StatusBadGateway, errors.New("WeChat returned an invalid current-menu response"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleWeChatAdminMenuDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireWeChatAdmin(w, r) {
		return
	}
	if s.wxMenu == nil {
		publicError(w, http.StatusBadGateway, errors.New("WeChat menu service is unavailable"))
		return
	}
	if err := s.wxMenu.DeleteMenu(r.Context()); err != nil {
		s.writeWeChatMenuGatewayError(w, "delete", err)
		return
	}
	publicMessage(w, http.StatusOK, "remote custom menu deleted")
}

func (s *Server) writeWeChatMenuGatewayError(w http.ResponseWriter, operation string, err error) {
	var apiError *wechatMenuAPIError
	if errors.As(err, &apiError) {
		message := strings.Join(strings.Fields(apiError.Message), " ")
		if s.cfg.WeChatAdminToken != "" {
			message = strings.ReplaceAll(message, s.cfg.WeChatAdminToken, "[REDACTED]")
		}
		if len(message) > 512 {
			message = message[:512]
		}
		safeError := fmt.Errorf("WeChat menu %s failed with error %d: %s", operation, apiError.Code, message)
		log.Printf("%v", safeError)
		publicError(w, http.StatusBadGateway, safeError)
		return
	}
	safeError := fmt.Errorf("WeChat menu %s request failed", operation)
	log.Printf("%v", safeError)
	publicError(w, http.StatusBadGateway, safeError)
}

func (s *Server) requireWeChatAdmin(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	expected := s.cfg.WeChatAdminToken
	if expected == "" {
		publicError(w, http.StatusServiceUnavailable, errors.New("WeChat management API is disabled"))
		return false
	}

	provided := ""
	validFormat := false
	authorizationValues := r.Header.Values("Authorization")
	if len(authorizationValues) == 1 {
		scheme, credential, found := strings.Cut(authorizationValues[0], " ")
		validFormat = found && strings.EqualFold(scheme, "Bearer") && credential != "" && strings.TrimSpace(credential) == credential && !strings.ContainsAny(credential, " \t\r\n")
		provided = credential
	}
	expectedHash := sha256.Sum256([]byte(expected))
	providedHash := sha256.Sum256([]byte(provided))
	validToken := subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
	if !validFormat || !validToken {
		w.Header().Set("WWW-Authenticate", `Bearer realm="wechat-admin"`)
		publicError(w, http.StatusUnauthorized, errors.New("valid WeChat admin bearer token required"))
		return false
	}
	return true
}

func readWeChatAdminRevision(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	values := r.Header.Values("If-Match")
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		publicError(w, http.StatusPreconditionRequired, errors.New("If-Match revision is required"))
		return 0, false
	}
	if len(values) != 1 {
		publicError(w, http.StatusBadRequest, errors.New("If-Match must contain exactly one revision"))
		return 0, false
	}
	value := strings.TrimSpace(values[0])
	if strings.HasPrefix(value, "W/") {
		publicError(w, http.StatusBadRequest, errors.New("If-Match must be a strong revision ETag"))
		return 0, false
	}
	if strings.HasPrefix(value, `"`) || strings.HasSuffix(value, `"`) {
		if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
			publicError(w, http.StatusBadRequest, errors.New("If-Match contains an invalid revision ETag"))
			return 0, false
		}
		value = value[1 : len(value)-1]
	}
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(revision, 10) != value {
		publicError(w, http.StatusBadRequest, errors.New("If-Match must contain a canonical decimal revision"))
		return 0, false
	}
	return revision, true
}

func decodeWeChatAdminRequest(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxWeChatAdminRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeWeChatAdminDecodeError(w, err)
		return false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			publicError(w, http.StatusBadRequest, errors.New("request body must contain exactly one JSON value"))
		} else {
			writeWeChatAdminDecodeError(w, err)
		}
		return false
	}
	return true
}

func writeWeChatAdminDecodeError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		publicError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", maxWeChatAdminRequestBody))
		return
	}
	publicError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON request body: %w", err))
}

func (s *Server) handleWeChatManagementUpdateError(w http.ResponseWriter, err error) {
	if errors.Is(err, errManagementRevisionConflict) {
		if s.management != nil {
			w.Header().Set("ETag", wechatManagementETag(s.management.Snapshot().Revision))
		}
		publicError(w, http.StatusPreconditionFailed, errors.New("management revision changed; refresh before saving"))
		return
	}
	log.Printf("save WeChat management state: %v", err)
	publicError(w, http.StatusInternalServerError, errors.New("unable to save WeChat management state"))
}

func (s *Server) writeWeChatAdminState(w http.ResponseWriter, status int, state WeChatManagementState) {
	w.Header().Set("ETag", wechatManagementETag(state.Revision))
	response := struct {
		WeChatManagementState
		CallbackURL string `json:"callback_url"`
		AESEnabled  bool   `json:"aes_enabled"`
	}{
		WeChatManagementState: state,
		CallbackURL:           absoluteURL(s.cfg.PublicURL, "/wechat/callback"),
		AESEnabled:            s.wxCryptor != nil,
	}
	writeJSON(w, status, response)
}

func wechatManagementETag(revision uint64) string {
	return `"` + strconv.FormatUint(revision, 10) + `"`
}

const wechatAdminPageHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>微信公众号管理</title>
  <style nonce="{{.Nonce}}">
    :root {
      color-scheme: light;
      --bg: #f3f5f4;
      --surface: #ffffff;
      --text: #17201c;
      --muted: #66736d;
      --border: #d7dedb;
      --green: #087a55;
      --green-dark: #056443;
      --blue: #175cd3;
      --red: #b42318;
      --amber: #b54708;
      --focus: #84caff;
      --radius: 6px;
      font-family: Inter, "Noto Sans SC", "Microsoft YaHei", system-ui, sans-serif;
      letter-spacing: 0;
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-width: 320px; background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.5; }
    button, input, select, textarea { font: inherit; letter-spacing: 0; }
    button, input, select, textarea { border-radius: var(--radius); }
    button { min-height: 36px; border: 1px solid transparent; padding: 7px 12px; cursor: pointer; font-weight: 650; background: var(--green); color: #fff; }
    button:hover:not(:disabled) { background: var(--green-dark); }
    button:disabled { cursor: wait; opacity: .55; }
    button.secondary { border-color: var(--border); background: var(--surface); color: var(--text); }
    button.secondary:hover:not(:disabled) { background: #edf1ef; }
    button.danger { background: var(--red); }
    button.danger:hover:not(:disabled) { background: #8f1c13; }
    button.icon { width: 34px; min-width: 34px; min-height: 34px; padding: 0; border-color: var(--border); background: var(--surface); color: var(--text); font-size: 17px; }
    button.icon:hover:not(:disabled) { background: #edf1ef; }
    button.icon.danger { color: var(--red); }
    button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline: 3px solid var(--focus); outline-offset: 1px; }
    input, select, textarea { width: 100%; border: 1px solid #b9c4bf; background: #fff; color: var(--text); padding: 8px 10px; }
    input, select { min-height: 38px; }
    textarea { resize: vertical; min-height: 86px; }
    code, pre, textarea.json { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
    [hidden] { display: none !important; }
    .topbar { min-height: 62px; display: flex; align-items: center; gap: 16px; padding: 10px max(18px, calc((100% - 1180px) / 2)); border-bottom: 1px solid var(--border); background: var(--surface); }
    .brand { display: flex; align-items: center; gap: 10px; min-width: 210px; }
    .brand-mark { display: grid; place-items: center; width: 34px; height: 34px; border-radius: var(--radius); background: var(--green); color: #fff; font-size: 18px; font-weight: 800; }
    .brand strong { display: block; font-size: 16px; }
    .brand small { color: var(--muted); }
    .top-meta { margin-left: auto; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    .badge { display: inline-flex; align-items: center; min-height: 28px; padding: 4px 9px; border: 1px solid var(--border); border-radius: 999px; background: #f8faf9; color: var(--muted); white-space: nowrap; }
    .badge[data-tone="ok"] { border-color: #9bd7bd; color: #05603f; background: #ecfdf3; }
    .badge[data-tone="warn"] { border-color: #f6c98d; color: #8a3900; background: #fff8eb; }
    main { width: min(1180px, calc(100% - 36px)); margin: 24px auto 56px; }
    .login-panel { width: min(440px, 100%); margin: 11vh auto 0; padding: 24px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); box-shadow: 0 10px 28px rgba(23, 32, 28, .08); }
    h1, h2, h3, p { margin-top: 0; }
    h1 { margin-bottom: 18px; font-size: 21px; }
    h2 { margin-bottom: 4px; font-size: 18px; }
    h3 { margin-bottom: 0; font-size: 15px; }
    .login-actions, .actions, .rule-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .login-actions { margin-top: 14px; }
    .field { display: grid; align-content: start; gap: 6px; min-width: 0; }
    .field > span { color: #3e4b45; font-weight: 650; }
    .status { min-height: 22px; margin: 10px 0 0; color: var(--muted); overflow-wrap: anywhere; }
    .status[data-tone="ok"] { color: var(--green-dark); }
    .status[data-tone="error"] { color: var(--red); }
    .status[data-tone="pending"] { color: var(--blue); }
    .workspace { display: grid; grid-template-columns: 190px minmax(0, 1fr); gap: 24px; align-items: start; }
    .tabs { position: sticky; top: 18px; display: grid; gap: 5px; }
    .tab { width: 100%; justify-content: flex-start; text-align: left; border-color: transparent; background: transparent; color: #34423b; }
    .tab:hover:not(:disabled) { background: #e7ece9; }
    .tab[aria-selected="true"] { border-color: #9bd7bd; background: #e7f7ef; color: #05603f; }
    .panel { min-width: 0; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); }
    .section { padding: 22px; border-bottom: 1px solid var(--border); }
    .section:last-child { border-bottom: 0; }
    .section-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 18px; }
    .section-head p { margin: 3px 0 0; color: var(--muted); }
    .switch { display: inline-flex; align-items: center; gap: 9px; font-weight: 650; white-space: nowrap; }
    .switch input, .check input { width: 18px; height: 18px; min-height: 18px; accent-color: var(--green); }
    .check { display: inline-flex; align-items: center; gap: 7px; white-space: nowrap; }
    .form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
    .form-grid .wide { grid-column: 1 / -1; }
    .rule-list { display: grid; gap: 12px; }
    .rule-card { border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; background: #fbfcfb; }
    .rule-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 14px; }
    .rule-title { display: flex; align-items: center; gap: 10px; min-width: 0; }
    .rule-title code { color: var(--muted); overflow-wrap: anywhere; }
    .empty { padding: 28px 14px; border: 1px dashed #b9c4bf; border-radius: var(--radius); text-align: center; color: var(--muted); }
    .menu-editor { min-height: 390px; line-height: 1.55; tab-size: 2; }
    .remote-output { min-height: 150px; max-height: 420px; margin: 14px 0 0; overflow: auto; padding: 14px; border: 1px solid var(--border); border-radius: var(--radius); background: #111815; color: #d6e3dc; white-space: pre-wrap; overflow-wrap: anywhere; }
    .callback { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 8px 12px; margin: 0; }
    .callback dt { color: var(--muted); }
    .callback dd { margin: 0; overflow-wrap: anywhere; }
    @media (max-width: 760px) {
      .topbar { align-items: flex-start; flex-wrap: wrap; padding: 10px 16px; }
      .top-meta { width: 100%; margin-left: 0; justify-content: flex-start; }
      main { width: min(100% - 24px, 680px); margin-top: 14px; }
      .workspace { grid-template-columns: 1fr; gap: 12px; }
      .tabs { position: static; grid-template-columns: 1fr 1fr; }
      .tab { text-align: center; }
      .section { padding: 16px; }
      .section-head, .rule-head { align-items: stretch; flex-direction: column; }
      .form-grid { grid-template-columns: 1fr; }
      .form-grid .wide { grid-column: auto; }
      .rule-actions { justify-content: flex-end; }
      .callback { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <span class="brand-mark" aria-hidden="true">微</span>
      <span><strong>微信公众号管理</strong><small>消息回复与自定义菜单</small></span>
    </div>
    <div class="top-meta">
      <span id="revisionBadge" class="badge">Revision --</span>
      <span id="aesBadge" class="badge">AES --</span>
      <button id="refreshButton" class="secondary" type="button" hidden>↻ 刷新</button>
      <button id="logoutButton" class="secondary" type="button" hidden>退出</button>
    </div>
  </header>

  <main>
    <section id="loginPanel" class="login-panel">
      <h1>管理令牌登录</h1>
      <form id="tokenForm">
        <label class="field">
          <span>Bearer Token</span>
          <input id="tokenInput" type="password" autocomplete="current-password" required>
        </label>
        <div class="login-actions">
          <button id="loginButton" type="submit">登录</button>
        </div>
      </form>
      <p id="loginStatus" class="status" role="status" aria-live="polite"></p>
    </section>

    <div id="workspace" class="workspace" hidden>
      <nav class="tabs" aria-label="管理视图">
        <button class="tab" type="button" data-panel="replyPanel" aria-selected="true">自动回复</button>
        <button class="tab" type="button" data-panel="menuPanel" aria-selected="false">自定义菜单</button>
      </nav>

      <div>
        <section id="replyPanel" class="panel">
          <div class="section">
            <div class="section-head">
              <div><h2>回复设置</h2><p id="callbackURL"></p></div>
              <label class="switch"><input id="replyEnabled" type="checkbox">启用自动回复</label>
            </div>
            <div class="form-grid">
              <label class="field">
                <span>默认回复</span>
                <select id="defaultReplyType"></select>
              </label>
              <label id="defaultReplyContentField" class="field">
                <span>默认文本</span>
                <textarea id="defaultReplyContent" maxlength="2048"></textarea>
              </label>
            </div>
          </div>
          <div class="section">
            <div class="section-head">
              <div><h2>回复规则</h2><p id="ruleCount"></p></div>
              <button id="addRuleButton" type="button">＋ 添加规则</button>
            </div>
            <div id="ruleList" class="rule-list"></div>
          </div>
          <div class="section">
            <div class="actions">
              <button id="saveRepliesButton" type="button">保存回复设置</button>
            </div>
            <p id="replyStatus" class="status" role="status" aria-live="polite"></p>
          </div>
        </section>

        <section id="menuPanel" class="panel" hidden>
          <div class="section">
            <div class="section-head"><div><h2>菜单草稿</h2></div></div>
            <label class="field">
              <span>菜单 JSON</span>
              <textarea id="menuEditor" class="json menu-editor" spellcheck="false"></textarea>
            </label>
            <div class="actions">
              <button id="saveMenuButton" type="button">保存草稿</button>
              <button id="publishMenuButton" class="secondary" type="button">发布已保存草稿</button>
            </div>
            <p id="menuStatus" class="status" role="status" aria-live="polite"></p>
          </div>
          <div class="section">
            <div class="section-head">
              <div><h2>远端菜单</h2></div>
              <div class="actions">
                <button id="readRemoteButton" class="secondary" type="button">读取远端</button>
                <button id="deleteRemoteButton" class="danger" type="button">删除远端</button>
              </div>
            </div>
            <pre id="remoteOutput" class="remote-output">尚未读取</pre>
            <p id="remoteStatus" class="status" role="status" aria-live="polite"></p>
          </div>
        </section>
      </div>
    </div>
  </main>

  <script nonce="{{.Nonce}}">
  (function () {
    "use strict";

    var tokenStorageKey = "wechat.admin.token";
    var adminToken = sessionStorage.getItem(tokenStorageKey) || "";
    var revision = 0;
    var revisionETag = "";
    var rules = [];
    var defaultReply = null;

    var triggerOptions = [
      ["any_message", "任意标准消息"], ["text", "文本"], ["image", "图片"],
      ["voice", "语音"], ["video", "视频"], ["shortvideo", "短视频"],
      ["location", "位置"], ["link", "链接"], ["subscribe", "关注事件"],
      ["unsubscribe", "取消关注"], ["scan", "参数二维码扫码"], ["click", "菜单点击"],
      ["view", "菜单链接"], ["scancode_push", "菜单扫码"], ["scancode_waitmsg", "菜单扫码等待"],
      ["pic_sysphoto", "菜单拍照"], ["pic_photo_or_album", "菜单相册"],
      ["pic_weixin", "菜单微信相册"], ["location_select", "菜单位置"],
      ["view_miniprogram", "菜单小程序"]
    ];
    var matchOptions = [
      ["any", "任意"], ["exact", "完全匹配"], ["contains", "包含"],
      ["prefix", "前缀"], ["regex", "正则表达式"]
    ];
    var replyTypeOptions = [
      ["text", "文本"], ["image", "图片 Media ID"], ["voice", "语音 Media ID"],
      ["video", "视频 Media ID"], ["official_ai", "官方 AI"], ["customer_service", "转客服"]
    ];
    var defaultTypeOptions = [
      ["none", "无"], ["text", "文本"], ["official_ai", "官方 AI"], ["customer_service", "转客服"]
    ];

    function byID(id) { return document.getElementById(id); }

    function setStatus(id, message, tone) {
      var target = byID(id);
      target.textContent = message || "";
      target.dataset.tone = tone || "";
    }

    function clone(value) {
      return value == null ? value : JSON.parse(JSON.stringify(value));
    }

    function showLogin(message) {
      byID("loginPanel").hidden = false;
      byID("workspace").hidden = true;
      byID("refreshButton").hidden = true;
      byID("logoutButton").hidden = true;
      if (message) { setStatus("loginStatus", message, "error"); }
    }

    function showWorkspace() {
      byID("loginPanel").hidden = true;
      byID("workspace").hidden = false;
      byID("refreshButton").hidden = false;
      byID("logoutButton").hidden = false;
      setStatus("loginStatus", "", "");
    }

    async function request(path, options) {
      options = options || {};
      var headers = new Headers(options.headers || {});
      headers.set("Authorization", "Bearer " + adminToken);
      if (options.body != null) { headers.set("Content-Type", "application/json"); }
      var response = await fetch(path, {
        method: options.method || "GET",
        headers: headers,
        body: options.body,
        cache: "no-store",
        credentials: "same-origin"
      });
      var raw = await response.text();
      var payload = null;
      if (raw) {
        try { payload = JSON.parse(raw); } catch (_) { payload = null; }
      }
      if (!response.ok) {
        var message = payload && payload.error ? payload.error : "请求失败 (" + response.status + ")";
        var error = new Error(message);
        error.status = response.status;
        error.response = response;
        if (response.status === 401) {
          sessionStorage.removeItem(tokenStorageKey);
          adminToken = "";
        }
        throw error;
      }
      return { response: response, payload: payload, raw: raw };
    }

    function updateRevision(result) {
      if (result.payload && result.payload.revision != null) {
        revision = result.payload.revision;
      }
      revisionETag = result.response.headers.get("ETag") || ("\"" + String(revision) + "\"");
      byID("revisionBadge").textContent = "Revision " + String(revision);
    }

    async function loadState() {
      setStatus("loginStatus", "正在验证...", "pending");
      try {
        var result = await request("/api/admin/wechat/state");
        var state = result.payload || {};
        updateRevision(result);
        rules = clone(state.replies && Array.isArray(state.replies.rules) ? state.replies.rules : []);
        defaultReply = clone(state.replies ? state.replies.default_reply : null);
        byID("replyEnabled").checked = Boolean(state.replies && state.replies.enabled);
        byID("menuEditor").value = JSON.stringify(state.menu || { button: [] }, null, 2);
        byID("callbackURL").textContent = state.callback_url || "";
        byID("aesBadge").textContent = state.aes_enabled ? "AES 已启用" : "AES 未启用";
        byID("aesBadge").dataset.tone = state.aes_enabled ? "ok" : "warn";
        renderDefaultReply();
        renderRules();
        showWorkspace();
      } catch (error) {
        if (error.status === 401) {
          showLogin("管理令牌无效");
        } else if (error.status === 503) {
          showLogin("管理 API 未启用");
        } else {
          showLogin(error.message);
        }
      }
    }

    function makeElement(tag, className, text) {
      var element = document.createElement(tag);
      if (className) { element.className = className; }
      if (text !== undefined) { element.textContent = text; }
      return element;
    }

    function optionList(base, current) {
      var options = base.slice();
      var known = options.some(function (item) { return item[0] === current; });
      if (current && !known) { options.push([current, "保留类型：" + current]); }
      return options;
    }

    function makeSelect(options, current, onChange) {
      var select = makeElement("select");
      options.forEach(function (item) {
        var option = makeElement("option", "", item[1]);
        option.value = item[0];
        select.appendChild(option);
      });
      select.value = current;
      select.addEventListener("change", function () { onChange(select.value); });
      return select;
    }

    function makeField(labelText, control, wide) {
      var label = makeElement("label", "field" + (wide ? " wide" : ""));
      label.appendChild(makeElement("span", "", labelText));
      label.appendChild(control);
      return label;
    }

    function renderDefaultReply() {
      var type = defaultReply && defaultReply.type ? defaultReply.type : "none";
      var select = byID("defaultReplyType");
      select.replaceChildren();
      optionList(defaultTypeOptions, type).forEach(function (item) {
        var option = makeElement("option", "", item[1]);
        option.value = item[0];
        select.appendChild(option);
      });
      select.value = type;
      byID("defaultReplyContentField").hidden = type !== "text";
      byID("defaultReplyContent").value = type === "text" && defaultReply ? (defaultReply.content || "") : "";
    }

    function renderRules() {
      var list = byID("ruleList");
      list.replaceChildren();
      byID("ruleCount").textContent = String(rules.length) + " 条，按显示顺序匹配";
      if (rules.length === 0) {
        list.appendChild(makeElement("div", "empty", "暂无规则"));
        return;
      }

      rules.forEach(function (rule, index) {
        if (!rule.reply) { rule.reply = { type: "text", content: "" }; }
        var card = makeElement("article", "rule-card");
        var head = makeElement("div", "rule-head");
        var title = makeElement("div", "rule-title");
        title.appendChild(makeElement("h3", "", "规则 " + String(index + 1)));
        title.appendChild(makeElement("code", "", rule.id || "--"));
        head.appendChild(title);

        var actions = makeElement("div", "rule-actions");
        var enabledLabel = makeElement("label", "check");
        var enabled = makeElement("input");
        enabled.type = "checkbox";
        enabled.checked = Boolean(rule.enabled);
        enabled.addEventListener("change", function () { rule.enabled = enabled.checked; });
        enabledLabel.appendChild(enabled);
        enabledLabel.appendChild(makeElement("span", "", "启用"));
        actions.appendChild(enabledLabel);

        var up = makeElement("button", "icon", "↑");
        up.type = "button";
        up.title = "上移";
        up.setAttribute("aria-label", "上移规则");
        up.disabled = index === 0;
        up.addEventListener("click", function () {
          var previous = rules[index - 1]; rules[index - 1] = rules[index]; rules[index] = previous; renderRules();
        });
        actions.appendChild(up);

        var down = makeElement("button", "icon", "↓");
        down.type = "button";
        down.title = "下移";
        down.setAttribute("aria-label", "下移规则");
        down.disabled = index === rules.length - 1;
        down.addEventListener("click", function () {
          var next = rules[index + 1]; rules[index + 1] = rules[index]; rules[index] = next; renderRules();
        });
        actions.appendChild(down);

        var remove = makeElement("button", "icon danger", "×");
        remove.type = "button";
        remove.title = "删除";
        remove.setAttribute("aria-label", "删除规则");
        remove.addEventListener("click", function () { rules.splice(index, 1); renderRules(); });
        actions.appendChild(remove);
        head.appendChild(actions);
        card.appendChild(head);

        var grid = makeElement("div", "form-grid");
        var nameInput = makeElement("input");
        nameInput.value = rule.name || "";
        nameInput.maxLength = 120;
        nameInput.addEventListener("input", function () { rule.name = nameInput.value; });
        grid.appendChild(makeField("名称", nameInput, false));

        grid.appendChild(makeField("触发类型", makeSelect(optionList(triggerOptions, rule.trigger), rule.trigger || "text", function (value) { rule.trigger = value; }), false));

        var matchSelect = makeSelect(optionList(matchOptions, rule.match), rule.match || "contains", function (value) {
          rule.match = value;
          if (value === "any") { rule.pattern = ""; }
          renderRules();
        });
        grid.appendChild(makeField("匹配方式", matchSelect, false));

        var patternInput = makeElement("input");
        patternInput.value = rule.pattern || "";
        patternInput.maxLength = 512;
        patternInput.disabled = (rule.match || "contains") === "any";
        patternInput.addEventListener("input", function () { rule.pattern = patternInput.value; });
        grid.appendChild(makeField("匹配内容", patternInput, false));

        var replyType = rule.reply.type || "text";
        var replySelect = makeSelect(optionList(replyTypeOptions, replyType), replyType, function (value) {
          rule.reply = { type: value };
          renderRules();
        });
        grid.appendChild(makeField("回复类型", replySelect, false));

        if (replyType === "text") {
          var content = makeElement("textarea");
          content.value = rule.reply.content || "";
          content.maxLength = 2048;
          content.addEventListener("input", function () { rule.reply.content = content.value; });
          grid.appendChild(makeField("回复文本", content, true));
        } else if (["image", "voice", "video"].indexOf(replyType) !== -1) {
          var media = makeElement("input");
          media.value = rule.reply.media_id || "";
          media.maxLength = 128;
          media.addEventListener("input", function () { rule.reply.media_id = media.value; });
          grid.appendChild(makeField("Media ID", media, false));
        }
        card.appendChild(grid);
        list.appendChild(card);
      });
    }

    function makeRuleID() {
      if (window.crypto && typeof window.crypto.randomUUID === "function") { return window.crypto.randomUUID(); }
      return "rule-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
    }

    function operationError(error) {
      if (error.status === 412) { return "版本冲突，请刷新状态后重试"; }
      if (error.status === 428) { return "缺少版本信息，请刷新状态"; }
      if (error.status === 401) { showLogin("管理令牌已失效"); }
      return error.message;
    }

    async function runOperation(button, statusID, pendingMessage, successMessage, operation) {
      button.disabled = true;
      setStatus(statusID, pendingMessage, "pending");
      try {
        await operation();
        setStatus(statusID, successMessage, "ok");
      } catch (error) {
        setStatus(statusID, operationError(error), "error");
      } finally {
        button.disabled = false;
      }
    }

    byID("tokenForm").addEventListener("submit", async function (event) {
      event.preventDefault();
      var token = byID("tokenInput").value.trim();
      if (!token) { setStatus("loginStatus", "请输入管理令牌", "error"); return; }
      adminToken = token;
      sessionStorage.setItem(tokenStorageKey, token);
      byID("loginButton").disabled = true;
      await loadState();
      byID("loginButton").disabled = false;
    });

    byID("logoutButton").addEventListener("click", function () {
      sessionStorage.removeItem(tokenStorageKey);
      adminToken = "";
      byID("tokenInput").value = "";
      showLogin("");
    });

    byID("refreshButton").addEventListener("click", async function () {
      var button = byID("refreshButton");
      button.disabled = true;
      await loadState();
      button.disabled = false;
    });

    document.querySelectorAll(".tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        document.querySelectorAll(".tab").forEach(function (item) { item.setAttribute("aria-selected", "false"); });
        tab.setAttribute("aria-selected", "true");
        byID("replyPanel").hidden = tab.dataset.panel !== "replyPanel";
        byID("menuPanel").hidden = tab.dataset.panel !== "menuPanel";
      });
    });

    byID("defaultReplyType").addEventListener("change", function () {
      var type = byID("defaultReplyType").value;
      if (type === "none") { defaultReply = null; }
      else if (!defaultReply || defaultReply.type !== type) { defaultReply = { type: type }; }
      renderDefaultReply();
    });

    byID("defaultReplyContent").addEventListener("input", function () {
      if (defaultReply && defaultReply.type === "text") { defaultReply.content = byID("defaultReplyContent").value; }
    });

    byID("addRuleButton").addEventListener("click", function () {
      rules.push({
        id: makeRuleID(), name: "新规则", enabled: true, trigger: "text",
        match: "contains", pattern: "", reply: { type: "text", content: "" }
      });
      renderRules();
    });

    byID("saveRepliesButton").addEventListener("click", function () {
      var button = byID("saveRepliesButton");
      runOperation(button, "replyStatus", "正在保存...", "回复设置已保存", async function () {
        var result = await request("/api/admin/wechat/replies", {
          method: "PUT",
          headers: { "If-Match": revisionETag },
          body: JSON.stringify({ enabled: byID("replyEnabled").checked, rules: rules, default_reply: defaultReply })
        });
        updateRevision(result);
      });
    });

    byID("saveMenuButton").addEventListener("click", function () {
      var button = byID("saveMenuButton");
      var menu;
      try { menu = JSON.parse(byID("menuEditor").value); }
      catch (error) { setStatus("menuStatus", "菜单 JSON 无效：" + error.message, "error"); return; }
      runOperation(button, "menuStatus", "正在保存...", "菜单草稿已保存", async function () {
        var result = await request("/api/admin/wechat/menu", {
          method: "PUT", headers: { "If-Match": revisionETag }, body: JSON.stringify(menu)
        });
        updateRevision(result);
        if (result.payload && result.payload.menu) {
          byID("menuEditor").value = JSON.stringify(result.payload.menu, null, 2);
        }
      });
    });

    byID("publishMenuButton").addEventListener("click", function () {
      var button = byID("publishMenuButton");
      runOperation(button, "menuStatus", "正在发布...", "菜单已发布", async function () {
        await request("/api/admin/wechat/menu/publish", { method: "POST", headers: { "If-Match": revisionETag } });
      });
    });

    byID("readRemoteButton").addEventListener("click", function () {
      var button = byID("readRemoteButton");
      runOperation(button, "remoteStatus", "正在读取...", "远端菜单已读取", async function () {
        var result = await request("/api/admin/wechat/menu/remote");
        byID("remoteOutput").textContent = result.payload ? JSON.stringify(result.payload, null, 2) : result.raw;
      });
    });

    byID("deleteRemoteButton").addEventListener("click", function () {
      if (!window.confirm("确认删除微信公众号当前远端自定义菜单？")) { return; }
      var button = byID("deleteRemoteButton");
      runOperation(button, "remoteStatus", "正在删除...", "远端菜单已删除", async function () {
        await request("/api/admin/wechat/menu/remote", { method: "DELETE" });
        byID("remoteOutput").textContent = "远端菜单已删除";
      });
    });

    if (adminToken) { loadState(); } else { showLogin(""); }
  }());
  </script>
</body>
</html>`
