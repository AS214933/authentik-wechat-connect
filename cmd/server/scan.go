package main

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const wechatLoginScenePrefix = "login:"

var scanPageTemplate = template.Must(template.New("scan").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>微信登录</title>
  <style>
    :root { color-scheme: light; --green:#07c160; --ink:#17233d; --muted:#6b778c; --line:#dfe4ea; --bg:#f5f7fa; --danger:#d93026; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:var(--ink); background:var(--bg); display:grid; place-items:center; padding:24px; }
    main { width:min(440px,100%); background:#fff; border:1px solid var(--line); border-radius:8px; padding:28px; box-shadow:0 16px 48px rgba(23,35,61,.08); }
    .brand { display:flex; align-items:center; gap:10px; margin-bottom:20px; font-weight:700; }
    .mark { width:28px; height:28px; border-radius:7px; background:var(--green); display:grid; place-items:center; color:#fff; font-weight:800; }
    h1 { font-size:24px; line-height:1.25; margin:0 0 8px; letter-spacing:0; }
    p { margin:0; color:var(--muted); line-height:1.6; }
    .qr { margin:24px auto 18px; width:min(280px,100%); aspect-ratio:1; border:1px solid var(--line); border-radius:8px; display:grid; place-items:center; background:#fff; padding:12px; }
    .qr img { display:block; width:100%; height:100%; object-fit:contain; }
    .status { display:flex; align-items:center; gap:10px; border-top:1px solid var(--line); padding-top:18px; min-height:44px; }
    .dot { width:12px; height:12px; border-radius:50%; background:var(--green); box-shadow:0 0 0 0 rgba(7,193,96,.48); animation:pulse 1.4s infinite; flex:0 0 auto; }
    .status.error .dot { background:var(--danger); animation:none; }
    .status.done .dot { animation:none; }
    .status strong { display:block; font-size:15px; }
    .status span { color:var(--muted); font-size:13px; }
    .actions { display:flex; gap:10px; margin-top:18px; }
    a.button { display:inline-flex; align-items:center; justify-content:center; height:40px; padding:0 14px; border-radius:7px; border:1px solid var(--line); color:var(--ink); text-decoration:none; font-size:14px; }
    @keyframes pulse { 0% { box-shadow:0 0 0 0 rgba(7,193,96,.48); } 70% { box-shadow:0 0 0 10px rgba(7,193,96,0); } 100% { box-shadow:0 0 0 0 rgba(7,193,96,0); } }
  </style>
</head>
<body>
  <main>
    <div class="brand"><div class="mark">微</div><div>Authentik WeChat Connect</div></div>
    <h1>请使用微信扫码登录</h1>
    <p>扫码后页面会自动完成绑定/登录并返回 Authentik。</p>
    <div class="qr"><img src="{{.QRImageURL}}" alt="微信登录二维码"></div>
    <div id="status" class="status">
      <div class="dot"></div>
      <div><strong id="status-title">等待扫码确认</strong><span id="status-detail">二维码将在 {{.ExpiresInSeconds}} 秒后过期</span></div>
    </div>
    <div class="actions"><a class="button" href="/">返回首页</a></div>
  </main>
  <script>
    const scanID = {{printf "%q" .ID}};
    const statusBox = document.getElementById("status");
    const title = document.getElementById("status-title");
    const detail = document.getElementById("status-detail");
    async function poll() {
      try {
        const response = await fetch("/api/scan/" + encodeURIComponent(scanID), { cache: "no-store" });
        const data = await response.json();
        if (data.status === "confirmed") {
          statusBox.className = "status done";
          title.textContent = "绑定/登录成功";
          detail.textContent = "正在返回 Authentik";
          window.setTimeout(() => { window.location.href = data.redirect_url || "/"; }, 900);
          return;
        }
        if (data.status === "expired") {
          statusBox.className = "status error";
          title.textContent = "二维码已过期";
          detail.textContent = "请重新发起微信登录";
          return;
        }
        if (data.status === "error") {
          statusBox.className = "status error";
          title.textContent = "登录未完成";
          detail.textContent = data.error || "请重新发起微信登录";
          return;
        }
      } catch (error) {
        detail.textContent = "网络不稳定，正在重试";
      }
      window.setTimeout(poll, 1400);
    }
    poll();
  </script>
</body>
</html>`))

type scanPageData struct {
	ID               string
	QRImageURL       string
	ExpiresInSeconds int
}

func (s *Server) createScanSession(ctx context.Context, kind string, oidc oidcAuthRequest, returnTo string) (scanSession, error) {
	id, err := randomToken(scanSessionIDBytes)
	if err != nil {
		return scanSession{}, err
	}
	qr, err := s.wx.CreateLoginQRCode(ctx, wechatLoginScenePrefix+id, s.cfg.WeChatQRCodeTTL)
	if err != nil {
		return scanSession{}, err
	}
	now := time.Now()
	ttl := s.cfg.WeChatQRCodeTTL
	if qr.ExpireAfter > 0 && qr.ExpireAfter < ttl {
		ttl = qr.ExpireAfter
	}
	scan := &scanSession{
		ID:         id,
		Kind:       kind,
		OIDC:       oidc,
		ReturnTo:   returnTo,
		QRImageURL: qr.ImageURL,
		Ticket:     qr.Ticket,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
	}
	s.mu.Lock()
	s.scans[id] = scan
	s.mu.Unlock()
	return *scan, nil
}

func (s *Server) handleScanPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, ok := s.scanSnapshot(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	expiresIn := int(time.Until(scan.ExpiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	if err := scanPageTemplate.Execute(w, scanPageData{
		ID:               scan.ID,
		QRImageURL:       scan.QRImageURL,
		ExpiresInSeconds: expiresIn,
	}); err != nil {
		logOAuthWarning(r, "render scan page failed scan_id_fp=%s: %v", tokenFingerprint(id), err)
	}
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, ok := s.scanSnapshot(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"status": "missing"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	response := map[string]any{
		"id":         scan.ID,
		"expires_at": scan.ExpiresAt.UTC().Format(time.RFC3339),
	}
	switch {
	case scan.Error != "":
		response["status"] = "error"
		response["error"] = scan.Error
	case time.Now().After(scan.ExpiresAt) && scan.User.OpenID == "":
		response["status"] = "expired"
	case scan.User.OpenID != "" && scan.RedirectURL != "":
		response["status"] = "confirmed"
		response["redirect_url"] = scan.RedirectURL
	default:
		response["status"] = "pending"
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) scanSnapshot(id string) (scanSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scan, ok := s.scans[id]
	if !ok {
		return scanSession{}, false
	}
	return *scan, true
}

func (s *Server) completeScan(r *http.Request, scene string, user User) error {
	scene = strings.TrimSpace(scene)
	if !strings.HasPrefix(scene, wechatLoginScenePrefix) {
		return errScanNotFound
	}
	scene = strings.TrimPrefix(scene, wechatLoginScenePrefix)
	if scene == "" {
		return errScanNotFound
	}
	s.mu.Lock()
	scan, ok := s.scans[scene]
	if !ok {
		s.mu.Unlock()
		return errScanNotFound
	}
	if time.Now().After(scan.ExpiresAt) {
		scan.Error = "二维码已过期"
		s.mu.Unlock()
		return nil
	}
	if scan.User.OpenID != "" || scan.Completing {
		s.mu.Unlock()
		return nil
	}
	scan.Completing = true
	kind := scan.Kind
	oidcReq := scan.OIDC
	returnTo := scan.ReturnTo
	s.mu.Unlock()

	var authCode string
	var redirectURL string
	var err error
	switch kind {
	case scanKindOIDC:
		authCode, err = s.createAuthCode(oidcReq, user)
		if err == nil {
			redirectURL, err = s.authentikRedirectURL(oidcReq, authCode)
		}
	case scanKindLocal:
		redirectURL = "/scan/" + url.PathEscape(scene) + "/complete?return_to=" + url.QueryEscape(validateRelativeReturnTo(returnTo))
	default:
		err = errScanNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	scan, ok = s.scans[scene]
	if !ok {
		return errScanNotFound
	}
	scan.Completing = false
	if err != nil {
		scan.Error = err.Error()
		return err
	}
	scan.User = user
	scan.AuthCode = authCode
	scan.RedirectURL = redirectURL
	scan.CompletedAt = time.Now()
	return nil
}

func (s *Server) handleLocalWeChatLogin(w http.ResponseWriter, r *http.Request) {
	if err := s.ensureWeChatConfigured(); err != nil {
		logOAuthWarning(r, "local wechat login rejected: %v", err)
		publicError(w, http.StatusServiceUnavailable, err)
		return
	}
	scan, err := s.createScanSession(r.Context(), scanKindLocal, oidcAuthRequest{}, validateRelativeReturnTo(r.URL.Query().Get("return_to")))
	if err != nil {
		logOAuthWarning(r, "local wechat login failed: create scan session: %v", err)
		publicError(w, http.StatusBadGateway, err)
		return
	}
	http.Redirect(w, r, "/scan/"+url.PathEscape(scan.ID), http.StatusFound)
}

func (s *Server) handleLocalScanComplete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, ok := s.scanSnapshot(id)
	if !ok || scan.Kind != scanKindLocal || scan.User.OpenID == "" {
		publicMessage(w, http.StatusBadRequest, "微信登录尚未完成")
		return
	}
	if err := s.createWebSession(w, scan.User); err != nil {
		publicError(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, validateRelativeReturnTo(r.URL.Query().Get("return_to")), http.StatusFound)
}

func (s *Server) handleAPIMe(w http.ResponseWriter, r *http.Request) {
	session, ok := s.currentWebSession(r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"user":          nil,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"user":          session.User,
	})
}

func (s *Server) handleAPILogout(w http.ResponseWriter, r *http.Request) {
	s.clearWebSession(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authentik WeChat Connect</title><style>body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7fa;color:#17233d;display:grid;place-items:center;padding:24px}.panel{width:min(520px,100%);background:#fff;border:1px solid #dfe4ea;border-radius:8px;padding:28px;box-shadow:0 16px 48px rgba(23,35,61,.08)}h1{font-size:24px;margin:0 0 10px}p{color:#6b778c;line-height:1.6}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px}a{height:40px;padding:0 14px;border-radius:7px;border:1px solid #dfe4ea;background:#fff;color:#17233d;text-decoration:none;display:inline-flex;align-items:center}.primary{background:#07c160;color:#fff;border-color:#07c160}</style></head><body><main class="panel"><h1>Authentik WeChat Connect</h1><p>OIDC、微信参数二维码登录、消息回复和自定义菜单管理已就绪。</p><div class="actions"><a class="primary" href="/login/wechat">微信登录</a><a href="/admin/wechat">公众号管理</a><a href="/.well-known/openid-configuration">Discovery</a></div></main></body></html>`))
}
