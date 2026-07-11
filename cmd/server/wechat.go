package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type wechatService interface {
	CreateLoginQRCode(ctx context.Context, scene string, ttl time.Duration) (WeChatQRCode, error)
	FetchUser(ctx context.Context, openID string) (User, error)
}

type WeChatQRCode struct {
	Ticket      string
	ImageURL    string
	ExpireAfter time.Duration
	URL         string
}

type WeChatClient struct {
	cfg Config

	httpClient       *http.Client
	tokenEndpoint    string
	qrCodeEndpoint   string
	userInfoEndpoint string

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

const (
	defaultWeChatTokenEndpoint    = "https://api.weixin.qq.com/cgi-bin/token"
	defaultWeChatQRCodeEndpoint   = "https://api.weixin.qq.com/cgi-bin/qrcode/create"
	defaultWeChatUserInfoEndpoint = "https://api.weixin.qq.com/cgi-bin/user/info"
	defaultWeChatQRCodeImageURL   = "https://mp.weixin.qq.com/cgi-bin/showqrcode"
)

type wechatTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}

type wechatQRCodeResponse struct {
	Ticket        string `json:"ticket"`
	ExpireSeconds int    `json:"expire_seconds"`
	URL           string `json:"url"`
	ErrCode       int    `json:"errcode"`
	ErrMsg        string `json:"errmsg"`
}

type wechatUserInfoResponse struct {
	Subscribe  int    `json:"subscribe"`
	OpenID     string `json:"openid"`
	Nickname   string `json:"nickname"`
	Sex        int    `json:"sex"`
	City       string `json:"city"`
	Province   string `json:"province"`
	Country    string `json:"country"`
	HeadImgURL string `json:"headimgurl"`
	UnionID    string `json:"unionid"`
	ErrCode    int    `json:"errcode"`
	ErrMsg     string `json:"errmsg"`
}

type wechatEventMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName"`
	FromUserName string   `xml:"FromUserName"`
	CreateTime   int64    `xml:"CreateTime"`
	MsgType      string   `xml:"MsgType"`
	Event        string   `xml:"Event"`
	EventKey     string   `xml:"EventKey"`
	Ticket       string   `xml:"Ticket"`
	Encrypt      string   `xml:"Encrypt"`
}

func NewWeChatClient(cfg Config) *WeChatClient {
	return &WeChatClient{
		cfg:              cfg,
		tokenEndpoint:    defaultWeChatTokenEndpoint,
		qrCodeEndpoint:   defaultWeChatQRCodeEndpoint,
		userInfoEndpoint: defaultWeChatUserInfoEndpoint,
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
	}
}

func (c *WeChatClient) CreateLoginQRCode(ctx context.Context, scene string, ttl time.Duration) (WeChatQRCode, error) {
	if scene == "" || len(scene) > maxScanSessionIDLength {
		return WeChatQRCode{}, fmt.Errorf("WeChat QR scene must be 1-%d bytes", maxScanSessionIDLength)
	}
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return WeChatQRCode{}, err
	}

	u, err := endpointURL(c.qrCodeEndpoint, defaultWeChatQRCodeEndpoint)
	if err != nil {
		return WeChatQRCode{}, err
	}
	q := u.Query()
	q.Set("access_token", token)
	u.RawQuery = q.Encode()

	payload := map[string]any{
		"expire_seconds": int(ttl.Seconds()),
		"action_name":    "QR_STR_SCENE",
		"action_info": map[string]any{
			"scene": map[string]string{"scene_str": scene},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return WeChatQRCode{}, err
	}
	respBody, err := c.do(ctx, http.MethodPost, u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return WeChatQRCode{}, err
	}
	var result wechatQRCodeResponse
	if err := json.Unmarshal([]byte(respBody), &result); err != nil {
		return WeChatQRCode{}, fmt.Errorf("decode WeChat QR code response: %w", err)
	}
	if result.ErrCode != 0 {
		return WeChatQRCode{}, fmt.Errorf("WeChat QR code error %d: %s", result.ErrCode, result.ErrMsg)
	}
	if result.Ticket == "" {
		return WeChatQRCode{}, fmt.Errorf("WeChat QR code response did not include ticket")
	}

	imageURL, err := wechatQRCodeImageURL(result.Ticket)
	if err != nil {
		return WeChatQRCode{}, err
	}
	return WeChatQRCode{
		Ticket:      result.Ticket,
		ImageURL:    imageURL,
		ExpireAfter: time.Duration(result.ExpireSeconds) * time.Second,
		URL:         result.URL,
	}, nil
}

func (c *WeChatClient) FetchUser(ctx context.Context, openID string) (User, error) {
	if openID == "" {
		return User{}, fmt.Errorf("openid is required")
	}
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return User{}, err
	}
	u, err := endpointURL(c.userInfoEndpoint, defaultWeChatUserInfoEndpoint)
	if err != nil {
		return User{}, err
	}
	q := u.Query()
	q.Set("access_token", token)
	q.Set("openid", openID)
	q.Set("lang", c.cfg.WeChatUserInfoLang)
	u.RawQuery = q.Encode()

	body, err := c.do(ctx, http.MethodGet, u.String(), "", nil)
	if err != nil {
		return User{}, err
	}
	var result wechatUserInfoResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return User{}, fmt.Errorf("decode WeChat user info response: %w", err)
	}
	if result.ErrCode != 0 {
		return User{}, fmt.Errorf("WeChat user info error %d: %s", result.ErrCode, result.ErrMsg)
	}
	if result.OpenID == "" {
		result.OpenID = openID
	}
	return User{
		OpenID:   result.OpenID,
		UnionID:  result.UnionID,
		Nickname: result.Nickname,
		Picture:  result.HeadImgURL,
		Gender:   wechatGender(result.Sex),
		City:     result.City,
		Province: result.Province,
		Country:  result.Country,
	}, nil
}

func (c *WeChatClient) getAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		token := c.accessToken
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	u, err := endpointURL(c.tokenEndpoint, defaultWeChatTokenEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("grant_type", "client_credential")
	q.Set("appid", c.cfg.WeChatAppID)
	q.Set("secret", c.cfg.WeChatAppSecret)
	u.RawQuery = q.Encode()

	body, err := c.do(ctx, http.MethodGet, u.String(), "", nil)
	if err != nil {
		return "", err
	}
	var result wechatTokenResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return "", fmt.Errorf("decode WeChat access token response: %w", err)
	}
	if result.ErrCode != 0 {
		return "", fmt.Errorf("WeChat access token error %d: %s", result.ErrCode, result.ErrMsg)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("WeChat access token response did not include access_token")
	}
	expiresIn := time.Duration(result.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 2 * time.Hour
	}
	expiry := time.Now().Add(expiresIn - time.Minute)
	if !expiry.After(time.Now()) {
		expiry = time.Now().Add(expiresIn / 2)
	}
	c.mu.Lock()
	c.accessToken = result.AccessToken
	c.tokenExpiry = expiry
	c.mu.Unlock()
	return result.AccessToken, nil
}

func (c *WeChatClient) do(ctx context.Context, method, rawURL, contentType string, body io.Reader) (string, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("WeChat endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return string(respBody), nil
}

func endpointURL(endpoint, fallback string) (*url.URL, error) {
	if endpoint == "" {
		endpoint = fallback
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint %q: %w", endpoint, err)
	}
	return u, nil
}

func wechatQRCodeImageURL(ticket string) (string, error) {
	u, err := url.Parse(defaultWeChatQRCodeImageURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("ticket", ticket)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func wechatGender(sex int) string {
	switch sex {
	case 1:
		return "male"
	case 2:
		return "female"
	default:
		return ""
	}
}

func (s *Server) handleWeChatCallback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.WeChatCallbackToken == "" {
		logOAuthWarning(r, "wechat callback rejected: WECHAT_CALLBACK_TOKEN is not configured")
		publicError(w, http.StatusServiceUnavailable, fmt.Errorf("WECHAT_CALLBACK_TOKEN must be configured"))
		return
	}
	query := r.URL.Query()
	signature := query.Get("signature")
	timestamp := query.Get("timestamp")
	nonce := query.Get("nonce")
	if !verifyWeChatSignature(s.cfg.WeChatCallbackToken, timestamp, nonce, signature) {
		logOAuthWarning(r, "wechat callback rejected: signature verification failed")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(query.Get("echostr")))
		return
	}

	if strings.EqualFold(query.Get("encrypt_type"), "aes") {
		logOAuthWarning(r, "wechat callback rejected: encrypted callbacks are not supported")
		http.Error(w, "encrypted WeChat callbacks are not supported; configure plaintext mode", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		logOAuthWarning(r, "wechat callback rejected: read body: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var event wechatEventMessage
	if err := xml.Unmarshal(body, &event); err != nil {
		logOAuthWarning(r, "wechat callback rejected: decode XML: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if event.Encrypt != "" {
		logOAuthWarning(r, "wechat callback rejected: encrypted message payload is not supported")
		http.Error(w, "encrypted WeChat callbacks are not supported; configure plaintext mode", http.StatusUnsupportedMediaType)
		return
	}

	scene, ok := sceneFromWeChatEvent(event)
	if !ok {
		logOAuthInfo(r, "wechat callback ignored: msg_type=%q event=%q", event.MsgType, event.Event)
		writeWeChatSuccess(w)
		return
	}
	if event.FromUserName == "" {
		logOAuthWarning(r, "wechat callback ignored: scan scene=%q missing FromUserName", scene)
		writeWeChatSuccess(w)
		return
	}

	user := User{OpenID: event.FromUserName}
	if fetched, err := s.wx.FetchUser(r.Context(), event.FromUserName); err == nil {
		user = fetched
	} else {
		log.Printf("wechat user info lookup failed openid_fp=%s: %v", tokenFingerprint(event.FromUserName), err)
	}
	if err := s.completeScan(r, scene, user); err != nil {
		logOAuthWarning(r, "wechat callback scan completion ignored scene_fp=%s openid_fp=%s: %v", tokenFingerprint(scene), tokenFingerprint(event.FromUserName), err)
	} else {
		logOAuthInfo(r, "wechat callback completed scan scene_fp=%s openid_fp=%s", tokenFingerprint(scene), tokenFingerprint(event.FromUserName))
	}
	writeWeChatSuccess(w)
}

func writeWeChatSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("success"))
}

func verifyWeChatSignature(token, timestamp, nonce, signature string) bool {
	if token == "" || timestamp == "" || nonce == "" || signature == "" {
		return false
	}
	parts := []string{token, timestamp, nonce}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	expected := hex.EncodeToString(sum[:])
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(signature)))
}

func signWeChatCallbackURL(callbackURL, token string) string {
	timestamp := fmt.Sprint(time.Now().Unix())
	nonce := fmt.Sprint(time.Now().UnixNano())
	parts := []string{token, timestamp, nonce}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	u, _ := url.Parse(callbackURL)
	q := u.Query()
	q.Set("signature", hex.EncodeToString(sum[:]))
	q.Set("timestamp", timestamp)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	return u.String()
}

func sceneFromWeChatEvent(event wechatEventMessage) (string, bool) {
	if strings.ToLower(event.MsgType) != "event" {
		return "", false
	}
	switch strings.ToUpper(event.Event) {
	case "SCAN":
		return strings.TrimSpace(event.EventKey), strings.TrimSpace(event.EventKey) != ""
	case "SUBSCRIBE":
		key := strings.TrimSpace(event.EventKey)
		key = strings.TrimPrefix(key, "qrscene_")
		return key, key != ""
	default:
		return "", false
	}
}
