package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	httpClient          *http.Client
	tokenEndpoint       string
	qrCodeEndpoint      string
	userInfoEndpoint    string
	menuCreateEndpoint  string
	menuGetEndpoint     string
	menuCurrentEndpoint string
	menuDeleteEndpoint  string

	mu           sync.Mutex
	accessToken  string
	tokenExpiry  time.Time
	tokenRefresh chan struct{}
}

const (
	defaultWeChatTokenEndpoint       = "https://api.weixin.qq.com/cgi-bin/token"
	defaultWeChatQRCodeEndpoint      = "https://api.weixin.qq.com/cgi-bin/qrcode/create"
	defaultWeChatUserInfoEndpoint    = "https://api.weixin.qq.com/cgi-bin/user/info"
	defaultWeChatQRCodeImageURL      = "https://mp.weixin.qq.com/cgi-bin/showqrcode"
	defaultWeChatMenuCreateEndpoint  = "https://api.weixin.qq.com/cgi-bin/menu/create"
	defaultWeChatMenuGetEndpoint     = "https://api.weixin.qq.com/cgi-bin/menu/get"
	defaultWeChatMenuCurrentEndpoint = "https://api.weixin.qq.com/cgi-bin/get_current_selfmenu_info"
	defaultWeChatMenuDeleteEndpoint  = "https://api.weixin.qq.com/cgi-bin/menu/delete"
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

func NewWeChatClient(cfg Config) *WeChatClient {
	return &WeChatClient{
		cfg:                 cfg,
		tokenEndpoint:       defaultWeChatTokenEndpoint,
		qrCodeEndpoint:      defaultWeChatQRCodeEndpoint,
		userInfoEndpoint:    defaultWeChatUserInfoEndpoint,
		menuCreateEndpoint:  defaultWeChatMenuCreateEndpoint,
		menuGetEndpoint:     defaultWeChatMenuGetEndpoint,
		menuCurrentEndpoint: defaultWeChatMenuCurrentEndpoint,
		menuDeleteEndpoint:  defaultWeChatMenuDeleteEndpoint,
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
	for {
		c.mu.Lock()
		if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
			token := c.accessToken
			c.mu.Unlock()
			return token, nil
		}
		if wait := c.tokenRefresh; wait != nil {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		refresh := make(chan struct{})
		c.tokenRefresh = refresh
		c.mu.Unlock()

		token, expiry, err := c.fetchAccessToken(ctx)
		c.mu.Lock()
		if err == nil {
			c.accessToken = token
			c.tokenExpiry = expiry
		}
		if c.tokenRefresh == refresh {
			c.tokenRefresh = nil
			close(refresh)
		}
		c.mu.Unlock()
		return token, err
	}
}

func (c *WeChatClient) fetchAccessToken(ctx context.Context) (string, time.Time, error) {
	u, err := endpointURL(c.tokenEndpoint, defaultWeChatTokenEndpoint)
	if err != nil {
		return "", time.Time{}, err
	}
	q := u.Query()
	q.Set("grant_type", "client_credential")
	q.Set("appid", c.cfg.WeChatAppID)
	q.Set("secret", c.cfg.WeChatAppSecret)
	u.RawQuery = q.Encode()

	body, err := c.do(ctx, http.MethodGet, u.String(), "", nil)
	if err != nil {
		return "", time.Time{}, err
	}
	var result wechatTokenResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode WeChat access token response: %w", err)
	}
	if result.ErrCode != 0 {
		return "", time.Time{}, fmt.Errorf("WeChat access token error %d: %s", result.ErrCode, result.ErrMsg)
	}
	if result.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("WeChat access token response did not include access_token")
	}
	expiresIn := time.Duration(result.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 2 * time.Hour
	}
	expiry := time.Now().Add(expiresIn - time.Minute)
	if !expiry.After(time.Now()) {
		expiry = time.Now().Add(expiresIn / 2)
	}
	return result.AccessToken, expiry, nil
}

func (c *WeChatClient) invalidateAccessToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken != token {
		return
	}
	c.accessToken = ""
	c.tokenExpiry = time.Time{}
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
