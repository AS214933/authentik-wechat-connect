package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr string
	PublicURL  string

	WeChatAppID              string
	WeChatAppSecret          string
	WeChatCallbackToken      string
	WeChatEncodingAESKey     string
	WeChatQRCodeTTL          time.Duration
	WeChatUserInfoLang       string
	WeChatCallbackTimeout    time.Duration
	WeChatManagementDataFile string
	WeChatAdminToken         string

	OIDCIssuer                    string
	OIDCClientID                  string
	OIDCClientSecret              string
	OIDCAllowedRedirectURIs       map[string]struct{}
	OIDCInsecureAllowAllRedirects bool
	OIDCPrivateKeyPEM             string
	OIDCPrivateKeyFile            string

	SessionSecret     []byte
	SessionCookieName string

	AuthCodeTTL    time.Duration
	AccessTokenTTL time.Duration
	SessionTTL     time.Duration
}

const maxWeChatTemporaryQRCodeTTL = 30 * 24 * time.Hour

func loadConfig() (Config, error) {
	publicURL := strings.TrimRight(env("PUBLIC_URL", "http://localhost:8080"), "/")
	if err := validateServiceURL("PUBLIC_URL", publicURL); err != nil {
		return Config{}, err
	}
	if _, err := url.ParseRequestURI(publicURL); err != nil {
		return Config{}, fmt.Errorf("PUBLIC_URL must be an absolute URL: %w", err)
	}

	issuer := strings.TrimRight(env("OIDC_ISSUER", publicURL), "/")
	if err := validateServiceURL("OIDC_ISSUER", issuer); err != nil {
		return Config{}, err
	}

	qrTTL := envDuration("WECHAT_QR_CODE_TTL", 5*time.Minute)
	if err := validateWeChatQRCodeTTL(qrTTL); err != nil {
		return Config{}, err
	}
	callbackTimeout := envDuration("WECHAT_CALLBACK_TIMEOUT", 3*time.Second)
	if err := validateWeChatCallbackTimeout(callbackTimeout); err != nil {
		return Config{}, err
	}

	sessionSecret := []byte(os.Getenv("SESSION_SECRET"))
	if len(sessionSecret) == 0 {
		sessionSecret = make([]byte, 32)
		if _, err := rand.Read(sessionSecret); err != nil {
			return Config{}, fmt.Errorf("generate session secret: %w", err)
		}
		log.Println("SESSION_SECRET is not set; generated an ephemeral secret for this process. Production deployments must set the same SESSION_SECRET on every replica so authorization codes and access tokens survive restarts")
	} else if len(sessionSecret) < 32 {
		log.Println("SESSION_SECRET should be at least 32 bytes for production deployments")
	}

	cfg := Config{
		ListenAddr: env("LISTEN_ADDR", ":8080"),
		PublicURL:  publicURL,

		WeChatAppID:              os.Getenv("WECHAT_APP_ID"),
		WeChatAppSecret:          os.Getenv("WECHAT_APP_SECRET"),
		WeChatCallbackToken:      os.Getenv("WECHAT_CALLBACK_TOKEN"),
		WeChatEncodingAESKey:     strings.TrimSpace(os.Getenv("WECHAT_ENCODING_AES_KEY")),
		WeChatQRCodeTTL:          qrTTL,
		WeChatUserInfoLang:       env("WECHAT_USER_INFO_LANG", "zh_CN"),
		WeChatCallbackTimeout:    callbackTimeout,
		WeChatManagementDataFile: env("WECHAT_MANAGEMENT_DATA_FILE", "data/wechat-management.json"),
		WeChatAdminToken:         strings.TrimSpace(os.Getenv("WECHAT_ADMIN_TOKEN")),

		OIDCIssuer:                    issuer,
		OIDCClientID:                  env("OIDC_CLIENT_ID", "authentik"),
		OIDCClientSecret:              env("OIDC_CLIENT_SECRET", "change-me"),
		OIDCAllowedRedirectURIs:       splitSet(os.Getenv("OIDC_ALLOWED_REDIRECT_URIS")),
		OIDCInsecureAllowAllRedirects: envBool("OIDC_INSECURE_ALLOW_ALL_REDIRECTS", false),
		OIDCPrivateKeyPEM:             os.Getenv("OIDC_RSA_PRIVATE_KEY_PEM"),
		OIDCPrivateKeyFile:            os.Getenv("OIDC_RSA_PRIVATE_KEY_FILE"),

		SessionSecret:     sessionSecret,
		SessionCookieName: env("SESSION_COOKIE_NAME", "wechat_connect_session"),

		AuthCodeTTL:    envDuration("AUTH_CODE_TTL", 10*time.Minute),
		AccessTokenTTL: envDuration("ACCESS_TOKEN_TTL", time.Hour),
		SessionTTL:     envDuration("SESSION_TTL", 24*time.Hour),
	}

	if err := validateProductionConfig(cfg); err != nil {
		return Config{}, err
	}

	if cfg.OIDCClientSecret == "change-me" {
		log.Println("OIDC_CLIENT_SECRET is using the development default; set a strong value before production use")
	}
	if cfg.WeChatAdminToken == "" {
		log.Println("WECHAT_ADMIN_TOKEN is not set; WeChat management APIs are disabled")
	} else if len(cfg.WeChatAdminToken) < 32 {
		log.Println("WECHAT_ADMIN_TOKEN should be at least 32 bytes; short tokens are accepted only for local development")
	}
	if len(cfg.OIDCAllowedRedirectURIs) == 0 && !cfg.OIDCInsecureAllowAllRedirects {
		log.Println("OIDC_ALLOWED_REDIRECT_URIS is empty; Authentik authorization requests will be rejected until it is configured")
	}
	if err := validateOIDCRedirectURIs(cfg.OIDCAllowedRedirectURIs); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateProductionConfig(cfg Config) error {
	if isLocalServiceURL(cfg.PublicURL) {
		return nil
	}
	if cfg.WeChatAdminToken != "" && len(cfg.WeChatAdminToken) < 32 {
		return fmt.Errorf("WECHAT_ADMIN_TOKEN must be at least 32 bytes for non-local PUBLIC_URL %q", cfg.PublicURL)
	}
	if os.Getenv("SESSION_SECRET") == "" {
		return fmt.Errorf("SESSION_SECRET must be set for non-local PUBLIC_URL %q so authorization codes and access tokens survive restarts", cfg.PublicURL)
	}
	if len(cfg.SessionSecret) < 32 {
		return fmt.Errorf("SESSION_SECRET must be at least 32 bytes for non-local PUBLIC_URL %q", cfg.PublicURL)
	}
	if cfg.OIDCPrivateKeyFile == "" && cfg.OIDCPrivateKeyPEM == "" {
		return fmt.Errorf("OIDC_RSA_PRIVATE_KEY_FILE or OIDC_RSA_PRIVATE_KEY_PEM must be set for non-local PUBLIC_URL %q so Authentik sees a stable JWKS/id_token signing key", cfg.PublicURL)
	}
	if cfg.OIDCClientSecret == "change-me" {
		return fmt.Errorf("OIDC_CLIENT_SECRET must not use the development default for non-local PUBLIC_URL %q", cfg.PublicURL)
	}
	return nil
}

func isLocalServiceURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func validateServiceURL(name, rawURL string) error {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || !parsed.IsAbs() {
		if err == nil {
			err = fmt.Errorf("URL is not absolute")
		}
		return fmt.Errorf("%s must be an absolute URL for this middleware service: %w", name, err)
	}
	if isAuthentikFlowURL(parsed) {
		return fmt.Errorf("%s points to an Authentik flow URL %q; set it to this middleware service base URL", name, rawURL)
	}
	return nil
}

func validateOIDCRedirectURIs(redirectURIs map[string]struct{}) error {
	for rawURL := range redirectURIs {
		parsed, err := url.ParseRequestURI(rawURL)
		if err != nil || !parsed.IsAbs() {
			if err == nil {
				err = fmt.Errorf("URL is not absolute")
			}
			return fmt.Errorf("OIDC_ALLOWED_REDIRECT_URIS contains an invalid redirect URI %q: %w", rawURL, err)
		}
		if isAuthentikFlowURL(parsed) {
			return fmt.Errorf("OIDC_ALLOWED_REDIRECT_URIS contains an Authentik flow URL %q; use the Source callback URL, usually /source/oauth/callback/<source-slug>/", rawURL)
		}
	}
	return nil
}

func validateWeChatQRCodeTTL(ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("WECHAT_QR_CODE_TTL must be greater than zero")
	}
	if ttl > maxWeChatTemporaryQRCodeTTL {
		return fmt.Errorf("WECHAT_QR_CODE_TTL must not exceed %s for temporary WeChat QR codes", maxWeChatTemporaryQRCodeTTL)
	}
	return nil
}

func validateWeChatCallbackTimeout(timeout time.Duration) error {
	if timeout <= 0 || timeout > 4*time.Second {
		return fmt.Errorf("WECHAT_CALLBACK_TIMEOUT must be greater than zero and no more than 4s")
	}
	return nil
}

func isAuthentikFlowURL(u *url.URL) bool {
	return strings.HasPrefix(u.Path, "/if/flow/") || strings.Contains(u.Path, "/if/flow/")
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("%s=%q is not a valid boolean; using %t", key, value, fallback)
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		log.Printf("%s=%q is not a valid duration; using %s", key, value, fallback)
		return fallback
	}
	return parsed
}

func splitSet(csv string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result[item] = struct{}{}
		}
	}
	return result
}

func base64Secret(secret []byte) string {
	return base64.RawURLEncoding.EncodeToString(secret)
}
