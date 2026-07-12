package main

import (
	"strings"
	"testing"
	"time"
)

func productionConfigForTest() Config {
	return Config{
		PublicURL:         "https://wechat-connect.example.com",
		OIDCClientSecret:  "oidc-secret",
		OIDCPrivateKeyPEM: "-----BEGIN RSA PRIVATE KEY-----\nplaceholder\n-----END RSA PRIVATE KEY-----",
		SessionSecret:     []byte("0123456789abcdef0123456789abcdef"),
		OIDCAllowedRedirectURIs: map[string]struct{}{
			"https://authentik.example.com/source/oauth/callback/wechat-connect/": {},
		},
	}
}

func TestValidateServiceURLRejectsAuthentikFlow(t *testing.T) {
	err := validateServiceURL("PUBLIC_URL", "https://auth.example.com/if/flow/default-authentication-flow/")
	if err == nil {
		t.Fatal("expected Authentik flow URL to be rejected")
	}
	if !strings.Contains(err.Error(), "PUBLIC_URL points to an Authentik flow URL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOIDCRedirectURIsRejectsAuthentikFlow(t *testing.T) {
	err := validateOIDCRedirectURIs(map[string]struct{}{
		"https://auth.example.com/if/flow/default-authentication-flow/": {},
	})
	if err == nil {
		t.Fatal("expected Authentik flow URL to be rejected")
	}
	if !strings.Contains(err.Error(), "OIDC_ALLOWED_REDIRECT_URIS contains an Authentik flow URL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOIDCRedirectURIsAcceptsSourceCallback(t *testing.T) {
	if err := validateOIDCRedirectURIs(map[string]struct{}{
		"https://authentik.example.com/source/oauth/callback/wechat-connect/": {},
	}); err != nil {
		t.Fatalf("OIDC source callback should be accepted: %v", err)
	}
}

func TestValidateWeChatQRCodeTTL(t *testing.T) {
	if err := validateWeChatQRCodeTTL(5 * time.Minute); err != nil {
		t.Fatalf("expected normal QR code TTL to be accepted: %v", err)
	}
	if err := validateWeChatQRCodeTTL(0); err == nil {
		t.Fatal("expected zero QR code TTL to be rejected")
	}
	if err := validateWeChatQRCodeTTL(maxWeChatTemporaryQRCodeTTL + time.Second); err == nil {
		t.Fatal("expected excessive QR code TTL to be rejected")
	}
}

func TestValidateWeChatCallbackTimeout(t *testing.T) {
	if err := validateWeChatCallbackTimeout(3 * time.Second); err != nil {
		t.Fatalf("expected callback timeout to be accepted: %v", err)
	}
	for _, timeout := range []time.Duration{0, -time.Second, 4*time.Second + time.Nanosecond} {
		if err := validateWeChatCallbackTimeout(timeout); err == nil {
			t.Errorf("expected callback timeout %s to be rejected", timeout)
		}
	}
}

func TestValidateProductionConfigRequiresSessionSecret(t *testing.T) {
	t.Setenv("SESSION_SECRET", "")
	cfg := productionConfigForTest()
	err := validateProductionConfig(cfg)
	if err == nil {
		t.Fatal("expected missing SESSION_SECRET to be rejected")
	}
	if !strings.Contains(err.Error(), "SESSION_SECRET must be set") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProductionConfigRequiresStableRSAKey(t *testing.T) {
	t.Setenv("SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	cfg := productionConfigForTest()
	cfg.OIDCPrivateKeyPEM = ""
	err := validateProductionConfig(cfg)
	if err == nil {
		t.Fatal("expected missing OIDC RSA key to be rejected")
	}
	if !strings.Contains(err.Error(), "OIDC_RSA_PRIVATE_KEY_FILE or OIDC_RSA_PRIVATE_KEY_PEM must be set") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProductionConfigAllowsLocalDevelopmentDefaults(t *testing.T) {
	t.Setenv("SESSION_SECRET", "")
	cfg := Config{PublicURL: "http://localhost:8080", OIDCClientSecret: "change-me"}
	if err := validateProductionConfig(cfg); err != nil {
		t.Fatalf("local development defaults should be accepted: %v", err)
	}
}

func TestValidateProductionConfigRequiresStrongWeChatAdminToken(t *testing.T) {
	t.Setenv("SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	cfg := productionConfigForTest()
	cfg.WeChatAdminToken = "short"
	err := validateProductionConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "WECHAT_ADMIN_TOKEN must be at least 32 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}
