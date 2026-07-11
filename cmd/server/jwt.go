package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

type JWTSigner struct {
	cfg Config
	key *rsa.PrivateKey
	kid string
}

func NewJWTSigner(cfg Config) (*JWTSigner, error) {
	keyPEM := cfg.OIDCPrivateKeyPEM
	if cfg.OIDCPrivateKeyFile != "" {
		body, err := os.ReadFile(cfg.OIDCPrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read OIDC_RSA_PRIVATE_KEY_FILE: %w", err)
		}
		keyPEM = string(body)
	}

	var key *rsa.PrivateKey
	var err error
	if keyPEM != "" {
		key, err = parseRSAPrivateKey([]byte(keyPEM))
		if err != nil {
			return nil, err
		}
	} else {
		log.Println("OIDC RSA private key is not configured; generated an ephemeral signing key for this process. Production deployments should set OIDC_RSA_PRIVATE_KEY_FILE or OIDC_RSA_PRIVATE_KEY_PEM to the same key on every replica")
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate OIDC signing key: %w", err)
		}
	}

	kid, err := keyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &JWTSigner{cfg: cfg, key: key, kid: kid}, nil
}

func parseRSAPrivateKey(body []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("OIDC RSA private key must be PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC RSA private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("OIDC private key is not RSA")
	}
	return key, nil
}

func keyID(publicKey *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16]), nil
}

func (s *JWTSigner) SignIDToken(clientID, nonce string, user User, expiresAt time.Time) (string, error) {
	now := time.Now()
	claims := user.oidcClaims()
	claims["iss"] = s.cfg.OIDCIssuer
	claims["aud"] = clientID
	claims["iat"] = now.Unix()
	claims["auth_time"] = now.Unix()
	claims["exp"] = expiresAt.Unix()
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return s.sign(claims)
}

func (s *JWTSigner) sign(claims map[string]any) (string, error) {
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": s.kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(signature), nil
}

func (s *JWTSigner) JWK() map[string]any {
	publicKey := s.key.Public().(*rsa.PublicKey)
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": s.kid,
		"alg": "RS256",
		"n":   b64(publicKey.N.Bytes()),
		"e":   b64(big.NewInt(int64(publicKey.E)).Bytes()),
	}
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
