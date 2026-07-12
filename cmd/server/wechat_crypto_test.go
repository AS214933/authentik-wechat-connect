package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
)

func TestWeChatCryptorRoundTrip(t *testing.T) {
	cryptor, err := newWeChatCryptor("wx-test-app", testWeChatEncodingAESKey())
	if err != nil {
		t.Fatalf("create cryptor: %v", err)
	}
	plaintext := []byte(`<xml><Content><![CDATA[微信消息]]></Content></xml>`)

	first, err := cryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt first message: %v", err)
	}
	second, err := cryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt second message: %v", err)
	}
	if first == second {
		t.Fatal("encryptions should use independent random prefixes")
	}

	for _, ciphertext := range []string{first, second} {
		got, err := cryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("decrypt message: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("decrypted plaintext = %q, want %q", got, plaintext)
		}
	}
}

func TestNewWeChatCryptorRejectsInvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "empty", key: ""},
		{name: "wrong length", key: strings.Repeat("A", 42)},
		{name: "invalid base64", key: strings.Repeat("!", 43)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newWeChatCryptor("wx-test-app", tt.key); err == nil {
				t.Fatal("expected invalid EncodingAESKey to be rejected")
			}
		})
	}
}

func TestNewWeChatCryptorRequiresAppID(t *testing.T) {
	if _, err := newWeChatCryptor("", testWeChatEncodingAESKey()); err == nil {
		t.Fatal("expected empty AppID to be rejected")
	}
}

func TestNewWeChatCryptorAccepts43CharacterWeChatKey(t *testing.T) {
	// WeChat's documented-style 43-character keys are decoded after appending
	// "="; their unused trailing Base64 bits are not required to be canonical.
	const encodingAESKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	if _, err := newWeChatCryptor("wx-test-app", encodingAESKey); err != nil {
		t.Fatalf("create cryptor from 43-character WeChat key: %v", err)
	}
}

func TestWeChatCryptorRejectsWrongKey(t *testing.T) {
	encryptor, err := newWeChatCryptor("wx-test-app", testWeChatEncodingAESKey())
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}
	wrongKey := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	decryptor, err := newWeChatCryptor("wx-test-app", strings.TrimSuffix(wrongKey, "="))
	if err != nil {
		t.Fatalf("create wrong-key decryptor: %v", err)
	}
	ciphertext, err := encryptor.Encrypt([]byte("<xml>message</xml>"))
	if err != nil {
		t.Fatalf("encrypt message: %v", err)
	}

	if _, err := decryptor.Decrypt(ciphertext); err == nil {
		t.Fatal("expected ciphertext decrypted with the wrong key to be rejected")
	}
}

func TestWeChatCryptorRejectsWrongAppID(t *testing.T) {
	key := testWeChatEncodingAESKey()
	encryptor, err := newWeChatCryptor("wx-test-app", key)
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}
	decryptor, err := newWeChatCryptor("wx-other-app", key)
	if err != nil {
		t.Fatalf("create decryptor: %v", err)
	}
	ciphertext, err := encryptor.Encrypt([]byte("<xml>message</xml>"))
	if err != nil {
		t.Fatalf("encrypt message: %v", err)
	}

	if _, err := decryptor.Decrypt(ciphertext); err == nil {
		t.Fatal("expected mismatched AppID to be rejected")
	}
}

func TestWeChatCryptorRejectsInvalidPadding(t *testing.T) {
	keyBytes := []byte("0123456789abcdef0123456789abcdef")
	cryptor, err := newWeChatCryptor("wx-test-app", testWeChatEncodingAESKey())
	if err != nil {
		t.Fatalf("create cryptor: %v", err)
	}

	tests := []struct {
		name      string
		configure func([]byte)
	}{
		{
			name: "zero length",
			configure: func(padded []byte) {
				padded[len(padded)-1] = 0
			},
		},
		{
			name: "over block size",
			configure: func(padded []byte) {
				padded[len(padded)-1] = wechatPKCS7BlockSize + 1
			},
		},
		{
			name: "inconsistent bytes",
			configure: func(padded []byte) {
				padded[len(padded)-2] = 1
				padded[len(padded)-1] = 2
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidPlaintext := make([]byte, wechatPKCS7BlockSize)
			tt.configure(invalidPlaintext)
			ciphertext := encryptWeChatTestBlocks(t, keyBytes, invalidPlaintext)
			if _, err := cryptor.Decrypt(ciphertext); err == nil {
				t.Fatal("expected invalid padding to be rejected")
			}
		})
	}
}

func TestVerifyWeChatMessageSignature(t *testing.T) {
	token := "callback-token"
	timestamp := "1720000000"
	nonce := "nonce"
	encrypted := "base64-encrypted-message"
	signature := testWeChatMessageSignature(token, timestamp, nonce, encrypted)

	if !verifyWeChatMessageSignature(token, timestamp, nonce, encrypted, signature) {
		t.Fatal("expected signature to verify")
	}
	if !verifyWeChatMessageSignature(token, timestamp, nonce, encrypted, strings.ToUpper(signature)) {
		t.Fatal("expected uppercase hexadecimal signature to verify")
	}
	if verifyWeChatMessageSignature(token, timestamp, nonce, encrypted+"-changed", signature) {
		t.Fatal("expected signature for different ciphertext to be rejected")
	}
	if verifyWeChatMessageSignature(token, timestamp, nonce, encrypted, strings.Repeat("0", sha1.Size*2)) {
		t.Fatal("expected incorrect signature to be rejected")
	}
	if verifyWeChatMessageSignature(token, timestamp, nonce, encrypted, "not-hex") {
		t.Fatal("expected malformed signature to be rejected")
	}
}

func testWeChatEncodingAESKey() string {
	encoded := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	return strings.TrimSuffix(encoded, "=")
}

func encryptWeChatTestBlocks(t *testing.T, key, plaintext []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("create test cipher: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, key[:aes.BlockSize]).CryptBlocks(ciphertext, plaintext)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func testWeChatMessageSignature(token, timestamp, nonce, encrypted string) string {
	parts := []string{token, timestamp, nonce, encrypted}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	return hex.EncodeToString(sum[:])
}
