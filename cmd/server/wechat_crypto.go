package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	wechatEncodingAESKeyLength = 43
	wechatPKCS7BlockSize       = 32
	wechatRandomPrefixLength   = 16
)

type wechatCryptor struct {
	appID []byte
	key   []byte
	block cipher.Block
}

func newWeChatCryptor(appID, encodingAESKey string) (*wechatCryptor, error) {
	if strings.TrimSpace(appID) == "" {
		return nil, errors.New("WeChat AppID is required when callback encryption is enabled")
	}
	if len(encodingAESKey) != wechatEncodingAESKeyLength {
		return nil, fmt.Errorf("WeChat EncodingAESKey must be %d characters", wechatEncodingAESKeyLength)
	}

	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, fmt.Errorf("decode WeChat EncodingAESKey: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("decoded WeChat EncodingAESKey must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create WeChat AES cipher: %w", err)
	}
	return &wechatCryptor{
		appID: []byte(appID),
		key:   key,
		block: block,
	}, nil
}

func (c *wechatCryptor) Encrypt(plaintext []byte) (string, error) {
	if uint64(len(plaintext)) > uint64(^uint32(0)) {
		return "", errors.New("WeChat plaintext is too large")
	}

	payload := make([]byte, wechatRandomPrefixLength+4+len(plaintext)+len(c.appID))
	if _, err := rand.Read(payload[:wechatRandomPrefixLength]); err != nil {
		return "", fmt.Errorf("generate WeChat message prefix: %w", err)
	}
	binary.BigEndian.PutUint32(payload[wechatRandomPrefixLength:], uint32(len(plaintext)))
	copy(payload[wechatRandomPrefixLength+4:], plaintext)
	copy(payload[wechatRandomPrefixLength+4+len(plaintext):], c.appID)

	padded := padWeChatPlaintext(payload)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(c.block, c.key[:aes.BlockSize]).CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *wechatCryptor) Decrypt(ciphertext string) ([]byte, error) {
	encrypted, err := base64.StdEncoding.Strict().DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode WeChat ciphertext: %w", err)
	}
	if len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("WeChat ciphertext length is not a non-zero AES block multiple")
	}

	decrypted := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(c.block, c.key[:aes.BlockSize]).CryptBlocks(decrypted, encrypted)
	unpadded, err := unpadWeChatPlaintext(decrypted)
	if err != nil {
		return nil, err
	}
	if len(unpadded) < wechatRandomPrefixLength+4 {
		return nil, errors.New("WeChat plaintext is shorter than its message header")
	}

	messageLength := uint64(binary.BigEndian.Uint32(unpadded[wechatRandomPrefixLength : wechatRandomPrefixLength+4]))
	remainingLength := len(unpadded) - wechatRandomPrefixLength - 4
	if messageLength > uint64(remainingLength) {
		return nil, errors.New("WeChat plaintext contains an invalid message length")
	}
	messageEnd := wechatRandomPrefixLength + 4 + int(messageLength)
	if len(unpadded)-messageEnd != len(c.appID) {
		return nil, errors.New("WeChat plaintext contains an invalid AppID length")
	}
	if subtle.ConstantTimeCompare(unpadded[messageEnd:], c.appID) != 1 {
		return nil, errors.New("WeChat plaintext AppID does not match")
	}

	message := make([]byte, int(messageLength))
	copy(message, unpadded[wechatRandomPrefixLength+4:messageEnd])
	return message, nil
}

func verifyWeChatMessageSignature(token, timestamp, nonce, encrypted, signature string) bool {
	if token == "" || timestamp == "" || nonce == "" || encrypted == "" || signature == "" {
		return false
	}

	provided, err := hex.DecodeString(signature)
	if err != nil || len(provided) != sha1.Size {
		return false
	}
	parts := []string{token, timestamp, nonce, encrypted}
	sort.Strings(parts)
	expected := sha1.Sum([]byte(strings.Join(parts, "")))
	return subtle.ConstantTimeCompare(expected[:], provided) == 1
}

func padWeChatPlaintext(plaintext []byte) []byte {
	paddingLength := wechatPKCS7BlockSize - len(plaintext)%wechatPKCS7BlockSize
	padded := make([]byte, len(plaintext)+paddingLength)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(paddingLength)
	}
	return padded
}

func unpadWeChatPlaintext(padded []byte) ([]byte, error) {
	if len(padded) == 0 || len(padded)%wechatPKCS7BlockSize != 0 {
		return nil, errors.New("WeChat plaintext has an invalid padded length")
	}
	paddingLength := int(padded[len(padded)-1])
	if paddingLength == 0 || paddingLength > wechatPKCS7BlockSize || paddingLength > len(padded) {
		return nil, errors.New("WeChat plaintext has invalid PKCS#7 padding")
	}

	valid := 1
	for _, value := range padded[len(padded)-paddingLength:] {
		valid &= subtle.ConstantTimeByteEq(value, byte(paddingLength))
	}
	if valid != 1 {
		return nil, errors.New("WeChat plaintext has invalid PKCS#7 padding")
	}
	return padded[:len(padded)-paddingLength], nil
}
