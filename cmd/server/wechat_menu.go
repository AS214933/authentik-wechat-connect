package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type wechatMenuService interface {
	PublishMenu(context.Context, WeChatMenu) error
	GetMenu(context.Context) (json.RawMessage, error)
	GetCurrentMenu(context.Context) (json.RawMessage, error)
	DeleteMenu(context.Context) error
}

type wechatMenuAPIResponse struct {
	ErrCode *int   `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type wechatMenuAPIError struct {
	Operation string
	Code      int
	Message   string
}

func (e *wechatMenuAPIError) Error() string {
	return fmt.Sprintf("WeChat menu %s error %d: %s", e.Operation, e.Code, e.Message)
}

const maxWeChatMenuRequestAttempts = 2

func (c *WeChatClient) PublishMenu(ctx context.Context, menu WeChatMenu) error {
	if err := menu.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(menu)
	if err != nil {
		return fmt.Errorf("encode WeChat menu: %w", err)
	}
	_, err = c.doMenuAPIRequest(ctx, "publish", http.MethodPost, c.menuCreateEndpoint, defaultWeChatMenuCreateEndpoint, payload)
	return err
}

func (c *WeChatClient) GetMenu(ctx context.Context) (json.RawMessage, error) {
	return c.doMenuAPIRequest(ctx, "get", http.MethodGet, c.menuGetEndpoint, defaultWeChatMenuGetEndpoint, nil)
}

func (c *WeChatClient) GetCurrentMenu(ctx context.Context) (json.RawMessage, error) {
	return c.doMenuAPIRequest(ctx, "get current", http.MethodGet, c.menuCurrentEndpoint, defaultWeChatMenuCurrentEndpoint, nil)
}

func (c *WeChatClient) DeleteMenu(ctx context.Context) error {
	_, err := c.doMenuAPIRequest(ctx, "delete", http.MethodGet, c.menuDeleteEndpoint, defaultWeChatMenuDeleteEndpoint, nil)
	return err
}

func (c *WeChatClient) doMenuAPIRequest(ctx context.Context, operation, method, endpoint, fallback string, payload []byte) (json.RawMessage, error) {
	for attempt := 0; attempt < maxWeChatMenuRequestAttempts; attempt++ {
		token, err := c.getAccessToken(ctx)
		if err != nil {
			return nil, err
		}

		u, err := endpointURL(endpoint, fallback)
		if err != nil {
			return nil, err
		}
		query := u.Query()
		query.Set("access_token", token)
		u.RawQuery = query.Encode()

		contentType := ""
		if payload != nil {
			contentType = "application/json"
		}
		body, err := c.do(ctx, method, u.String(), contentType, bytes.NewReader(payload))
		if err != nil {
			return nil, redactWeChatMenuToken(err, token)
		}

		raw := json.RawMessage(body)
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			if err == nil {
				err = fmt.Errorf("response must be a JSON object")
			}
			return nil, fmt.Errorf("decode WeChat menu %s response: %w", operation, err)
		}
		var result wechatMenuAPIResponse
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, fmt.Errorf("decode WeChat menu %s response: %w", operation, err)
		}
		requireErrCode := operation == "publish" || operation == "delete"
		if result.ErrCode == nil {
			if requireErrCode {
				return nil, fmt.Errorf("decode WeChat menu %s response: errcode is required", operation)
			}
			return raw, nil
		}
		if *result.ErrCode == 0 {
			return raw, nil
		}
		if isWeChatAccessTokenError(*result.ErrCode) {
			c.invalidateAccessToken(token)
			if attempt+1 < maxWeChatMenuRequestAttempts {
				continue
			}
		}
		message := strings.ReplaceAll(result.ErrMsg, token, "[REDACTED]")
		return nil, &wechatMenuAPIError{Operation: operation, Code: *result.ErrCode, Message: message}
	}
	return nil, fmt.Errorf("WeChat menu %s request exhausted retries", operation)
}

func isWeChatAccessTokenError(code int) bool {
	switch code {
	case 40001, 40014, 42001:
		return true
	default:
		return false
	}
}

func redactWeChatMenuToken(err error, token string) error {
	if err == nil || token == "" {
		return err
	}
	return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), token, "[REDACTED]"))
}

var _ wechatMenuService = (*WeChatClient)(nil)
