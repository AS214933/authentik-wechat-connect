package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const importedMenuReplyRulePrefix = "__wechat_connect_menu_text_"

type weChatCurrentMenuEnvelope struct {
	IsMenuOpen   *int                       `json:"is_menu_open"`
	SelfMenuInfo *weChatCurrentMenuContents `json:"selfmenu_info"`
}

type weChatCurrentMenuContents struct {
	Button []weChatCurrentMenuButton `json:"button"`
}

type weChatCurrentMenuButton struct {
	Type      string                      `json:"type,omitempty"`
	Name      string                      `json:"name"`
	Key       string                      `json:"key,omitempty"`
	URL       string                      `json:"url,omitempty"`
	Value     string                      `json:"value,omitempty"`
	AppID     string                      `json:"appid,omitempty"`
	PagePath  string                      `json:"pagepath,omitempty"`
	MediaID   string                      `json:"media_id,omitempty"`
	ArticleID string                      `json:"article_id,omitempty"`
	NewsInfo  json.RawMessage             `json:"news_info,omitempty"`
	SubButton weChatCurrentMenuButtonList `json:"sub_button,omitempty"`
}

// get_current_selfmenu_info wraps children in {"list": [...]}, unlike the
// sub_button array accepted by menu/create.
type weChatCurrentMenuButtonList struct {
	List []weChatCurrentMenuButton
}

func (l *weChatCurrentMenuButtonList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	var wrapper struct {
		List []weChatCurrentMenuButton `json:"list"`
	}
	if err := decodeStrictJSONValue(data, &wrapper); err != nil {
		return err
	}
	l.List = wrapper.List
	return nil
}

// decodeWeChatAdminMenuPayload accepts either the canonical menu/create body
// or the documented get_current_selfmenu_info response. The latter is
// normalized into a publishable menu and managed click reply rules.
func decodeWeChatAdminMenuPayload(raw []byte) (WeChatMenu, []WeChatReplyRule, bool, error) {
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		return WeChatMenu{}, nil, false, err
	}
	_, hasOpenState := shape["is_menu_open"]
	_, hasCurrentMenu := shape["selfmenu_info"]
	if !hasOpenState && !hasCurrentMenu {
		var menu WeChatMenu
		if err := decodeStrictJSONValue(raw, &menu); err != nil {
			return WeChatMenu{}, nil, false, err
		}
		return menu, nil, false, nil
	}

	var envelope weChatCurrentMenuEnvelope
	if err := decodeStrictJSONValue(raw, &envelope); err != nil {
		return WeChatMenu{}, nil, true, fmt.Errorf("decode get_current_selfmenu_info response: %w", err)
	}
	if envelope.IsMenuOpen != nil && *envelope.IsMenuOpen != 0 && *envelope.IsMenuOpen != 1 {
		return WeChatMenu{}, nil, true, fmt.Errorf("get_current_selfmenu_info is_menu_open must be 0 or 1")
	}
	if envelope.SelfMenuInfo == nil {
		return WeChatMenu{}, nil, true, errors.New("get_current_selfmenu_info response does not contain selfmenu_info")
	}

	buttons, rules, err := convertWeChatCurrentMenuButtons(envelope.SelfMenuInfo.Button, "button")
	if err != nil {
		return WeChatMenu{}, nil, true, err
	}
	return WeChatMenu{Button: buttons}, rules, true, nil
}

func convertWeChatCurrentMenuButtons(source []weChatCurrentMenuButton, path string) ([]WeChatMenuButton, []WeChatReplyRule, error) {
	buttons := make([]WeChatMenuButton, 0, len(source))
	var rules []WeChatReplyRule
	for i, current := range source {
		buttonPath := fmt.Sprintf("%s[%d]", path, i)
		button, nestedRules, err := convertWeChatCurrentMenuButton(current, buttonPath)
		if err != nil {
			return nil, nil, err
		}
		buttons = append(buttons, button)
		rules = append(rules, nestedRules...)
	}
	return buttons, rules, nil
}

func convertWeChatCurrentMenuButton(current weChatCurrentMenuButton, path string) (WeChatMenuButton, []WeChatReplyRule, error) {
	name := current.Name
	if len(current.SubButton.List) != 0 {
		if current.Type != "" || hasWeChatCurrentMenuActionFields(current) {
			return WeChatMenuButton{}, nil, fmt.Errorf("%s: a menu group cannot contain type or action fields", path)
		}
		children, rules, err := convertWeChatCurrentMenuButtons(current.SubButton.List, path+".sub_button")
		if err != nil {
			return WeChatMenuButton{}, nil, err
		}
		return WeChatMenuButton{Name: name, SubButton: children}, rules, nil
	}

	typeName := normalizeWeChatValue(current.Type)
	button := WeChatMenuButton{Type: typeName, Name: name}
	switch typeName {
	case "click", "scancode_push", "scancode_waitmsg", "pic_sysphoto", "pic_photo_or_album", "pic_weixin", "location_select":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"key": true}); err != nil {
			return WeChatMenuButton{}, nil, err
		}
		button.Key = current.Key
	case "view":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"url": true}); err != nil {
			return WeChatMenuButton{}, nil, err
		}
		button.URL = current.URL
	case "media_id", "view_limited":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"media_id": true}); err != nil {
			return WeChatMenuButton{}, nil, err
		}
		button.MediaID = current.MediaID
	case "article_id", "article_view_limited":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"article_id": true}); err != nil {
			return WeChatMenuButton{}, nil, err
		}
		button.ArticleID = current.ArticleID
	case "miniprogram":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"url": true, "appid": true, "pagepath": true}); err != nil {
			return WeChatMenuButton{}, nil, err
		}
		button.URL = current.URL
		button.AppID = current.AppID
		button.PagePath = current.PagePath
	case "text":
		if current.Value == "" {
			return WeChatMenuButton{}, nil, fmt.Errorf("%s: website text menu value is required", path)
		}
		if current.Key != "" || current.URL != "" || current.AppID != "" || current.PagePath != "" || current.MediaID != "" || current.ArticleID != "" || hasJSONValue(current.NewsInfo) {
			return WeChatMenuButton{}, nil, fmt.Errorf("%s: website text menu contains fields for another action type", path)
		}
		key, rule := importedTextMenuAction(path, name, current.Value)
		if err := rule.Validate(); err != nil {
			return WeChatMenuButton{}, nil, fmt.Errorf("%s: convert website text menu: %w", path, err)
		}
		return WeChatMenuButton{Type: "click", Name: name, Key: key}, []WeChatReplyRule{rule}, nil
	case "img", "voice", "video", "news":
		return WeChatMenuButton{}, nil, fmt.Errorf("%s: website menu type %q cannot be published by menu/create without migrating its media to a permanent API asset", path, typeName)
	case "":
		return WeChatMenuButton{}, nil, fmt.Errorf("%s: leaf menu button type is required", path)
	default:
		return WeChatMenuButton{}, nil, fmt.Errorf("%s: unsupported current menu button type %q", path, current.Type)
	}
	return button, nil, nil
}

func importedTextMenuAction(path, name, content string) (string, WeChatReplyRule) {
	digest := sha256.Sum256([]byte(path + "\x00" + name + "\x00" + content))
	suffix := fmt.Sprintf("%x", digest[:12])
	key := "wechat_connect_text_" + suffix
	return key, WeChatReplyRule{
		ID:      importedMenuReplyRulePrefix + suffix,
		Name:    "导入菜单：" + name,
		Enabled: true,
		Trigger: "click",
		Match:   "exact",
		Pattern: key,
		Reply:   WeChatReply{Type: "text", Content: content},
	}
}

func mergeImportedMenuReplyRules(settings WeChatReplySettings, imported []WeChatReplyRule) WeChatReplySettings {
	settings = cloneWeChatReplySettings(settings)
	rules := make([]WeChatReplyRule, 0, len(imported)+len(settings.Rules))
	rules = append(rules, imported...)
	for _, rule := range settings.Rules {
		if isImportedMenuReplyRuleID(rule.ID) {
			continue
		}
		rules = append(rules, rule)
	}
	settings.Rules = rules
	if len(imported) != 0 {
		settings.Enabled = true
	}
	return settings
}

func isImportedMenuReplyRuleID(id string) bool {
	suffix, ok := strings.CutPrefix(id, importedMenuReplyRulePrefix)
	if !ok || len(suffix) != 24 {
		return false
	}
	for _, character := range suffix {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func hasWeChatCurrentMenuActionFields(button weChatCurrentMenuButton) bool {
	return button.Key != "" || button.URL != "" || button.Value != "" || button.AppID != "" || button.PagePath != "" || button.MediaID != "" || button.ArticleID != "" || hasJSONValue(button.NewsInfo)
}

func validateWeChatCurrentMenuActionFields(button weChatCurrentMenuButton, path string, allowed map[string]bool) error {
	unexpected := ""
	switch {
	case button.Key != "" && !allowed["key"]:
		unexpected = "key"
	case button.URL != "" && !allowed["url"]:
		unexpected = "url"
	case button.Value != "" && !allowed["value"]:
		unexpected = "value"
	case button.AppID != "" && !allowed["appid"]:
		unexpected = "appid"
	case button.PagePath != "" && !allowed["pagepath"]:
		unexpected = "pagepath"
	case button.MediaID != "" && !allowed["media_id"]:
		unexpected = "media_id"
	case button.ArticleID != "" && !allowed["article_id"]:
		unexpected = "article_id"
	case hasJSONValue(button.NewsInfo) && !allowed["news_info"]:
		unexpected = "news_info"
	}
	if unexpected != "" {
		return fmt.Errorf("%s: %s menu contains unexpected field %q", path, normalizeWeChatValue(button.Type), unexpected)
	}
	return nil
}

func hasJSONValue(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null"))
}

func decodeStrictJSONValue(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON must contain exactly one value")
		}
		return err
	}
	return nil
}
