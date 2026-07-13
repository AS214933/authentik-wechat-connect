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

const (
	legacyImportedMenuClickRulePrefix = "__wechat_connect_menu_text_"
	importedMenuKeywordRulePrefix     = "__wechat_connect_menu_keyword_"
)

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
// or an active API-managed get_current_selfmenu_info response. Website menu
// actions are deliberately not converted because doing so would require a
// successful menu/create call before WeChat could emit their generated keys.
func decodeWeChatAdminMenuPayload(raw []byte) (WeChatMenu, bool, error) {
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		return WeChatMenu{}, false, err
	}
	_, hasOpenState := shape["is_menu_open"]
	_, hasCurrentMenu := shape["selfmenu_info"]
	if !hasOpenState && !hasCurrentMenu {
		var menu WeChatMenu
		if err := decodeStrictJSONValue(raw, &menu); err != nil {
			return WeChatMenu{}, false, err
		}
		return menu, false, nil
	}

	envelope, err := decodeWeChatCurrentMenuEnvelope(raw)
	if err != nil {
		return WeChatMenu{}, true, err
	}
	if *envelope.IsMenuOpen == 0 {
		return WeChatMenu{}, true, errors.New("get_current_selfmenu_info reports is_menu_open=0; the website menu is inactive and cannot be imported as an API menu draft")
	}
	if envelope.SelfMenuInfo == nil {
		return WeChatMenu{}, true, errors.New("get_current_selfmenu_info response does not contain selfmenu_info")
	}

	buttons, err := convertWeChatCurrentMenuButtons(envelope.SelfMenuInfo.Button, "button")
	if err != nil {
		return WeChatMenu{}, true, err
	}
	return WeChatMenu{Button: buttons}, true, nil
}

func decodeWeChatCurrentMenuEnvelope(raw []byte) (weChatCurrentMenuEnvelope, error) {
	var envelope weChatCurrentMenuEnvelope
	if err := decodeStrictJSONValue(raw, &envelope); err != nil {
		return weChatCurrentMenuEnvelope{}, fmt.Errorf("decode get_current_selfmenu_info response: %w", err)
	}
	if envelope.IsMenuOpen == nil {
		return weChatCurrentMenuEnvelope{}, errors.New("get_current_selfmenu_info response does not contain is_menu_open")
	}
	if *envelope.IsMenuOpen != 0 && *envelope.IsMenuOpen != 1 {
		return weChatCurrentMenuEnvelope{}, errors.New("get_current_selfmenu_info is_menu_open must be 0 or 1")
	}
	return envelope, nil
}

func convertWeChatCurrentMenuButtons(source []weChatCurrentMenuButton, path string) ([]WeChatMenuButton, error) {
	buttons := make([]WeChatMenuButton, 0, len(source))
	for i, current := range source {
		buttonPath := fmt.Sprintf("%s[%d]", path, i)
		button, err := convertWeChatCurrentMenuButton(current, buttonPath)
		if err != nil {
			return nil, err
		}
		buttons = append(buttons, button)
	}
	return buttons, nil
}

func convertWeChatCurrentMenuButton(current weChatCurrentMenuButton, path string) (WeChatMenuButton, error) {
	name := current.Name
	if len(current.SubButton.List) != 0 {
		if current.Type != "" || hasWeChatCurrentMenuActionFields(current) {
			return WeChatMenuButton{}, fmt.Errorf("%s: a menu group cannot contain type or action fields", path)
		}
		children, err := convertWeChatCurrentMenuButtons(current.SubButton.List, path+".sub_button")
		if err != nil {
			return WeChatMenuButton{}, err
		}
		return WeChatMenuButton{Name: name, SubButton: children}, nil
	}

	typeName := normalizeWeChatValue(current.Type)
	button := WeChatMenuButton{Type: typeName, Name: name}
	switch typeName {
	case "click", "scancode_push", "scancode_waitmsg", "pic_sysphoto", "pic_photo_or_album", "pic_weixin", "location_select":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"key": true}); err != nil {
			return WeChatMenuButton{}, err
		}
		button.Key = current.Key
	case "view":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"url": true}); err != nil {
			return WeChatMenuButton{}, err
		}
		button.URL = current.URL
	case "media_id", "view_limited":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"media_id": true}); err != nil {
			return WeChatMenuButton{}, err
		}
		button.MediaID = current.MediaID
	case "article_id", "article_view_limited":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"article_id": true}); err != nil {
			return WeChatMenuButton{}, err
		}
		button.ArticleID = current.ArticleID
	case "miniprogram":
		if err := validateWeChatCurrentMenuActionFields(current, path, map[string]bool{"url": true, "appid": true, "pagepath": true}); err != nil {
			return WeChatMenuButton{}, err
		}
		button.URL = current.URL
		button.AppID = current.AppID
		button.PagePath = current.PagePath
	case "text":
		return WeChatMenuButton{}, fmt.Errorf("%s: website text menus cannot be imported as API click menus; import them as keyword replies instead", path)
	case "img", "voice", "video", "news":
		return WeChatMenuButton{}, fmt.Errorf("%s: website menu type %q cannot be imported as an API menu action", path, typeName)
	case "":
		return WeChatMenuButton{}, fmt.Errorf("%s: leaf menu button type is required", path)
	default:
		return WeChatMenuButton{}, fmt.Errorf("%s: unsupported current menu button type %q", path, current.Type)
	}
	return button, nil
}

func decodeWeChatWebsiteMenuKeywordRules(raw []byte) ([]WeChatReplyRule, error) {
	envelope, err := decodeWeChatCurrentMenuEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if envelope.SelfMenuInfo == nil {
		return nil, errors.New("get_current_selfmenu_info response does not contain selfmenu_info")
	}
	seenKeywords := make(map[string]string)
	rules, err := convertWeChatWebsiteMenuKeywordButtons(envelope.SelfMenuInfo.Button, "button", seenKeywords)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, errors.New("current website menu does not contain any text actions to import")
	}
	return rules, nil
}

func convertWeChatWebsiteMenuKeywordButtons(source []weChatCurrentMenuButton, path string, seenKeywords map[string]string) ([]WeChatReplyRule, error) {
	var rules []WeChatReplyRule
	for i, current := range source {
		buttonPath := fmt.Sprintf("%s[%d]", path, i)
		if len(current.SubButton.List) != 0 {
			if current.Type != "" || hasWeChatCurrentMenuActionFields(current) {
				return nil, fmt.Errorf("%s: a menu group cannot contain type or action fields", buttonPath)
			}
			nested, err := convertWeChatWebsiteMenuKeywordButtons(current.SubButton.List, buttonPath+".sub_button", seenKeywords)
			if err != nil {
				return nil, err
			}
			rules = append(rules, nested...)
			continue
		}

		if normalizeWeChatValue(current.Type) != "text" {
			return nil, fmt.Errorf("%s: website menu type %q cannot be imported as a text keyword reply", buttonPath, current.Type)
		}
		if current.Value == "" {
			return nil, fmt.Errorf("%s: website text menu value is required", buttonPath)
		}
		if current.Key != "" || current.URL != "" || current.AppID != "" || current.PagePath != "" || current.MediaID != "" || current.ArticleID != "" || hasJSONValue(current.NewsInfo) {
			return nil, fmt.Errorf("%s: website text menu contains fields for another action type", buttonPath)
		}
		keyword := current.Name
		if keyword == "" || strings.TrimSpace(keyword) != keyword {
			return nil, fmt.Errorf("%s: website text menu name must be non-empty and have no surrounding whitespace", buttonPath)
		}
		if normalizeLoginCode(keyword) != "" {
			return nil, fmt.Errorf("%s: eight-digit numeric menu names are reserved for login codes", buttonPath)
		}
		if previousPath, exists := seenKeywords[keyword]; exists {
			return nil, fmt.Errorf("%s: keyword %q duplicates %s", buttonPath, keyword, previousPath)
		}
		seenKeywords[keyword] = buttonPath

		rule := importedTextMenuKeywordRule(buttonPath, keyword, current.Value)
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("%s: convert website text menu to keyword reply: %w", buttonPath, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func importedTextMenuKeywordRule(path, keyword, content string) WeChatReplyRule {
	digest := sha256.Sum256([]byte(path + "\x00" + keyword + "\x00" + content))
	suffix := fmt.Sprintf("%x", digest[:12])
	return WeChatReplyRule{
		ID:      importedMenuKeywordRulePrefix + suffix,
		Name:    "菜单关键词：" + keyword,
		Enabled: true,
		Trigger: "text",
		Match:   "exact",
		Pattern: keyword,
		Reply:   WeChatReply{Type: "text", Content: content},
	}
}

func mergeImportedMenuKeywordRules(settings WeChatReplySettings, imported []WeChatReplyRule) (WeChatReplySettings, error) {
	settings = cloneWeChatReplySettings(settings)
	rules := make([]WeChatReplyRule, 0, len(imported)+len(settings.Rules))
	for _, rule := range settings.Rules {
		if isImportedMenuKeywordRuleID(rule.ID) {
			continue
		}
		if rule.Enabled {
			for _, keywordRule := range imported {
				message := WeChatInboundMessage{MsgType: "text", Content: keywordRule.Pattern}
				if ruleMatchesWeChatMessage(&rule, message) {
					return WeChatReplySettings{}, fmt.Errorf("keyword %q is shadowed by enabled reply rule %q", keywordRule.Pattern, rule.ID)
				}
			}
		}
		rules = append(rules, rule)
	}
	// Imported rules come last so importing cannot change the precedence of
	// existing user-managed rules.
	rules = append(rules, imported...)
	settings.Rules = rules
	if len(imported) != 0 {
		settings.Enabled = true
	}
	return settings, nil
}

func isImportedMenuKeywordRuleID(id string) bool {
	return hasImportedMenuRuleIDPrefix(id, importedMenuKeywordRulePrefix)
}

func isLegacyImportedMenuClickRuleID(id string) bool {
	return hasImportedMenuRuleIDPrefix(id, legacyImportedMenuClickRulePrefix)
}

func hasImportedMenuRuleIDPrefix(id, prefix string) bool {
	suffix, ok := strings.CutPrefix(id, prefix)
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
