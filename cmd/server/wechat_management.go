package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	wechatManagementSchemaVersion = 1
	maxWeChatReplyRules           = 200
)

var errManagementRevisionConflict = errors.New("WeChat management revision conflict")

// WeChatInboundMessage contains the union of fields sent for standard messages
// and events. Keeping one XML shape avoids losing fields before reply matching.
type WeChatInboundMessage struct {
	XMLName          xml.Name               `xml:"xml"`
	ToUserName       string                 `xml:"ToUserName"`
	FromUserName     string                 `xml:"FromUserName"`
	CreateTime       int64                  `xml:"CreateTime"`
	MsgType          string                 `xml:"MsgType"`
	MsgID            int64                  `xml:"MsgId"`
	MsgDataID        int64                  `xml:"MsgDataId"`
	Idx              int                    `xml:"Idx"`
	Content          string                 `xml:"Content"`
	PicURL           string                 `xml:"PicUrl"`
	MediaID          string                 `xml:"MediaId"`
	MediaID16K       string                 `xml:"MediaId16K"`
	Format           string                 `xml:"Format"`
	Recognition      string                 `xml:"Recognition"`
	ThumbMediaID     string                 `xml:"ThumbMediaId"`
	LocationX        float64                `xml:"Location_X"`
	LocationY        float64                `xml:"Location_Y"`
	Scale            int                    `xml:"Scale"`
	Label            string                 `xml:"Label"`
	Title            string                 `xml:"Title"`
	Description      string                 `xml:"Description"`
	URL              string                 `xml:"Url"`
	Event            string                 `xml:"Event"`
	EventKey         string                 `xml:"EventKey"`
	Ticket           string                 `xml:"Ticket"`
	MenuID           string                 `xml:"MenuId"`
	Latitude         float64                `xml:"Latitude"`
	Longitude        float64                `xml:"Longitude"`
	Precision        float64                `xml:"Precision"`
	Encrypt          string                 `xml:"Encrypt"`
	ScanCodeInfo     WeChatScanCodeInfo     `xml:"ScanCodeInfo"`
	SendPicsInfo     WeChatSendPicsInfo     `xml:"SendPicsInfo"`
	SendLocationInfo WeChatSendLocationInfo `xml:"SendLocationInfo"`
}

type WeChatScanCodeInfo struct {
	ScanType   string `xml:"ScanType"`
	ScanResult string `xml:"ScanResult"`
}

type WeChatSendPicsInfo struct {
	Count   int                  `xml:"Count"`
	PicList WeChatPictureMD5List `xml:"PicList"`
}

type WeChatPictureMD5List struct {
	Items []WeChatPictureMD5 `xml:"item"`
}

type WeChatPictureMD5 struct {
	PicMD5Sum string `xml:"PicMd5Sum"`
}

type WeChatSendLocationInfo struct {
	LocationX float64 `xml:"Location_X"`
	LocationY float64 `xml:"Location_Y"`
	Scale     int     `xml:"Scale"`
	Label     string  `xml:"Label"`
	Poiname   string  `xml:"Poiname"`
}

// wechatEventMessage is retained for the scan callback helpers and their
// existing callers while the callback uses the complete inbound shape.
type wechatEventMessage = WeChatInboundMessage

type WeChatNewsArticle struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	PicURL      string `json:"pic_url,omitempty"`
	URL         string `json:"url"`
}

type WeChatReply struct {
	Type         string              `json:"type"`
	Content      string              `json:"content,omitempty"`
	MediaID      string              `json:"media_id,omitempty"`
	Title        string              `json:"title,omitempty"`
	Description  string              `json:"description,omitempty"`
	MusicURL     string              `json:"music_url,omitempty"`
	HQMusicURL   string              `json:"hq_music_url,omitempty"`
	ThumbMediaID string              `json:"thumb_media_id,omitempty"`
	Articles     []WeChatNewsArticle `json:"articles,omitempty"`
}

func (r WeChatReply) Validate() error {
	if len(r.MediaID) > 128 {
		return errors.New("reply media_id must not exceed 128 bytes")
	}
	if len(r.ThumbMediaID) > 128 {
		return errors.New("reply thumb_media_id must not exceed 128 bytes")
	}
	if r.MusicURL != "" {
		if err := validateAbsoluteHTTPURL(r.MusicURL); err != nil {
			return fmt.Errorf("reply music_url: %w", err)
		}
	}
	if r.HQMusicURL != "" {
		if err := validateAbsoluteHTTPURL(r.HQMusicURL); err != nil {
			return fmt.Errorf("reply hq_music_url: %w", err)
		}
	}
	for i, article := range r.Articles {
		if article.URL != "" {
			if err := validateAbsoluteHTTPURL(article.URL); err != nil {
				return fmt.Errorf("news article %d url: %w", i+1, err)
			}
		}
		if article.PicURL != "" {
			if err := validateAbsoluteHTTPURL(article.PicURL); err != nil {
				return fmt.Errorf("news article %d pic_url: %w", i+1, err)
			}
		}
	}
	switch r.Type {
	case "text":
		if r.Content == "" {
			return errors.New("text reply content is required")
		}
		if len(r.Content) > 2048 {
			return errors.New("text reply content must not exceed 2048 bytes")
		}
	case "image", "voice", "video":
		if strings.TrimSpace(r.MediaID) == "" {
			return fmt.Errorf("%s reply media_id is required", r.Type)
		}
	case "music":
		if strings.TrimSpace(r.ThumbMediaID) == "" {
			return errors.New("music reply thumb_media_id is required")
		}
	case "news":
		if len(r.Articles) < 1 || len(r.Articles) > 8 {
			return errors.New("news reply must contain between 1 and 8 articles")
		}
		for i, article := range r.Articles {
			if strings.TrimSpace(article.Title) == "" {
				return fmt.Errorf("news article %d title is required", i+1)
			}
		}
	case "official_ai", "customer_service":
		if r.Content != "" || r.MediaID != "" || r.Title != "" || r.Description != "" || r.MusicURL != "" || r.HQMusicURL != "" || r.ThumbMediaID != "" || len(r.Articles) != 0 {
			return fmt.Errorf("%s reply must not contain a payload", r.Type)
		}
	default:
		return fmt.Errorf("unsupported WeChat reply type %q", r.Type)
	}
	return nil
}

type WeChatReplyRule struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Enabled bool        `json:"enabled"`
	Trigger string      `json:"trigger"`
	Match   string      `json:"match"`
	Pattern string      `json:"pattern,omitempty"`
	Reply   WeChatReply `json:"reply"`

	compiledPattern *regexp.Regexp
}

func (r WeChatReplyRule) Validate() error {
	return validateWeChatReplyRule(&r)
}

func validateWeChatReplyRule(rule *WeChatReplyRule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return errors.New("reply rule id is required")
	}
	if len(rule.ID) > 128 {
		return fmt.Errorf("reply rule %q id must not exceed 128 bytes", rule.ID)
	}
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("reply rule %q name is required", rule.ID)
	}
	if len(rule.Name) > 128 {
		return fmt.Errorf("reply rule %q name must not exceed 128 bytes", rule.ID)
	}
	if len(rule.Pattern) > 512 {
		return fmt.Errorf("reply rule %q pattern must not exceed 512 bytes", rule.ID)
	}
	trigger := rule.Trigger
	if !validWeChatReplyTriggers[trigger] {
		return fmt.Errorf("reply rule %q has unsupported trigger %q", rule.ID, rule.Trigger)
	}
	match := rule.Match
	if !validWeChatRuleMatches[match] {
		return fmt.Errorf("reply rule %q has unsupported match %q", rule.ID, rule.Match)
	}
	if match == "any" {
		if rule.Pattern != "" {
			return fmt.Errorf("reply rule %q pattern must be empty for an any match", rule.ID)
		}
		rule.compiledPattern = nil
	} else if rule.Pattern == "" {
		return fmt.Errorf("reply rule %q pattern is required for a %s match", rule.ID, match)
	} else if match == "regex" {
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("reply rule %q pattern is not a valid regular expression: %w", rule.ID, err)
		}
		rule.compiledPattern = compiled
	} else {
		rule.compiledPattern = nil
	}
	if err := rule.Reply.Validate(); err != nil {
		return fmt.Errorf("reply rule %q: %w", rule.ID, err)
	}
	if isWeChatEventTrigger(trigger) && isWeChatHandoffReply(rule.Reply.Type) {
		return fmt.Errorf("reply rule %q cannot use %s for an event trigger", rule.ID, rule.Reply.Type)
	}
	if !isWeChatEventTrigger(trigger) && rule.Reply.Type == "news" && len(rule.Reply.Articles) > 1 {
		return fmt.Errorf("reply rule %q standard messages support at most 1 news article", rule.ID)
	}
	return nil
}

var validWeChatReplyTriggers = map[string]bool{
	"any_message":        true,
	"text":               true,
	"image":              true,
	"voice":              true,
	"video":              true,
	"shortvideo":         true,
	"location":           true,
	"link":               true,
	"subscribe":          true,
	"unsubscribe":        true,
	"scan":               true,
	"click":              true,
	"view":               true,
	"scancode_push":      true,
	"scancode_waitmsg":   true,
	"pic_sysphoto":       true,
	"pic_photo_or_album": true,
	"pic_weixin":         true,
	"location_select":    true,
	"view_miniprogram":   true,
}

var validWeChatRuleMatches = map[string]bool{
	"any":      true,
	"exact":    true,
	"contains": true,
	"prefix":   true,
	"regex":    true,
}

type WeChatReplySettings struct {
	Enabled      bool              `json:"enabled"`
	Rules        []WeChatReplyRule `json:"rules"`
	DefaultReply *WeChatReply      `json:"default_reply,omitempty"`
}

func (s WeChatReplySettings) Validate() error {
	clone := cloneWeChatReplySettings(s)
	return validateWeChatReplySettings(&clone)
}

func validateWeChatReplySettings(settings *WeChatReplySettings) error {
	if len(settings.Rules) > maxWeChatReplyRules {
		return fmt.Errorf("reply settings must not contain more than %d rules", maxWeChatReplyRules)
	}
	seen := make(map[string]struct{}, len(settings.Rules))
	for i := range settings.Rules {
		rule := &settings.Rules[i]
		if err := validateWeChatReplyRule(rule); err != nil {
			return fmt.Errorf("reply rules[%d]: %w", i, err)
		}
		if _, exists := seen[rule.ID]; exists {
			return fmt.Errorf("reply rule id %q is duplicated", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
	if settings.DefaultReply != nil {
		if err := settings.DefaultReply.Validate(); err != nil {
			return fmt.Errorf("default reply: %w", err)
		}
		if settings.DefaultReply.Type == "news" && len(settings.DefaultReply.Articles) > 1 {
			return errors.New("default reply standard messages support at most 1 news article")
		}
	}
	return nil
}

// SelectReply returns a detached reply and either the matching rule ID or
// "default". Events deliberately never fall through to DefaultReply.
func (s WeChatReplySettings) SelectReply(msg WeChatInboundMessage) (*WeChatReply, string) {
	if !s.Enabled {
		return nil, ""
	}
	for i := range s.Rules {
		rule := &s.Rules[i]
		if !rule.Enabled || !ruleMatchesWeChatMessage(rule, msg) {
			continue
		}
		if isWeChatHandoffReply(rule.Reply.Type) && !isWeChatStandardMessage(msg) {
			continue
		}
		reply := cloneWeChatReply(rule.Reply)
		return &reply, rule.ID
	}
	if s.DefaultReply == nil || !isWeChatStandardMessage(msg) {
		return nil, ""
	}
	if isWeChatHandoffReply(s.DefaultReply.Type) && !isWeChatStandardMessage(msg) {
		return nil, ""
	}
	reply := cloneWeChatReply(*s.DefaultReply)
	return &reply, "default"
}

func ruleMatchesWeChatMessage(rule *WeChatReplyRule, msg WeChatInboundMessage) bool {
	if !triggerMatchesWeChatMessage(rule.Trigger, msg) {
		return false
	}
	value := weChatMessageMatchValue(msg)
	switch normalizeWeChatValue(rule.Match) {
	case "any":
		return true
	case "exact":
		return value == rule.Pattern
	case "contains":
		return strings.Contains(value, rule.Pattern)
	case "prefix":
		return strings.HasPrefix(value, rule.Pattern)
	case "regex":
		compiled := rule.compiledPattern
		if compiled == nil || compiled.String() != rule.Pattern {
			var err error
			compiled, err = regexp.Compile(rule.Pattern)
			if err != nil {
				return false
			}
		}
		return compiled.MatchString(value)
	default:
		return false
	}
}

func triggerMatchesWeChatMessage(trigger string, msg WeChatInboundMessage) bool {
	trigger = normalizeWeChatValue(trigger)
	if trigger == "any_message" {
		return isWeChatStandardMessage(msg)
	}
	if normalizeWeChatValue(msg.MsgType) == "event" {
		return trigger == normalizeWeChatValue(msg.Event) && isWeChatEventTrigger(trigger)
	}
	return trigger == normalizeWeChatValue(msg.MsgType) && isWeChatStandardMessage(msg)
}

func isWeChatStandardMessage(msg WeChatInboundMessage) bool {
	switch normalizeWeChatValue(msg.MsgType) {
	case "text", "image", "voice", "video", "shortvideo", "location", "link":
		return true
	default:
		return false
	}
}

func isWeChatEventTrigger(trigger string) bool {
	switch normalizeWeChatValue(trigger) {
	case "subscribe", "unsubscribe", "scan", "click", "view", "scancode_push", "scancode_waitmsg", "pic_sysphoto", "pic_photo_or_album", "pic_weixin", "location_select", "view_miniprogram":
		return true
	default:
		return false
	}
}

func isWeChatHandoffReply(replyType string) bool {
	switch normalizeWeChatValue(replyType) {
	case "official_ai", "customer_service":
		return true
	default:
		return false
	}
}

func weChatMessageMatchValue(msg WeChatInboundMessage) string {
	if normalizeWeChatValue(msg.MsgType) == "event" {
		switch normalizeWeChatValue(msg.Event) {
		case "scancode_push", "scancode_waitmsg":
			if msg.ScanCodeInfo.ScanResult != "" {
				return msg.ScanCodeInfo.ScanResult
			}
		case "pic_sysphoto", "pic_photo_or_album", "pic_weixin":
			values := make([]string, 0, len(msg.SendPicsInfo.PicList.Items))
			for _, picture := range msg.SendPicsInfo.PicList.Items {
				if picture.PicMD5Sum != "" {
					values = append(values, picture.PicMD5Sum)
				}
			}
			if len(values) != 0 {
				return strings.Join(values, "\n")
			}
		case "location_select":
			value := strings.TrimSpace(strings.Join([]string{msg.SendLocationInfo.Label, msg.SendLocationInfo.Poiname}, "\n"))
			if value != "" {
				return value
			}
		}
		return msg.EventKey
	}
	switch normalizeWeChatValue(msg.MsgType) {
	case "text":
		return msg.Content
	case "voice":
		if msg.Recognition != "" {
			return msg.Recognition
		}
		return msg.MediaID
	case "image", "video", "shortvideo":
		return msg.MediaID
	case "location":
		return msg.Label
	case "link":
		return msg.URL
	default:
		return ""
	}
}

type WeChatMenu struct {
	Button []WeChatMenuButton `json:"button"`
}

type WeChatMenuButton struct {
	Type      string             `json:"type,omitempty"`
	Name      string             `json:"name"`
	Key       string             `json:"key,omitempty"`
	URL       string             `json:"url,omitempty"`
	AppID     string             `json:"appid,omitempty"`
	PagePath  string             `json:"pagepath,omitempty"`
	MediaID   string             `json:"media_id,omitempty"`
	ArticleID string             `json:"article_id,omitempty"`
	SubButton []WeChatMenuButton `json:"sub_button,omitempty"`
}

func (m WeChatMenu) Validate() error {
	if len(m.Button) > 3 {
		return errors.New("WeChat menu must not contain more than 3 top-level buttons")
	}
	for i := range m.Button {
		if err := validateWeChatMenuButton(m.Button[i], false); err != nil {
			return fmt.Errorf("menu button[%d]: %w", i, err)
		}
	}
	return nil
}

func validateWeChatMenuButton(button WeChatMenuButton, secondary bool) error {
	if strings.TrimSpace(button.Name) == "" {
		return errors.New("name is required")
	}
	maxNameBytes := 16
	if secondary {
		maxNameBytes = 60
	}
	if len(button.Name) > maxNameBytes {
		return fmt.Errorf("name must not exceed %d bytes", maxNameBytes)
	}
	if len(button.Key) > 128 {
		return errors.New("key must not exceed 128 bytes")
	}
	if len(button.MediaID) > 128 {
		return errors.New("media_id must not exceed 128 bytes")
	}
	if len(button.ArticleID) > 128 {
		return errors.New("article_id must not exceed 128 bytes")
	}
	if len(button.AppID) > 64 {
		return errors.New("appid must not exceed 64 bytes")
	}
	if len(button.PagePath) > 1024 {
		return errors.New("pagepath must not exceed 1024 bytes")
	}
	if button.URL != "" {
		if err := validateWeChatMenuURL(button.URL); err != nil {
			return err
		}
	}
	if secondary && len(button.SubButton) != 0 {
		return errors.New("third-level menu buttons are not supported")
	}
	if len(button.SubButton) != 0 {
		if len(button.SubButton) > 5 {
			return errors.New("a top-level menu button must not contain more than 5 sub-buttons")
		}
		if button.Type != "" || hasWeChatMenuActionFields(button) {
			return errors.New("a menu group cannot define a leaf type or action fields")
		}
		for i := range button.SubButton {
			if err := validateWeChatMenuButton(button.SubButton[i], true); err != nil {
				return fmt.Errorf("sub_button[%d]: %w", i, err)
			}
		}
		return nil
	}

	typeName := button.Type
	if typeName == "" {
		return errors.New("leaf menu button type is required")
	}
	switch typeName {
	case "click", "scancode_push", "scancode_waitmsg", "pic_sysphoto", "pic_photo_or_album", "pic_weixin", "location_select":
		if strings.TrimSpace(button.Key) == "" {
			return fmt.Errorf("%s menu button key is required", typeName)
		}
		if button.URL != "" || button.AppID != "" || button.PagePath != "" || button.MediaID != "" || button.ArticleID != "" {
			return fmt.Errorf("%s menu button contains fields for another action type", typeName)
		}
	case "view":
		if button.URL == "" {
			return errors.New("view menu button url is required")
		}
		if button.Key != "" || button.AppID != "" || button.PagePath != "" || button.MediaID != "" || button.ArticleID != "" {
			return errors.New("view menu button contains fields for another action type")
		}
	case "media_id", "view_limited":
		if strings.TrimSpace(button.MediaID) == "" {
			return fmt.Errorf("%s menu button media_id is required", typeName)
		}
		if button.Key != "" || button.URL != "" || button.AppID != "" || button.PagePath != "" || button.ArticleID != "" {
			return fmt.Errorf("%s menu button contains fields for another action type", typeName)
		}
	case "article_id", "article_view_limited":
		if strings.TrimSpace(button.ArticleID) == "" {
			return fmt.Errorf("%s menu button article_id is required", typeName)
		}
		if button.Key != "" || button.URL != "" || button.AppID != "" || button.PagePath != "" || button.MediaID != "" {
			return fmt.Errorf("%s menu button contains fields for another action type", typeName)
		}
	case "miniprogram":
		if button.URL == "" || strings.TrimSpace(button.AppID) == "" || strings.TrimSpace(button.PagePath) == "" {
			return errors.New("miniprogram menu button url, appid, and pagepath are required")
		}
		if button.Key != "" || button.MediaID != "" || button.ArticleID != "" {
			return errors.New("miniprogram menu button contains fields for another action type")
		}
		if button.AppID != strings.ToLower(button.AppID) {
			return errors.New("miniprogram menu button appid must be lowercase")
		}
	default:
		return fmt.Errorf("unsupported menu button type %q", button.Type)
	}
	return nil
}

func validateWeChatMenuURL(rawURL string) error {
	if len(rawURL) > 1024 {
		return errors.New("menu button url must not exceed 1024 bytes")
	}
	if err := validateAbsoluteHTTPURL(rawURL); err != nil {
		return fmt.Errorf("menu button url: %w", err)
	}
	return nil
}

func validateAbsoluteHTTPURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("must be an absolute http or https URL")
	}
	return nil
}

func hasWeChatMenuActionFields(button WeChatMenuButton) bool {
	return button.Key != "" || button.URL != "" || button.AppID != "" || button.PagePath != "" || button.MediaID != "" || button.ArticleID != ""
}

type WeChatManagementState struct {
	SchemaVersion int                 `json:"schema_version"`
	Revision      uint64              `json:"revision"`
	Replies       WeChatReplySettings `json:"replies"`
	Menu          WeChatMenu          `json:"menu"`
	UpdatedAt     time.Time           `json:"updated_at"`
}

func (s WeChatManagementState) Validate() error {
	clone := cloneWeChatManagementState(s)
	return validateWeChatManagementState(&clone)
}

func validateWeChatManagementState(state *WeChatManagementState) error {
	if state.SchemaVersion != wechatManagementSchemaVersion {
		return fmt.Errorf("unsupported WeChat management schema version %d", state.SchemaVersion)
	}
	if err := validateWeChatReplySettings(&state.Replies); err != nil {
		return fmt.Errorf("replies: %w", err)
	}
	if err := state.Menu.Validate(); err != nil {
		return fmt.Errorf("menu: %w", err)
	}
	return nil
}

type wechatManagementStore struct {
	mu    sync.RWMutex
	path  string
	state WeChatManagementState
}

func newWeChatManagementStore(path string) (*wechatManagementStore, error) {
	store := &wechatManagementStore{
		path: path,
		state: WeChatManagementState{
			SchemaVersion: wechatManagementSchemaVersion,
			Replies:       WeChatReplySettings{Rules: []WeChatReplyRule{}},
			Menu:          WeChatMenu{Button: []WeChatMenuButton{}},
		},
	}
	if path == "" {
		return store, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read WeChat management state: %w", err)
	}
	var state WeChatManagementState
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("decode WeChat management state: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("decode WeChat management state: multiple JSON values")
		}
		return nil, fmt.Errorf("decode WeChat management state: %w", err)
	}
	if err := validateWeChatManagementState(&state); err != nil {
		return nil, fmt.Errorf("validate WeChat management state: %w", err)
	}
	store.state = cloneWeChatManagementState(state)
	return store, nil
}

func (s *wechatManagementStore) Snapshot() WeChatManagementState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneWeChatManagementState(s.state)
}

func (s *wechatManagementStore) UpdateReplies(expectedRevision uint64, replies WeChatReplySettings) (WeChatManagementState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedRevision != s.state.Revision {
		return WeChatManagementState{}, fmt.Errorf("%w: expected %d, current %d", errManagementRevisionConflict, expectedRevision, s.state.Revision)
	}
	candidate := cloneWeChatManagementState(s.state)
	candidate.Replies = cloneWeChatReplySettings(replies)
	if err := validateWeChatReplySettings(&candidate.Replies); err != nil {
		return WeChatManagementState{}, fmt.Errorf("validate replies: %w", err)
	}
	return s.commitLocked(candidate)
}

func (s *wechatManagementStore) UpdateMenu(expectedRevision uint64, menu WeChatMenu) (WeChatManagementState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedRevision != s.state.Revision {
		return WeChatManagementState{}, fmt.Errorf("%w: expected %d, current %d", errManagementRevisionConflict, expectedRevision, s.state.Revision)
	}
	candidate := cloneWeChatManagementState(s.state)
	candidate.Menu = cloneWeChatMenu(menu)
	if err := candidate.Menu.Validate(); err != nil {
		return WeChatManagementState{}, fmt.Errorf("validate menu: %w", err)
	}
	return s.commitLocked(candidate)
}

func (s *wechatManagementStore) commitLocked(candidate WeChatManagementState) (WeChatManagementState, error) {
	candidate.SchemaVersion = wechatManagementSchemaVersion
	candidate.Revision = s.state.Revision + 1
	candidate.UpdatedAt = time.Now().UTC()
	if err := persistWeChatManagementState(s.path, candidate); err != nil {
		return WeChatManagementState{}, err
	}
	s.state = cloneWeChatManagementState(candidate)
	return cloneWeChatManagementState(candidate), nil
}

func persistWeChatManagementState(path string, state WeChatManagementState) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode WeChat management state: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create WeChat management state directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary WeChat management state: %w", err)
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set temporary WeChat management state permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary WeChat management state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary WeChat management state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary WeChat management state: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace WeChat management state: %w", err)
	}
	removeTemp = false
	// The rename is already committed at this point. Directory sync is best
	// effort so an unusual filesystem error cannot make memory lag disk.
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func cloneWeChatManagementState(state WeChatManagementState) WeChatManagementState {
	clone := state
	clone.Replies = cloneWeChatReplySettings(state.Replies)
	clone.Menu = cloneWeChatMenu(state.Menu)
	return clone
}

func cloneWeChatReplySettings(settings WeChatReplySettings) WeChatReplySettings {
	clone := settings
	if settings.Rules != nil {
		clone.Rules = make([]WeChatReplyRule, len(settings.Rules))
		for i := range settings.Rules {
			clone.Rules[i] = settings.Rules[i]
			clone.Rules[i].Reply = cloneWeChatReply(settings.Rules[i].Reply)
		}
	}
	if settings.DefaultReply != nil {
		defaultReply := cloneWeChatReply(*settings.DefaultReply)
		clone.DefaultReply = &defaultReply
	}
	return clone
}

func cloneWeChatReply(reply WeChatReply) WeChatReply {
	clone := reply
	if reply.Articles != nil {
		clone.Articles = append([]WeChatNewsArticle(nil), reply.Articles...)
	}
	return clone
}

func cloneWeChatMenu(menu WeChatMenu) WeChatMenu {
	clone := menu
	if menu.Button != nil {
		clone.Button = make([]WeChatMenuButton, len(menu.Button))
		for i := range menu.Button {
			clone.Button[i] = cloneWeChatMenuButton(menu.Button[i])
		}
	}
	return clone
}

func cloneWeChatMenuButton(button WeChatMenuButton) WeChatMenuButton {
	clone := button
	if button.SubButton != nil {
		clone.SubButton = make([]WeChatMenuButton, len(button.SubButton))
		for i := range button.SubButton {
			clone.SubButton[i] = cloneWeChatMenuButton(button.SubButton[i])
		}
	}
	return clone
}

func normalizeWeChatValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
