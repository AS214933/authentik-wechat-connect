package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWeChatInboundMessageXMLFields(t *testing.T) {
	input := `<xml><ToUserName>to</ToUserName><FromUserName>from</FromUserName><CreateTime>10</CreateTime><MsgType>location</MsgType><MsgId>11</MsgId><MsgDataId>12</MsgDataId><Idx>2</Idx><Content>hello</Content><PicUrl>https://example.com/p</PicUrl><MediaId>media</MediaId><MediaId16K>media-16k</MediaId16K><Format>amr</Format><Recognition>speech</Recognition><ThumbMediaId>thumb</ThumbMediaId><Location_X>1.25</Location_X><Location_Y>2.5</Location_Y><Scale>15</Scale><Label>label</Label><Title>title</Title><Description>description</Description><Url>https://example.com</Url><Event>CLICK</Event><EventKey>key</EventKey><Ticket>ticket</Ticket><MenuId>menu-id</MenuId><Latitude>3.5</Latitude><Longitude>4.5</Longitude><Precision>0.25</Precision><ScanCodeInfo><ScanType>qrcode</ScanType><ScanResult>scan-value</ScanResult></ScanCodeInfo><SendPicsInfo><Count>1</Count><PicList><item><PicMd5Sum>pic-md5</PicMd5Sum></item></PicList></SendPicsInfo><SendLocationInfo><Location_X>30.1</Location_X><Location_Y>120.2</Location_Y><Scale>16</Scale><Label>address</Label><Poiname>place</Poiname></SendLocationInfo><Encrypt>ciphertext</Encrypt></xml>`
	var message WeChatInboundMessage
	if err := xml.Unmarshal([]byte(input), &message); err != nil {
		t.Fatal(err)
	}
	if message.XMLName.Local != "xml" || message.ToUserName != "to" || message.FromUserName != "from" || message.CreateTime != 10 || message.MsgType != "location" || message.MsgID != 11 || message.MsgDataID != 12 || message.Idx != 2 || message.Content != "hello" || message.PicURL == "" || message.MediaID != "media" || message.MediaID16K != "media-16k" || message.Format != "amr" || message.Recognition != "speech" || message.ThumbMediaID != "thumb" || message.LocationX != 1.25 || message.LocationY != 2.5 || message.Scale != 15 || message.Label != "label" || message.Title != "title" || message.Description != "description" || message.URL == "" || message.Event != "CLICK" || message.EventKey != "key" || message.Ticket != "ticket" || message.MenuID != "menu-id" || message.Latitude != 3.5 || message.Longitude != 4.5 || message.Precision != 0.25 || message.ScanCodeInfo.ScanType != "qrcode" || message.ScanCodeInfo.ScanResult != "scan-value" || message.SendPicsInfo.Count != 1 || len(message.SendPicsInfo.PicList.Items) != 1 || message.SendPicsInfo.PicList.Items[0].PicMD5Sum != "pic-md5" || message.SendLocationInfo.Label != "address" || message.SendLocationInfo.Poiname != "place" || message.Encrypt != "ciphertext" {
		t.Fatalf("unexpected decoded message: %#v", message)
	}
}

func TestWeChatReplyValidation(t *testing.T) {
	valid := []WeChatReply{
		{Type: "text", Content: "hello"},
		{Type: "image", MediaID: "media"},
		{Type: "voice", MediaID: "media"},
		{Type: "video", MediaID: "media"},
		{Type: "music", ThumbMediaID: "thumb"},
		{Type: "news", Articles: []WeChatNewsArticle{{Title: "article"}}},
		{Type: "official_ai"},
		{Type: "customer_service"},
	}
	for _, reply := range valid {
		if err := reply.Validate(); err != nil {
			t.Errorf("valid %s reply rejected: %v", reply.Type, err)
		}
	}

	invalid := []WeChatReply{
		{},
		{Type: "TEXT", Content: "uppercase enum"},
		{Type: "text"},
		{Type: "text", Content: strings.Repeat("界", 683)},
		{Type: "image"},
		{Type: "image", MediaID: strings.Repeat("m", 129)},
		{Type: "voice"},
		{Type: "video"},
		{Type: "music"},
		{Type: "music", ThumbMediaID: strings.Repeat("m", 129)},
		{Type: "music", ThumbMediaID: "thumb", MusicURL: "/relative"},
		{Type: "news"},
		{Type: "news", Articles: make([]WeChatNewsArticle, 9)},
		{Type: "news", Articles: []WeChatNewsArticle{{URL: "https://example.com"}}},
		{Type: "news", Articles: []WeChatNewsArticle{{Title: "title", URL: "ftp://example.com"}}},
		{Type: "news", Articles: []WeChatNewsArticle{{Title: "title", URL: "https://example.com", PicURL: "/relative"}}},
		{Type: "official_ai", Content: "payload"},
		{Type: "customer_service", MediaID: "payload"},
	}
	for i, reply := range invalid {
		if err := reply.Validate(); err == nil {
			t.Errorf("invalid reply %d was accepted: %#v", i, reply)
		}
	}
}

func TestWeChatReplySettingsValidation(t *testing.T) {
	settings := WeChatReplySettings{Rules: []WeChatReplyRule{
		{ID: "one", Name: "one", Enabled: true, Trigger: "text", Match: "regex", Pattern: `^hello`, Reply: WeChatReply{Type: "text", Content: "one"}},
		{ID: "two", Name: "two", Enabled: true, Trigger: "click", Match: "exact", Pattern: "menu-key", Reply: WeChatReply{Type: "text", Content: "two"}},
	}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}

	cases := []WeChatReplySettings{
		{Rules: []WeChatReplyRule{{ID: "", Name: "name", Trigger: "text", Match: "any", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "", Trigger: "text", Match: "any", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "unknown", Match: "any", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "text", Match: "unknown", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "text", Match: "regex", Pattern: "[", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "text", Match: "any", Pattern: "unexpected", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{
			{ID: "same", Name: "one", Trigger: "text", Match: "any", Reply: WeChatReply{Type: "text", Content: "x"}},
			{ID: "same", Name: "two", Trigger: "image", Match: "any", Reply: WeChatReply{Type: "text", Content: "x"}},
		}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "click", Match: "any", Reply: WeChatReply{Type: "official_ai"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "subscribe", Match: "any", Reply: WeChatReply{Type: "customer_service"}}}},
		{Rules: []WeChatReplyRule{{ID: strings.Repeat("i", 129), Name: "name", Trigger: "text", Match: "any", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: strings.Repeat("n", 129), Trigger: "text", Match: "any", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "text", Match: "exact", Pattern: strings.Repeat("p", 513), Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "Text", Match: "any", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "text", Match: "Any", Reply: WeChatReply{Type: "text", Content: "x"}}}},
		{Rules: []WeChatReplyRule{{ID: "id", Name: "name", Trigger: "text", Match: "any", Reply: WeChatReply{Type: "news", Articles: []WeChatNewsArticle{{Title: "one", URL: "https://example.com/1"}, {Title: "two", URL: "https://example.com/2"}}}}}},
		{DefaultReply: &WeChatReply{Type: "news", Articles: []WeChatNewsArticle{{Title: "one", URL: "https://example.com/1"}, {Title: "two", URL: "https://example.com/2"}}}},
	}
	tooMany := WeChatReplySettings{Rules: make([]WeChatReplyRule, maxWeChatReplyRules+1)}
	cases = append(cases, tooMany)
	for i, testCase := range cases {
		if err := testCase.Validate(); err == nil {
			t.Errorf("invalid reply settings %d were accepted", i)
		}
	}
	eventNews := WeChatReplySettings{Rules: []WeChatReplyRule{{
		ID:      "event-news",
		Name:    "event news",
		Trigger: "click",
		Match:   "any",
		Reply: WeChatReply{Type: "news", Articles: []WeChatNewsArticle{
			{Title: "one", URL: "https://example.com/1"},
			{Title: "two", URL: "https://example.com/2"},
		}},
	}}}
	if err := eventNews.Validate(); err != nil {
		t.Fatalf("event news reply with multiple articles rejected: %v", err)
	}
}

func TestSelectWeChatReplyUsesOrderedRulesAndDefaultOnlyForMessages(t *testing.T) {
	defaultReply := &WeChatReply{Type: "text", Content: "default"}
	settings := WeChatReplySettings{Enabled: true, DefaultReply: defaultReply, Rules: []WeChatReplyRule{
		{ID: "disabled", Name: "disabled", Enabled: false, Trigger: "text", Match: "any", Reply: WeChatReply{Type: "text", Content: "disabled"}},
		{ID: "first", Name: "first", Enabled: true, Trigger: "text", Match: "contains", Pattern: "hello", Reply: WeChatReply{Type: "news", Articles: []WeChatNewsArticle{{Title: "first", URL: "https://example.com"}}}},
		{ID: "second", Name: "second", Enabled: true, Trigger: "any_message", Match: "prefix", Pattern: "hello", Reply: WeChatReply{Type: "text", Content: "second"}},
		{ID: "menu", Name: "menu", Enabled: true, Trigger: "click", Match: "exact", Pattern: "help", Reply: WeChatReply{Type: "text", Content: "clicked"}},
	}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}

	reply, source := settings.SelectReply(WeChatInboundMessage{MsgType: "text", Content: "say hello"})
	if reply == nil || source != "first" || reply.Articles[0].Title != "first" {
		t.Fatalf("unexpected first match: reply=%#v source=%q", reply, source)
	}
	reply.Articles[0].Title = "mutated"
	if settings.Rules[1].Reply.Articles[0].Title != "first" {
		t.Fatal("SelectReply returned storage-owned article data")
	}

	reply, source = settings.SelectReply(WeChatInboundMessage{MsgType: "image", MediaID: "unmatched"})
	if reply == nil || source != "default" || reply.Content != "default" {
		t.Fatalf("standard message did not select default: reply=%#v source=%q", reply, source)
	}
	reply, source = settings.SelectReply(WeChatInboundMessage{MsgType: "event", Event: "CLICK", EventKey: "help"})
	if reply == nil || source != "menu" || reply.Content != "clicked" {
		t.Fatalf("event rule did not match: reply=%#v source=%q", reply, source)
	}
	reply, source = settings.SelectReply(WeChatInboundMessage{MsgType: "event", Event: "subscribe"})
	if reply != nil || source != "" {
		t.Fatalf("event fell through to default: reply=%#v source=%q", reply, source)
	}
	settings.Enabled = false
	if reply, source := settings.SelectReply(WeChatInboundMessage{MsgType: "text", Content: "hello"}); reply != nil || source != "" {
		t.Fatalf("disabled settings selected a reply: %#v %q", reply, source)
	}
}

func TestSelectWeChatReplyMatchesAdvancedMenuEventPayloads(t *testing.T) {
	settings := WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{
		{ID: "scan-code", Name: "scan code", Enabled: true, Trigger: "scancode_push", Match: "exact", Pattern: "decoded-value", Reply: WeChatReply{Type: "text", Content: "scan reply"}},
		{ID: "pictures", Name: "pictures", Enabled: true, Trigger: "pic_photo_or_album", Match: "contains", Pattern: "md5-two", Reply: WeChatReply{Type: "text", Content: "picture reply"}},
		{ID: "selected-location", Name: "location", Enabled: true, Trigger: "location_select", Match: "contains", Pattern: "Central Park", Reply: WeChatReply{Type: "text", Content: "location reply"}},
	}}
	if err := settings.Validate(); err != nil {
		t.Fatalf("validate settings: %v", err)
	}
	tests := []struct {
		message WeChatInboundMessage
		ruleID  string
	}{
		{message: WeChatInboundMessage{MsgType: "event", Event: "scancode_push", EventKey: "scan-button", ScanCodeInfo: WeChatScanCodeInfo{ScanResult: "decoded-value"}}, ruleID: "scan-code"},
		{message: WeChatInboundMessage{MsgType: "event", Event: "pic_photo_or_album", EventKey: "photo-button", SendPicsInfo: WeChatSendPicsInfo{PicList: WeChatPictureMD5List{Items: []WeChatPictureMD5{{PicMD5Sum: "md5-one"}, {PicMD5Sum: "md5-two"}}}}}, ruleID: "pictures"},
		{message: WeChatInboundMessage{MsgType: "event", Event: "location_select", EventKey: "location-button", SendLocationInfo: WeChatSendLocationInfo{Label: "59th Street", Poiname: "Central Park"}}, ruleID: "selected-location"},
	}
	for _, tt := range tests {
		reply, ruleID := settings.SelectReply(tt.message)
		if reply == nil || ruleID != tt.ruleID {
			t.Errorf("event=%s reply=%#v rule=%q want %q", tt.message.Event, reply, ruleID, tt.ruleID)
		}
	}
}

func TestWeChatMenuValidation(t *testing.T) {
	validLeaves := []WeChatMenuButton{
		{Type: "click", Name: "click", Key: "key"},
		{Type: "view", Name: "view", URL: "https://example.com"},
		{Type: "scancode_push", Name: "scan", Key: "key"},
		{Type: "scancode_waitmsg", Name: "wait", Key: "key"},
		{Type: "pic_sysphoto", Name: "photo", Key: "key"},
		{Type: "pic_photo_or_album", Name: "album", Key: "key"},
		{Type: "pic_weixin", Name: "wechat", Key: "key"},
		{Type: "location_select", Name: "location", Key: "key"},
		{Type: "media_id", Name: "media", MediaID: "media"},
		{Type: "view_limited", Name: "limited", MediaID: "media"},
		{Type: "article_id", Name: "article", ArticleID: "article"},
		{Type: "article_view_limited", Name: "limited article", ArticleID: "article"},
		{Type: "miniprogram", Name: "mini", URL: "http://example.com", AppID: "wx-app", PagePath: "pages/home"},
	}
	for _, button := range validLeaves {
		if err := (WeChatMenu{Button: []WeChatMenuButton{button}}).Validate(); err != nil {
			t.Errorf("valid %s button rejected: %v", button.Type, err)
		}
	}
	validGroup := WeChatMenu{Button: []WeChatMenuButton{{Name: "group", SubButton: validLeaves[:5]}}}
	if err := validGroup.Validate(); err != nil {
		t.Fatalf("valid submenu rejected: %v", err)
	}
	if err := (WeChatMenu{}).Validate(); err != nil {
		t.Fatalf("empty draft rejected: %v", err)
	}

	invalid := []WeChatMenu{
		{Button: make([]WeChatMenuButton, 4)},
		{Button: []WeChatMenuButton{{Type: "click", Name: "", Key: "key"}}},
		{Button: []WeChatMenuButton{{Type: "click", Name: strings.Repeat("界", 6), Key: "key"}}},
		{Button: []WeChatMenuButton{{Name: "group", SubButton: make([]WeChatMenuButton, 6)}}},
		{Button: []WeChatMenuButton{{Name: "group", SubButton: []WeChatMenuButton{{Name: "sub", SubButton: []WeChatMenuButton{{Type: "click", Name: "third", Key: "key"}}}}}}},
		{Button: []WeChatMenuButton{{Type: "click", Name: "click"}}},
		{Button: []WeChatMenuButton{{Type: "click", Name: "click", Key: strings.Repeat("k", 129)}}},
		{Button: []WeChatMenuButton{{Type: "media_id", Name: "media", MediaID: strings.Repeat("m", 129)}}},
		{Button: []WeChatMenuButton{{Type: "article_id", Name: "article", ArticleID: strings.Repeat("a", 129)}}},
		{Button: []WeChatMenuButton{{Type: "click", Name: "click", Key: "key", URL: "https://example.com"}}},
		{Button: []WeChatMenuButton{{Type: "view", Name: "view", URL: "ftp://example.com"}}},
		{Button: []WeChatMenuButton{{Type: "view", Name: "view", URL: "https:///missing-host"}}},
		{Button: []WeChatMenuButton{{Type: "view", Name: "view", URL: "https://example.com/" + strings.Repeat("x", 1025)}}},
		{Button: []WeChatMenuButton{{Type: "miniprogram", Name: "mini", URL: "https://example.com", AppID: "wx-app"}}},
		{Button: []WeChatMenuButton{{Type: "miniprogram", Name: "mini", URL: "https://example.com", AppID: "WX-App", PagePath: "pages/home"}}},
		{Button: []WeChatMenuButton{{Type: "CLICK", Name: "click", Key: "key"}}},
		{Button: []WeChatMenuButton{{Type: "unknown", Name: "unknown"}}},
	}
	for i, menu := range invalid {
		if err := menu.Validate(); err == nil {
			t.Errorf("invalid menu %d was accepted: %#v", i, menu)
		}
	}
}

func TestWeChatManagementStoreRevisionPersistenceAndIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "management.json")
	store, err := newWeChatManagementStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing state file was unexpectedly created: %v", err)
	}
	initial := store.Snapshot()
	if initial.SchemaVersion != wechatManagementSchemaVersion || initial.Revision != 0 {
		t.Fatalf("unexpected initial state: %#v", initial)
	}

	replies := WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{{
		ID: "hello", Name: "hello", Enabled: true, Trigger: "text", Match: "exact", Pattern: "hello", Reply: WeChatReply{Type: "text", Content: "world"},
	}}}
	updated, err := store.UpdateReplies(0, replies)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 1 || updated.UpdatedAt.IsZero() || updated.UpdatedAt.Location().String() != "UTC" {
		t.Fatalf("unexpected updated state: %#v", updated)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode is %o, want 600", info.Mode().Perm())
	}

	updated.Replies.Rules[0].Reply.Content = "changed return"
	replies.Rules[0].Reply.Content = "changed input"
	if got := store.Snapshot().Replies.Rules[0].Reply.Content; got != "world" {
		t.Fatalf("store aliases caller data: %q", got)
	}
	snapshot := store.Snapshot()
	snapshot.Replies.Rules[0].Reply.Content = "changed snapshot"
	if got := store.Snapshot().Replies.Rules[0].Reply.Content; got != "world" {
		t.Fatalf("snapshot aliases store data: %q", got)
	}

	if _, err := store.UpdateMenu(0, WeChatMenu{}); !errors.Is(err, errManagementRevisionConflict) {
		t.Fatalf("revision conflict = %v", err)
	}
	menu := WeChatMenu{Button: []WeChatMenuButton{{Type: "click", Name: "menu", Key: "key"}}}
	updated, err = store.UpdateMenu(1, menu)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 {
		t.Fatalf("revision = %d, want 2", updated.Revision)
	}

	reloaded, err := newWeChatManagementStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restored := reloaded.Snapshot()
	if restored.Revision != 2 || restored.Replies.Rules[0].Reply.Content != "world" || restored.Menu.Button[0].Key != "key" {
		t.Fatalf("unexpected restored state: %#v", restored)
	}
}

func TestWeChatManagementStoreRejectsCorruptAndInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte(`{"schema_version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newWeChatManagementStore(corrupt); err == nil {
		t.Fatal("corrupt state was accepted")
	}

	invalid := filepath.Join(dir, "invalid.json")
	state := WeChatManagementState{
		SchemaVersion: wechatManagementSchemaVersion,
		Replies: WeChatReplySettings{Rules: []WeChatReplyRule{{
			ID: "bad", Name: "bad", Trigger: "text", Match: "regex", Pattern: "[", Reply: WeChatReply{Type: "text", Content: "x"},
		}}},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalid, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newWeChatManagementStore(invalid); err == nil {
		t.Fatal("invalid state was accepted")
	}
}

func TestWeChatManagementStoreWriteFailureDoesNotUpdateMemory(t *testing.T) {
	dirAsPath := t.TempDir()
	store, err := newWeChatManagementStore("")
	if err != nil {
		t.Fatal(err)
	}
	store.path = dirAsPath
	settings := WeChatReplySettings{Enabled: true, DefaultReply: &WeChatReply{Type: "text", Content: "reply"}}
	if _, err := store.UpdateReplies(0, settings); err == nil {
		t.Fatal("expected persistence failure")
	}
	state := store.Snapshot()
	if state.Revision != 0 || state.Replies.DefaultReply != nil || !state.UpdatedAt.IsZero() {
		t.Fatalf("failed write changed memory: %#v", state)
	}
}
