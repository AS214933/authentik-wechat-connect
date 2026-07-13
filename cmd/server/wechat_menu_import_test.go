package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const currentWebsiteTextMenuFixture = `{
  "is_menu_open": 0,
  "selfmenu_info": {
    "button": [
      {
        "name": "了解更多",
        "sub_button": {
          "list": [
            {
              "type": "text",
              "name": "关于此公众号",
              "value": "你好，感谢关注！\n这里是公众号介绍。"
            },
            {
              "type": "text",
              "name": "我的主页和博客",
              "value": "个人主页：byteloid.one\n个人博客：blog.byteloid.one"
            }
          ]
        }
      },
      {
        "type": "text",
        "name": "商务合作",
        "value": "咱就是说我真的能接到商单？"
      }
    ]
  }
}`

func TestCurrentWebsiteTextMenuImportsAsKeywordReplies(t *testing.T) {
	rules, err := decodeWeChatWebsiteMenuKeywordRules([]byte(currentWebsiteTextMenuFixture))
	if err != nil {
		t.Fatalf("decode current website menu keywords: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("rules=%d want 3", len(rules))
	}
	wantKeywords := []string{"关于此公众号", "我的主页和博客", "商务合作"}
	seenIDs := make(map[string]bool)
	for i, rule := range rules {
		if !strings.HasPrefix(rule.ID, importedMenuKeywordRulePrefix) || seenIDs[rule.ID] {
			t.Fatalf("rule %d has invalid or duplicate id: %#v", i, rule)
		}
		seenIDs[rule.ID] = true
		if rule.Trigger != "text" || rule.Match != "exact" || rule.Pattern != wantKeywords[i] || rule.Reply.Type != "text" {
			t.Fatalf("rule %d is not an exact text keyword reply: %#v", i, rule)
		}
	}
	if rules[0].Reply.Content != "你好，感谢关注！\n这里是公众号介绍。" {
		t.Fatalf("first reply=%q", rules[0].Reply.Content)
	}

	settings := WeChatReplySettings{Enabled: true, Rules: rules}
	reply, _ := settings.SelectReply(WeChatInboundMessage{MsgType: "text", Content: "关于此公众号"})
	if reply == nil || reply.Content != rules[0].Reply.Content {
		t.Fatalf("text keyword reply=%#v", reply)
	}
	if reply, _ := settings.SelectReply(WeChatInboundMessage{MsgType: "event", Event: "CLICK", EventKey: "关于此公众号"}); reply != nil {
		t.Fatalf("website keyword unexpectedly matched CLICK: %#v", reply)
	}
}

func TestInactiveCurrentMenuCannotBecomeAPIMenuDraft(t *testing.T) {
	_, imported, err := decodeWeChatAdminMenuPayload([]byte(currentWebsiteTextMenuFixture))
	if !imported || err == nil || !strings.Contains(err.Error(), "is_menu_open=0") {
		t.Fatalf("imported=%t error=%v", imported, err)
	}
}

func TestImportedKeywordRulesReplaceOnlyGeneratedRules(t *testing.T) {
	imported, err := decodeWeChatWebsiteMenuKeywordRules([]byte(currentWebsiteTextMenuFixture))
	if err != nil {
		t.Fatal(err)
	}
	settings := WeChatReplySettings{Rules: []WeChatReplyRule{
		{ID: importedMenuKeywordRulePrefix + "0123456789abcdef01234567", Name: "old keyword import", Enabled: true, Trigger: "text", Match: "exact", Pattern: "old", Reply: WeChatReply{Type: "text", Content: "old"}},
		{ID: legacyImportedMenuClickRulePrefix + "0123456789abcdef01234567", Name: "failed click import", Enabled: true, Trigger: "click", Match: "exact", Pattern: "old-key", Reply: WeChatReply{Type: "text", Content: "old"}},
		{ID: "user-rule", Name: "user rule", Enabled: true, Trigger: "text", Match: "exact", Pattern: "hello", Reply: WeChatReply{Type: "text", Content: "world"}},
	}}
	merged, err := mergeImportedMenuKeywordRules(settings, imported)
	if err != nil {
		t.Fatal(err)
	}
	if !merged.Enabled || len(merged.Rules) != len(imported)+2 {
		t.Fatalf("merged settings=%#v", merged)
	}
	if !isLegacyImportedMenuClickRuleID(merged.Rules[0].ID) || merged.Rules[1].ID != "user-rule" {
		t.Fatalf("user rule order was not preserved: %#v", merged.Rules)
	}
	for _, rule := range merged.Rules {
		if isImportedMenuKeywordRuleID(rule.ID) && rule.Pattern == "old" {
			t.Fatalf("stale generated rule was preserved: %#v", rule)
		}
	}
	reply, ruleID := merged.SelectReply(WeChatInboundMessage{MsgType: "text", Content: "hello"})
	if reply == nil || reply.Content != "world" || ruleID != "user-rule" {
		t.Fatalf("existing user rule was not preserved: reply=%#v id=%q", reply, ruleID)
	}
}

func TestImportedKeywordRulesRejectShadowingUserRules(t *testing.T) {
	imported, err := decodeWeChatWebsiteMenuKeywordRules([]byte(currentWebsiteTextMenuFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []WeChatReplyRule{
		{ID: "exact", Name: "exact", Enabled: true, Trigger: "text", Match: "exact", Pattern: "关于此公众号", Reply: WeChatReply{Type: "text", Content: "existing"}},
		{ID: "catch-all", Name: "catch all", Enabled: true, Trigger: "any_message", Match: "any", Reply: WeChatReply{Type: "text", Content: "existing"}},
		{ID: "regex", Name: "regex", Enabled: true, Trigger: "text", Match: "regex", Pattern: ".*", Reply: WeChatReply{Type: "text", Content: "existing"}},
	} {
		t.Run(rule.ID, func(t *testing.T) {
			settings := WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{rule}}
			if _, err := mergeImportedMenuKeywordRules(settings, imported); err == nil || !strings.Contains(err.Error(), rule.ID) {
				t.Fatalf("shadowing rule was accepted: %v", err)
			}
		})
	}
}

func TestCurrentMenuImportPreservesActiveAPIActions(t *testing.T) {
	raw := []byte(`{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"click","name":"帮助","key":"help"},{"type":"view","name":"网站","url":"https://example.com/"}]}}`)
	menu, imported, err := decodeWeChatAdminMenuPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := WeChatMenu{Button: []WeChatMenuButton{
		{Type: "click", Name: "帮助", Key: "help"},
		{Type: "view", Name: "网站", URL: "https://example.com/"},
	}}
	if !imported || !reflect.DeepEqual(menu, want) {
		t.Fatalf("menu=%#v imported=%t", menu, imported)
	}
}

func TestCurrentWebsiteActionsCannotBecomeAPIMenuDraft(t *testing.T) {
	for _, typeName := range []string{"text", "img", "voice", "video", "news"} {
		t.Run(typeName, func(t *testing.T) {
			raw := []byte(`{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"` + typeName + `","name":"素材","value":"upstream-value"}]}}`)
			_, imported, err := decodeWeChatAdminMenuPayload(raw)
			if !imported || err == nil || !strings.Contains(err.Error(), "button[0]") || !strings.Contains(err.Error(), "cannot be imported") {
				t.Fatalf("imported=%t error=%v", imported, err)
			}
		})
	}
}

func TestKeywordImportRejectsUnsupportedOrAmbiguousMenus(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "no contents", raw: `{"is_menu_open":0}`, want: "selfmenu_info"},
		{name: "invalid open state", raw: `{"is_menu_open":2,"selfmenu_info":{"button":[]}}`, want: "0 or 1"},
		{name: "missing open state", raw: `{"selfmenu_info":{"button":[]}}`, want: "is_menu_open"},
		{name: "no text", raw: `{"is_menu_open":1,"selfmenu_info":{"button":[]}}`, want: "does not contain"},
		{name: "API click", raw: `{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"click","name":"帮助","key":"help"}]}}`, want: "cannot be imported"},
		{name: "duplicate keyword", raw: `{"is_menu_open":0,"selfmenu_info":{"button":[{"type":"text","name":"帮助","value":"one"},{"type":"text","name":"帮助","value":"two"}]}}`, want: "duplicates"},
		{name: "login code keyword", raw: `{"is_menu_open":0,"selfmenu_info":{"button":[{"type":"text","name":"12345678","value":"reserved"}]}}`, want: "reserved"},
		{name: "surrounding whitespace", raw: `{"is_menu_open":0,"selfmenu_info":{"button":[{"type":"text","name":" 帮助","value":"bad"}]}}`, want: "whitespace"},
		{name: "conflicting fields", raw: `{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"text","name":"帮助","value":"reply","key":"other"}]}}`, want: "another action"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeWeChatWebsiteMenuKeywordRules([]byte(test.raw))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestCurrentMenuImportRejectsNonDocumentedShapes(t *testing.T) {
	for _, raw := range []string{
		`{"is_menu_open":1,"selfmenu_info":{"button":[{"name":"分组","sub_button":[]}]}}`,
		`{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"click","name":"帮助","key":"help","news_info":{"list":[]}}]}}`,
	} {
		if _, imported, err := decodeWeChatAdminMenuPayload([]byte(raw)); !imported || err == nil {
			t.Fatalf("raw=%s imported=%t error=%v", raw, imported, err)
		}
	}
}

func TestCurrentTextKeywordImportEnforcesReplyLength(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		wantErr bool
	}{
		{name: "maximum", content: strings.Repeat("x", 2048)},
		{name: "too long", content: strings.Repeat("x", 2049), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := json.Marshal(tt.content)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"is_menu_open":0,"selfmenu_info":{"button":[{"type":"text","name":"文本","value":` + string(encoded) + `}]}}`)
			_, err = decodeWeChatWebsiteMenuKeywordRules(raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v wantErr=%t", err, tt.wantErr)
			}
		})
	}
}
