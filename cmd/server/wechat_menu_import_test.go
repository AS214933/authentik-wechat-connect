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

func TestDecodeCurrentWebsiteTextMenuForCreate(t *testing.T) {
	menu, rules, imported, err := decodeWeChatAdminMenuPayload([]byte(currentWebsiteTextMenuFixture))
	if err != nil {
		t.Fatalf("decode current website menu: %v", err)
	}
	if !imported {
		t.Fatal("current-menu response was not recognized as an import")
	}
	if err := menu.Validate(); err != nil {
		t.Fatalf("converted menu is not publishable: %v", err)
	}
	if len(menu.Button) != 2 || len(menu.Button[0].SubButton) != 2 {
		t.Fatalf("converted menu shape=%#v", menu)
	}
	leaves := []WeChatMenuButton{menu.Button[0].SubButton[0], menu.Button[0].SubButton[1], menu.Button[1]}
	if len(rules) != len(leaves) {
		t.Fatalf("rules=%d leaves=%d", len(rules), len(leaves))
	}
	seenKeys := map[string]bool{}
	for i, leaf := range leaves {
		if leaf.Type != "click" || leaf.Key == "" {
			t.Fatalf("leaf %d was not converted to click: %#v", i, leaf)
		}
		if seenKeys[leaf.Key] {
			t.Fatalf("duplicate generated key %q", leaf.Key)
		}
		seenKeys[leaf.Key] = true
		if rules[i].Trigger != "click" || rules[i].Match != "exact" || rules[i].Pattern != leaf.Key || rules[i].Reply.Type != "text" {
			t.Fatalf("rule %d does not match leaf: %#v", i, rules[i])
		}
	}
	if rules[0].Reply.Content != "你好，感谢关注！\n这里是公众号介绍。" {
		t.Fatalf("first text reply=%q", rules[0].Reply.Content)
	}

	payload, err := json.Marshal(menu)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"type":"text"`, `"value"`, `"is_menu_open"`, `"selfmenu_info"`, `"list"`} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("menu/create payload contains %s: %s", forbidden, payload)
		}
	}
}

func TestImportedTextMenuRulesReplaceOnlyPreviousImports(t *testing.T) {
	_, imported, _, err := decodeWeChatAdminMenuPayload([]byte(currentWebsiteTextMenuFixture))
	if err != nil {
		t.Fatal(err)
	}
	settings := WeChatReplySettings{Rules: []WeChatReplyRule{
		{ID: importedMenuReplyRulePrefix + "0123456789abcdef01234567", Name: "old import", Enabled: true, Trigger: "click", Match: "exact", Pattern: "old", Reply: WeChatReply{Type: "text", Content: "old"}},
		{ID: "user-rule", Name: "user rule", Enabled: true, Trigger: "text", Match: "exact", Pattern: "hello", Reply: WeChatReply{Type: "text", Content: "world"}},
	}}
	merged := mergeImportedMenuReplyRules(settings, imported)
	if !merged.Enabled || len(merged.Rules) != len(imported)+1 {
		t.Fatalf("merged settings=%#v", merged)
	}
	if merged.Rules[len(imported)].ID != "user-rule" {
		t.Fatalf("user rule was not preserved: %#v", merged.Rules)
	}
	for _, rule := range merged.Rules {
		if rule.ID == importedMenuReplyRulePrefix+"0123456789abcdef01234567" {
			t.Fatal("stale imported rule was preserved")
		}
	}
}

func TestCurrentMenuImportPreservesAPIActions(t *testing.T) {
	raw := []byte(`{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"click","name":"帮助","key":"help"},{"type":"view","name":"网站","url":"https://example.com/"}]}}`)
	menu, rules, imported, err := decodeWeChatAdminMenuPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := WeChatMenu{Button: []WeChatMenuButton{
		{Type: "click", Name: "帮助", Key: "help"},
		{Type: "view", Name: "网站", URL: "https://example.com/"},
	}}
	if !imported || len(rules) != 0 || !reflect.DeepEqual(menu, want) {
		t.Fatalf("menu=%#v rules=%#v imported=%t", menu, rules, imported)
	}
}

func TestCurrentMenuImportRejectsNonReusableWebsiteMedia(t *testing.T) {
	for _, typeName := range []string{"img", "voice", "video", "news"} {
		t.Run(typeName, func(t *testing.T) {
			raw := []byte(`{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"` + typeName + `","name":"素材","value":"upstream-value"}]}}`)
			_, _, imported, err := decodeWeChatAdminMenuPayload(raw)
			if !imported || err == nil || !strings.Contains(err.Error(), "button[0]") || !strings.Contains(err.Error(), "cannot be published") {
				t.Fatalf("imported=%t error=%v", imported, err)
			}
		})
	}
}

func TestCurrentMenuImportRequiresContentsAndValidOpenState(t *testing.T) {
	for _, raw := range []string{
		`{"is_menu_open":0}`,
		`{"is_menu_open":2,"selfmenu_info":{"button":[]}}`,
	} {
		if _, _, imported, err := decodeWeChatAdminMenuPayload([]byte(raw)); !imported || err == nil {
			t.Fatalf("raw=%s imported=%t error=%v", raw, imported, err)
		}
	}
}

func TestCurrentMenuImportRejectsNonDocumentedShapesAndConflictingFields(t *testing.T) {
	for _, raw := range []string{
		`{"is_menu_open":1,"selfmenu_info":{"button":[{"name":"分组","sub_button":[]}]}}`,
		`{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"click","name":"帮助","key":"help","news_info":{"list":[]}}]}}`,
	} {
		if _, _, imported, err := decodeWeChatAdminMenuPayload([]byte(raw)); !imported || err == nil {
			t.Fatalf("raw=%s imported=%t error=%v", raw, imported, err)
		}
	}
}

func TestCurrentTextMenuImportEnforcesReplyLength(t *testing.T) {
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
			raw := []byte(`{"is_menu_open":1,"selfmenu_info":{"button":[{"type":"text","name":"文本","value":` + string(encoded) + `}]}}`)
			_, _, _, err = decodeWeChatAdminMenuPayload(raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v wantErr=%t", err, tt.wantErr)
			}
		})
	}
}
