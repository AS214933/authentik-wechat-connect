package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRenderWeChatTextReplySwapsUsersAndPreservesContent(t *testing.T) {
	message := WeChatInboundMessage{ToUserName: "official-account", FromUserName: "user-openid"}
	content := "你好 ]]> <微信> & everyone"
	body, err := renderWeChatPassiveReply(message, WeChatReply{Type: "text", Content: content}, time.Unix(1720000000, 0))
	if err != nil {
		t.Fatalf("render reply: %v", err)
	}
	var decoded wechatPassiveReplyXML
	if err := xml.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode rendered reply: %v\n%s", err, body)
	}
	if string(decoded.ToUserName) != message.FromUserName || string(decoded.FromUserName) != message.ToUserName {
		t.Fatalf("users were not swapped: %#v", decoded)
	}
	if decoded.CreateTime != 1720000000 || decoded.MsgType != "text" || string(decoded.Content) != content {
		t.Fatalf("unexpected text reply: %#v", decoded)
	}
}

func TestRenderWeChatOfficialAIReplyUsesDocumentedMessageType(t *testing.T) {
	body, err := renderWeChatPassiveReply(
		WeChatInboundMessage{ToUserName: "official", FromUserName: "user"},
		WeChatReply{Type: "official_ai"},
		time.Unix(1720000000, 0),
	)
	if err != nil {
		t.Fatalf("render AI reply: %v", err)
	}
	var decoded wechatPassiveReplyXML
	if err := xml.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode AI reply: %v", err)
	}
	if decoded.MsgType != "transfer_biz_ai_ivr" {
		t.Fatalf("AI MsgType=%q want transfer_biz_ai_ivr", decoded.MsgType)
	}
	if strings.Contains(string(body), "transfer_customer_service") {
		t.Fatalf("AI reply was confused with customer service: %s", body)
	}
	want := `<xml><ToUserName><![CDATA[user]]></ToUserName><FromUserName><![CDATA[official]]></FromUserName><CreateTime>1720000000</CreateTime><MsgType><![CDATA[transfer_biz_ai_ivr]]></MsgType></xml>`
	if string(body) != want {
		t.Fatalf("AI reply XML=%s\nwant=%s", body, want)
	}
}

func TestRenderWeChatPassiveReplyPayloadTypes(t *testing.T) {
	message := WeChatInboundMessage{ToUserName: "official", FromUserName: "user"}
	tests := []struct {
		name   string
		reply  WeChatReply
		assert func(*testing.T, wechatPassiveReplyXML)
	}{
		{name: "image", reply: WeChatReply{Type: "image", MediaID: "image-id"}, assert: func(t *testing.T, got wechatPassiveReplyXML) {
			if got.Image == nil || got.Image.MediaID != "image-id" {
				t.Fatalf("image=%#v", got.Image)
			}
		}},
		{name: "voice", reply: WeChatReply{Type: "voice", MediaID: "voice-id"}, assert: func(t *testing.T, got wechatPassiveReplyXML) {
			if got.Voice == nil || got.Voice.MediaID != "voice-id" {
				t.Fatalf("voice=%#v", got.Voice)
			}
		}},
		{name: "video", reply: WeChatReply{Type: "video", MediaID: "video-id", Title: "标题", Description: "说明"}, assert: func(t *testing.T, got wechatPassiveReplyXML) {
			if got.Video == nil || got.Video.MediaID != "video-id" || got.Video.Title != "标题" || got.Video.Description != "说明" {
				t.Fatalf("video=%#v", got.Video)
			}
		}},
		{name: "music", reply: WeChatReply{Type: "music", Title: "音乐", MusicURL: "https://example.com/music", HQMusicURL: "https://example.com/hq", ThumbMediaID: "thumb-id"}, assert: func(t *testing.T, got wechatPassiveReplyXML) {
			if got.Music == nil || got.Music.ThumbMediaID != "thumb-id" || got.Music.MusicURL != "https://example.com/music" {
				t.Fatalf("music=%#v", got.Music)
			}
		}},
		{name: "news", reply: WeChatReply{Type: "news", Articles: []WeChatNewsArticle{{Title: "文章", Description: "摘要", PicURL: "https://example.com/pic", URL: "https://example.com/article"}}}, assert: func(t *testing.T, got wechatPassiveReplyXML) {
			if got.ArticleCount != 1 || got.Articles == nil || len(got.Articles.Items) != 1 || got.Articles.Items[0].Title != "文章" {
				t.Fatalf("articles=%#v count=%d", got.Articles, got.ArticleCount)
			}
		}},
		{name: "customer service", reply: WeChatReply{Type: "customer_service"}, assert: func(t *testing.T, got wechatPassiveReplyXML) {
			if got.MsgType != "transfer_customer_service" {
				t.Fatalf("MsgType=%q", got.MsgType)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := renderWeChatPassiveReply(message, tt.reply, time.Unix(1720000000, 0))
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			var decoded wechatPassiveReplyXML
			if err := xml.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("decode: %v\n%s", err, body)
			}
			tt.assert(t, decoded)
		})
	}
}

func TestRenderWeChatNewsIncludesAllDocumentedArticleElements(t *testing.T) {
	body, err := renderWeChatPassiveReply(
		WeChatInboundMessage{ToUserName: "official", FromUserName: "user"},
		WeChatReply{Type: "news", Articles: []WeChatNewsArticle{{Title: "标题"}}},
		time.Unix(1720000000, 0),
	)
	if err != nil {
		t.Fatalf("render news: %v", err)
	}
	for _, element := range []string{
		`<Title><![CDATA[标题]]></Title>`,
		`<Description></Description>`,
		`<PicUrl></PicUrl>`,
		`<Url></Url>`,
	} {
		if !strings.Contains(string(body), element) {
			t.Errorf("news XML is missing %s: %s", element, body)
		}
	}
}

func TestWeChatTextCallbackUsesManagedReplyAndReplaysDuplicate(t *testing.T) {
	server := testServer(t)
	firstSettings := WeChatReplySettings{
		Enabled: true,
		Rules: []WeChatReplyRule{{
			ID: "hello", Name: "问候", Enabled: true, Trigger: "text", Match: "exact", Pattern: "你好",
			Reply: WeChatReply{Type: "text", Content: "欢迎使用"},
		}},
	}
	state, err := server.management.UpdateReplies(0, firstSettings)
	if err != nil {
		t.Fatalf("save reply settings: %v", err)
	}
	body := `<xml><ToUserName><![CDATA[official]]></ToUserName><FromUserName><![CDATA[user-1]]></FromUserName><CreateTime>1720000000</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[你好]]></Content><MsgId>10001</MsgId></xml>`

	first := performSignedWeChatCallback(t, server, body)
	if first.Code != http.StatusOK || first.Header().Get("Content-Type") != "application/xml; charset=utf-8" {
		t.Fatalf("first callback status=%d type=%q body=%s", first.Code, first.Header().Get("Content-Type"), first.Body.String())
	}
	var reply wechatPassiveReplyXML
	if err := xml.Unmarshal(first.Body.Bytes(), &reply); err != nil {
		t.Fatalf("decode first reply: %v", err)
	}
	if reply.Content != "欢迎使用" || reply.ToUserName != "user-1" || reply.FromUserName != "official" {
		t.Fatalf("unexpected first reply: %#v", reply)
	}

	firstSettings.Rules[0].Reply.Content = "已经修改"
	if _, err := server.management.UpdateReplies(state.Revision, firstSettings); err != nil {
		t.Fatalf("update reply settings: %v", err)
	}
	second := performSignedWeChatCallback(t, server, body)
	if second.Body.String() != first.Body.String() {
		t.Fatalf("duplicate callback did not replay identical response\nfirst:  %s\nsecond: %s", first.Body.String(), second.Body.String())
	}
}

func TestImportedMenuKeywordUsesTextCallbackNotClickEvent(t *testing.T) {
	server := testServer(t)
	rules, err := decodeWeChatWebsiteMenuKeywordRules([]byte(currentWebsiteTextMenuFixture))
	if err != nil {
		t.Fatalf("decode menu keywords: %v", err)
	}
	if _, err := server.management.UpdateReplies(0, WeChatReplySettings{Enabled: true, Rules: rules}); err != nil {
		t.Fatalf("save keyword replies: %v", err)
	}
	textBody := `<xml><ToUserName>official</ToUserName><FromUserName>keyword-user</FromUserName><CreateTime>1720000012</CreateTime><MsgType>text</MsgType><Content>关于此公众号</Content><MsgId>10012</MsgId></xml>`
	textReply := performSignedWeChatCallback(t, server, textBody)
	if textReply.Code != http.StatusOK || textReply.Header().Get("Content-Type") != "application/xml; charset=utf-8" {
		t.Fatalf("text status=%d type=%q body=%s", textReply.Code, textReply.Header().Get("Content-Type"), textReply.Body.String())
	}
	var decoded wechatPassiveReplyXML
	if err := xml.Unmarshal(textReply.Body.Bytes(), &decoded); err != nil || decoded.Content != "你好，感谢关注！\n这里是公众号介绍。" {
		t.Fatalf("text reply=%#v err=%v body=%s", decoded, err, textReply.Body.String())
	}

	clickBody := `<xml><ToUserName>official</ToUserName><FromUserName>keyword-user</FromUserName><CreateTime>1720000013</CreateTime><MsgType>event</MsgType><Event>CLICK</Event><EventKey>关于此公众号</EventKey></xml>`
	clickReply := performSignedWeChatCallback(t, server, clickBody)
	if clickReply.Code != http.StatusOK || clickReply.Body.String() != "success" {
		t.Fatalf("CLICK status=%d body=%q", clickReply.Code, clickReply.Body.String())
	}
}

func TestEightDigitMessageCodeTakesPriorityOverBroadTextRule(t *testing.T) {
	server := testServer(t)
	server.cfg.WeChatLoginMode = wechatLoginModeMessageCode
	server.wx = fakeWeChatService{}
	if _, err := server.management.UpdateReplies(0, WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{{
		ID: "numeric-text", Name: "numeric text", Enabled: true, Trigger: "text", Match: "regex", Pattern: `^[0-9]{8}$`,
		Reply: WeChatReply{Type: "text", Content: "ordinary numeric reply"},
	}}}); err != nil {
		t.Fatalf("save broad numeric rule: %v", err)
	}
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create message-code scan: %v", err)
	}
	body := fmt.Sprintf(`<xml><ToUserName>official</ToUserName><FromUserName>numeric-login-user</FromUserName><CreateTime>1720000014</CreateTime><MsgType>text</MsgType><Content>%s</Content><MsgId>10014</MsgId></xml>`, scan.LoginCode)
	recorder := performSignedWeChatCallback(t, server, body)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "登录已确认") || strings.Contains(recorder.Body.String(), "ordinary numeric reply") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	completed, ok := server.scanSnapshot(scan.ID)
	if !ok || completed.User.OpenID != "numeric-login-user" {
		t.Fatalf("login not completed: %#v ok=%t", completed, ok)
	}
}

func TestSubscribeQRCodeCompletesLoginAndReturnsSubscribeReply(t *testing.T) {
	server := testServer(t)
	if _, err := server.management.UpdateReplies(0, WeChatReplySettings{
		Enabled: true,
		Rules: []WeChatReplyRule{{
			ID: "subscribe", Name: "关注回复", Enabled: true, Trigger: "subscribe", Match: "any",
			Reply: WeChatReply{Type: "text", Content: "感谢关注"},
		}},
	}); err != nil {
		t.Fatalf("save subscribe rule: %v", err)
	}
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	body := fmt.Sprintf(`<xml><ToUserName><![CDATA[official]]></ToUserName><FromUserName><![CDATA[openid-123]]></FromUserName><CreateTime>1720000001</CreateTime><MsgType><![CDATA[event]]></MsgType><Event><![CDATA[subscribe]]></Event><EventKey><![CDATA[qrscene_%s%s]]></EventKey></xml>`, wechatLoginScenePrefix, scan.ID)
	rec := performSignedWeChatCallback(t, server, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", rec.Code, rec.Body.String())
	}
	var reply wechatPassiveReplyXML
	if err := xml.Unmarshal(rec.Body.Bytes(), &reply); err != nil || reply.Content != "感谢关注" {
		t.Fatalf("subscribe reply=%#v err=%v body=%s", reply, err, rec.Body.String())
	}
	completed, ok := server.scanSnapshot(scan.ID)
	if !ok || completed.User.OpenID != "openid-123" || completed.RedirectURL == "" {
		t.Fatalf("scan was not completed: %#v ok=%t", completed, ok)
	}
}

func TestMenuClickCannotCompleteLoginScene(t *testing.T) {
	server := testServer(t)
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	body := fmt.Sprintf(`<xml><ToUserName><![CDATA[official]]></ToUserName><FromUserName><![CDATA[openid-123]]></FromUserName><CreateTime>1720000002</CreateTime><MsgType><![CDATA[event]]></MsgType><Event><![CDATA[CLICK]]></Event><EventKey><![CDATA[%s%s]]></EventKey></xml>`, wechatLoginScenePrefix, scan.ID)
	rec := performSignedWeChatCallback(t, server, body)
	if rec.Code != http.StatusOK || rec.Body.String() != "success" {
		t.Fatalf("click callback status=%d body=%q", rec.Code, rec.Body.String())
	}
	unchanged, ok := server.scanSnapshot(scan.ID)
	if !ok || unchanged.User.OpenID != "" || unchanged.RedirectURL != "" {
		t.Fatalf("CLICK event incorrectly completed QR scan: %#v", unchanged)
	}
}

func TestWeChatAESImportedKeywordUsesTextCallbackNotClickEvent(t *testing.T) {
	cfg := testConfig()
	cfg.WeChatEncodingAESKey = testWeChatEncodingAESKey()
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new encrypted server: %v", err)
	}
	server.wx = fakeWeChatService{}
	rules, err := decodeWeChatWebsiteMenuKeywordRules([]byte(currentWebsiteTextMenuFixture))
	if err != nil {
		t.Fatalf("decode menu keywords: %v", err)
	}
	if _, err := server.management.UpdateReplies(0, WeChatReplySettings{
		Enabled: true,
		Rules:   rules,
	}); err != nil {
		t.Fatalf("save encrypted reply: %v", err)
	}
	plaintext := []byte(`<xml><ToUserName><![CDATA[official]]></ToUserName><FromUserName><![CDATA[user-aes]]></FromUserName><CreateTime>1720000003</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[关于此公众号]]></Content><MsgId>10003</MsgId></xml>`)
	encrypted, err := server.wxCryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt callback: %v", err)
	}
	timestamp, nonce := "1720000003", "aes-nonce"
	signature := calculateWeChatMessageSignature(server.cfg.WeChatCallbackToken, timestamp, nonce, encrypted)
	envelope, err := xml.Marshal(wechatEncryptedEnvelope{Encrypt: wechatCDATA(encrypted)})
	if err != nil {
		t.Fatalf("marshal encrypted envelope: %v", err)
	}
	target := "/wechat/callback?encrypt_type=aes&timestamp=" + timestamp + "&nonce=" + nonce + "&msg_signature=" + signature
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(string(envelope)))
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("encrypted callback status=%d body=%s", rec.Code, rec.Body.String())
	}
	var responseEnvelope wechatEncryptedEnvelope
	if err := xml.Unmarshal(rec.Body.Bytes(), &responseEnvelope); err != nil {
		t.Fatalf("decode encrypted response envelope: %v\n%s", err, rec.Body.String())
	}
	if !verifyWeChatMessageSignature(server.cfg.WeChatCallbackToken, fmt.Sprint(responseEnvelope.TimeStamp), string(responseEnvelope.Nonce), string(responseEnvelope.Encrypt), string(responseEnvelope.MsgSignature)) {
		t.Fatalf("encrypted response signature is invalid: %#v", responseEnvelope)
	}
	decrypted, err := server.wxCryptor.Decrypt(string(responseEnvelope.Encrypt))
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	var reply wechatPassiveReplyXML
	if err := xml.Unmarshal(decrypted, &reply); err != nil || reply.Content != "你好，感谢关注！\n这里是公众号介绍。" || reply.ToUserName != "user-aes" {
		t.Fatalf("decrypted reply=%#v err=%v body=%s", reply, err, decrypted)
	}
	clickBody := `<xml><ToUserName>official</ToUserName><FromUserName>user-aes</FromUserName><CreateTime>1720000004</CreateTime><MsgType>event</MsgType><Event>CLICK</Event><EventKey>关于此公众号</EventKey></xml>`
	clickReply := performEncryptedWeChatCallback(t, server, clickBody, "1720000004", "keyword-click-nonce")
	if clickReply.Code != http.StatusOK || clickReply.Body.String() != "success" {
		t.Fatalf("encrypted CLICK status=%d body=%q", clickReply.Code, clickReply.Body.String())
	}
}

func TestWeChatAESMessageCodeCompletesLogin(t *testing.T) {
	cfg := testConfig()
	cfg.WeChatEncodingAESKey = testWeChatEncodingAESKey()
	cfg.WeChatLoginMode = wechatLoginModeMessageCode
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new encrypted server: %v", err)
	}
	server.wx = fakeWeChatService{}
	if _, err := server.management.UpdateReplies(0, WeChatReplySettings{Enabled: true, Rules: []WeChatReplyRule{{
		ID: "numeric-text", Name: "numeric text", Enabled: true, Trigger: "text", Match: "regex", Pattern: `^[0-9]{8}$`,
		Reply: WeChatReply{Type: "text", Content: "ordinary numeric reply"},
	}}}); err != nil {
		t.Fatalf("save broad numeric rule: %v", err)
	}
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create message-code scan: %v", err)
	}
	body := fmt.Sprintf(`<xml><ToUserName>official</ToUserName><FromUserName>aes-login-user</FromUserName><CreateTime>1720000009</CreateTime><MsgType>text</MsgType><Content>%s</Content><MsgId>10009</MsgId></xml>`, scan.LoginCode)
	recorder := performEncryptedWeChatCallback(t, server, body, "1720000009", "login-nonce")
	assertEncryptedWeChatTextReply(t, server, recorder, "登录已确认，请返回浏览器继续。")
	completed, ok := server.scanSnapshot(scan.ID)
	if !ok || completed.User.OpenID != "aes-login-user" || completed.RedirectURL == "" {
		t.Fatalf("AES message code did not complete login: %#v ok=%t", completed, ok)
	}
}

func TestEightDigitLoginCodeFormatAndParsing(t *testing.T) {
	for value, expected := range map[int64]string{
		0:        "00000000",
		1:        "00000001",
		12345678: "12345678",
		99999999: "99999999",
	} {
		if actual := formatLoginCode(value); actual != expected {
			t.Errorf("formatLoginCode(%d)=%q want %q", value, actual, expected)
		}
	}
	for i := 0; i < 32; i++ {
		code, err := randomLoginCode()
		if err != nil {
			t.Fatalf("generate login code: %v", err)
		}
		if len(code) != 8 || normalizeLoginCode(code) != code {
			t.Fatalf("generated code is not eight ASCII digits: %q", code)
		}
	}

	tests := []struct {
		name    string
		message WeChatInboundMessage
		want    string
	}{
		{name: "digits", message: WeChatInboundMessage{MsgType: "text", Content: "12345678"}, want: "12345678"},
		{name: "leading zero", message: WeChatInboundMessage{MsgType: "text", Content: "00000001"}, want: "00000001"},
		{name: "leading space", message: WeChatInboundMessage{MsgType: "text", Content: " 12345678"}},
		{name: "trailing space", message: WeChatInboundMessage{MsgType: "text", Content: "12345678 "}},
		{name: "seven digits", message: WeChatInboundMessage{MsgType: "text", Content: "1234567"}},
		{name: "nine digits", message: WeChatInboundMessage{MsgType: "text", Content: "123456789"}},
		{name: "Chinese prefix", message: WeChatInboundMessage{MsgType: "text", Content: "登录 12345678"}},
		{name: "English prefix", message: WeChatInboundMessage{MsgType: "text", Content: "LOGIN 12345678"}},
		{name: "letters", message: WeChatInboundMessage{MsgType: "text", Content: "1234ABCD"}},
		{name: "full width", message: WeChatInboundMessage{MsgType: "text", Content: "１２３４５６７８"}},
		{name: "event", message: WeChatInboundMessage{MsgType: "event", Content: "12345678"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, ok := loginCodeFromWeChatText(test.message)
			if actual != test.want || ok != (test.want != "") {
				t.Fatalf("loginCodeFromWeChatText()=(%q,%t) want (%q,%t)", actual, ok, test.want, test.want != "")
			}
		})
	}
}

func TestMessageCodeTTLIsCapped(t *testing.T) {
	server := testServer(t)
	server.cfg.WeChatLoginMode = wechatLoginModeMessageCode
	server.cfg.WeChatQRCodeTTL = 24 * time.Hour
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create message-code scan: %v", err)
	}
	if ttl := scan.ExpiresAt.Sub(scan.CreatedAt); ttl != maxWeChatMessageCodeTTL {
		t.Fatalf("message-code TTL=%s want %s", ttl, maxWeChatMessageCodeTTL)
	}
}

func TestLoginCodeInvalidAttemptLimit(t *testing.T) {
	server := testServer(t)
	server.cfg.WeChatLoginMode = wechatLoginModeMessageCode
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create message-code scan: %v", err)
	}
	invalidCode := "00000000"
	if invalidCode == scan.LoginCode {
		invalidCode = "99999999"
	}
	const openID = "guessing-user"
	for attempt := 0; attempt < wechatLoginAttemptMaxFailures; attempt++ {
		if _, _, ok := server.pendingLoginScene(WeChatInboundMessage{MsgType: "text", FromUserName: openID, Content: invalidCode}); ok {
			t.Fatalf("invalid attempt %d unexpectedly matched", attempt+1)
		}
	}
	if _, _, ok := server.pendingLoginScene(WeChatInboundMessage{MsgType: "text", FromUserName: openID, Content: scan.LoginCode}); ok {
		t.Fatal("rate-limited OpenID used the correct code before its window expired")
	}
	pending, _ := server.scanSnapshot(scan.ID)
	if pending.ClaimedOpenID != "" {
		t.Fatalf("rate-limited attempt claimed scan: %#v", pending)
	}

	server.mu.Lock()
	attempt := server.wechatLoginAttempts[openID]
	attempt.WindowStart = time.Now().Add(-wechatLoginAttemptWindow)
	server.wechatLoginAttempts[openID] = attempt
	server.mu.Unlock()
	scene, messageCode, ok := server.pendingLoginScene(WeChatInboundMessage{MsgType: "text", FromUserName: openID, Content: scan.LoginCode})
	if !ok || !messageCode || scene != wechatLoginScenePrefix+scan.ID {
		t.Fatalf("correct code after rate-limit reset scene=%q messageCode=%t ok=%t", scene, messageCode, ok)
	}
}

func TestLoginCodeGlobalAttemptLimit(t *testing.T) {
	server := testServer(t)
	server.cfg.WeChatLoginMode = wechatLoginModeMessageCode
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create message-code scan: %v", err)
	}
	now := time.Now()
	server.mu.Lock()
	server.wechatGlobalAttempts = wechatLoginAttempt{WindowStart: now, Failures: wechatLoginGlobalMaxFailures}
	server.mu.Unlock()
	message := WeChatInboundMessage{MsgType: "text", FromUserName: "legitimate-user", Content: scan.LoginCode}
	if _, _, ok := server.pendingLoginScene(message); ok {
		t.Fatal("global rate limit allowed a code attempt")
	}
	pending, _ := server.scanSnapshot(scan.ID)
	if pending.ClaimedOpenID != "" {
		t.Fatalf("globally limited attempt claimed scan: %#v", pending)
	}

	server.mu.Lock()
	server.wechatGlobalAttempts.WindowStart = now.Add(-wechatLoginGlobalWindow)
	server.mu.Unlock()
	scene, messageCode, ok := server.pendingLoginScene(message)
	if !ok || !messageCode || scene != wechatLoginScenePrefix+scan.ID {
		t.Fatalf("correct code after global reset scene=%q messageCode=%t ok=%t", scene, messageCode, ok)
	}
}

func TestWeChatResponseCacheSeparatesPlaintextAndAESModes(t *testing.T) {
	cfg := testConfig()
	cfg.WeChatEncodingAESKey = testWeChatEncodingAESKey()
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new encrypted server: %v", err)
	}
	server.wx = fakeWeChatService{}
	if _, err := server.management.UpdateReplies(0, WeChatReplySettings{
		Enabled:      true,
		DefaultReply: &WeChatReply{Type: "text", Content: "mode-safe"},
	}); err != nil {
		t.Fatalf("save reply: %v", err)
	}

	plainThenAES := `<xml><ToUserName>official</ToUserName><FromUserName>mode-user</FromUserName><CreateTime>1720000010</CreateTime><MsgType>text</MsgType><Content>one</Content><MsgId>20001</MsgId></xml>`
	plain := performSignedWeChatCallback(t, server, plainThenAES)
	if plain.Code != http.StatusOK || strings.Contains(plain.Body.String(), "<Encrypt>") {
		t.Fatalf("plain response status=%d body=%s", plain.Code, plain.Body.String())
	}
	aes := performEncryptedWeChatCallback(t, server, plainThenAES, "1720000010", "mode-nonce-1")
	assertEncryptedWeChatTextReply(t, server, aes, "mode-safe")

	aesThenPlain := `<xml><ToUserName>official</ToUserName><FromUserName>mode-user</FromUserName><CreateTime>1720000011</CreateTime><MsgType>text</MsgType><Content>two</Content><MsgId>20002</MsgId></xml>`
	aes = performEncryptedWeChatCallback(t, server, aesThenPlain, "1720000011", "mode-nonce-2")
	assertEncryptedWeChatTextReply(t, server, aes, "mode-safe")
	plain = performSignedWeChatCallback(t, server, aesThenPlain)
	if plain.Code != http.StatusOK || strings.Contains(plain.Body.String(), "<Encrypt>") {
		t.Fatalf("plain response after AES status=%d body=%s", plain.Code, plain.Body.String())
	}
	var reply wechatPassiveReplyXML
	if err := xml.Unmarshal(plain.Body.Bytes(), &reply); err != nil || reply.Content != "mode-safe" {
		t.Fatalf("plain response after AES reply=%#v err=%v body=%s", reply, err, plain.Body.String())
	}
}

func TestWeChatEncryptedVerificationDecryptsEcho(t *testing.T) {
	cfg := testConfig()
	cfg.WeChatEncodingAESKey = testWeChatEncodingAESKey()
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new encrypted server: %v", err)
	}
	encrypted, err := server.wxCryptor.Encrypt([]byte("verified-echo"))
	if err != nil {
		t.Fatalf("encrypt echo: %v", err)
	}
	timestamp, nonce := "1720000004", "verify-nonce"
	signature := calculateWeChatMessageSignature(server.cfg.WeChatCallbackToken, timestamp, nonce, encrypted)
	target := "/wechat/callback?encrypt_type=aes&timestamp=" + timestamp + "&nonce=" + nonce + "&echostr=" + url.QueryEscape(encrypted) + "&msg_signature=" + signature
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "verified-echo" {
		t.Fatalf("verification status=%d body=%q", rec.Code, rec.Body.String())
	}
}

type slowFetchWeChatService struct{}

func (slowFetchWeChatService) CreateLoginQRCode(_ context.Context, scene string, ttl time.Duration) (WeChatQRCode, error) {
	return WeChatQRCode{Ticket: "ticket-" + scene, ImageURL: "https://example.test/qr", ExpireAfter: ttl}, nil
}

type countingFetchWeChatService struct {
	calls atomic.Int32
}

func (*countingFetchWeChatService) CreateLoginQRCode(_ context.Context, scene string, ttl time.Duration) (WeChatQRCode, error) {
	return WeChatQRCode{Ticket: "ticket-" + scene, ImageURL: "https://example.test/qr", ExpireAfter: ttl}, nil
}

func (service *countingFetchWeChatService) FetchUser(ctx context.Context, openID string) (User, error) {
	service.calls.Add(1)
	select {
	case <-time.After(50 * time.Millisecond):
		return User{OpenID: openID}, nil
	case <-ctx.Done():
		return User{}, ctx.Err()
	}
}

func TestConcurrentDuplicateWeChatEventIsProcessedOnce(t *testing.T) {
	server := testServer(t)
	service := &countingFetchWeChatService{}
	server.wx = service
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	body := fmt.Sprintf(`<xml><ToUserName>official</ToUserName><FromUserName>concurrent-user</FromUserName><CreateTime>1720000020</CreateTime><MsgType>event</MsgType><Event>SCAN</Event><EventKey>%s%s</EventKey></xml>`, wechatLoginScenePrefix, scan.ID)
	const workers = 8
	start := make(chan struct{})
	recorders := make([]*httptest.ResponseRecorder, workers)
	var wait sync.WaitGroup
	for i := range recorders {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			recorder := httptest.NewRecorder()
			request := signedWeChatRequest(server, http.MethodPost, "/wechat/callback", strings.NewReader(body))
			server.Routes().ServeHTTP(recorder, request)
			recorders[index] = recorder
		}(i)
	}
	close(start)
	wait.Wait()
	if calls := service.calls.Load(); calls != 1 {
		t.Fatalf("FetchUser calls=%d want 1", calls)
	}
	for i, recorder := range recorders {
		if recorder.Code != http.StatusOK || recorder.Body.String() != "success" {
			t.Errorf("response[%d] status=%d body=%q", i, recorder.Code, recorder.Body.String())
		}
	}
}

func TestConcurrentMessageCodeCallbacksConsumeLoginOnce(t *testing.T) {
	server := testServer(t)
	server.cfg.WeChatLoginMode = wechatLoginModeMessageCode
	server.wx = fakeWeChatService{}
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create message-code scan: %v", err)
	}
	bodies := []string{
		fmt.Sprintf(`<xml><ToUserName>official</ToUserName><FromUserName>message-user-a</FromUserName><CreateTime>1720000030</CreateTime><MsgType>text</MsgType><Content>%s</Content><MsgId>1030</MsgId></xml>`, scan.LoginCode),
		fmt.Sprintf(`<xml><ToUserName>official</ToUserName><FromUserName>message-user-b</FromUserName><CreateTime>1720000031</CreateTime><MsgType>text</MsgType><Content>%s</Content><MsgId>1031</MsgId></xml>`, scan.LoginCode),
	}
	start := make(chan struct{})
	recorders := make([]*httptest.ResponseRecorder, len(bodies))
	var wait sync.WaitGroup
	for i := range bodies {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			recorders[index] = performSignedWeChatCallback(t, server, bodies[index])
		}(i)
	}
	close(start)
	wait.Wait()

	confirmedReplies := 0
	for i, recorder := range recorders {
		if recorder.Code != http.StatusOK {
			t.Fatalf("callback[%d] status=%d body=%s", i, recorder.Code, recorder.Body.String())
		}
		if strings.Contains(recorder.Body.String(), "登录已确认") {
			confirmedReplies++
		}
	}
	if confirmedReplies != 1 {
		t.Fatalf("confirmed replies=%d want 1", confirmedReplies)
	}
	completed, ok := server.scanSnapshot(scan.ID)
	if !ok || (completed.User.OpenID != "message-user-a" && completed.User.OpenID != "message-user-b") {
		t.Fatalf("message-code scan was not completed exactly once: %#v ok=%t", completed, ok)
	}
	if _, exists := server.loginCodes[normalizeLoginCode(scan.LoginCode)]; exists {
		t.Fatal("login code remained usable after completion")
	}
	firstComplete := httptest.NewRecorder()
	server.Routes().ServeHTTP(firstComplete, httptest.NewRequest(http.MethodGet, completed.RedirectURL, nil))
	if firstComplete.Code != http.StatusFound || len(firstComplete.Result().Cookies()) == 0 {
		t.Fatalf("first local completion status=%d cookies=%d body=%s", firstComplete.Code, len(firstComplete.Result().Cookies()), firstComplete.Body.String())
	}
	secondComplete := httptest.NewRecorder()
	server.Routes().ServeHTTP(secondComplete, httptest.NewRequest(http.MethodGet, completed.RedirectURL, nil))
	if secondComplete.Code != http.StatusBadRequest || len(secondComplete.Result().Cookies()) != 0 {
		t.Fatalf("replayed local completion status=%d cookies=%d body=%s", secondComplete.Code, len(secondComplete.Result().Cookies()), secondComplete.Body.String())
	}
}

func TestPlaintextSignatureCannotBeReusedWithForgedLoginBody(t *testing.T) {
	server := testServer(t)
	server.cfg.WeChatLoginMode = wechatLoginModeMessageCode
	server.wx = fakeWeChatService{}
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create message-code scan: %v", err)
	}
	timestamp := fmt.Sprint(time.Now().Unix())
	nonce := "captured-plaintext-nonce"
	signature := testWeChatSignature(server.cfg.WeChatCallbackToken, timestamp, nonce)
	target := "/wechat/callback?signature=" + signature + "&timestamp=" + timestamp + "&nonce=" + nonce

	originalBody := `<xml><ToUserName>official</ToUserName><FromUserName>ordinary-user</FromUserName><CreateTime>1720000040</CreateTime><MsgType>text</MsgType><Content>普通消息</Content><MsgId>1040</MsgId></xml>`
	original := httptest.NewRecorder()
	server.Routes().ServeHTTP(original, httptest.NewRequest(http.MethodPost, target, strings.NewReader(originalBody)))
	if original.Code != http.StatusOK {
		t.Fatalf("original callback status=%d body=%s", original.Code, original.Body.String())
	}

	forgedBody := fmt.Sprintf(`<xml><ToUserName>official</ToUserName><FromUserName>forged-openid</FromUserName><CreateTime>1720000041</CreateTime><MsgType>text</MsgType><Content>%s</Content><MsgId>1041</MsgId></xml>`, scan.LoginCode)
	forged := httptest.NewRecorder()
	server.Routes().ServeHTTP(forged, httptest.NewRequest(http.MethodPost, target, strings.NewReader(forgedBody)))
	if forged.Code != http.StatusForbidden {
		t.Fatalf("forged callback status=%d body=%s", forged.Code, forged.Body.String())
	}
	pending, ok := server.scanSnapshot(scan.ID)
	if !ok || pending.User.OpenID != "" || pending.ClaimedOpenID != "" {
		t.Fatalf("forged body changed login session: %#v ok=%t", pending, ok)
	}
}

func TestWeChatResponseCacheHasCapacityLimit(t *testing.T) {
	server := &Server{
		wechatResponses: make(map[string]wechatCachedResponse),
		wechatInFlight:  make(map[string]chan struct{}),
	}
	for i := 0; i < wechatResponseCacheMaxEntries+100; i++ {
		server.cacheWeChatResponse(fmt.Sprint(i), "text/plain", []byte("success"))
	}
	if size := len(server.wechatResponses); size != wechatResponseCacheMaxEntries {
		t.Fatalf("cache size=%d want %d", size, wechatResponseCacheMaxEntries)
	}
}

func (slowFetchWeChatService) FetchUser(ctx context.Context, _ string) (User, error) {
	<-ctx.Done()
	return User{}, ctx.Err()
}

func TestWeChatScanCallbackFallsBackToOpenIDAtDeadline(t *testing.T) {
	server := testServer(t)
	server.wx = slowFetchWeChatService{}
	server.cfg.WeChatCallbackTimeout = 20 * time.Millisecond
	scan, err := server.createScanSession(context.Background(), scanKindLocal, oidcAuthRequest{}, "/")
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	body := fmt.Sprintf(`<xml><ToUserName><![CDATA[official]]></ToUserName><FromUserName><![CDATA[slow-user]]></FromUserName><CreateTime>1720000005</CreateTime><MsgType><![CDATA[event]]></MsgType><Event><![CDATA[SCAN]]></Event><EventKey><![CDATA[%s%s]]></EventKey></xml>`, wechatLoginScenePrefix, scan.ID)
	started := time.Now()
	rec := performSignedWeChatCallback(t, server, body)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("callback exceeded bounded deadline: %s", elapsed)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "success" {
		t.Fatalf("callback status=%d body=%q", rec.Code, rec.Body.String())
	}
	completed, ok := server.scanSnapshot(scan.ID)
	if !ok || completed.User.OpenID != "slow-user" {
		t.Fatalf("OpenID fallback did not complete scan: %#v", completed)
	}
}

func TestWeChatCallbackRejectsOversizedBody(t *testing.T) {
	server := testServer(t)
	body := strings.Repeat("x", maxWeChatCallbackBody+1)
	req := signedWeChatRequest(server, http.MethodPost, "/wechat/callback", strings.NewReader(body))
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func performSignedWeChatCallback(t *testing.T, server *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := signedWeChatRequest(server, http.MethodPost, "/wechat/callback", strings.NewReader(body))
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	return rec
}

func performEncryptedWeChatCallback(t *testing.T, server *Server, plaintext, timestamp, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	encrypted, err := server.wxCryptor.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("encrypt callback: %v", err)
	}
	envelope, err := xml.Marshal(wechatEncryptedEnvelope{Encrypt: wechatCDATA(encrypted)})
	if err != nil {
		t.Fatalf("marshal encrypted callback: %v", err)
	}
	signature := calculateWeChatMessageSignature(server.cfg.WeChatCallbackToken, timestamp, nonce, encrypted)
	target := "/wechat/callback?encrypt_type=aes&timestamp=" + timestamp + "&nonce=" + nonce + "&msg_signature=" + signature
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, target, strings.NewReader(string(envelope))))
	return recorder
}

func assertEncryptedWeChatTextReply(t *testing.T, server *Server, recorder *httptest.ResponseRecorder, want string) {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("encrypted response status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var envelope wechatEncryptedEnvelope
	if err := xml.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil || envelope.Encrypt == "" {
		t.Fatalf("decode encrypted response envelope=%#v err=%v body=%s", envelope, err, recorder.Body.String())
	}
	decrypted, err := server.wxCryptor.Decrypt(string(envelope.Encrypt))
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	var reply wechatPassiveReplyXML
	if err := xml.Unmarshal(decrypted, &reply); err != nil || reply.Content != wechatCDATA(want) {
		t.Fatalf("encrypted reply=%#v err=%v body=%s", reply, err, decrypted)
	}
}
