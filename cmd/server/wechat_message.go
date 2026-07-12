package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxWeChatCallbackBody          = 1 << 20
	wechatResponseCacheTTL         = 10 * time.Minute
	wechatResponseCacheMaxEntries  = 10000
	wechatPlainSignatureTTL        = 10 * time.Minute
	wechatPlainSignatureMaxEntries = 10000
	wechatLoginAttemptWindow       = 5 * time.Minute
	wechatLoginAttemptMaxFailures  = 5
	wechatLoginGlobalWindow        = time.Minute
	wechatLoginGlobalMaxFailures   = 100
	wechatLoginAttemptMaxEntries   = 10000
)

type wechatCachedResponse struct {
	ContentType string
	Body        []byte
	ExpiresAt   time.Time
}

type wechatPlainSignatureRecord struct {
	BodyHash  [sha256.Size]byte
	ExpiresAt time.Time
}

type wechatLoginAttempt struct {
	WindowStart time.Time
	Failures    int
}

type wechatEncryptedEnvelope struct {
	XMLName      xml.Name    `xml:"xml"`
	Encrypt      wechatCDATA `xml:"Encrypt"`
	MsgSignature wechatCDATA `xml:"MsgSignature,omitempty"`
	TimeStamp    int64       `xml:"TimeStamp,omitempty"`
	Nonce        wechatCDATA `xml:"Nonce,omitempty"`
}

type wechatPassiveReplyXML struct {
	XMLName      xml.Name           `xml:"xml"`
	ToUserName   wechatCDATA        `xml:"ToUserName"`
	FromUserName wechatCDATA        `xml:"FromUserName"`
	CreateTime   int64              `xml:"CreateTime"`
	MsgType      wechatCDATA        `xml:"MsgType"`
	Content      wechatCDATA        `xml:"Content,omitempty"`
	Image        *wechatMediaXML    `xml:"Image,omitempty"`
	Voice        *wechatMediaXML    `xml:"Voice,omitempty"`
	Video        *wechatVideoXML    `xml:"Video,omitempty"`
	Music        *wechatMusicXML    `xml:"Music,omitempty"`
	ArticleCount int                `xml:"ArticleCount,omitempty"`
	Articles     *wechatArticlesXML `xml:"Articles,omitempty"`
}

type wechatMediaXML struct {
	MediaID wechatCDATA `xml:"MediaId"`
}

type wechatVideoXML struct {
	MediaID     wechatCDATA `xml:"MediaId"`
	Title       wechatCDATA `xml:"Title,omitempty"`
	Description wechatCDATA `xml:"Description,omitempty"`
}

type wechatMusicXML struct {
	Title        wechatCDATA `xml:"Title,omitempty"`
	Description  wechatCDATA `xml:"Description,omitempty"`
	MusicURL     wechatCDATA `xml:"MusicUrl,omitempty"`
	HQMusicURL   wechatCDATA `xml:"HQMusicUrl,omitempty"`
	ThumbMediaID wechatCDATA `xml:"ThumbMediaId"`
}

type wechatArticlesXML struct {
	Items []wechatArticleXML `xml:"item"`
}

type wechatArticleXML struct {
	Title       wechatCDATA `xml:"Title"`
	Description wechatCDATA `xml:"Description"`
	PicURL      wechatCDATA `xml:"PicUrl"`
	URL         wechatCDATA `xml:"Url"`
}

type wechatCDATA string

func (value wechatCDATA) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	return encoder.EncodeElement(struct {
		Value string `xml:",cdata"`
	}{Value: string(value)}, start)
}

func (value *wechatCDATA) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	var decoded string
	if err := decoder.DecodeElement(&decoded, &start); err != nil {
		return err
	}
	*value = wechatCDATA(decoded)
	return nil
}

func (s *Server) handleWeChatCallback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.WeChatCallbackToken == "" {
		logOAuthWarning(r, "wechat callback rejected: WECHAT_CALLBACK_TOKEN is not configured")
		publicError(w, http.StatusServiceUnavailable, fmt.Errorf("WECHAT_CALLBACK_TOKEN must be configured"))
		return
	}
	if r.Method == http.MethodGet {
		s.handleWeChatCallbackVerification(w, r)
		return
	}

	body, err := readWeChatCallbackBody(r.Body)
	if err != nil {
		logOAuthWarning(r, "wechat callback rejected: %v", err)
		http.Error(w, "request body is too large", http.StatusRequestEntityTooLarge)
		return
	}
	query := r.URL.Query()
	plaintext := body
	encryptedResponse := false
	var encryptedEnvelope wechatEncryptedEnvelope
	envelopeErr := xml.Unmarshal(body, &encryptedEnvelope)
	if strings.EqualFold(query.Get("encrypt_type"), "aes") && (envelopeErr != nil || encryptedEnvelope.Encrypt == "") {
		logOAuthWarning(r, "wechat callback rejected: AES mode request did not contain Encrypt")
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if envelopeErr == nil && encryptedEnvelope.Encrypt != "" {
		encryptedResponse = true
		encrypted := string(encryptedEnvelope.Encrypt)
		if s.wxCryptor == nil {
			logOAuthWarning(r, "wechat callback rejected: encrypted callback received but WECHAT_ENCODING_AES_KEY is not configured")
			http.Error(w, "WeChat callback encryption is not configured", http.StatusServiceUnavailable)
			return
		}
		if !verifyWeChatMessageSignature(s.cfg.WeChatCallbackToken, query.Get("timestamp"), query.Get("nonce"), encrypted, query.Get("msg_signature")) {
			logOAuthWarning(r, "wechat encrypted callback rejected: message signature verification failed")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		plaintext, err = s.wxCryptor.Decrypt(encrypted)
		if err != nil {
			logOAuthWarning(r, "wechat encrypted callback rejected: decrypt message: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
	} else {
		if !verifyWeChatSignature(s.cfg.WeChatCallbackToken, query.Get("timestamp"), query.Get("nonce"), query.Get("signature")) {
			logOAuthWarning(r, "wechat callback rejected: signature verification failed")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !s.acceptWeChatPlainSignature(query.Get("signature"), query.Get("timestamp"), query.Get("nonce"), body, time.Now()) {
			logOAuthWarning(r, "wechat callback rejected: plaintext signature is stale or was reused with a different body")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	var message WeChatInboundMessage
	if err := xml.Unmarshal(plaintext, &message); err != nil {
		logOAuthWarning(r, "wechat callback rejected: decode XML: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(message.ToUserName) == "" || strings.TrimSpace(message.FromUserName) == "" || strings.TrimSpace(message.MsgType) == "" || message.CreateTime <= 0 {
		logOAuthWarning(r, "wechat callback rejected: required XML fields are missing")
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if isWeChatStandardMessage(message) && message.MsgID == 0 {
		logOAuthWarning(r, "wechat callback rejected: standard message is missing MsgId")
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	transportMode := "plain"
	if encryptedResponse {
		transportMode = "aes"
	}
	cacheKey := transportMode + "\x00" + wechatInboundCacheKey(message)
	for {
		cached, wait, leader := s.acquireWeChatResponse(cacheKey)
		if cached != nil {
			writeWeChatCallbackResponse(w, cached.ContentType, cached.Body)
			return
		}
		if leader {
			break
		}
		select {
		case <-wait:
			continue
		case <-r.Context().Done():
			http.Error(w, "request cancelled", http.StatusRequestTimeout)
			return
		}
	}
	defer s.abortWeChatResponse(cacheKey)

	completedByMessageCode := s.processWeChatLogin(r, message)
	state := s.management.Snapshot()
	reply, ruleID := state.Replies.SelectReply(message)
	if completedByMessageCode {
		reply = &WeChatReply{Type: "text", Content: "登录已确认，请返回浏览器继续。"}
		ruleID = "wechat-login-code"
	}
	responseBody := []byte("success")
	contentType := "text/plain; charset=utf-8"
	if reply != nil {
		responseBody, err = renderWeChatPassiveReply(message, *reply, time.Now())
		if err != nil {
			logOAuthWarning(r, "wechat reply rendering failed rule_id=%q: %v", ruleID, err)
			responseBody = []byte("success")
		} else {
			contentType = "application/xml; charset=utf-8"
		}
	}
	if encryptedResponse && string(responseBody) != "success" {
		responseBody, err = s.encryptWeChatReply(responseBody)
		if err != nil {
			logOAuthWarning(r, "wechat reply encryption failed: %v", err)
			http.Error(w, "failed to encrypt response", http.StatusInternalServerError)
			return
		}
		contentType = "application/xml; charset=utf-8"
	}

	s.cacheWeChatResponse(cacheKey, contentType, responseBody)
	logOAuthInfo(r, "wechat callback handled msg_type=%q event=%q reply_rule=%q encrypted=%t", message.MsgType, message.Event, ruleID, encryptedResponse)
	writeWeChatCallbackResponse(w, contentType, responseBody)
}

func (s *Server) handleWeChatCallbackVerification(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	echo := query.Get("echostr")
	if query.Get("msg_signature") != "" || strings.EqualFold(query.Get("encrypt_type"), "aes") {
		if s.wxCryptor == nil {
			http.Error(w, "WeChat callback encryption is not configured", http.StatusServiceUnavailable)
			return
		}
		if !verifyWeChatMessageSignature(s.cfg.WeChatCallbackToken, query.Get("timestamp"), query.Get("nonce"), echo, query.Get("msg_signature")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		plaintext, err := s.wxCryptor.Decrypt(echo)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		echo = string(plaintext)
	} else if !verifyWeChatSignature(s.cfg.WeChatCallbackToken, query.Get("timestamp"), query.Get("nonce"), query.Get("signature")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(echo))
}

func (s *Server) processWeChatLogin(r *http.Request, message WeChatInboundMessage) bool {
	scene, messageCode, ok := s.pendingLoginScene(message)
	if !ok {
		return false
	}
	user := User{OpenID: message.FromUserName}
	timeout := s.cfg.WeChatCallbackTimeout
	if timeout <= 0 || timeout > 4*time.Second {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	if fetched, err := s.wx.FetchUser(ctx, message.FromUserName); err == nil {
		if fetched.OpenID == message.FromUserName {
			user = fetched
		} else {
			log.Printf("wechat user info lookup returned a mismatched OpenID requested_fp=%s returned_fp=%s", tokenFingerprint(message.FromUserName), tokenFingerprint(fetched.OpenID))
		}
	} else {
		log.Printf("wechat user info lookup failed openid_fp=%s: %v", tokenFingerprint(message.FromUserName), err)
	}
	completed, err := s.completeScan(r, scene, user)
	if err != nil {
		logOAuthWarning(r, "wechat callback scan completion ignored scene_fp=%s openid_fp=%s: %v", tokenFingerprint(scene), tokenFingerprint(message.FromUserName), err)
	} else if completed {
		logOAuthInfo(r, "wechat callback completed scan scene_fp=%s openid_fp=%s", tokenFingerprint(scene), tokenFingerprint(message.FromUserName))
	}
	return messageCode && completed
}

func (s *Server) pendingLoginScene(message WeChatInboundMessage) (string, bool, bool) {
	if scene, ok := sceneFromWeChatEvent(message); ok && strings.HasPrefix(scene, wechatLoginScenePrefix) {
		id := strings.TrimPrefix(scene, wechatLoginScenePrefix)
		s.mu.Lock()
		scan, exists := s.scans[id]
		accepted := exists && scan.LoginMode != wechatLoginModeMessageCode && scan.User.OpenID == "" && scan.Error == "" && time.Now().Before(scan.ExpiresAt)
		s.mu.Unlock()
		if accepted {
			return scene, false, true
		}
	}
	code, ok := loginCodeFromWeChatText(message)
	if !ok {
		return "", false, false
	}
	s.mu.Lock()
	now := time.Now()
	if !s.loginCodeAttemptAllowedLocked(message.FromUserName, now) {
		s.mu.Unlock()
		return "", false, false
	}
	id, exists := s.loginCodes[code]
	scan := s.scans[id]
	accepted := exists && scan != nil && scan.LoginMode == wechatLoginModeMessageCode && scan.User.OpenID == "" && scan.Error == "" && now.Before(scan.ExpiresAt)
	if accepted {
		scan.ClaimedOpenID = message.FromUserName
		delete(s.loginCodes, code)
		delete(s.wechatLoginAttempts, message.FromUserName)
	} else {
		s.recordLoginCodeFailureLocked(message.FromUserName, now)
	}
	s.mu.Unlock()
	if !accepted {
		return "", false, false
	}
	return wechatLoginScenePrefix + id, true, true
}

func (s *Server) loginCodeAttemptAllowedLocked(openID string, now time.Time) bool {
	if openID == "" {
		return false
	}
	if s.wechatGlobalAttempts.WindowStart.IsZero() || !now.Before(s.wechatGlobalAttempts.WindowStart.Add(wechatLoginGlobalWindow)) {
		s.wechatGlobalAttempts = wechatLoginAttempt{WindowStart: now}
	}
	if s.wechatGlobalAttempts.Failures >= wechatLoginGlobalMaxFailures {
		return false
	}
	attempt, exists := s.wechatLoginAttempts[openID]
	if !exists || !now.Before(attempt.WindowStart.Add(wechatLoginAttemptWindow)) {
		return true
	}
	return attempt.Failures < wechatLoginAttemptMaxFailures
}

func (s *Server) recordLoginCodeFailureLocked(openID string, now time.Time) {
	if s.wechatLoginAttempts == nil {
		s.wechatLoginAttempts = make(map[string]wechatLoginAttempt)
	}
	if s.wechatGlobalAttempts.WindowStart.IsZero() || !now.Before(s.wechatGlobalAttempts.WindowStart.Add(wechatLoginGlobalWindow)) {
		s.wechatGlobalAttempts = wechatLoginAttempt{WindowStart: now}
	}
	s.wechatGlobalAttempts.Failures++
	attempt, exists := s.wechatLoginAttempts[openID]
	if !exists || !now.Before(attempt.WindowStart.Add(wechatLoginAttemptWindow)) {
		if !exists && len(s.wechatLoginAttempts) >= wechatLoginAttemptMaxEntries {
			for candidate := range s.wechatLoginAttempts {
				delete(s.wechatLoginAttempts, candidate)
				break
			}
		}
		attempt = wechatLoginAttempt{WindowStart: now}
	}
	attempt.Failures++
	s.wechatLoginAttempts[openID] = attempt
}

func loginCodeFromWeChatText(message WeChatInboundMessage) (string, bool) {
	if !strings.EqualFold(message.MsgType, "text") {
		return "", false
	}
	code := normalizeLoginCode(message.Content)
	return code, code != ""
}

func renderWeChatPassiveReply(message WeChatInboundMessage, reply WeChatReply, now time.Time) ([]byte, error) {
	if err := reply.Validate(); err != nil {
		return nil, err
	}
	result := wechatPassiveReplyXML{
		ToUserName:   wechatCDATA(message.FromUserName),
		FromUserName: wechatCDATA(message.ToUserName),
		CreateTime:   now.Unix(),
		MsgType:      wechatCDATA(reply.Type),
	}
	switch reply.Type {
	case "text":
		result.Content = wechatCDATA(reply.Content)
	case "image":
		result.Image = &wechatMediaXML{MediaID: wechatCDATA(reply.MediaID)}
	case "voice":
		result.Voice = &wechatMediaXML{MediaID: wechatCDATA(reply.MediaID)}
	case "video":
		result.Video = &wechatVideoXML{MediaID: wechatCDATA(reply.MediaID), Title: wechatCDATA(reply.Title), Description: wechatCDATA(reply.Description)}
	case "music":
		result.Music = &wechatMusicXML{Title: wechatCDATA(reply.Title), Description: wechatCDATA(reply.Description), MusicURL: wechatCDATA(reply.MusicURL), HQMusicURL: wechatCDATA(reply.HQMusicURL), ThumbMediaID: wechatCDATA(reply.ThumbMediaID)}
	case "news":
		items := make([]wechatArticleXML, 0, len(reply.Articles))
		for _, article := range reply.Articles {
			items = append(items, wechatArticleXML{Title: wechatCDATA(article.Title), Description: wechatCDATA(article.Description), PicURL: wechatCDATA(article.PicURL), URL: wechatCDATA(article.URL)})
		}
		result.ArticleCount = len(items)
		result.Articles = &wechatArticlesXML{Items: items}
	case "official_ai":
		result.MsgType = wechatCDATA("transfer_biz_ai_ivr")
	case "customer_service":
		result.MsgType = wechatCDATA("transfer_customer_service")
	default:
		return nil, fmt.Errorf("unsupported WeChat reply type %q", reply.Type)
	}
	return xml.Marshal(result)
}

func (s *Server) encryptWeChatReply(plaintext []byte) ([]byte, error) {
	encrypted, err := s.wxCryptor.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken(12)
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().Unix()
	envelope := wechatEncryptedEnvelope{
		Encrypt:      wechatCDATA(encrypted),
		MsgSignature: wechatCDATA(calculateWeChatMessageSignature(s.cfg.WeChatCallbackToken, fmt.Sprint(timestamp), nonce, encrypted)),
		TimeStamp:    timestamp,
		Nonce:        wechatCDATA(nonce),
	}
	return xml.Marshal(envelope)
}

func readWeChatCallbackBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxWeChatCallbackBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxWeChatCallbackBody {
		return nil, fmt.Errorf("request body exceeds %d bytes", maxWeChatCallbackBody)
	}
	return data, nil
}

func calculateWeChatMessageSignature(parts ...string) string {
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	return hex.EncodeToString(sum[:])
}

func verifyWeChatSignature(token, timestamp, nonce, signature string) bool {
	if token == "" || timestamp == "" || nonce == "" || signature == "" {
		return false
	}
	expected := calculateWeChatMessageSignature(token, timestamp, nonce)
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(signature)))
}

func (s *Server) acceptWeChatPlainSignature(signature, timestamp, nonce string, body []byte, now time.Time) bool {
	unixTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	signedAt := time.Unix(unixTimestamp, 0)
	if signedAt.Before(now.Add(-wechatPlainSignatureTTL)) || signedAt.After(now.Add(wechatPlainSignatureTTL)) {
		return false
	}
	key := signature + "\x00" + timestamp + "\x00" + nonce
	bodyHash := sha256.Sum256(body)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wechatPlainSignatures == nil {
		s.wechatPlainSignatures = make(map[string]wechatPlainSignatureRecord)
	}
	if previous, exists := s.wechatPlainSignatures[key]; exists && now.Before(previous.ExpiresAt) {
		return previous.BodyHash == bodyHash
	}
	if len(s.wechatPlainSignatures) >= wechatPlainSignatureMaxEntries {
		for candidate := range s.wechatPlainSignatures {
			delete(s.wechatPlainSignatures, candidate)
			break
		}
	}
	s.wechatPlainSignatures[key] = wechatPlainSignatureRecord{
		BodyHash:  bodyHash,
		ExpiresAt: signedAt.Add(wechatPlainSignatureTTL),
	}
	return true
}

func sceneFromWeChatEvent(message WeChatInboundMessage) (string, bool) {
	if !strings.EqualFold(message.MsgType, "event") {
		return "", false
	}
	switch strings.ToUpper(message.Event) {
	case "SCAN":
		scene := strings.TrimSpace(message.EventKey)
		return scene, scene != ""
	case "SUBSCRIBE":
		scene := strings.TrimSpace(message.EventKey)
		if !strings.HasPrefix(scene, "qrscene_") {
			return "", false
		}
		scene = strings.TrimPrefix(scene, "qrscene_")
		return scene, scene != ""
	default:
		return "", false
	}
}

func wechatInboundCacheKey(message WeChatInboundMessage) string {
	if message.MsgID != 0 {
		return "msg\x00" + message.FromUserName + "\x00" + fmt.Sprint(message.MsgID)
	}
	return "event\x00" + strings.Join([]string{
		message.ToUserName,
		message.FromUserName,
		fmt.Sprint(message.CreateTime),
		strings.ToLower(message.MsgType),
		strings.ToUpper(message.Event),
		message.EventKey,
		message.Ticket,
		message.MenuID,
		message.ScanCodeInfo.ScanType,
		weChatMessageMatchValue(message),
		fmt.Sprint(message.SendLocationInfo.LocationX),
		fmt.Sprint(message.SendLocationInfo.LocationY),
	}, "\x00")
}

func (s *Server) acquireWeChatResponse(key string) (*wechatCachedResponse, <-chan struct{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	response, ok := s.wechatResponses[key]
	if ok && time.Now().Before(response.ExpiresAt) {
		response.Body = append([]byte(nil), response.Body...)
		return &response, nil, false
	}
	if ok {
		delete(s.wechatResponses, key)
	}
	if wait, ok := s.wechatInFlight[key]; ok {
		return nil, wait, false
	}
	wait := make(chan struct{})
	s.wechatInFlight[key] = wait
	return nil, wait, true
}

func (s *Server) cacheWeChatResponse(key, contentType string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.wechatResponses[key]; !exists && len(s.wechatResponses) >= wechatResponseCacheMaxEntries {
		for candidate := range s.wechatResponses {
			delete(s.wechatResponses, candidate)
			break
		}
	}
	s.wechatResponses[key] = wechatCachedResponse{
		ContentType: contentType,
		Body:        append([]byte(nil), body...),
		ExpiresAt:   time.Now().Add(wechatResponseCacheTTL),
	}
	if wait, ok := s.wechatInFlight[key]; ok {
		delete(s.wechatInFlight, key)
		close(wait)
	}
}

func (s *Server) abortWeChatResponse(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if wait, ok := s.wechatInFlight[key]; ok {
		delete(s.wechatInFlight, key)
		close(wait)
	}
}

func writeWeChatCallbackResponse(w http.ResponseWriter, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(body)
}
