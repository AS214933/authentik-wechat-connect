# Authentik WeChat Connect

一个 Go 中间件，把微信公众号“带参数二维码 + 事件推送”登录包装成标准 OAuth/OIDC Provider，供 Authentik 的 Generic OAuth Source 使用。

## 登录链路

1. 用户在 Authentik 选择微信登录。
2. Authentik 跳转到本服务 `/oauth/authorize`。
3. 本服务调用微信公众号接口生成临时带参数二维码，并展示扫码页。
4. 用户使用微信扫码；公众号向本服务 `/wechat/callback` 推送 `SCAN` 或 `subscribe` 事件。
5. 本服务按二维码 scene 找回 Authentik 授权请求，生成 authorization code。
6. 浏览器轮询到成功状态，提示“绑定/登录成功”，然后跳回 Authentik Source callback。
7. Authentik 调用 `/oauth/token` 和 `/oauth/userinfo` 完成登录或绑定。

## 端点

- Discovery: `/.well-known/openid-configuration`
- Authorize: `/oauth/authorize`
- Token: `/oauth/token`
- UserInfo: `/oauth/userinfo`
- JWKS: `/oauth/jwks`
- 微信服务器回调: `/wechat/callback`
- 扫码页: `/scan/{id}`
- 扫码状态: `/api/scan/{id}`
- 健康检查: `/healthz`

## 微信公众号配置

在公众号后台配置服务器地址：

```text
${PUBLIC_URL}/wechat/callback
```

Token 填写与 `WECHAT_CALLBACK_TOKEN` 完全相同的值。消息加解密方式请选择明文模式；当前服务会校验微信 `signature`，但不处理 AES 加密消息。

本服务使用微信公众号临时带参数二维码：

- 已关注用户扫码时，微信推送 `SCAN` 事件，`EventKey` 是二维码 scene。
- 未关注用户扫码并关注时，微信推送 `subscribe` 事件，`EventKey` 是 `qrscene_` 加 scene。
- `FromUserName` 作为用户的公众号 OpenID；如果用户信息接口可用，会补充昵称、头像、UnionID 等 claims。

## Authentik 配置

在 Authentik 创建 Generic OAuth Source，推荐填 discovery URL：

```text
https://wechat-connect.example.com/.well-known/openid-configuration
```

也可以手填：

```text
Authorization URL: https://wechat-connect.example.com/oauth/authorize
Token URL:         https://wechat-connect.example.com/oauth/token
User Info URL:     https://wechat-connect.example.com/oauth/userinfo
JWKS URL:          https://wechat-connect.example.com/oauth/jwks
Scopes:            openid profile
Client ID:         与 OIDC_CLIENT_ID 相同
Client Secret:     与 OIDC_CLIENT_SECRET 相同
```

把 Authentik Source 生成的回调地址加入 `OIDC_ALLOWED_REDIRECT_URIS`。常见格式类似：

```text
https://authentik.example.com/source/oauth/callback/wechat-connect/
```

不要把 `PUBLIC_URL`、`OIDC_ISSUER` 或 `OIDC_ALLOWED_REDIRECT_URIS` 配成 Authentik flow URL，例如 `/if/flow/default-authentication-flow/`。`OIDC_ALLOWED_REDIRECT_URIS` 应该是 Source callback URL。

## 环境变量

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `PUBLIC_URL` | 外部访问本服务的 URL | `http://localhost:8080` |
| `LISTEN_ADDR` | HTTP 监听地址 | `:8080` |
| `WECHAT_APP_ID` | 微信公众号 AppID | 空 |
| `WECHAT_APP_SECRET` | 微信公众号 AppSecret | 空 |
| `WECHAT_CALLBACK_TOKEN` | 微信服务器回调 Token | 空 |
| `WECHAT_QR_CODE_TTL` | 临时二维码有效期，最长 30 天 | `5m` |
| `WECHAT_USER_INFO_LANG` | 微信用户信息语言 | `zh_CN` |
| `OIDC_ISSUER` | OIDC issuer | `${PUBLIC_URL}` |
| `OIDC_CLIENT_ID` | Authentik 连接本服务的 client id | `authentik` |
| `OIDC_CLIENT_SECRET` | Authentik 连接本服务的 client secret | `change-me` |
| `OIDC_ALLOWED_REDIRECT_URIS` | 允许的 Authentik 回调地址，逗号分隔 | 空 |
| `OIDC_INSECURE_ALLOW_ALL_REDIRECTS` | 是否允许任意 redirect_uri，仅开发调试使用 | `false` |
| `OIDC_RSA_PRIVATE_KEY_FILE` | OIDC RS256 私钥文件 | 空 |
| `OIDC_RSA_PRIVATE_KEY_PEM` | OIDC RS256 私钥内容 | 空 |
| `SESSION_SECRET` | Web session、authorization code、access token 加密密钥，生产必填 | 启动时临时生成 |
| `SESSION_COOKIE_NAME` | 本地网页登录 cookie 名 | `wechat_connect_session` |
| `AUTH_CODE_TTL` | OIDC authorization code 有效期 | `10m` |
| `ACCESS_TOKEN_TTL` | OIDC access token 有效期 | `1h` |
| `SESSION_TTL` | 本地网页登录 session 有效期 | `24h` |

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

然后访问 `http://localhost:8080`。本地调试 Authentik 时，可以临时设置：

```env
OIDC_INSECURE_ALLOW_ALL_REDIRECTS=true
```

## 生产部署注意事项

- 生产环境必须设置稳定且足够随机的 `SESSION_SECRET`，建议至少 32 字节。
- 生产环境必须设置稳定的 `OIDC_RSA_PRIVATE_KEY_FILE` 或 `OIDC_RSA_PRIVATE_KEY_PEM`，避免服务重启后 JWKS 变化导致 Authentik 无法验证 `id_token`。
- 非 localhost 的 `PUBLIC_URL` 会拒绝默认 `OIDC_CLIENT_SECRET=change-me`。
- 微信扫码会话保存在本服务内存中。多副本部署时，需要让 `/oauth/authorize`、`/wechat/callback` 和 `/api/scan/{id}` 命中同一个副本，或先扩展外部共享状态存储。
- 微信后台服务器地址必须是本服务的 `${PUBLIC_URL}/wechat/callback`，不是 Authentik 的 Source callback 或 flow URL。

## 参考

- Authentik Federated identity providers: https://docs.goauthentik.io/users-sources/sources/social-logins/
- 微信接收事件推送: https://developers.weixin.qq.com/doc/service/guide/product/message/Receiving_event_pushes.html
- 微信生成带参数二维码: https://developers.weixin.qq.com/doc/service/api/qrcode/qrcodes/api_createqrcode.html
