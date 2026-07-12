# Authentik WeChat Connect

A Go middleware service that turns WeChat Official Account QR-code login into a standard OAuth/OIDC provider for Authentik Generic OAuth Sources. It also handles pushed Official Account messages, managed passive replies, and custom menus after server push is enabled.

## Login Flow

1. The user selects WeChat login in Authentik.
2. Authentik redirects the browser to this service at `/oauth/authorize`.
3. This service creates a temporary WeChat parameterized QR code and shows the scan page.
4. The user scans the QR code in WeChat. The Official Account sends a `SCAN` or `subscribe` event to `/wechat/callback`.
5. This service matches the QR-code scene to the original Authentik authorization request and creates an authorization code.
6. The scan page polls until the callback arrives, shows a successful binding/login state, and redirects back to the Authentik Source callback.
7. Authentik calls `/oauth/token` and `/oauth/userinfo` to finish login or account binding.

## Endpoints

- Discovery: `/.well-known/openid-configuration`
- Authorize: `/oauth/authorize`
- Token: `/oauth/token`
- UserInfo: `/oauth/userinfo`
- JWKS: `/oauth/jwks`
- WeChat server callback: `/wechat/callback`
- WeChat management page: `/admin/wechat`
- Management state: `GET /api/admin/wechat/state`
- Reply rules: `PUT /api/admin/wechat/replies`
- Menu draft: `PUT /api/admin/wechat/menu`
- Publish menu: `POST /api/admin/wechat/menu/publish`
- Read/delete remote menu: `GET|DELETE /api/admin/wechat/menu/remote`
- Scan page: `/scan/{id}`
- Scan status: `/api/scan/{id}`
- Health check: `/healthz`

## WeChat Official Account Setup

Configure the server URL in the WeChat Official Account admin console:

```text
${PUBLIC_URL}/wechat/callback
```

Set the WeChat callback token to the exact same value as `WECHAT_CALLBACK_TOKEN`.

- Plaintext mode verifies `signature`.
- Compatibility and safe modes verify `msg_signature`, decrypt the callback with `WECHAT_ENCODING_AES_KEY`, validate the embedded AppID, and encrypt passive replies. Safe mode is recommended.
- The EncodingAESKey is the 43-character value configured in the WeChat console. `WECHAT_APP_ID` must also be set when AES is enabled.

Enabling server push disables the automatic replies and custom menus configured on the WeChat website. Configure replacements through this service before enabling push. The website has no API that can write those old rules, so this service stores its own managed rules.

The service uses temporary parameterized QR codes:

- If the user already follows the account, WeChat sends `Event=SCAN` and `EventKey=<scene>`.
- If the user follows the account after scanning, WeChat sends `Event=subscribe` and `EventKey=qrscene_<scene>`.
- WeChat does not send a separate `start` field. The parameter analogous to a start parameter is the QR-code `scene`.
- Login scenes use the `login:<random-session-id>` namespace. A menu click is a separate `Event=CLICK` with `EventKey=<button key>` and can never complete a login scan.
- `FromUserName` is used as the user's Official Account OpenID. If the user-info API is available, the service also adds nickname, avatar, UnionID, and profile claims.

## Replies And Menu Management

Set a strong `WECHAT_ADMIN_TOKEN`, start the service, and open:

```text
${PUBLIC_URL}/admin/wechat
```

The token is sent as a Bearer credential and is kept in browser `sessionStorage`, so it is cleared when the browser session ends. It is independent from `OIDC_CLIENT_SECRET`.

Reply rules are ordered and use the first match. They can match standard messages (`text`, `image`, `voice`, `video`, `shortvideo`, `location`, and `link`) or events such as `subscribe`, parameter QR `scan`, and menu `click`. Match modes are `any`, `exact`, `contains`, `prefix`, and RE2 regular expressions. `click` matches the button key; menu scan events match the decoded scan result; photo events match selected-image MD5 values; location selection matches its label/place name. An optional default reply applies only to standard messages, never events.

Passive reply types are text, image, voice, video, music, news, official AI, and customer-service transfer. Media replies require a Media ID already uploaded to WeChat. Official AI emits the documented `transfer_biz_ai_ivr` message type; it only works for standard user messages when the account has WeChat AI reply enabled and its historical articles have finished training. It is distinct from `transfer_customer_service`.

The menu editor saves a local draft first. **Save draft does not change WeChat.** Publish explicitly calls `/cgi-bin/menu/create`; reading the remote menu calls `/cgi-bin/get_current_selfmenu_info`; deleting calls `/cgi-bin/menu/delete`. The current-menu response uses a different shape from the create request (`selfmenu_info.button` and `sub_button.list`) and may contain website-only actions. Use **Import as draft** to normalize it. Website `text` actions are converted to `click` buttons plus exact managed reply rules; website `img`, `voice`, `video`, and `news` actions are rejected because their returned temporary/download fields cannot be reused as permanent API media. WeChat may take about five minutes to refresh clients.

Reading and publishing have different account permissions. An account may be allowed to call `/cgi-bin/get_current_selfmenu_info` but not `/cgi-bin/menu/create`; unverified Subscription Accounts generally cannot publish API-managed menus. Publishing also requires the AppSecret API-call IP allowlist to include this service.

Example menu draft:

```json
{
  "button": [
    {"type": "click", "name": "帮助", "key": "help"},
    {"type": "view", "name": "网站", "url": "https://example.com/"}
  ]
}
```

Use a `click` reply rule with an exact `pattern` of `help` to reply to the first button. The API uses strong revision ETags: fetch `/api/admin/wechat/state`, then send its `ETag` in `If-Match` when replacing replies, saving the menu draft, or publishing it. This prevents two open management pages from silently overwriting or publishing each other's drafts.

## Authentik Setup

Create a Generic OAuth Source in Authentik. The recommended configuration is the discovery URL:

```text
https://wechat-connect.example.com/.well-known/openid-configuration
```

You can also configure the endpoints manually:

```text
Authorization URL: https://wechat-connect.example.com/oauth/authorize
Token URL:         https://wechat-connect.example.com/oauth/token
User Info URL:     https://wechat-connect.example.com/oauth/userinfo
JWKS URL:          https://wechat-connect.example.com/oauth/jwks
Scopes:            openid profile
Client ID:         same value as OIDC_CLIENT_ID
Client Secret:     same value as OIDC_CLIENT_SECRET
```

Add the Authentik Source callback URL to `OIDC_ALLOWED_REDIRECT_URIS`. It usually looks like this:

```text
https://authentik.example.com/source/oauth/callback/wechat-connect/
```

Do not set `PUBLIC_URL`, `OIDC_ISSUER`, or `OIDC_ALLOWED_REDIRECT_URIS` to an Authentik flow URL such as `/if/flow/default-authentication-flow/`. `OIDC_ALLOWED_REDIRECT_URIS` must contain the Source callback URL.

## Environment Variables

| Variable | Description | Default |
| --- | --- | --- |
| `PUBLIC_URL` | Public base URL for this middleware service | `http://localhost:8080` |
| `LISTEN_ADDR` | HTTP listen address | `:8080` |
| `WECHAT_APP_ID` | WeChat Official Account AppID | empty |
| `WECHAT_APP_SECRET` | WeChat Official Account AppSecret | empty |
| `WECHAT_CALLBACK_TOKEN` | WeChat server callback token | empty |
| `WECHAT_ENCODING_AES_KEY` | 43-character callback EncodingAESKey; enables compatibility/safe mode | empty |
| `WECHAT_QR_CODE_TTL` | Temporary QR-code lifetime, maximum 30 days | `5m` |
| `WECHAT_USER_INFO_LANG` | WeChat user-info language | `zh_CN` |
| `WECHAT_CALLBACK_TIMEOUT` | Maximum user-profile lookup time inside the 5-second callback window; maximum 4 seconds | `3s` |
| `WECHAT_ADMIN_TOKEN` | Independent Bearer token for the WeChat management API; 32+ bytes in production | empty (management API disabled) |
| `WECHAT_MANAGEMENT_DATA_FILE` | Atomic JSON state file for replies and menu draft | `data/wechat-management.json` |
| `OIDC_ISSUER` | OIDC issuer | `${PUBLIC_URL}` |
| `OIDC_CLIENT_ID` | Client ID used by Authentik to call this service | `authentik` |
| `OIDC_CLIENT_SECRET` | Client secret used by Authentik to call this service | `change-me` |
| `OIDC_ALLOWED_REDIRECT_URIS` | Allowed Authentik callback URLs, comma-separated | empty |
| `OIDC_INSECURE_ALLOW_ALL_REDIRECTS` | Allow any `redirect_uri`; development only | `false` |
| `OIDC_RSA_PRIVATE_KEY_FILE` | Optional persistent OIDC RS256 private key file | empty |
| `OIDC_RSA_PRIVATE_KEY_PEM` | Optional persistent OIDC RS256 private key content | empty |
| `SESSION_SECRET` | Encryption key for web sessions, authorization codes, and access tokens; required in production | generated at startup |
| `SESSION_COOKIE_NAME` | Local web-login cookie name | `wechat_connect_session` |
| `AUTH_CODE_TTL` | OIDC authorization-code lifetime | `10m` |
| `ACCESS_TOKEN_TTL` | OIDC access-token lifetime | `1h` |
| `SESSION_TTL` | Local web-login session lifetime | `24h` |

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

Then open `http://localhost:8080`. Compose mounts the named `wechat-data` volume at `/app/data`, so reply rules and menu drafts survive container replacement.

For local Authentik testing, you can temporarily set:

```env
OIDC_INSECURE_ALLOW_ALL_REDIRECTS=true
```

## GHCR Image

The CI workflow publishes multi-architecture images to GitHub Container Registry on pushes to `main` and on `v*` tags:

```text
ghcr.io/as214933/authentik-wechat-connect:main
ghcr.io/as214933/authentik-wechat-connect:sha-<commit>
ghcr.io/as214933/authentik-wechat-connect:<version>
```

Example:

```bash
docker run --rm -p 8080:8080 --env-file .env \
  -v wechat-data:/app/data \
  ghcr.io/as214933/authentik-wechat-connect:main
```

## Production Notes

- Set a stable, random `SESSION_SECRET` in production. At least 32 bytes is recommended.
- Without `OIDC_RSA_PRIVATE_KEY_FILE` or `OIDC_RSA_PRIVATE_KEY_PEM`, the service generates an ephemeral signing key at startup. This is supported, but a persistent key avoids JWKS changes across restarts and replicas.
- Non-localhost `PUBLIC_URL` rejects the default `OIDC_CLIENT_SECRET=change-me`.
- Non-localhost deployments reject a configured `WECHAT_ADMIN_TOKEN` shorter than 32 bytes. Generate an independent random value, for example with `openssl rand -base64 32`.
- Back up `WECHAT_MANAGEMENT_DATA_FILE`. The included Docker Compose volume persists it; a container without a volume loses it when removed.
- WeChat scan sessions are stored in this service's memory. For multiple replicas, route `/oauth/authorize`, `/wechat/callback`, and `/api/scan/{id}` for the same login to the same replica, or extend the service with shared external state.
- The JSON management store is a single-replica store. Do not let multiple replicas write separate copies; use one management/callback replica or replace it with shared storage.
- WeChat retries callbacks that do not receive a valid response within five seconds. The service bounds profile lookup, falls back to the signed OpenID, and replays a cached identical response for duplicate `MsgId`/event deliveries.
- The WeChat admin server URL must be `${PUBLIC_URL}/wechat/callback`, not the Authentik Source callback or an Authentik flow URL.

## References

- Authentik Federated identity providers: https://docs.goauthentik.io/users-sources/sources/social-logins/
- WeChat Subscription Account custom menus: https://developers.weixin.qq.com/doc/subscription/guide/product/menu/intro.html
- WeChat current custom menu response: https://developers.weixin.qq.com/doc/subscription/api/custommenu/api_getcurrentselfmenuinfo
- WeChat custom menu creation: https://developers.weixin.qq.com/doc/subscription/api/custommenu/api_createcustommenu
- WeChat Subscription Account standard messages: https://developers.weixin.qq.com/doc/subscription/guide/product/message/Receiving_standard_messages.html
- WeChat event callbacks: https://developers.weixin.qq.com/doc/service/guide/product/message/Receiving_event_pushes.html
- WeChat parameterized QR codes: https://developers.weixin.qq.com/doc/service/api/qrcode/qrcodes/api_createqrcode.html
