# Authentik WeChat Connect

A Go middleware service that turns WeChat Official Account QR-code login into a standard OAuth/OIDC provider for Authentik Generic OAuth Sources.

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
- Scan page: `/scan/{id}`
- Scan status: `/api/scan/{id}`
- Health check: `/healthz`

## WeChat Official Account Setup

Configure the server URL in the WeChat Official Account admin console:

```text
${PUBLIC_URL}/wechat/callback
```

Set the WeChat callback token to the exact same value as `WECHAT_CALLBACK_TOKEN`. Use plaintext message mode. The service verifies the WeChat `signature`, but it does not decrypt AES-encrypted messages.

The service uses temporary parameterized QR codes:

- If the user already follows the account, WeChat sends a `SCAN` event and the `EventKey` is the QR-code scene.
- If the user follows the account after scanning, WeChat sends a `subscribe` event and the `EventKey` is `qrscene_` plus the scene.
- `FromUserName` is used as the user's Official Account OpenID. If the user-info API is available, the service also adds nickname, avatar, UnionID, and profile claims.

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
| `WECHAT_QR_CODE_TTL` | Temporary QR-code lifetime, maximum 30 days | `5m` |
| `WECHAT_USER_INFO_LANG` | WeChat user-info language | `zh_CN` |
| `OIDC_ISSUER` | OIDC issuer | `${PUBLIC_URL}` |
| `OIDC_CLIENT_ID` | Client ID used by Authentik to call this service | `authentik` |
| `OIDC_CLIENT_SECRET` | Client secret used by Authentik to call this service | `change-me` |
| `OIDC_ALLOWED_REDIRECT_URIS` | Allowed Authentik callback URLs, comma-separated | empty |
| `OIDC_INSECURE_ALLOW_ALL_REDIRECTS` | Allow any `redirect_uri`; development only | `false` |
| `OIDC_RSA_PRIVATE_KEY_FILE` | OIDC RS256 private key file | empty |
| `OIDC_RSA_PRIVATE_KEY_PEM` | OIDC RS256 private key content | empty |
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

Then open `http://localhost:8080`.

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
docker run --rm -p 8080:8080 --env-file .env ghcr.io/as214933/authentik-wechat-connect:main
```

## Production Notes

- Set a stable, random `SESSION_SECRET` in production. At least 32 bytes is recommended.
- Set a stable `OIDC_RSA_PRIVATE_KEY_FILE` or `OIDC_RSA_PRIVATE_KEY_PEM` in production, otherwise Authentik may fail to validate `id_token` after restarts because JWKS changed.
- Non-localhost `PUBLIC_URL` rejects the default `OIDC_CLIENT_SECRET=change-me`.
- WeChat scan sessions are stored in this service's memory. For multiple replicas, route `/oauth/authorize`, `/wechat/callback`, and `/api/scan/{id}` for the same login to the same replica, or extend the service with shared external state.
- The WeChat admin server URL must be `${PUBLIC_URL}/wechat/callback`, not the Authentik Source callback or an Authentik flow URL.

## References

- Authentik Federated identity providers: https://docs.goauthentik.io/users-sources/sources/social-logins/
- WeChat event callbacks: https://developers.weixin.qq.com/doc/service/guide/product/message/Receiving_event_pushes.html
- WeChat parameterized QR codes: https://developers.weixin.qq.com/doc/service/api/qrcode/qrcodes/api_createqrcode.html
