# GoAuth

JWT Authentication microservice for managing users, sessions, and access control.

## Quick Start

### Pull the image

```bash
docker pull ghcr.io/aymankastali/go_auth:latest
```

Or a specific version:

```bash
docker pull ghcr.io/aymankastali/go_auth:1.0.0
```

### Run with Docker Compose

1. Create a `.env` file with your configuration (see [Environment Variables](#environment-variables) below).

2. Start the service:

```bash
docker compose -f docker-compose.prod.yml up -d
```

3. The API is available at `http://localhost:8080` (or the port you configured with `GA_HTTP_PORT`).

### Override the image version

```bash
GA_IMAGE=ghcr.io/aymankastali/go_auth:1.0.0 docker compose -f docker-compose.prod.yml up -d
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GA_APP_NAME` | Application name | `GoAuth` |
| `GA_APP_ENV` | Environment (`development` / `production`) | `development` |
| `GA_DEBUG` | Enable debug mode | `true` |
| `GA_LOG_LEVEL` | Log level | `debug` |
| `GA_HTTP_PORT` | HTTP server port | `8080` |
| `GA_DATABASE_URL` | PostgreSQL connection string | -- |
| `GA_JWT_SECRET` | JWT signing secret (base64) | -- |
| `GA_JWT_ISSUER` | JWT issuer claim | `go-auth-service` |
| `GA_JWT_AUDIENCE` | JWT audience claim | `go-web-client` |
| `GA_JWT_ACCESS_TTL` | Access token TTL | `15m` |
| `GA_PASSWORD_BCRYPT_COST` | Bcrypt cost factor | `12` |
| `GA_PASS_MIN_LEN` | Minimum password length | `12` |
| `GA_PASS_MAX_LEN` | Maximum password length | `128` |
| `GA_PASS_REQ_UPPER` | Require uppercase letter | `true` |
| `GA_PASS_REQ_NUM` | Require number | `true` |
| `GA_PASS_REQ_SPECIAL` | Require special character | `true` |
| `GA_SESSION_LIFETIME` | Session TTL | `24h` |
| `GA_SESSION_MAX_ACTIVE` | Max concurrent sessions per user | `5` |
| `GA_ADMIN_EMAIL` | Seed admin email | -- |
| `GA_ADMIN_PASSWORD` | Seed admin password | -- |
| `GA_EMAIL_HOST` | SMTP host | `localhost` |
| `GA_EMAIL_PORT` | SMTP port | `587` |
| `GA_EMAIL_USERNAME` | SMTP username | -- |
| `GA_EMAIL_PASSWORD` | SMTP password | -- |
| `GA_EMAIL_FROM` | Sender address | `noreply@go-auth.com` |
| `GA_EMAIL_RESET_BASE_URL` | Password reset base URL | -- |
| `GA_RECOVERY_TOKEN_LIFETIME` | Recovery token TTL | `15m` |
| `GA_REGISTER_ALLOW_PUBLIC` | Allow public registration | `true` |
| `GA_REGISTER_BLOCKED_DOMAINS` | Comma-separated blocked email domains | -- |
| `GA_IMAGE` | Docker image override for compose | `ghcr.io/aymankastali/go_auth:latest` |

## Versioning

Images are tagged using semantic versioning. Available tags:

| Tag | Example | Description |
|-----|---------|-------------|
| `X.Y.Z` | `1.0.0` | Exact release |
| `X.Y` | `1.0` | Latest patch for that minor |
| `X` | `1` | Latest minor/patch for that major |
| `main` | `main` | Latest build from main branch |
| `sha-*` | `sha-abc1234` | Specific commit |

For production, pin to an exact version (`1.0.0`). For staging, `main` or a minor tag (`1.0`) works well.

## License

See [LICENSE](LICENSE) for details.
