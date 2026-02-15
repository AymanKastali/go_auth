# GoAuth

JWT Authentication microservice for managing users, sessions, roles, permissions, and access control.

## Features

- User registration with configurable policies (public/private, blocked domains)
- Email activation (optional, configurable)
- JWT-based access tokens with role & permission claims
- Session management with device fingerprinting and hijack detection
- Password recovery via email with time-limited tokens
- Account lockout after configurable failed login attempts (brute-force protection)
- Role-based access control (RBAC) with fine-grained permissions
- Dynamic roles & permissions seeded from YAML configuration
- Rate limiting on authentication endpoints
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- CORS middleware with configurable allowed origins
- Swagger/OpenAPI documentation

## Quick Start

### Pull the image

```bash
docker pull ghcr.io/aymankastali/go_auth:latest
```

Or a specific version:

```bash
docker pull ghcr.io/aymankastali/go_auth:0.1.0
```

### Run with Docker Compose

1. Create a `.env` file with your configuration (see [Environment Variables](#environment-variables) below).

2. Start the service:

```bash
docker compose -f docker-compose.prod.yml up -d
```

3. The API is available at `http://localhost:8080` (or the port you configured with `GA_HTTP_PORT`).

4. Swagger docs are available at `http://localhost:8080/swagger/index.html`.

### Override the image version

```bash
GA_IMAGE=ghcr.io/aymankastali/go_auth:0.1.0 docker compose -f docker-compose.prod.yml up -d
```

## Environment Variables

### Application

| Variable | Description | Default |
|----------|-------------|---------|
| `GA_APP_NAME` | Application name | `GoAuthService` |
| `GA_APP_ENV` | Environment (`development` / `production`) | `development` |
| `GA_DEBUG` | Enable debug mode | `false` |
| `GA_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) | `info` |
| `GA_HTTP_PORT` | HTTP server port | `8080` |
| `GA_CORS_ORIGINS` | Allowed CORS origins (comma-separated) | `*` |

### Database & JWT

| Variable | Description | Default |
|----------|-------------|---------|
| `GA_DATABASE_URL` | PostgreSQL connection string | **required** |
| `GA_JWT_SECRET` | JWT signing secret (base64-encoded, must decode to >= 32 bytes) | **required** |
| `GA_JWT_ISSUER` | JWT issuer claim | `go-auth-service` |
| `GA_JWT_AUDIENCE` | JWT audience claim | `go-auth-client` |
| `GA_JWT_ACCESS_TTL` | Access token TTL | `15m` |

### Password Policy

| Variable | Description | Default |
|----------|-------------|---------|
| `GA_PASSWORD_BCRYPT_COST` | Bcrypt cost factor | `12` |
| `GA_PASS_MIN_LEN` | Minimum password length | `8` |
| `GA_PASS_MAX_LEN` | Maximum password length | `64` |
| `GA_PASS_REQ_UPPER` | Require uppercase letter | `true` |
| `GA_PASS_REQ_NUM` | Require number | `true` |
| `GA_PASS_REQ_SPECIAL` | Require special character | `true` |

### Session & Recovery

| Variable | Description | Default |
|----------|-------------|---------|
| `GA_SESSION_LIFETIME` | Session TTL | `24h` |
| `GA_SESSION_MAX_ACTIVE` | Max concurrent sessions per user | `5` |
| `GA_RECOVERY_TOKEN_LIFETIME` | Recovery token TTL | `15m` |

### Login Policy (Account Lockout)

| Variable | Description | Default |
|----------|-------------|---------|
| `GA_LOGIN_MAX_ATTEMPTS` | Failed login attempts before account lockout | `5` |
| `GA_LOGIN_LOCKOUT_DURATION` | Duration of account lockout after max attempts | `15m` |

### Registration & Activation

| Variable | Description | Default |
|----------|-------------|---------|
| `GA_REGISTER_ALLOW_PUBLIC` | Allow public registration | `true` |
| `GA_REGISTER_BLOCKED_DOMAINS` | Comma-separated blocked email domains | -- |
| `GA_ACTIVATION_REQUIRE_EMAIL` | Require email verification before account is active | `false` |
| `GA_ACTIVATION_TOKEN_LIFETIME` | Activation token TTL | `24h` |
| `GA_EMAIL_ACTIVATION_BASE_URL` | Base URL for the activation link sent to users | **required** when activation is enabled |

### Email (SMTP)

| Variable | Description | Default |
|----------|-------------|---------|
| `GA_EMAIL_HOST` | SMTP host | `localhost` |
| `GA_EMAIL_PORT` | SMTP port | `587` |
| `GA_EMAIL_USERNAME` | SMTP username | -- |
| `GA_EMAIL_PASSWORD` | SMTP password | -- |
| `GA_EMAIL_FROM` | Sender address | **required** |
| `GA_EMAIL_RESET_BASE_URL` | Password reset link base URL | **required** |

### System Seeding

| Variable | Description | Default |
|----------|-------------|---------|
| `GA_ADMIN_EMAIL` | Seed admin email (created on first startup) | **required** |
| `GA_ADMIN_PASSWORD` | Seed admin password | **required** |
| `GA_SEED_ROLES_PATH` | Path to roles & permissions YAML seed file | `/config/seed_roles.yml` |
| `GA_IMAGE` | Docker image override for compose | `ghcr.io/aymankastali/go_auth:latest` |

## Custom Roles & Permissions

The image ships with a default `seed_roles.yml` that defines 8 roles (`super_admin`, `admin`, `editor`, `moderator`, `member`, `premium`, `guest`, `partner`) and their permissions. Roles are seeded on first startup and skipped if they already exist.

To customize, create your own YAML file following the same format:

```yaml
roles:
  - name: admin
    description: Administrative access
    permissions:
      - "users:read"
      - "users:write"
      - "roles:read"
```

Then mount it into the container:

```yaml
# docker-compose.yml
services:
  auth:
    image: ghcr.io/aymankastali/go_auth:latest
    volumes:
      - ./my_roles.yml:/config/seed_roles.yml
```

Or mount to a custom path and set the env var:

```yaml
services:
  auth:
    image: ghcr.io/aymankastali/go_auth:latest
    volumes:
      - ./my_roles.yml:/etc/myapp/roles.yml
    environment:
      - GA_SEED_ROLES_PATH=/etc/myapp/roles.yml
```

## Development

### Prerequisites

- [VS Code](https://code.visualstudio.com/) with the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
- [Docker](https://docs.docker.com/get-docker/)

### Getting started

1. Clone the repository
2. Copy `.env.example` to `.devcontainer/.env` and adjust values
3. Open the project in VS Code
4. When prompted, click **Reopen in Container** (or run `Dev Containers: Reopen in Container` from the command palette)

The devcontainer will:
- Build the Go development image with debugging and linting tools
- Start PostgreSQL and MailHog alongside the app
- Install Go dependencies and generate Swagger docs
- Start the server with hot-reload (`air`) and debugger support (`dlv`)

### Debugging

Press **F5** to attach the debugger to the running server. Breakpoints work immediately — no restart needed.

### Available tools inside the container

| Tool | Purpose |
|------|---------|
| `air` | Hot-reload — rebuilds and restarts on file save |
| `dlv` | Delve debugger (runs automatically via air) |
| `swag` | Swagger doc generation |
| `golangci-lint` | Linter (runs on save in VS Code) |

### MailHog

MailHog captures all outgoing emails (activation, password reset) in development. Open `http://localhost:8025` to view them.

## Versioning

Images are tagged using semantic versioning. Available tags:

| Tag | Example | Description |
|-----|---------|-------------|
| `X.Y.Z` | `0.1.0` | Exact release |
| `X.Y` | `1.0` | Latest patch for that minor |
| `X` | `1` | Latest minor/patch for that major |
| `main` | `main` | Latest build from main branch |
| `sha-*` | `sha-abc1234` | Specific commit |

For production, pin to an exact version (`0.1.0`). For staging, `main` or a minor tag (`0.1`) works well.

## License

See [LICENSE](LICENSE) for details.
