# Deployment Guide

## Pulling from GHCR

Images are published to GitHub Container Registry on every push to `main` and on version tags.

```bash
# Latest from main
docker pull ghcr.io/aymankastali/go_auth:main

# Specific version
docker pull ghcr.io/aymankastali/go_auth:1.0.0

# Specific commit
docker pull ghcr.io/aymankastali/go_auth:sha-abc1234
```

## Running with Docker Compose

```bash
docker compose -f docker-compose.prod.yml up -d
```

Override the image reference with `GA_IMAGE`:

```bash
GA_IMAGE=ghcr.io/aymankastali/go_auth:1.2.3 docker compose -f docker-compose.prod.yml up -d
```

## Versioning Strategy

The CI pipeline generates Docker tags automatically based on git refs:

| Git ref | Docker tags |
|---------|-------------|
| `v1.2.3` tag | `1.2.3`, `1.2`, `1`, `sha-<hash>` |
| `main` branch push | `main`, `sha-<hash>` |

To release a new version:

```bash
git tag v1.0.0
git push origin v1.0.0
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

## Docker Hub (Optional)

To also push images to Docker Hub, add a second login step to the CI workflow:

```yaml
- name: Login to Docker Hub
  uses: docker/login-action@v3
  with:
    username: ${{ secrets.DOCKERHUB_USERNAME }}
    password: ${{ secrets.DOCKERHUB_TOKEN }}
```

Then add the Docker Hub image to the `metadata-action` images list:

```yaml
images: |
  ghcr.io/${{ github.repository }}
  docker.io/<your-dockerhub-username>/go_auth
```
