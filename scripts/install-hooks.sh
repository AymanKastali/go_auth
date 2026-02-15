#!/usr/bin/env bash
set -e

HOOKS_DIR=".git/hooks"

# --- pre-commit: fast checks (build + vet + lint) ---
cat > "$HOOKS_DIR/pre-commit" << 'EOF'
#!/usr/bin/env bash
set -e

echo ">> go build ./..."
go build ./...

echo ">> go vet ./..."
go vet ./...

if command -v golangci-lint &> /dev/null; then
  echo ">> golangci-lint run"
  golangci-lint run
else
  echo ">> golangci-lint not found, skipping (install: https://golangci-lint.run/usage/install/)"
fi

echo "Pre-commit checks passed."
EOF
chmod +x "$HOOKS_DIR/pre-commit"
echo "pre-commit hook installed."

# --- pre-push: full checks (lint + tests with race detector) ---
cat > "$HOOKS_DIR/pre-push" << 'EOF'
#!/usr/bin/env bash
set -e

echo ">> golangci-lint run"
golangci-lint run

echo ">> go test -count=1 -race ./..."
go test -count=1 -race ./...

echo "All pre-push checks passed."
EOF
chmod +x "$HOOKS_DIR/pre-push"
echo "pre-push hook installed."
