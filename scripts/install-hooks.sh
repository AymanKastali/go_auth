#!/usr/bin/env bash
set -e

HOOK_FILE=".git/hooks/pre-push"

cat > "$HOOK_FILE" << 'EOF'
#!/usr/bin/env bash
set -e

echo ">> golangci-lint run"
golangci-lint run

echo ">> go test -count=1 -race ./..."
go test -count=1 -race ./...

echo "All checks passed."
EOF

chmod +x "$HOOK_FILE"
echo "pre-push hook installed."
