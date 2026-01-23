package utils

import (
	"context"
	"log/slog"
)

type ctxKey int

const (
	requestKey ctxKey = iota
	authKey
)

type RequestContext struct {
	RequestID         string
	DeviceFingerprint string
	DeviceName        string
	UserAgent         string
	IPAddress         string
	Logger            *slog.Logger
}

type AuthContext struct {
	RequestContext
	UserID                   string
	Roles                    []string
	SessionRenewalRawTokenID string
}

// FromContext handles the "No Redundancy" logic.
// It tries to find AuthContext first, then RequestContext, then returns a default.
func FromContext(ctx context.Context) *RequestContext {
	if ac, ok := ctx.Value(authKey).(*AuthContext); ok {
		return &ac.RequestContext
	}
	if rc, ok := ctx.Value(requestKey).(*RequestContext); ok {
		return rc
	}
	return &RequestContext{RequestID: "system", Logger: slog.Default()}
}

func AuthFromContext(ctx context.Context) (*AuthContext, bool) {
	ac, ok := ctx.Value(authKey).(*AuthContext)
	return ac, ok
}

// Injections
func WithRequest(ctx context.Context, rc *RequestContext) context.Context {
	return context.WithValue(ctx, requestKey, rc)
}

func WithAuth(ctx context.Context, ac *AuthContext) context.Context {
	return context.WithValue(ctx, authKey, ac)
}
