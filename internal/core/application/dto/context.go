package dto

import (
	"context"
	"log/slog"
)

type ctxKey struct{}

type RequestContext struct {
	RequestID         string
	DeviceFingerprint string
	DeviceName        string
	UserAgent         string
	IPAddress         string
	Logger            *slog.Logger
}

type AuthContext struct {
	*RequestContext
	UserID                string
	Roles                 []string
	SessionRenewalTokenID string
}

func Inject(ctx context.Context, val any) context.Context {
	return context.WithValue(ctx, ctxKey{}, val)
}

func Extract(ctx context.Context) any {
	return ctx.Value(ctxKey{})
}

func FromContext(ctx context.Context) *RequestContext {
	val := ctx.Value(ctxKey{})
	switch t := val.(type) {
	case *AuthContext:
		return t.RequestContext
	case *RequestContext:
		return t
	default:
		// Use a "System" context instead of a default to make debugging easier
		return &RequestContext{RequestID: "sys_gen", Logger: slog.Default()}
	}
}

func AuthFromContext(ctx context.Context) (*AuthContext, bool) {
	auth, ok := ctx.Value(ctxKey{}).(*AuthContext)
	return auth, ok
}

// MustAuthFromContext is a helper for use cases that require authentication.
func MustAuthFromContext(ctx context.Context) *AuthContext {
	auth, ok := AuthFromContext(ctx)
	if !ok {
		panic("auth context missing in a protected route")
	}
	return auth
}
