package dto

import (
	"context"
	"log/slog"
)

type ctxKey struct{}

type RequestContext struct {
	RequestID  string
	DeviceID   string
	DeviceName string
	UserAgent  string
	IPAddress  string
	Logger     *slog.Logger
}

type AuthContext struct {
	*RequestContext
	UserID  string
	Roles   []string
	TokenID string
}

func Inject(ctx context.Context, val any) context.Context {
	return context.WithValue(ctx, ctxKey{}, val)
}

func Extract(ctx context.Context) any {
	return ctx.Value(ctxKey{})
}

func GetRequestContext(ctx context.Context) *RequestContext {
	val := Extract(ctx)
	switch t := val.(type) {
	case *AuthContext:
		return t.RequestContext
	case *RequestContext:
		return t
	default:
		return &RequestContext{RequestID: "system", Logger: slog.Default()}
	}
}
