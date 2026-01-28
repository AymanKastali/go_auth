package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// Context Utils
type ctxKey struct{}

var appCtxKey = ctxKey{}

type UserContext struct {
	UserID    domain.UserID
	SessionID domain.SessionID
}

type ClientContext struct {
	Identity domain.DeviceIdentity
}

type AppContext struct {
	User   *UserContext
	Client ClientContext
	Logger *slog.Logger
}

func NewAppContext(
	userID, sessionID string,
	ua, ip, os, browser, model, lang string,
	isMobile bool,
	logger *slog.Logger,
) (*AppContext, error) {

	// 1. Build Client Context (Always required)
	identity, err := domain.NewDeviceIdentity(ip, os, browser, model, lang, ua, isMobile)
	if err != nil {
		return nil, err
	}

	appCtx := &AppContext{
		Client: ClientContext{
			Identity: identity,
		},
		Logger: logger,
	}

	// 2. Build User Context (Only if IDs are provided)
	if userID != "" && sessionID != "" {
		uid, err := domain.NewUserID(userID)
		if err != nil {
			return nil, err
		}
		sid, err := domain.NewSessionID(sessionID)
		if err != nil {
			return nil, err
		}
		appCtx.User = &UserContext{
			UserID:    uid,
			SessionID: sid,
		}

		// Enrich logger with user details
		appCtx.Logger = logger.With(
			slog.String("user_id", userID),
			slog.String("session_id", sessionID),
		)
	}

	return appCtx, nil
}

// --- Standard Context Helpers ---

func WithAppContext(ctx context.Context, appCtx *AppContext) context.Context {
	return context.WithValue(ctx, appCtxKey, appCtx)
}

func FromContext(ctx context.Context) (*AppContext, bool) {
	val, ok := ctx.Value(appCtxKey).(*AppContext)
	return val, ok
}

// Getters
func GetUserID(ctx context.Context) domain.UserID {
	if appCtx, ok := FromContext(ctx); ok && appCtx.User != nil {
		return appCtx.User.UserID
	}
	return domain.UserID{} // Or a predefined "Null" UserID
}

// GetSessionID returns the SessionID if authenticated.
func GetSessionID(ctx context.Context) domain.SessionID {
	if appCtx, ok := FromContext(ctx); ok && appCtx.User != nil {
		return appCtx.User.SessionID
	}
	return domain.SessionID{}
}

// GetIdentity returns the DeviceIdentity.
func GetIdentity(ctx context.Context) domain.DeviceIdentity {
	if appCtx, ok := FromContext(ctx); ok {
		return appCtx.Client.Identity
	}
	return domain.DeviceIdentity{}
}

// GetLogger returns the contextual logger or a default one if missing.
func GetLogger(ctx context.Context) *slog.Logger {
	if appCtx, ok := FromContext(ctx); ok && appCtx.Logger != nil {
		return appCtx.Logger
	}
	return slog.Default()
}

// IsAuthenticated is a quick helper to check if a user is present.
func IsAuthenticated(ctx context.Context) bool {
	appCtx, ok := FromContext(ctx)
	return ok && appCtx.User != nil
}
