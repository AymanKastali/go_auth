package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

// Context Utils
type ctxKey struct{}

var appCtxKey = ctxKey{}

type UserContext struct {
	UserID    domain.UserID
	SessionID domain.SessionID
	Roles     []string
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
	roles []string,
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
			Roles:     roles,
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
	if ctx == nil {
		return domain.ZeroUserID
	}
	if appCtx, ok := FromContext(ctx); ok && appCtx != nil && appCtx.User != nil {
		return appCtx.User.UserID
	}
	return domain.ZeroUserID
}

// GetSessionID returns the SessionID if authenticated, otherwise ZeroSessionID.
func GetSessionID(ctx context.Context) domain.SessionID {
	if ctx == nil {
		return domain.ZeroSessionID
	}
	if appCtx, ok := FromContext(ctx); ok && appCtx != nil && appCtx.User != nil {
		return appCtx.User.SessionID
	}
	return domain.ZeroSessionID
}

// GetIdentity returns the DeviceIdentity or ZeroDeviceIdentity if missing.
func GetIdentity(ctx context.Context) domain.DeviceIdentity {
	if ctx == nil {
		return domain.ZeroDeviceIdentity
	}
	if appCtx, ok := FromContext(ctx); ok && appCtx != nil {
		return appCtx.Client.Identity
	}
	return domain.ZeroDeviceIdentity
}

// GetLogger returns the contextual logger or a default one if missing.
func GetLogger(ctx context.Context) *slog.Logger {
	if appCtx, ok := FromContext(ctx); ok && appCtx.Logger != nil {
		return appCtx.Logger
	}
	return slog.Default()
}

// GetRoles returns the user's roles from the context or an empty slice.
func GetRoles(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	if appCtx, ok := FromContext(ctx); ok && appCtx != nil && appCtx.User != nil {
		return appCtx.User.Roles
	}
	return nil
}

// IsAuthenticated is a quick helper to check if a user is present.
func IsAuthenticated(ctx context.Context) bool {
	appCtx, ok := FromContext(ctx)
	return ok && appCtx.User != nil
}

// LoadRoles resolves role names to full Role aggregates via the repository.
func LoadRoles(ctx context.Context, roleRepo domain.IRoleRepository, roleNames []domain.RoleName) ([]*domain.Role, error) {
	var roles []*domain.Role
	for _, rn := range roleNames {
		role, err := roleRepo.FindByName(ctx, rn)
		if err != nil {
			return nil, err
		}
		if role != nil {
			roles = append(roles, role)
		}
	}
	return roles, nil
}
