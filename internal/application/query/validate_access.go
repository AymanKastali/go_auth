package query

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IValidateAccessHandler interface {
	Handle(ctx context.Context, query ValidateAccessQuery) (ValidateAccessResponse, error)
}

type validateAccessHandler struct {
	accessSvc    domain.IAccessService
	userRepo     domain.IUserRepository
	sessionRepo  domain.ISessionRepository
	roleRepo     domain.IRoleRepository
	permResolver domain.IResolvePermissions
	clock        domain.IClock
}

func NewValidateAccessHandler(
	accessSvc domain.IAccessService,
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	roleRepo domain.IRoleRepository,
	permResolver domain.IResolvePermissions,
	clock domain.IClock,
) IValidateAccessHandler {
	return &validateAccessHandler{
		accessSvc:    accessSvc,
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		roleRepo:     roleRepo,
		permResolver: permResolver,
		clock:        clock,
	}
}

func (h *validateAccessHandler) Handle(ctx context.Context, query ValidateAccessQuery) (ValidateAccessResponse, error) {
	logger := application.GetLogger(ctx).With(slog.String("handler", "ValidateAccess"))

	token, err := domain.NewAccessToken(query.AccessToken)
	if err != nil {
		return ZeroValidateAccessResponse, err
	}

	now := h.clock.Now()

	identity, err := h.accessSvc.Validate(token)
	if err != nil {
		logger.Warn("token_validation_failed", slog.Any("error", err))
		return ZeroValidateAccessResponse, err
	}

	user, err := h.userRepo.FindByID(ctx, identity.UserID())
	if err != nil || user == nil {
		logger.Warn("user_not_found", slog.Any("error", err))
		return ZeroValidateAccessResponse, domain.ErrUserNotFound
	}

	if user.IsDeleted() || !user.IsActive() {
		return ZeroValidateAccessResponse, domain.ErrUserInactive
	}

	session, err := h.sessionRepo.FindByID(ctx, identity.SessionID())
	if err != nil || session == nil {
		logger.Warn("session_not_found", slog.Any("error", err))
		return ZeroValidateAccessResponse, domain.ErrSessionNotFound
	}

	if !session.IsValid(now) {
		return ZeroValidateAccessResponse, domain.ErrSessionExpired
	}

	resp := ValidateAccessResponse{
		UserID:    user.ID().String(),
		SessionID: session.ID().String(),
		Roles:     user.RoleNames(),
	}

	if query.IncludePermissions {
		roles, err := application.LoadRoles(ctx, h.roleRepo, user.Roles())
		if err != nil {
			logger.Warn("role_loading_failed", slog.Any("error", err))
			return ZeroValidateAccessResponse, err
		}
		permissions := h.permResolver.Resolve(roles)
		permStrings := make([]string, len(permissions))
		for i, p := range permissions {
			permStrings[i] = p.String()
		}
		resp.Permissions = permStrings
	}

	return resp, nil
}
