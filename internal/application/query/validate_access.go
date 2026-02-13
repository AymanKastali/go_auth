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
	verifier     domain.IVerifyAccess
	permResolver domain.IResolvePermissions
	clock        domain.IClock
}

func NewValidateAccessHandler(
	verifier domain.IVerifyAccess,
	permResolver domain.IResolvePermissions,
	clock domain.IClock,
) IValidateAccessHandler {
	return &validateAccessHandler{
		verifier:     verifier,
		permResolver: permResolver,
		clock:        clock,
	}
}

func (h *validateAccessHandler) Handle(ctx context.Context, query ValidateAccessQuery) (ValidateAccessResponse, error) {
	logger := application.GetLogger(ctx).With(slog.String("handler", "ValidateAccess"))

	token, err := domain.NewAccessToken(query.AccessToken)
	if err != nil {
		logger.Warn("invalid_access_token", slog.Any("error", err))
		return ZeroValidateAccessResponse, err
	}

	now := h.clock.Now()
	user, session, err := h.verifier.Verify(ctx, token, now)
	if err != nil {
		logger.Warn("access_verification_failed", slog.Any("error", err))
		return ZeroValidateAccessResponse, err
	}

	resp := ValidateAccessResponse{
		UserID:    user.ID().String(),
		SessionID: session.ID().String(),
		Roles:     user.RoleNames(),
	}

	if query.IncludePermissions {
		permissions, err := h.permResolver.Resolve(ctx, user.Roles())
		if err != nil {
			logger.Warn("permission_resolution_failed", slog.Any("error", err))
			return ZeroValidateAccessResponse, err
		}
		permStrings := make([]string, len(permissions))
		for i, p := range permissions {
			permStrings[i] = p.String()
		}
		resp.Permissions = permStrings
	}

	return resp, nil
}
