package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// --- Validate Access Use Case ---
type validateAccessUseCase struct {
	accessManager domain.IAccessManager
	clock         domain.IClock
}

func NewValidateAccessUseCase(
	accessManager domain.IAccessManager,
	clock domain.IClock,
) IValidateAccessUseCase {
	return &validateAccessUseCase{
		accessManager: accessManager,
		clock:         clock,
	}
}

func (uc *validateAccessUseCase) Execute(ctx context.Context, query ValidateAccessQuery) (ValidateAccessResponse, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "ValidateAccess"))

	// 1. VO Conversion
	token, err := domain.NewAccessToken(query.AccessToken)
	if err != nil {
		logger.Warn("invalid_access_token", slog.Any("error", err))
		return ZeroValidateAccessResponse, err
	}

	// 2. Delegate to Domain Service
	// This encapsulates: Crypto check -> User Fetch -> Session Integrity
	now := uc.clock.Now()
	user, sid, err := uc.accessManager.VerifyAccess(ctx, token, now)
	if err != nil {
		logger.Warn("access_verification_failed", slog.Any("error", err))
		return ZeroValidateAccessResponse, err
	}

	// 3. Response Formatting
	return ValidateAccessResponse{
		UserID:    user.ID().String(),
		SessionID: sid.String(),
		Roles:     user.RoleNames(),
	}, nil
}
