package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type LogoutUseCase struct {
	sessionRenewalRepo ports.ISessionRenewalTokenRepository
	clockSvc           ports.IClockService
	tokenHasher        ports.ITokenHasherService
}

func NewLogoutUseCase(
	repo ports.ISessionRenewalTokenRepository,
	clockSvc ports.IClockService,
	tokenHasher ports.ITokenHasherService,
) *LogoutUseCase {
	return &LogoutUseCase{
		sessionRenewalRepo: repo,
		clockSvc:           clockSvc,
		tokenHasher:        tokenHasher,
	}
}

// Execute performs the logout logic by revoking the session renewal token.
func (uc *LogoutUseCase) Execute(l *slog.Logger, rawToken string) error {
	l.Info("Executing user logout")

	now, err := uc.clockSvc.Now()
	if err != nil {
		return apperr.Map(err)
	}

	tokenVO, err := valueobjects.ParseSessionRenewalRawToken(rawToken)
	if err != nil {
		l.Warn("Logout failed: invalid token format")
		return apperr.Validation("Invalid session renewal token", nil)
	}

	tokenEntity, err := uc.sessionRenewalRepo.FindByID(tokenVO.ID())
	if err != nil {
		l.Error("Database error during token lookup", slog.Any("error", err))
		return apperr.Map(err)
	}

	// If the token doesn't exist, we consider it "logged out" (idempotency)
	if tokenEntity == nil {
		l.Debug("Logout idempotency: token not found in repository")
		return nil
	}

	// Verify token integrity
	valid, err := uc.tokenHasher.Compare(tokenVO.Secret(), tokenEntity.SessionRenewalHashedToken())
	if err != nil {
		return apperr.Map(err)
	}
	if !valid {
		l.Warn("Logout failed: token secret mismatch")
		return apperr.Unauthorized("Invalid session renewal token", nil)
	}

	// Revoke the token
	if err := tokenEntity.Revoke(now); err != nil {
		l.Warn("Logout failed: token already revoked or expired", slog.Any("error", err))
		return apperr.Map(err)
	}

	if err := uc.sessionRenewalRepo.Save(tokenEntity); err != nil {
		l.Error("Failed to save revoked token status", slog.Any("error", err))
		return apperr.Map(err)
	}

	l.Info("User logged out successfully")
	return nil
}
