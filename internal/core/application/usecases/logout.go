package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type LogoutUseCase struct {
	repo             ports.ISessionRenewalTokenRepository
	sessionDomainSvc ports.ISessionDomainService
	clockSvc         ports.IClockService
}

func NewLogoutUseCase(
	repo ports.ISessionRenewalTokenRepository,
	sessionDomainSvc ports.ISessionDomainService,
	clockSvc ports.IClockService,
) *LogoutUseCase {
	return &LogoutUseCase{
		repo:             repo,
		sessionDomainSvc: sessionDomainSvc,
		clockSvc:         clockSvc,
	}
}

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

	renewalTokenID := tokenVO.ID()
	tokenEntity, err := uc.repo.FindByID(renewalTokenID)
	if err != nil {
		l.Error("Database error during token lookup", slog.Any("error", err))
		return apperr.Map(err)
	}

	// If the token doesn't exist, we consider it "logged out" (idempotency)
	if tokenEntity == nil {
		l.Debug("token not found in repository")
		return apperr.NotFound("RenewalToken", renewalTokenID.String())
	}

	if err := uc.sessionDomainSvc.RevokeSession(tokenEntity, tokenVO.Secret(), now); err != nil {
		l.Warn("Logout business rule violation", slog.Any("error", err))
		return apperr.Map(err)
	}

	if err := uc.repo.Save(tokenEntity); err != nil {
		l.Error("Failed to save revoked token status", slog.Any("error", err))
		return apperr.Map(err)
	}

	l.Info("User logged out successfully")
	return nil
}
