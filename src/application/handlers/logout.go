package handlers

import (
	"time"

	"go_auth/src/application/ports/repositories"
	"go_auth/src/application/ports/security"
)

type LogoutHandler struct {
	refreshRepo  repositories.RefreshTokenRepositoryPort
	tokenService security.TokenServicePort
}

func NewLogoutHandler(
	refreshRepo repositories.RefreshTokenRepositoryPort,
	tokenService security.TokenServicePort,
) *LogoutHandler {
	return &LogoutHandler{
		refreshRepo:  refreshRepo,
		tokenService: tokenService,
	}
}

func (h *LogoutHandler) Execute(refreshToken string) error {
	claims, err := h.tokenService.ValidateRefreshToken(refreshToken)
	if err != nil {
		return err
	}

	ttl := time.Until(claims.ExpiresAt)
	if ttl <= 0 {
		return nil // token already expired, nothing to blacklist
	}

	return h.refreshRepo.Revoke(claims.JTI)
}
