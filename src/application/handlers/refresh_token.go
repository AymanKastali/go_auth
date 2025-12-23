package handlers

import (
	"fmt"
	"go_auth/src/application/dto"
	appRepo "go_auth/src/application/ports/repositories"
	"go_auth/src/application/ports/security"
	"go_auth/src/domain/errors"
	domainRepo "go_auth/src/domain/ports/repositories"
	"go_auth/src/infra/mappers"
)

type RefreshTokenHandler struct {
	userRepository domainRepo.UserRepositoryPort
	refreshRepo    appRepo.RefreshTokenRepositoryPort
	tokenService   security.TokenServicePort
	uuidMapper     mappers.UUIDMapper
}

func NewRefreshTokenHandler(
	userRepository domainRepo.UserRepositoryPort,
	refreshRepo appRepo.RefreshTokenRepositoryPort,
	tokenService security.TokenServicePort,
	uuidMapper mappers.UUIDMapper,
) *RefreshTokenHandler {
	return &RefreshTokenHandler{
		userRepository: userRepository,
		refreshRepo:    refreshRepo,
		tokenService:   tokenService,
		uuidMapper:     uuidMapper,
	}
}

func (h *RefreshTokenHandler) Execute(oldRefreshToken string) (*dto.AuthResponse, error) {
	// 1. Cryptographic check (Signature, Expiry, Type)
	claims, err := h.tokenService.ValidateRefreshToken(oldRefreshToken)
	if err != nil {
		return nil, err
	}

	// 2. Database check (Revocation status)
	// This checks if the JTI exists AND if 'revoked_at' is null
	isRevoked, err := h.refreshRepo.IsRevoked(claims.JTI)
	if err != nil {
		return nil, err
	}
	if isRevoked {
		// SECURITY: If the token is cryptographically valid but revoked in DB,
		// it might be a reuse/replay attack.
		return nil, errors.ErrInvalidToken
	}

	userIDVO, err := h.uuidMapper.FromString(claims.Subject)
	if err != nil {
		return nil, err
	}

	// 3. Get fresh user data (to ensure roles/permissions are current)
	user, err := h.userRepository.GetByID(userIDVO)
	if err != nil || user == nil {
		return nil, errors.ErrUserNotFound
	}

	// 4. Issue NEW tokens (Rotation)
	userIDStr := user.ID.Value.String()

	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = string(r)
	}

	newAccessToken, err := h.tokenService.IssueAccessToken(userIDStr, roles)
	if err != nil {
		return nil, err
	}

	// Note: IssueRefreshToken should return a struct with JTI and ExpiresAt
	newRefreshToken, err := h.tokenService.IssueRefreshToken(userIDStr)
	if err != nil {
		return nil, err
	}

	newClaims, _ := h.tokenService.ValidateRefreshToken(newRefreshToken.Value)

	// 5. Atomic Rotation: Revoke old and Save new
	// In a production app, you'd ideally wrap these two in a DB transaction
	err = h.refreshRepo.Revoke(claims.JTI)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	err = h.refreshRepo.Save(
		newClaims.JTI,
		userIDStr,
		newRefreshToken.Value,
		newClaims.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save new token: %w", err)
	}

	return &dto.AuthResponse{
		AccessToken:  newAccessToken.Value,
		RefreshToken: newRefreshToken.Value,
	}, nil
}
