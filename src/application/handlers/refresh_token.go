package handlers

import (
	"fmt"
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/security"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	"time"
)

type RefreshTokenHandler struct {
	userRepository repositories.UserRepositoryPort
	refreshRepo    repositories.RefreshTokenRepositoryPort
	tokenService   security.TokenServicePort
	idFactory      factories.IDFactory
}

func NewRefreshTokenHandler(
	userRepository repositories.UserRepositoryPort,
	refreshRepo repositories.RefreshTokenRepositoryPort,
	tokenService security.TokenServicePort,
	idFactory factories.IDFactory,
) *RefreshTokenHandler {
	return &RefreshTokenHandler{
		userRepository: userRepository,
		refreshRepo:    refreshRepo,
		tokenService:   tokenService,
		idFactory:      idFactory,
	}
}

func (h *RefreshTokenHandler) Execute(
	oldRefreshToken string,
	deviceIdStr string,
) (*dto.AuthResponse, error) {

	// --- 1. Validate old refresh token (crypto) ---
	claims, err := h.tokenService.ValidateRefreshToken(oldRefreshToken)
	if err != nil {
		return nil, err
	}

	// --- 2. Convert old token JTI to VO ---
	oldTokenID, err := h.idFactory.TokenIDFromString(claims.JTI)
	if err != nil {
		return nil, err
	}

	// --- 3. Check revocation status in DB ---
	isRevoked, err := h.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, err
	}
	if isRevoked {
		return nil, errors.ErrInvalidToken
	}

	// --- 4. Load user ---
	userIDVO, err := h.idFactory.UserIDFromString(claims.Subject)
	if err != nil {
		return nil, err
	}

	user, err := h.userRepository.GetByID(userIDVO)
	if err != nil || user == nil {
		return nil, errors.ErrUserNotFound
	}

	// --- 5. Convert deviceId string to VO ---
	deviceID, err := h.idFactory.DeviceIDFromString(deviceIdStr)
	if err != nil {
		return nil, err
	}

	// --- 6. Issue new tokens ---
	userIDStr := user.ID.Value.String()
	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = string(r)
	}

	newAccessToken, err := h.tokenService.IssueAccessToken(userIDStr, deviceIdStr, roles)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := h.tokenService.IssueRefreshToken(userIDStr, deviceIdStr)
	if err != nil {
		return nil, err
	}

	newClaims, err := h.tokenService.ValidateRefreshToken(newRefreshToken.Value)
	if err != nil {
		return nil, err
	}

	// --- 7. Convert new token JTI to VO ---
	newTokenID, err := h.idFactory.TokenIDFromString(newClaims.JTI)
	if err != nil {
		return nil, err
	}

	// --- 8. Atomic rotation ---
	now := time.Now()

	// Revoke old refresh token
	if err := h.refreshRepo.Revoke(oldTokenID, now); err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	// Save new refresh token
	rtEntity := &entities.RefreshToken{
		ID:        newTokenID,
		UserId:    user.ID,
		DeviceId:  deviceID,
		Token:     newRefreshToken.Value,
		ExpiresAt: newClaims.ExpiresAt,
		RevokedAt: nil,
	}

	if err := h.refreshRepo.Save(rtEntity); err != nil {
		return nil, fmt.Errorf("failed to save new token: %w", err)
	}

	// --- 9. Return new tokens ---
	return &dto.AuthResponse{
		AccessToken:  newAccessToken.Value,
		RefreshToken: newRefreshToken.Value,
	}, nil
}
