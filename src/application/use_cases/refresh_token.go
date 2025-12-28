package use_cases

import (
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/security"
	"go_auth/src/application/ports/use_cases"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	"log/slog"
	"time"
)

type refreshTokenUseCase struct {
	userRepository repositories.UserRepositoryPort
	refreshRepo    repositories.RefreshTokenRepositoryPort
	deviceRepo     repositories.DeviceRepositoryPort
	tokenService   security.TokenServicePort
	idFactory      factories.IDFactory
	logger         *slog.Logger
}

var _ use_cases.RefreshTokenUseCasePort = (*refreshTokenUseCase)(nil)

func NewRefreshTokenUseCase(
	userRepository repositories.UserRepositoryPort,
	refreshRepo repositories.RefreshTokenRepositoryPort,
	deviceRepo repositories.DeviceRepositoryPort,
	tokenService security.TokenServicePort,
	idFactory factories.IDFactory,
	logger *slog.Logger,
) *refreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepository: userRepository,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		tokenService:   tokenService,
		idFactory:      idFactory,
		logger:         logger,
	}
}

func (h *refreshTokenUseCase) RefreshToken(
	oldRefreshToken, deviceIdStr string,
) (*dto.AuthResponse, error) {

	h.logger.Info("Starting refresh token process", "deviceID", deviceIdStr)

	// --- Validate old refresh token ---
	claims, err := h.tokenService.ValidateRefreshToken(oldRefreshToken)
	if err != nil {
		h.logger.Warn("Old refresh token expired or invalid", "error", err)
		return nil, errors.ErrRefreshTokenExpired
	}
	h.logger.Info("Old refresh token validated", "tokenID", claims.JTI, "userID", claims.Subject)

	// --- Parse token IDs ---
	oldTokenID, err := h.idFactory.TokenIDFromString(claims.JTI)
	if err != nil {
		h.logger.Error("Failed to parse old token ID", "jti", claims.JTI, "error", err)
		return nil, errors.ErrInvalidToken
	}

	// --- Check if token is revoked ---
	isRevoked, err := h.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		h.logger.Error("Failed to check token revocation", "tokenID", oldTokenID, "error", err)
		return nil, errors.ErrInvalidToken
	}
	if isRevoked {
		h.logger.Warn("Old refresh token is revoked", "tokenID", oldTokenID)
		return nil, errors.ErrRefreshTokenRevoked
	}

	// --- Fetch user ---
	userIDVO, err := h.idFactory.UserIDFromString(claims.Subject)
	if err != nil {
		h.logger.Error("Invalid user ID in refresh token", "userID", claims.Subject, "error", err)
		return nil, errors.ErrInvalidTokenUser
	}

	user, err := h.userRepository.GetByID(userIDVO)
	if err != nil || user == nil {
		h.logger.Warn("User not found for refresh token", "userID", userIDVO)
		return nil, errors.ErrUserNotFound
	}
	h.logger.Info("User retrieved for refresh token", "userID", user.ID)

	// --- Fetch device ---
	deviceID, err := h.idFactory.DeviceIDFromString(deviceIdStr)
	if err != nil {
		h.logger.Error("Invalid device ID", "deviceID", deviceIdStr, "error", err)
		return nil, errors.ErrInvalidDeviceID
	}

	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		h.logger.Error("Failed to fetch device", "deviceID", deviceID, "error", err)
		return nil, err
	}
	if device == nil {
		h.logger.Warn("Device not found", "deviceID", deviceID)
		return nil, errors.ErrInvalidDeviceID
	}

	// --- Issue new tokens ---
	userIDStr := user.ID.Value.String()
	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = string(r)
	}

	newAccessToken, err := h.tokenService.IssueAccessToken(userIDStr, deviceIdStr, roles)
	if err != nil {
		h.logger.Error("Failed to issue new access token", "userID", user.ID, "error", err)
		return nil, errors.ErrInvalidToken
	}

	newRefreshToken, err := h.tokenService.IssueRefreshToken(userIDStr, deviceIdStr)
	if err != nil {
		h.logger.Error("Failed to issue new refresh token", "userID", user.ID, "error", err)
		return nil, errors.ErrInvalidToken
	}

	newClaims, err := h.tokenService.ValidateRefreshToken(newRefreshToken.Value)
	if err != nil {
		h.logger.Error("Failed to validate new refresh token", "userID", user.ID, "error", err)
		return nil, errors.ErrInvalidToken
	}

	newTokenID, err := h.idFactory.TokenIDFromString(newClaims.JTI)
	if err != nil {
		h.logger.Error("Failed to parse new token ID", "jti", newClaims.JTI, "error", err)
		return nil, errors.ErrInvalidToken
	}

	// --- Revoke old token ---
	now := time.Now()
	if err := h.refreshRepo.Revoke(oldTokenID, now); err != nil {
		h.logger.Error("Failed to revoke old refresh token", "tokenID", oldTokenID, "error", err)
		return nil, errors.ErrRefreshTokenRevoked
	}

	// --- Save new refresh token ---
	rtEntity := &entities.RefreshToken{
		ID:        newTokenID,
		UserID:    user.ID,
		DeviceID:  deviceID,
		Token:     newRefreshToken.Value,
		ExpiresAt: newClaims.ExpiresAt,
		RevokedAt: nil,
	}

	if err := h.refreshRepo.Save(rtEntity); err != nil {
		h.logger.Error("Failed to save new refresh token", "tokenID", newTokenID, "error", err)
		return nil, errors.ErrInvalidToken
	}

	h.logger.Info("Refresh token rotated successfully", "userID", user.ID, "deviceID", deviceID)

	// --- Return new tokens ---
	return &dto.AuthResponse{
		AccessToken:  newAccessToken.Value,
		RefreshToken: newRefreshToken.Value,
	}, nil
}
