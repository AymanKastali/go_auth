package use_cases

import (
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/application/ports/use_cases"
	"go_auth/internal/core/domain/domainerr"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports/repositories"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type refreshTokenUseCase struct {
	userRepository repositories.UserRepositoryPort
	refreshRepo    repositories.RefreshTokenRepositoryPort
	deviceRepo     repositories.DeviceRepositoryPort
	tokenService   security.TokenServicePort
	logger         *slog.Logger
}

var _ use_cases.RefreshTokenUseCasePort = (*refreshTokenUseCase)(nil)

func NewRefreshTokenUseCase(
	userRepository repositories.UserRepositoryPort,
	refreshRepo repositories.RefreshTokenRepositoryPort,
	deviceRepo repositories.DeviceRepositoryPort,
	tokenService security.TokenServicePort,
	logger *slog.Logger,
) *refreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepository: userRepository,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		tokenService:   tokenService,
		logger:         logger,
	}
}

func (h *refreshTokenUseCase) RefreshToken(
	oldRefreshToken, deviceIDStr string,
) (*dto.AuthResponse, error) {

	h.logger.Info("Starting refresh token process", "deviceID", deviceIDStr)

	// --- Validate old refresh token ---
	claims, err := h.tokenService.ValidateRefreshToken(oldRefreshToken)
	if err != nil {
		h.logger.Warn("Old refresh token expired or invalid", "error", err)
		return nil, domainerr.ErrRefreshTokenExpired
	}
	h.logger.Info("Old refresh token validated", "tokenID", claims.JTI, "userID", claims.Subject)

	// --- Parse token IDs ---
	oldTokenID, err := valueobjects.TokenIDFromString(claims.JTI)
	if err != nil {
		h.logger.Error("Failed to parse old token ID", "jti", claims.JTI, "error", err)
		return nil, domainerr.ErrInvalidToken
	}

	// --- Check if token is revoked ---
	isRevoked, err := h.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		h.logger.Error("Failed to check token revocation", "tokenID", oldTokenID, "error", err)
		return nil, domainerr.ErrInvalidToken
	}
	if isRevoked {
		h.logger.Warn("Old refresh token is revoked", "tokenID", oldTokenID)
		return nil, domainerr.ErrRefreshTokenRevoked
	}

	// --- Fetch user ---
	userIDVO, err := valueobjects.UserIDFromString(claims.Subject)
	if err != nil {
		h.logger.Error("Invalid user ID in refresh token", "userID", claims.Subject, "error", err)
		return nil, domainerr.ErrInvalidTokenUser
	}

	user, err := h.userRepository.GetByID(userIDVO)
	if err != nil || user == nil {
		h.logger.Warn("User not found for refresh token", "userID", userIDVO)
		return nil, domainerr.ErrUserNotFound
	}
	h.logger.Info("User retrieved for refresh token", "userID", user.ID)

	// --- Fetch device ---
	deviceID, err := valueobjects.DeviceIDFromString(deviceIDStr)
	if err != nil {
		h.logger.Error("Invalid device ID", "deviceID", deviceIDStr, "error", err)
		return nil, domainerr.ErrInvalidDeviceID
	}

	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		h.logger.Error("Failed to fetch device", "deviceID", deviceID, "error", err)
		return nil, err
	}
	if device == nil {
		h.logger.Warn("Device not found", "deviceID", deviceID)
		return nil, domainerr.ErrInvalidDeviceID
	}

	userRoles := user.Roles()
	// --- Issue new tokens ---
	userIDStr := user.ID().String()
	roles := make([]string, len(userRoles))
	for i, r := range userRoles {
		roles[i] = string(r)
	}

	newAccessToken, err := h.tokenService.IssueAccessToken(userIDStr, deviceIDStr, roles)
	if err != nil {
		h.logger.Error("Failed to issue new access token", "userID", user.ID, "error", err)
		return nil, domainerr.ErrInvalidToken
	}

	newRefreshToken, err := h.tokenService.IssueRefreshToken(userIDStr, deviceIDStr)
	if err != nil {
		h.logger.Error("Failed to issue new refresh token", "userID", user.ID, "error", err)
		return nil, domainerr.ErrInvalidToken
	}

	newClaims, err := h.tokenService.ValidateRefreshToken(newRefreshToken.Value)
	if err != nil {
		h.logger.Error("Failed to validate new refresh token", "userID", user.ID, "error", err)
		return nil, domainerr.ErrInvalidToken
	}

	newTokenID, err := valueobjects.TokenIDFromString(newClaims.JTI)
	if err != nil {
		h.logger.Error("Failed to parse new token ID", "jti", newClaims.JTI, "error", err)
		return nil, domainerr.ErrInvalidToken
	}

	// --- Revoke old token ---
	now := time.Now()
	if err := h.refreshRepo.Revoke(oldTokenID, now); err != nil {
		h.logger.Error("Failed to revoke old refresh token", "tokenID", oldTokenID, "error", err)
		return nil, domainerr.ErrRefreshTokenRevoked
	}

	// --- Save new refresh token ---
	rtEntity := &entities.RefreshToken{
		ID:        newTokenID,
		UserID:    user.ID(),
		DeviceID:  deviceID,
		Token:     newRefreshToken.Value,
		ExpiresAt: newClaims.ExpiresAt,
		RevokedAt: nil,
	}

	if err := h.refreshRepo.Save(rtEntity); err != nil {
		h.logger.Error("Failed to save new refresh token", "tokenID", newTokenID, "error", err)
		return nil, domainerr.ErrInvalidToken
	}

	h.logger.Info("Refresh token rotated successfully", "userID", user.ID, "deviceID", deviceID)

	// --- Return new tokens ---
	return &dto.AuthResponse{
		AccessToken:  newAccessToken.Value,
		RefreshToken: newRefreshToken.Value,
	}, nil
}
