package use_cases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/application/ports/use_cases"
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

	// 1. INFRASTRUCTURE: External Token Service failure
	claims, err := h.tokenService.ValidateRefreshToken(oldRefreshToken)
	if err != nil {
		h.logger.Warn("Token validation failed", "error", err)
		// Logic: If the token is cryptographically invalid, it's an Application Unauthorized error
		return nil, apperr.ErrUnauthorized
	}

	// 2. DOMAIN: Value Object parsing (The "What")
	oldTokenID, err := valueobjects.TokenIDFromString(claims.JTI)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	userIDVO, err := valueobjects.UserIDFromString(claims.Subject)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	deviceID, err := valueobjects.DeviceIDFromString(deviceIDStr)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 3. INFRASTRUCTURE: Database failures (The "Firewall")
	isRevoked, err := h.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		h.logger.Error("DB error checking revocation", "error", err)
		return nil, apperr.ErrInternal // Never leak DB errors
	}
	if isRevoked {
		return nil, apperr.ErrUnauthorized
	}

	user, err := h.userRepository.GetByID(userIDVO)
	if err != nil {
		h.logger.Error("DB error fetching user", "error", err)
		return nil, apperr.ErrInternal
	}
	if user == nil {
		return nil, apperr.ErrUnauthorized
	}

	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		h.logger.Error("DB error fetching device", "error", err)
		return nil, apperr.ErrInternal
	}
	if device == nil {
		// Specific application error for missing device
		return nil, apperr.ErrDeviceNotFound
	}

	// 4. APPLICATION Logic: Cross-referencing data
	// The token claims MUST match the device ID provided in the request
	if claims.DeviceID != deviceID.String() {
		h.logger.Warn("Token/Device mismatch", "tokenDevice", claims.DeviceID, "reqDevice", deviceIDStr)
		return nil, apperr.ErrUnauthorized
	}

	// 5. INFRASTRUCTURE: Issuing new tokens
	newAccessToken, err := h.tokenService.IssueAccessToken(user.ID().String(), deviceID.String(), user.RolesAsStrings())
	if err != nil {
		return nil, apperr.ErrInternal
	}

	newRefreshToken, err := h.tokenService.IssueRefreshToken(user.ID().String(), deviceID.String())
	if err != nil {
		return nil, apperr.ErrInternal
	}

	// 6. DOMAIN: Re-validating new token data
	newClaims, err := h.tokenService.ValidateRefreshToken(newRefreshToken.Value)
	if err != nil {
		return nil, apperr.ErrInternal
	}

	newTokenID, err := valueobjects.TokenIDFromString(newClaims.JTI)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 7. PERSISTENCE: Atomic Rotation
	now := time.Now().UTC()

	rtEntity, err := entities.NewRefreshToken(
		newTokenID,
		user.ID(),
		device.ID(),
		newRefreshToken.Value,
		newClaims.ExpiresAt,
		now,
	)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// Execute rotation
	if err := h.refreshRepo.Revoke(oldTokenID, now); err != nil {
		h.logger.Error("Revocation failed", "error", err)
		return nil, apperr.ErrInternal
	}

	if err := h.refreshRepo.Save(rtEntity); err != nil {
		h.logger.Error("Save failed", "error", err)
		return nil, apperr.ErrInternal
	}

	return &dto.AuthResponse{
		AccessToken:  newAccessToken.Value,
		RefreshToken: newRefreshToken.Value,
	}, nil
}
