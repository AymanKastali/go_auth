package use_cases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/repositories"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/application/ports/use_cases"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type refreshTokenUseCase struct {
	userRepository repositories.UserRepositoryPort
	refreshRepo    repositories.RefreshTokenRepositoryPort
	deviceRepo     repositories.DeviceRepositoryPort
	roleRepo       repositories.RoleRepositoryPort
	tokenService   security.TokenServicePort
	logger         *slog.Logger
}

var _ use_cases.RefreshTokenUseCasePort = (*refreshTokenUseCase)(nil)

// Constructor
func NewRefreshTokenUseCase(
	userRepository repositories.UserRepositoryPort,
	refreshRepo repositories.RefreshTokenRepositoryPort,
	deviceRepo repositories.DeviceRepositoryPort,
	roleRepo repositories.RoleRepositoryPort,
	tokenService security.TokenServicePort,
	logger *slog.Logger,
) *refreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepository: userRepository,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		roleRepo:       roleRepo,
		tokenService:   tokenService,
		logger:         logger,
	}
}

// RefreshToken rotates an existing refresh token and issues new tokens
func (h *refreshTokenUseCase) RefreshToken(
	oldRefreshToken, deviceIDStr string,
) (*dto.AuthResponse, error) {

	// 1️⃣ Validate old refresh token
	claims, err := h.tokenService.ValidateRefreshToken(oldRefreshToken)
	if err != nil {
		return nil, apperr.NewUnauthorizedErr("session expired or invalid")
	}

	oldTokenID, err := valueobjects.TokenIDFromString(claims.JTI)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	userIDVO, err := valueobjects.UserIDFromString(claims.Subject)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	deviceID, err := valueobjects.DeviceIDFromString(deviceIDStr)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	// 2️⃣ Check revocation
	isRevoked, err := h.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, apperr.NewInternalErr("token check failed")
	}
	if isRevoked {
		return nil, apperr.NewUnauthorizedErr("token revoked")
	}

	// 3️⃣ Fetch user and device
	user, err := h.userRepository.GetByID(userIDVO)
	if err != nil {
		return nil, apperr.NewInternalErr("user lookup failed")
	}
	if user == nil {
		return nil, apperr.NewUnauthorizedErr("user no longer exists")
	}

	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		return nil, apperr.NewInternalErr("device lookup failed")
	}
	if device == nil {
		return nil, apperr.NewNotFoundErr("device", deviceID.String())
	}

	if claims.DeviceID != deviceID.String() {
		return nil, apperr.NewUnauthorizedErr("device mismatch")
	}

	// 4️⃣ Map role IDs to role names
	roleNames := make([]string, len(user.RoleIDs()))
	for i, roleID := range user.RoleIDs() {
		role, err := h.roleRepo.GetByID(roleID)
		if err != nil {
			return nil, apperr.NewInternalErr("failed to fetch role for token")
		}
		if role == nil {
			return nil, apperr.NewInternalErr("role missing for user")
		}
		roleNames[i] = role.Name()
	}

	// 5️⃣ Issue new tokens
	newAccessToken, err := h.tokenService.IssueAccessToken(user.ID().String(), device.ID().String(), roleNames)
	if err != nil {
		return nil, apperr.NewInternalErr("failed to issue access token")
	}

	newRefreshToken, err := h.tokenService.IssueRefreshToken(user.ID().String(), device.ID().String())
	if err != nil {
		return nil, apperr.NewInternalErr("failed to issue refresh token")
	}

	// 6️⃣ Create new refresh token entity
	newClaims, _ := h.tokenService.ValidateRefreshToken(newRefreshToken.Value)
	newTokenID, err := valueobjects.TokenIDFromString(newClaims.JTI)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

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
		return nil, apperr.MapDomainErr(err)
	}

	// 7️⃣ Persist new token and revoke old one atomically
	if err := h.refreshRepo.Revoke(oldTokenID, now); err != nil {
		return nil, apperr.NewInternalErr("failed to rotate session")
	}
	if err := h.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.NewInternalErr("failed to persist session")
	}

	return &dto.AuthResponse{
		AccessToken:  newAccessToken.Value,
		RefreshToken: newRefreshToken.Value,
	}, nil
}
