package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type refreshTokenUseCase struct {
	userRepo    ports.UserRepositoryPort
	refreshRepo ports.RefreshTokenRepositoryPort
	deviceRepo  ports.DeviceRepositoryPort
	roleRepo    ports.RoleRepositoryPort
	tokenSvc    ports.TokenServicePort
	logger      *slog.Logger
}

var _ ports.RefreshTokenUseCasePort = (*refreshTokenUseCase)(nil)

func NewRefreshTokenUseCase(
	userRepo ports.UserRepositoryPort,
	refreshRepo ports.RefreshTokenRepositoryPort,
	deviceRepo ports.DeviceRepositoryPort,
	roleRepo ports.RoleRepositoryPort,
	tokenSvc ports.TokenServicePort,
	logger *slog.Logger,
) ports.RefreshTokenUseCasePort {
	return &refreshTokenUseCase{
		userRepo:    userRepo,
		refreshRepo: refreshRepo,
		deviceRepo:  deviceRepo,
		roleRepo:    roleRepo,
		tokenSvc:    tokenSvc,
		logger:      logger,
	}
}

func (h *refreshTokenUseCase) Execute(
	oldRefreshToken, deviceIDStr string,
) (*dto.AuthResponse, error) {

	// 1️⃣ Validate old refresh token string
	claims, err := h.tokenSvc.ValidateRefreshToken(oldRefreshToken)
	if err != nil {
		return nil, apperr.NewUnauthorizedErr("session expired or invalid")
	}

	// 2️⃣ Parse Value Objects
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

	// 3️⃣ Check revocation (Infrastructure)
	isRevoked, err := h.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, err // Repo returns apperr
	}
	if isRevoked {
		return nil, apperr.NewUnauthorizedErr("session has been revoked")
	}

	// 4️⃣ Fetch user and device (Infrastructure)
	user, err := h.userRepo.GetByID(userIDVO)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, apperr.NewUnauthorizedErr("user account no longer exists")
	}

	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, apperr.NewNotFoundErr("device", deviceID.String())
	}

	// Security Check: Ensure token belongs to this device
	if claims.DeviceID != deviceID.String() {
		h.logger.Warn("Device mismatch during refresh", "expected", claims.DeviceID, "got", deviceID.String())
		return nil, apperr.NewUnauthorizedErr("device mismatch")
	}

	// 5️⃣ Map role names for the new Access Token
	roleNames := make([]string, len(user.RoleIDs()))
	for i, roleID := range user.RoleIDs() {
		role, err := h.roleRepo.GetByID(roleID)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return nil, apperr.NewInternalErr("assigned role not found")
		}
		roleNames[i] = role.Name()
	}

	// 6️⃣ Issue new tokens
	newAccessToken, err := h.tokenSvc.IssueAccessToken(user.ID().String(), device.ID().String(), roleNames)
	if err != nil {
		return nil, apperr.NewInternalErr("failed to issue session")
	}

	newRefreshToken, err := h.tokenSvc.IssueRefreshToken(user.ID().String(), device.ID().String())
	if err != nil {
		return nil, apperr.NewInternalErr("failed to issue refresh session")
	}

	// 7️⃣ Create new refresh token entity
	newClaims, _ := h.tokenSvc.ValidateRefreshToken(newRefreshToken.Value)
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

	// 8️⃣ Rotation: Revoke old and save new
	if err := h.refreshRepo.Revoke(oldTokenID, now); err != nil {
		return nil, err
	}

	if err := h.refreshRepo.Save(rtEntity); err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		AccessToken:  newAccessToken.Value,
		RefreshToken: newRefreshToken.Value,
	}, nil
}
