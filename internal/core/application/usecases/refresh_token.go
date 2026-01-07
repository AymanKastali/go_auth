package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
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
	now := time.Now().UTC()

	// 1. Validate Token & Context
	claims, oldTokenID, err := h.validateSession(oldRefreshToken, deviceIDStr)
	if err != nil {
		return nil, err
	}

	// 2. Fetch Entities
	user, device, err := h.fetchRequiredEntities(claims.Subject, deviceIDStr)
	if err != nil {
		return nil, err
	}

	// 3. Authorization Context
	roleNames, err := h.getRoleNames(user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 4. Token Rotation (Issue new, revoke old)
	return h.rotateTokens(user, device, oldTokenID, roleNames, now)
}

// --- Internal Helper Methods ---

func (h *refreshTokenUseCase) validateSession(tokenStr, deviceIDStr string) (*dto.RefreshTokenClaims, valueobjects.TokenID, error) {
	// JWT Validation
	claims, err := h.tokenSvc.ValidateRefreshToken(tokenStr)
	if err != nil {
		return nil, valueobjects.TokenID{}, err // Already returns apperr via adapter
	}

	// Security check: Device binding
	if claims.DeviceID != deviceIDStr {
		h.logger.Warn("Device mismatch", "expected", claims.DeviceID, "got", deviceIDStr)
		return nil, valueobjects.TokenID{}, apperr.NewUnauthorizedErr("invalid session context")
	}

	// Token ID Validation
	oldTokenID, err := valueobjects.TokenIDFromString(claims.JTI)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.MapDomainErr(err)
	}

	// Revocation check
	isRevoked, err := h.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.NewInternalErr("persistence error")
	}
	if isRevoked {
		return nil, valueobjects.TokenID{}, apperr.NewUnauthorizedErr("session has been revoked")
	}

	return claims, oldTokenID, nil
}

func (h *refreshTokenUseCase) fetchRequiredEntities(uIDStr, dIDStr string) (*aggregates.User, *entities.Device, error) {
	uID, _ := valueobjects.UserIDFromString(uIDStr)
	dID, _ := valueobjects.DeviceIDFromString(dIDStr)

	user, err := h.userRepo.GetByID(uID)
	if err != nil || user == nil {
		return nil, nil, apperr.NewUnauthorizedErr("user no longer exists")
	}

	device, err := h.deviceRepo.GetByID(dID)
	if err != nil || device == nil {
		return nil, nil, apperr.NewNotFoundErr("device", dIDStr)
	}

	return user, device, nil
}

func (h *refreshTokenUseCase) getRoleNames(roleIDs []valueobjects.RoleID) ([]string, error) {
	names := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := h.roleRepo.GetByID(id)
		if err != nil {
			return nil, apperr.NewInternalErr("failed to fetch roles")
		}
		if role != nil {
			names = append(names, role.Name())
		}
	}
	return names, nil
}

func (h *refreshTokenUseCase) rotateTokens(
	user *aggregates.User,
	device *entities.Device,
	oldID valueobjects.TokenID,
	roles []string,
	now time.Time,
) (*dto.AuthResponse, error) {
	// 1. Issue New Tokens
	at, _, err := h.tokenSvc.IssueAccessToken(user.ID().String(), device.ID().String(), roles)
	if err != nil {
		return nil, err
	}

	rt, rtClaims, err := h.tokenSvc.IssueRefreshToken(user.ID().String(), device.ID().String())
	if err != nil {
		return nil, err
	}

	// 2. Map to Entity
	newTokenID, _ := valueobjects.TokenIDFromString(rtClaims.JTI)
	rtEntity, err := entities.NewRefreshToken(
		newTokenID, user.ID(), device.ID(), rt.Value(), rtClaims.ExpiresAt, now,
	)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	// 3. Persist Rotation (Revoke old, save new)
	if err := h.refreshRepo.Revoke(oldID, now); err != nil {
		return nil, apperr.NewInternalErr("failed to revoke old session")
	}

	if err := h.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.NewInternalErr("failed to save new session")
	}

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
