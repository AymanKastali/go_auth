package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type refreshTokenUseCase struct {
	userRepo    dports.IUserRepository
	refreshRepo dports.IRefreshTokenRepository
	deviceRepo  dports.IDeviceRepository
	roleRepo    dports.IRoleRepository
	tokenSvc    aports.ITokenService
	idSvc       ports.IIDService
	clock       dports.IClockService
	logger      *slog.Logger
}

func NewRefreshTokenUseCase(
	userRepo dports.IUserRepository,
	refreshRepo dports.IRefreshTokenRepository,
	deviceRepo dports.IDeviceRepository,
	roleRepo dports.IRoleRepository,
	tokenSvc aports.ITokenService,
	idSvc ports.IIDService,
	clock dports.IClockService,
	logger *slog.Logger,
) *refreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepo:    userRepo,
		refreshRepo: refreshRepo,
		deviceRepo:  deviceRepo,
		roleRepo:    roleRepo,
		tokenSvc:    tokenSvc,
		idSvc:       idSvc,
		clock:       clock,
		logger:      logger,
	}
}

func (uc *refreshTokenUseCase) Execute(requestID, oldRefreshToken, deviceIDStr string) (*dto.AuthResponse, error) {
	uc.logger.Info("Starting token rotation", "request_id", requestID)

	claims, oldTokenID, err := uc.validateSession(requestID, oldRefreshToken, deviceIDStr)
	if err != nil {
		return nil, err
	}

	user, device, err := uc.fetchRequiredEntities(requestID, claims.Subject, deviceIDStr)
	if err != nil {
		return nil, err
	}

	roleNames, err := uc.getRoleNames(requestID, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	return uc.rotateTokens(requestID, user, device, oldTokenID, roleNames, uc.clock.Now().UTC())
}

func (uc *refreshTokenUseCase) validateSession(requestID, tokenStr, deviceIDStr string) (*dto.RefreshTokenClaims, valueobjects.TokenID, error) {
	claims, err := uc.tokenSvc.ValidateRefreshToken(tokenStr)
	if err != nil {
		uc.logger.Warn("refresh token validation failed", "request_id", requestID, "error", err)
		return nil, valueobjects.TokenID{}, apperr.FromDomain(err, requestID)
	}

	if claims.DeviceID != deviceIDStr {
		uc.logger.Warn("device mismatch during refresh", "request_id", requestID)
		return nil, valueobjects.TokenID{}, apperr.Unauthorized("session bound to another device", requestID, nil)
	}

	tokenIDStr := claims.JTI

	if !uc.idSvc.IsValid(tokenIDStr) {
		return nil, valueobjects.TokenID{}, apperr.Invalid("invalid jti format", requestID, nil)
	}

	oldTokenID := valueobjects.ReconstituteTokenID(tokenIDStr)

	isRevoked, err := uc.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.FromDomain(err, requestID)
	}
	if isRevoked {
		uc.logger.Warn("reuse detection: revoked token used", "request_id", requestID, "jti", tokenIDStr)
		return nil, valueobjects.TokenID{}, apperr.Unauthorized("session invalidated", requestID, nil)
	}

	return claims, oldTokenID, nil
}

func (uc *refreshTokenUseCase) fetchRequiredEntities(requestID, userIDStr, deviceIDStr string) (*aggregates.User, *entities.Device, error) {
	if !uc.idSvc.IsValid(userIDStr) {
		return nil, nil, apperr.Invalid("invalid user id format", requestID, nil)
	}
	if !uc.idSvc.IsValid(deviceIDStr) {
		return nil, nil, apperr.Invalid("invalid device id format", requestID, nil)
	}

	userIDVO := valueobjects.ReconstituteUserID(userIDStr)
	deviceIDVO := valueobjects.ReconstituteDeviceID(deviceIDStr)

	user, err := uc.userRepo.GetByID(userIDVO)
	if err != nil {
		return nil, nil, apperr.FromDomain(err, requestID)
	}
	if user == nil {
		return nil, nil, apperr.Unauthorized("user context lost", requestID, nil)
	}

	device, err := uc.deviceRepo.GetByID(deviceIDVO)
	if err != nil {
		return nil, nil, apperr.FromDomain(err, requestID)
	}
	if device == nil {
		return nil, nil, apperr.NotFound("device record missing", requestID, nil)
	}

	return user, device, nil
}

func (uc *refreshTokenUseCase) getRoleNames(requestID string, roleIDs []valueobjects.RoleID) ([]string, error) {
	names := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := uc.roleRepo.GetByID(id)
		if err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}
		if role != nil {
			names = append(names, role.Name())
		}
	}
	return names, nil
}

func (uc *refreshTokenUseCase) rotateTokens(
	requestID string,
	user *aggregates.User,
	device *entities.Device,
	oldID valueobjects.TokenID,
	roles []string,
	currentTime time.Time,
) (*dto.AuthResponse, error) {
	newTokenID, err := valueobjects.NewTokenID(uc.idSvc.Generate())
	if err != nil {
		return nil, apperr.Internal("id generation failed", requestID, err)
	}

	at, _, err := uc.tokenSvc.IssueAccessToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), roles, currentTime)
	if err != nil {
		return nil, apperr.Internal("access token issue failed", requestID, err)
	}

	rt, rtClaims, err := uc.tokenSvc.IssueRefreshToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), currentTime)
	if err != nil {
		return nil, apperr.Internal("refresh token issue failed", requestID, err)
	}

	rtEntity, err := entities.NewRefreshToken(newTokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, currentTime)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	// Persist Rotation: Kill the OLD and Save the NEW
	if err := uc.refreshRepo.Revoke(oldID, currentTime); err != nil {
		uc.logger.Warn("rotation persistence failed", "request_id", requestID, "old_id", oldID.Value())
		return nil, apperr.FromDomain(err, requestID)
	}

	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.Internal("failed to persist new session", requestID, err)
	}

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
