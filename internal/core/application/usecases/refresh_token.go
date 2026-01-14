package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type refreshTokenUseCase struct {
	userRepo      dports.UserRepositoryPort
	refreshRepo   dports.RefreshTokenRepositoryPort
	deviceRepo    dports.DeviceRepositoryPort
	roleRepo      dports.RoleRepositoryPort
	tokenSvc      aports.TokenServicePort
	uuidGenerator interfaces.IUUIDGeneratorService
	uuidParser    interfaces.IUUIDParserService
	clock         interfaces.IClock
	logger        *slog.Logger
}

var _ aports.RefreshTokenUseCasePort = (*refreshTokenUseCase)(nil)

func NewRefreshTokenUseCase(
	userRepo dports.UserRepositoryPort,
	refreshRepo dports.RefreshTokenRepositoryPort,
	deviceRepo dports.DeviceRepositoryPort,
	roleRepo dports.RoleRepositoryPort,
	tokenSvc aports.TokenServicePort,
	uuidGenerator interfaces.IUUIDGeneratorService,
	uuidParser interfaces.IUUIDParserService,
	clock interfaces.IClock,
	logger *slog.Logger,
) aports.RefreshTokenUseCasePort {
	return &refreshTokenUseCase{
		userRepo:      userRepo,
		refreshRepo:   refreshRepo,
		deviceRepo:    deviceRepo,
		roleRepo:      roleRepo,
		tokenSvc:      tokenSvc,
		uuidGenerator: uuidGenerator,
		uuidParser:    uuidParser,
		clock:         clock,
		logger:        logger,
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

	return uc.rotateTokens(requestID, user, device, oldTokenID, roleNames, uc.clock.NowUTC())
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

	oldTokenID, err := uc.uuidParser.ParseTokenID(claims.JTI)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.Invalid("invalid token identifier", requestID, err)
	}

	isRevoked, err := uc.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.FromDomain(err, requestID)
	}
	if isRevoked {
		uc.logger.Warn("reuse detection: revoked token used", "request_id", requestID, "jti", claims.JTI)
		return nil, valueobjects.TokenID{}, apperr.Unauthorized("session invalidated", requestID, nil)
	}

	return claims, oldTokenID, nil
}

func (uc *refreshTokenUseCase) fetchRequiredEntities(requestID, uIDStr, dIDStr string) (*aggregates.User, *entities.Device, error) {
	uID, err := uc.uuidParser.ParseUserID(uIDStr)
	if err != nil {
		return nil, nil, apperr.Invalid("invalid user id", requestID, err)
	}

	dID, err := uc.uuidParser.ParseDeviceID(dIDStr)
	if err != nil {
		return nil, nil, apperr.Invalid("invalid device id", requestID, err)
	}

	user, err := uc.userRepo.GetByID(uID)
	if err != nil {
		return nil, nil, apperr.FromDomain(err, requestID)
	}
	if user == nil {
		return nil, nil, apperr.Unauthorized("user context lost", requestID, nil)
	}

	device, err := uc.deviceRepo.GetByID(dID)
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
	newTokenID, err := uc.uuidGenerator.NewTokenID()
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
