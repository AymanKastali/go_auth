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

func (uc *refreshTokenUseCase) validateSession(tid, tokenStr, deviceIDStr string) (*dto.RefreshTokenClaims, valueobjects.TokenID, error) {
	claims, err := uc.tokenSvc.ValidateRefreshToken(tokenStr)
	if err != nil {
		uc.logger.Warn("refresh token validation failed", "request_id", tid, "error", err)
		return nil, valueobjects.TokenID{}, apperr.FromDomain(err, tid)
	}

	if claims.DeviceID != deviceIDStr {
		uc.logger.Warn("device mismatch during refresh", "request_id", tid)
		return nil, valueobjects.TokenID{}, apperr.Forbidden("session bound to another device", tid, nil)
	}

	oldTokenID, err := uc.uuidParser.ParseTokenID(claims.JTI)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.BadRequest("invalid token identifier", tid, err)
	}

	isRevoked, err := uc.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.FromDomain(err, tid)
	}
	if isRevoked {
		uc.logger.Warn("reuse detection: revoked token used", "request_id", tid, "jti", claims.JTI)
		return nil, valueobjects.TokenID{}, apperr.Unauthorized("session invalidated", tid, nil)
	}

	return claims, oldTokenID, nil
}

func (uc *refreshTokenUseCase) fetchRequiredEntities(tid, uIDStr, dIDStr string) (*aggregates.User, *entities.Device, error) {
	uID, err := uc.uuidParser.ParseUserID(uIDStr)
	if err != nil {
		return nil, nil, apperr.BadRequest("invalid user id", tid, err)
	}

	dID, err := uc.uuidParser.ParseDeviceID(dIDStr)
	if err != nil {
		return nil, nil, apperr.BadRequest("invalid device id", tid, err)
	}

	user, err := uc.userRepo.GetByID(uID)
	if err != nil {
		return nil, nil, apperr.FromDomain(err, tid)
	}
	if user == nil {
		return nil, nil, apperr.Unauthorized("user context lost", tid, nil)
	}

	device, err := uc.deviceRepo.GetByID(dID)
	if err != nil {
		return nil, nil, apperr.FromDomain(err, tid)
	}
	if device == nil {
		return nil, nil, apperr.NotFound("device record missing", tid, nil)
	}

	return user, device, nil
}

func (uc *refreshTokenUseCase) getRoleNames(tid string, roleIDs []valueobjects.RoleID) ([]string, error) {
	names := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := uc.roleRepo.GetByID(id)
		if err != nil {
			return nil, apperr.FromDomain(err, tid)
		}
		if role != nil {
			names = append(names, role.Name())
		}
	}
	return names, nil
}

func (uc *refreshTokenUseCase) rotateTokens(
	tid string,
	user *aggregates.User,
	device *entities.Device,
	oldID valueobjects.TokenID,
	roles []string,
	now time.Time,
) (*dto.AuthResponse, error) {
	newTokenID, err := uc.uuidGenerator.NewTokenID()
	if err != nil {
		return nil, apperr.Internal("id generation failed", tid, err)
	}

	at, _, err := uc.tokenSvc.IssueAccessToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), roles, now)
	if err != nil {
		return nil, apperr.Internal("access token issue failed", tid, err)
	}

	rt, rtClaims, err := uc.tokenSvc.IssueRefreshToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), now)
	if err != nil {
		return nil, apperr.Internal("refresh token issue failed", tid, err)
	}

	rtEntity, err := entities.NewRefreshToken(newTokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, now)
	if err != nil {
		return nil, apperr.FromDomain(err, tid)
	}

	// Persist Rotation: Kill the OLD and Save the NEW
	if err := uc.refreshRepo.Revoke(oldID, now); err != nil {
		uc.logger.Warn("rotation persistence failed", "request_id", tid, "old_id", oldID.Value())
		return nil, apperr.FromDomain(err, tid)
	}

	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.Internal("failed to persist new session", tid, err)
	}

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
