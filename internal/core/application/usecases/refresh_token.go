package usecases

import (
	"errors"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/derr"
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

func (uc *refreshTokenUseCase) Execute(oldRefreshToken, deviceIDStr string) (*dto.AuthResponse, error) {
	claims, oldTokenID, err := uc.validateSession(oldRefreshToken, deviceIDStr)
	if err != nil {
		return nil, err
	}

	user, device, err := uc.fetchRequiredEntities(claims.Subject, deviceIDStr)
	if err != nil {
		return nil, err
	}

	roleNames, err := uc.getRoleNames(user.RoleIDs())
	if err != nil {
		return nil, err
	}

	return uc.rotateTokens(user, device, oldTokenID, roleNames, uc.clock.NowUTC())
}

func (uc *refreshTokenUseCase) validateSession(tokenStr, deviceIDStr string) (*dto.RefreshTokenClaims, valueobjects.TokenID, error) {
	claims, err := uc.tokenSvc.ValidateRefreshToken(tokenStr)
	if err != nil {
		uc.logger.Warn("refresh token signature or expiry check failed", slog.Any("error", err))
		return nil, valueobjects.TokenID{}, apperr.Unauthorized(err)
	}

	if claims.DeviceID != deviceIDStr {
		uc.logger.Warn("device mismatch during refresh attempt",
			slog.String("token_device", claims.DeviceID),
			slog.String("request_device", deviceIDStr))
		return nil, valueobjects.TokenID{}, apperr.Forbidden(errors.New("this session is bound to another device"))
	}

	oldTokenID, err := uc.uuidParser.ParseTokenID(claims.JTI)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.Validation(err)
	}

	isRevoked, err := uc.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.Internal(err)
	}
	if isRevoked {
		uc.logger.Warn("reuse detection triggered: attempt to use a revoked token", slog.String("jti", claims.JTI))
		return nil, valueobjects.TokenID{}, apperr.Unauthorized(errors.New("session has been invalidated"))
	}

	return claims, oldTokenID, nil
}

func (uc *refreshTokenUseCase) fetchRequiredEntities(uIDStr, dIDStr string) (*aggregates.User, *entities.Device, error) {
	uID, err := uc.uuidParser.ParseUserID(uIDStr)
	if err != nil {
		return nil, nil, apperr.Validation(err)
	}

	dID, err := uc.uuidParser.ParseDeviceID(dIDStr)
	if err != nil {
		return nil, nil, apperr.Validation(err)
	}

	user, err := uc.userRepo.GetByID(uID)
	if err != nil {
		return nil, nil, apperr.Internal(err)
	}
	if user == nil {
		return nil, nil, apperr.Unauthorized(errors.New("user context lost"))
	}

	device, err := uc.deviceRepo.GetByID(dID)
	if err != nil {
		return nil, nil, apperr.Internal(err)
	}
	if device == nil {
		return nil, nil, apperr.NotFound(errors.New("device record missing"))
	}

	return user, device, nil
}

func (uc *refreshTokenUseCase) getRoleNames(roleIDs []valueobjects.RoleID) ([]string, error) {
	names := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := uc.roleRepo.GetByID(id)
		if err != nil {
			return nil, apperr.Internal(err)
		}
		if role != nil {
			names = append(names, role.Name())
		}
	}
	return names, nil
}

func (uc *refreshTokenUseCase) rotateTokens(
	user *aggregates.User,
	device *entities.Device,
	oldID valueobjects.TokenID,
	roles []string,
	now time.Time,
) (*dto.AuthResponse, error) {
	newTokenID, err := uc.uuidGenerator.NewTokenID()
	if err != nil {
		return nil, apperr.Internal(err)
	}

	at, _, err := uc.tokenSvc.IssueAccessToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), roles, now)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	rt, rtClaims, err := uc.tokenSvc.IssueRefreshToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), now)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	rtEntity, err := entities.NewRefreshToken(newTokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, now)
	if err != nil {
		return nil, apperr.Validation(err)
	}

	// Persist Rotation: Kill the OLD token and Save the NEW one
	err = uc.refreshRepo.Revoke(oldID, now)
	if err != nil {
		var dErr derr.DomainError
		if errors.As(err, &dErr) {
			if dErr.Op() == derr.OpNotFound {
				uc.logger.Warn("rotation failed: old token ID not found in store", slog.String("old_id", oldID.Value()))
				return nil, apperr.Unauthorized(errors.New("session is no longer active"))
			}
			return nil, apperr.Conflict(dErr)
		}
		return nil, apperr.Internal(err)
	}

	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.Internal(err)
	}

	uc.logger.Info("token rotation complete",
		slog.String("user", user.ID().Value()),
		slog.String("revoked", oldID.Value()),
		slog.String("issued", newTokenID.Value()))

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
