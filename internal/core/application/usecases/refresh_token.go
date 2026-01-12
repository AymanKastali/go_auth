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

func (uc *refreshTokenUseCase) Execute(
	oldRefreshToken, deviceIDStr string,
) (*dto.AuthResponse, error) {

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
	// 1. JWT Verification
	claims, err := uc.tokenSvc.ValidateRefreshToken(tokenStr)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.Unauthorized(err)
	}

	// 2. Context Verification
	if claims.DeviceID != deviceIDStr {
		uc.logger.Warn("Device mismatch", "expected", claims.DeviceID, "got", deviceIDStr)
		return nil, valueobjects.TokenID{}, apperr.Forbidden(nil)
	}

	// 3. ID Verification
	oldTokenID, err := uc.uuidParser.ParseTokenID(claims.JTI)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.Validation(err)
	}

	// 4. Persistence Verification (Revocation Check)
	isRevoked, err := uc.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.Internal(err)
	}
	if isRevoked {
		return nil, valueobjects.TokenID{}, apperr.Unauthorized(nil)
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
		return nil, nil, apperr.Unauthorized(nil)
	}

	device, err := uc.deviceRepo.GetByID(dID)
	if err != nil {
		return nil, nil, apperr.Internal(err)
	}
	if device == nil {
		return nil, nil, apperr.NotFound(nil)
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
	tokenID, err := uc.uuidGenerator.NewTokenID()
	if err != nil {
		return nil, apperr.Internal(err)
	}

	at, _, err := uc.tokenSvc.IssueAccessToken(
		tokenID.Value(),
		user.ID().Value(),
		device.ID().Value(),
		roles,
		now,
	)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	rt, rtClaims, err := uc.tokenSvc.IssueRefreshToken(
		tokenID.Value(),
		user.ID().Value(),
		device.ID().Value(),
		now,
	)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	// 5. Domain Object Creation (Logic Check)
	rtEntity, err := entities.NewRefreshToken(
		tokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, now,
	)
	if err != nil {
		return nil, apperr.Validation(err)
	}

	// 6. Persistence Operations
	if err := uc.refreshRepo.Revoke(oldID, now); err != nil {
		return nil, apperr.Internal(err)
	}

	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.Internal(err)
	}

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
