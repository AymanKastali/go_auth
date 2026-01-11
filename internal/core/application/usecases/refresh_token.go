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

	// 1. Validate Token & Context
	claims, oldTokenID, err := uc.validateSession(oldRefreshToken, deviceIDStr)
	if err != nil {
		return nil, err
	}

	// 2. Fetch Entities
	user, device, err := uc.fetchRequiredEntities(claims.Subject, deviceIDStr)
	if err != nil {
		return nil, err
	}

	// 3. Authorization Context
	roleNames, err := uc.getRoleNames(user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 4. Token Rotation (Issue new, revoke old)
	return uc.rotateTokens(user, device, oldTokenID, roleNames, uc.clock.NowUTC())
}

// --- Internal Helper Methods ---

func (uc *refreshTokenUseCase) validateSession(tokenStr, deviceIDStr string) (*dto.RefreshTokenClaims, valueobjects.TokenID, error) {
	// JWT Validation
	claims, err := uc.tokenSvc.ValidateRefreshToken(tokenStr)
	if err != nil {
		return nil, valueobjects.TokenID{}, err // Already returns apperr via adapter
	}

	// Security check: Device binding
	if claims.DeviceID != deviceIDStr {
		uc.logger.Warn("Device mismatch", "expected", claims.DeviceID, "got", deviceIDStr)
		return nil, valueobjects.TokenID{}, apperr.NewUnauthorizedErr("invalid session context")
	}

	// Token ID Validation
	oldTokenID, err := uc.uuidParser.ParseTokenID(claims.JTI)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.MapDomainErr(err)
	}

	// Revocation check
	isRevoked, err := uc.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.NewInternalErr("persistence error")
	}
	if isRevoked {
		return nil, valueobjects.TokenID{}, apperr.NewUnauthorizedErr("session has been revoked")
	}

	return claims, oldTokenID, nil
}

func (uc *refreshTokenUseCase) fetchRequiredEntities(uIDStr, dIDStr string) (*aggregates.User, *entities.Device, error) {
	uID, err := uc.uuidParser.ParseUserID(uIDStr)
	if err != nil {
		uc.logger.Error("Failed to generate user ID", "error", err)
		return nil, nil, apperr.NewInternalErr("failed to generate user id")
	}

	dID, err := uc.uuidParser.ParseDeviceID(dIDStr)
	if err != nil {
		return nil, nil, apperr.NewInternalErr("failed to generate user id")
	}

	user, err := uc.userRepo.GetByID(uID)
	if err != nil || user == nil {
		return nil, nil, apperr.NewUnauthorizedErr("user no longer exists")
	}

	device, err := uc.deviceRepo.GetByID(dID)
	if err != nil || device == nil {
		return nil, nil, apperr.NewNotFoundErr("device", dIDStr)
	}

	return user, device, nil
}

func (uc *refreshTokenUseCase) getRoleNames(roleIDs []valueobjects.RoleID) ([]string, error) {
	names := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := uc.roleRepo.GetByID(id)
		if err != nil {
			return nil, apperr.NewInternalErr("failed to fetch roles")
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
	// 1. Issue New Tokens
	tokenID, err := uc.uuidGenerator.NewTokenID()
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	at, _, err := uc.tokenSvc.IssueAccessToken(
		tokenID.Value(),
		user.ID().Value(),
		device.ID().Value(),
		roles,
		now,
	)
	if err != nil {
		return nil, err
	}

	rt, rtClaims, err := uc.tokenSvc.IssueRefreshToken(
		tokenID.Value(),
		user.ID().Value(),
		device.ID().Value(),
		now,
	)
	if err != nil {
		return nil, err
	}

	rtEntity, err := entities.NewRefreshToken(
		tokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, now,
	)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	// 3. Persist Rotation (Revoke old, save new)
	if err := uc.refreshRepo.Revoke(oldID, now); err != nil {
		return nil, apperr.NewInternalErr("failed to revoke old session")
	}

	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.NewInternalErr("failed to save new session")
	}

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
