package usecases

import (
	"context"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
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
	idSvc       dports.IIDService
	clockSvc    dports.IClockService
}

func NewRefreshTokenUseCase(
	userRepo dports.IUserRepository,
	refreshRepo dports.IRefreshTokenRepository,
	deviceRepo dports.IDeviceRepository,
	roleRepo dports.IRoleRepository,
	tokenSvc aports.ITokenService,
	idSvc dports.IIDService,
	clockSvc dports.IClockService,
) *refreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepo:    userRepo,
		refreshRepo: refreshRepo,
		deviceRepo:  deviceRepo,
		roleRepo:    roleRepo,
		tokenSvc:    tokenSvc,
		idSvc:       idSvc,
		clockSvc:    clockSvc,
	}
}

func (uc *refreshTokenUseCase) Execute(c context.Context, oldRefreshToken string) (*dto.AuthResponse, error) {
	req := dto.FromContext(c)
	currentTime := uc.clockSvc.Now().UTC()

	// 1. Validate the session and get the existing domain entity
	claims, oldTokenEntity, err := uc.validateSession(req, oldRefreshToken)
	if err != nil {
		return nil, err
	}

	// 2. Fetch the User and Device (Helper implemented below)
	user, device, err := uc.fetchRequiredEntities(req, claims.Subject)
	if err != nil {
		return nil, err
	}

	// 3. Hydrate Role Names (Helper implemented below)
	roleNames, err := uc.getRoleNames(req, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 4. Perform the rotation
	return uc.rotateTokens(user, device, oldTokenEntity, roleNames, currentTime)
}

// --- CORE LOGIC ---

func (uc *refreshTokenUseCase) validateSession(req *dto.RequestContext, tokenStr string) (*dto.RefreshTokenClaims, *entities.RefreshToken, error) {
	claims, err := uc.tokenSvc.ValidateRefreshToken(tokenStr)
	if err != nil {
		return nil, nil, apperr.Unauthorized("invalid or expired session", err)
	}

	if claims.DeviceID != req.DeviceID {
		return nil, nil, apperr.Forbidden("session bound to different device", nil)
	}

	tokenID := valueobjects.ReconstituteTokenID(claims.JTI)
	oldTokenEntity, err := uc.refreshRepo.GetByID(tokenID)
	if err != nil {
		return nil, nil, apperr.Map(err)
	}

	if oldTokenEntity == nil {
		return nil, nil, apperr.NotFound("Session", claims.JTI)
	}

	if oldTokenEntity.IsRevoked() {
		req.Logger.Error("SECURITY ALERT: Reuse detected", slog.String("jti", claims.JTI))
		return nil, nil, apperr.Unauthorized("session has been invalidated", nil)
	}

	return claims, oldTokenEntity, nil
}

func (uc *refreshTokenUseCase) rotateTokens(
	user *aggregates.User,
	device *entities.Device,
	oldToken *entities.RefreshToken,
	roles []string,
	currentTime time.Time,
) (*dto.AuthResponse, error) {

	// Domain State Change: Invalidate the old token
	if err := oldToken.Revoke(currentTime); err != nil {
		return nil, apperr.Map(err)
	}

	// Issue new token credentials
	newTokenIDStr := uc.idSvc.Generate()
	at, _, err := uc.tokenSvc.IssueAccessToken(newTokenIDStr, user.ID().Value(), device.ID().Value(), roles, currentTime)
	if err != nil {
		return nil, apperr.Internal("failed to issue access token", err)
	}

	rt, rtClaims, err := uc.tokenSvc.IssueRefreshToken(newTokenIDStr, user.ID().Value(), device.ID().Value(), currentTime)
	if err != nil {
		return nil, apperr.Internal("failed to issue refresh token", err)
	}

	// Create New Active Entity (No .Revoke() call here!)
	newTokenID := valueobjects.ReconstituteTokenID(newTokenIDStr)
	rtEntity, err := entities.NewRefreshToken(newTokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, currentTime)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// Persist changes
	if err := uc.refreshRepo.Save(oldToken); err != nil {
		return nil, apperr.Map(err)
	}
	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.Map(err)
	}

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}

// --- MISSING HELPERS ---

func (uc *refreshTokenUseCase) fetchRequiredEntities(req *dto.RequestContext, userIDStr string) (*aggregates.User, *entities.Device, error) {
	if !uc.idSvc.IsValid(userIDStr) {
		return nil, nil, apperr.Validation("invalid user id format", map[string]any{"id": userIDStr})
	}

	user, err := uc.userRepo.GetByID(valueobjects.ReconstituteUserID(userIDStr))
	if err != nil {
		return nil, nil, apperr.Map(err)
	}
	if user == nil {
		return nil, nil, apperr.Unauthorized("user context no longer valid", nil)
	}

	device, err := uc.deviceRepo.GetByID(valueobjects.ReconstituteDeviceID(req.DeviceID))
	if err != nil {
		return nil, nil, apperr.Map(err)
	}
	if device == nil {
		return nil, nil, apperr.NotFound("Device", req.DeviceID)
	}

	return user, device, nil
}

func (uc *refreshTokenUseCase) getRoleNames(req *dto.RequestContext, roleIDs []valueobjects.RoleID) ([]string, error) {
	names := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := uc.roleRepo.GetByID(id)
		if err != nil {
			return nil, apperr.Map(err)
		}
		if role != nil {
			names = append(names, role.Name())
		}
	}
	return names, nil
}
