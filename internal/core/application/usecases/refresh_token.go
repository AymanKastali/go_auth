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
	clock       dports.IClockService
}

func NewRefreshTokenUseCase(
	userRepo dports.IUserRepository,
	refreshRepo dports.IRefreshTokenRepository,
	deviceRepo dports.IDeviceRepository,
	roleRepo dports.IRoleRepository,
	tokenSvc aports.ITokenService,
	idSvc dports.IIDService,
	clock dports.IClockService,
) *refreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepo:    userRepo,
		refreshRepo: refreshRepo,
		deviceRepo:  deviceRepo,
		roleRepo:    roleRepo,
		tokenSvc:    tokenSvc,
		idSvc:       idSvc,
		clock:       clock,
	}
}

func (uc *refreshTokenUseCase) Execute(
	c context.Context,
	oldRefreshToken string,
) (*dto.AuthResponse, error) {
	req := dto.GetRequestContext(c)
	now := uc.clock.Now().UTC()

	req.Logger.Info("Executing token rotation", slog.String("device_id", req.DeviceID))

	claims, oldTokenID, err := uc.validateSession(req, oldRefreshToken)
	if err != nil {
		return nil, err
	}

	user, device, err := uc.fetchRequiredEntities(req, claims.Subject)
	if err != nil {
		return nil, err
	}

	roleNames, err := uc.getRoleNames(req, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	return uc.rotateTokens(req, user, device, oldTokenID, roleNames, now)
}

func (uc *refreshTokenUseCase) validateSession(req *dto.RequestContext, tokenStr string) (*dto.RefreshTokenClaims, valueobjects.TokenID, error) {
	claims, err := uc.tokenSvc.ValidateRefreshToken(tokenStr)
	if err != nil {
		req.Logger.Warn("Token rotation failed: invalid or expired token", slog.Any("error", err))
		return nil, valueobjects.TokenID{}, apperr.Unauthorized("invalid or expired session", err)
	}

	if claims.DeviceID != req.DeviceID {
		req.Logger.Warn("SECURITY ALERT: device mismatch during rotation",
			slog.String("token_device_id", claims.DeviceID),
			slog.String("request_device_id", req.DeviceID),
		)
		return nil, valueobjects.TokenID{}, apperr.Forbidden("session is bound to a different device", nil)
	}

	if !uc.idSvc.IsValid(claims.JTI) {
		return nil, valueobjects.TokenID{}, apperr.Validation("malformed token identifier in claims", map[string]any{"jti": claims.JTI})
	}

	oldTokenID := valueobjects.ReconstituteTokenID(claims.JTI)

	isRevoked, err := uc.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		req.Logger.Error("Database error checking revocation status", slog.Any("error", err))
		return nil, valueobjects.TokenID{}, apperr.Map(err)
	}

	if isRevoked {
		req.Logger.Error("SECURITY ALERT: REUSE DETECTION TRIGGERED",
			slog.String("token_id", claims.JTI),
			slog.String("user_id", claims.Subject),
		)
		return nil, valueobjects.TokenID{}, apperr.Unauthorized("session has been invalidated", nil)
	}

	return claims, oldTokenID, nil
}

func (uc *refreshTokenUseCase) fetchRequiredEntities(req *dto.RequestContext, userIDStr string) (*aggregates.User, *entities.Device, error) {
	if !uc.idSvc.IsValid(userIDStr) {
		return nil, nil, apperr.Validation("invalid user id format", map[string]any{"id": userIDStr})
	}

	user, err := uc.userRepo.GetByID(valueobjects.ReconstituteUserID(userIDStr))
	if err != nil {
		req.Logger.Error("Database error during user lookup", slog.Any("error", err))
		return nil, nil, apperr.Map(err)
	}
	if user == nil {
		req.Logger.Warn("Rotation failed: user no longer exists", slog.String("user_id", userIDStr))
		return nil, nil, apperr.Unauthorized("user context no longer valid", nil)
	}

	device, err := uc.deviceRepo.GetByID(valueobjects.ReconstituteDeviceID(req.DeviceID))
	if err != nil {
		req.Logger.Error("Database error during device lookup", slog.Any("error", err))
		return nil, nil, apperr.Map(err)
	}
	if device == nil {
		req.Logger.Warn("Rotation failed: device not found", slog.String("device_id", req.DeviceID))
		return nil, nil, apperr.NotFound("Device", req.DeviceID)
	}

	return user, device, nil
}

func (uc *refreshTokenUseCase) getRoleNames(req *dto.RequestContext, roleIDs []valueobjects.RoleID) ([]string, error) {
	req.Logger.Debug("Hydrating role names", slog.Int("count", len(roleIDs)))
	names := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := uc.roleRepo.GetByID(id)
		if err != nil {
			req.Logger.Error("Database error during role lookup", slog.String("role_id", id.Value()), slog.Any("error", err))
			return nil, apperr.Map(err)
		}
		if role == nil {
			req.Logger.Error("DATA INTEGRITY VIOLATION: assigned role missing", slog.String("role_id", id.Value()))
			return nil, apperr.Internal("system inconsistency: role not found", nil)
		}
		names = append(names, role.Name())
	}
	return names, nil
}

func (uc *refreshTokenUseCase) rotateTokens(
	req *dto.RequestContext,
	user *aggregates.User,
	device *entities.Device,
	oldID valueobjects.TokenID,
	roles []string,
	currentTime time.Time,
) (*dto.AuthResponse, error) {
	newTokenID := valueobjects.ReconstituteTokenID(uc.idSvc.Generate())

	at, _, err := uc.tokenSvc.IssueAccessToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), roles, currentTime)
	if err != nil {
		req.Logger.Error("Token service error: access token issuance", slog.Any("error", err))
		return nil, apperr.Internal("failed to issue access token", err)
	}

	rt, rtClaims, err := uc.tokenSvc.IssueRefreshToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), currentTime)
	if err != nil {
		req.Logger.Error("Token service error: refresh token issuance", slog.Any("error", err))
		return nil, apperr.Internal("failed to issue refresh token", err)
	}

	rtEntity, err := entities.NewRefreshToken(newTokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, currentTime)
	if err != nil {
		return nil, apperr.Map(err)
	}

	if err := uc.refreshRepo.Revoke(oldID, currentTime); err != nil {
		req.Logger.Error("Database error: revoking old token", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		req.Logger.Error("Database error: saving new token", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	req.Logger.Info("Token rotation successful",
		slog.String("old_jti", oldID.Value()),
		slog.String("new_jti", newTokenID.Value()),
	)

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
