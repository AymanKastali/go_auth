package usecases

import (
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
	logger      *slog.Logger
}

func NewRefreshTokenUseCase(
	userRepo dports.IUserRepository,
	refreshRepo dports.IRefreshTokenRepository,
	deviceRepo dports.IDeviceRepository,
	roleRepo dports.IRoleRepository,
	tokenSvc aports.ITokenService,
	idSvc dports.IIDService,
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

func (uc *refreshTokenUseCase) Execute(traceID, oldRefreshToken, deviceIDStr string) (*dto.AuthResponse, error) {
	uc.logger.Info("Starting token rotation", "trace_id", traceID)

	// 1. Session Validation
	claims, oldTokenID, err := uc.validateSession(traceID, oldRefreshToken, deviceIDStr)
	if err != nil {
		return nil, err
	}

	// 2. Entity Loading
	user, device, err := uc.fetchRequiredEntities(traceID, claims.Subject, deviceIDStr)
	if err != nil {
		return nil, err
	}

	// 3. Authorization Data (Fetch role names for new token claims)
	roleNames, err := uc.getRoleNames(traceID, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 4. Atomic Rotation
	return uc.rotateTokens(traceID, user, device, oldTokenID, roleNames, uc.clock.Now().UTC())
}

func (uc *refreshTokenUseCase) validateSession(traceID, tokenStr, deviceIDStr string) (*dto.RefreshTokenClaims, valueobjects.TokenID, error) {
	claims, err := uc.tokenSvc.ValidateRefreshToken(tokenStr)
	if err != nil {
		uc.logger.Warn("refresh token validation failed", "trace_id", traceID, "error", err)
		// Use Unauthorized factory for token validation failure
		return nil, valueobjects.TokenID{}, apperr.Unauthorized("invalid or expired session", traceID, err)
	}

	// Device Binding Check (Security Invariant)
	if claims.DeviceID != deviceIDStr {
		uc.logger.Warn("device mismatch during refresh", "trace_id", traceID, "expected", claims.DeviceID, "actual", deviceIDStr)
		return nil, valueobjects.TokenID{}, apperr.Forbidden("session is bound to a different device", traceID, nil)
	}

	if !uc.idSvc.IsValid(claims.JTI) {
		return nil, valueobjects.TokenID{}, apperr.Validation("malformed token identifier in claims", traceID, map[string]any{"jti": claims.JTI})
	}

	oldTokenID := valueobjects.ReconstituteTokenID(claims.JTI)

	// Reuse Detection (Check if token was already rotated/revoked)
	isRevoked, err := uc.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, valueobjects.TokenID{}, apperr.Map(err, traceID)
	}
	if isRevoked {
		uc.logger.Error("REUSE DETECTION TRIGGERED", "trace_id", traceID, "token_id", claims.JTI)
		return nil, valueobjects.TokenID{}, apperr.Unauthorized("session has been invalidated", traceID, nil)
	}

	return claims, oldTokenID, nil
}

func (uc *refreshTokenUseCase) fetchRequiredEntities(traceID, userIDStr, deviceIDStr string) (*aggregates.User, *entities.Device, error) {
	// Identity Format Validation
	if !uc.idSvc.IsValid(userIDStr) {
		return nil, nil, apperr.Validation("invalid user id format", traceID, map[string]any{"id": userIDStr})
	}
	if !uc.idSvc.IsValid(deviceIDStr) {
		return nil, nil, apperr.Validation("invalid device id format", traceID, map[string]any{"id": deviceIDStr})
	}

	user, err := uc.userRepo.GetByID(valueobjects.ReconstituteUserID(userIDStr))
	if err != nil {
		return nil, nil, apperr.Map(err, traceID)
	}
	if user == nil {
		// If user is missing, it's an authorization failure (context lost)
		return nil, nil, apperr.Unauthorized("user context no longer valid", traceID, nil)
	}

	device, err := uc.deviceRepo.GetByID(valueobjects.ReconstituteDeviceID(deviceIDStr))
	if err != nil {
		return nil, nil, apperr.Map(err, traceID)
	}
	if device == nil {
		// Use NotFound factory for missing resource
		return nil, nil, apperr.NotFound("Device", deviceIDStr, traceID)
	}

	return user, device, nil
}

func (uc *refreshTokenUseCase) getRoleNames(traceID string, roleIDs []valueobjects.RoleID) ([]string, error) {
	names := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := uc.roleRepo.GetByID(id)
		if err != nil {
			return nil, apperr.Map(err, traceID)
		}
		if role == nil {
			// System inconsistency: a role assigned to a user doesn't exist in roles table
			return nil, apperr.Internal("system inconsistency: assigned role not found", traceID, nil)
		}
		names = append(names, role.Name())
	}
	return names, nil
}

func (uc *refreshTokenUseCase) rotateTokens(
	traceID string,
	user *aggregates.User,
	device *entities.Device,
	oldID valueobjects.TokenID,
	roles []string,
	currentTime time.Time,
) (*dto.AuthResponse, error) {
	// 1. Generate NEW Identity
	newTokenID := valueobjects.ReconstituteTokenID(uc.idSvc.Generate())

	// 2. Issue new JWTs (Infrastructure capability)
	at, _, err := uc.tokenSvc.IssueAccessToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), roles, currentTime)
	if err != nil {
		return nil, apperr.Internal("failed to issue access token", traceID, err)
	}

	rt, rtClaims, err := uc.tokenSvc.IssueRefreshToken(newTokenID.Value(), user.ID().Value(), device.ID().Value(), currentTime)
	if err != nil {
		return nil, apperr.Internal("failed to issue refresh token", traceID, err)
	}

	// 3. Create Domain Entity (Logical validation)
	rtEntity, err := entities.NewRefreshToken(newTokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, currentTime)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	// 4. Persistence Atomicity
	// Revoke the old token (prevents reuse)
	if err := uc.refreshRepo.Revoke(oldID, currentTime); err != nil {
		return nil, apperr.Map(err, traceID)
	}

	// Save the new token
	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.Map(err, traceID)
	}

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
