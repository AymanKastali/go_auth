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

type renewalTokenUseCase struct {
	userRepo       dports.IUserRepository
	renewalRepo    dports.IRenewalTokenRepository
	deviceRepo     dports.IDeviceRepository
	roleRepo       dports.IRoleRepository
	tokenSvc       aports.ISessionTokenIssuerService
	idSvc          dports.IIDService
	clockSvc       dports.IClockService
	tokenHasher    dports.ITokenHasherService
	tokenGenerator dports.IRandomTokenGenerator
}

func NewRenewalTokenUseCase(
	userRepo dports.IUserRepository,
	renewalRepo dports.IRenewalTokenRepository,
	deviceRepo dports.IDeviceRepository,
	roleRepo dports.IRoleRepository,
	tokenSvc aports.ISessionTokenIssuerService,
	idSvc dports.IIDService,
	clockSvc dports.IClockService,
	tokenHasher dports.ITokenHasherService,
	tokenGenerator dports.IRandomTokenGenerator,
) *renewalTokenUseCase {
	return &renewalTokenUseCase{
		userRepo:       userRepo,
		renewalRepo:    renewalRepo,
		deviceRepo:     deviceRepo,
		roleRepo:       roleRepo,
		tokenSvc:       tokenSvc,
		idSvc:          idSvc,
		clockSvc:       clockSvc,
		tokenHasher:    tokenHasher,
		tokenGenerator: tokenGenerator,
	}
}

func (uc *renewalTokenUseCase) Execute(c context.Context, oldRenewalToken string) (*dto.AuthResponse, error) {
	req := dto.FromContext(c)
	currentTime := uc.clockSvc.Now().UTC()

	// 1. Validate the old Renewal token and fetch the domain entity
	claims, oldTokenEntity, err := uc.validateSession(req, oldRenewalToken)
	if err != nil {
		return nil, err
	}

	// 2. Fetch user and device entities
	user, device, err := uc.fetchRequiredEntities(req, claims.UserID)
	if err != nil {
		return nil, err
	}

	// 3. Hydrate role names
	roleNames, err := uc.getRoleNames(req, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 4. Rotate tokens
	return uc.rotateTokens(req, user, device, oldTokenEntity, roleNames, currentTime)
}

// --- Core logic ---

func (uc *renewalTokenUseCase) validateSession(
	req *dto.RequestContext,
	tokenStr string,
) (*dto.SessionTokenMetadata, *entities.RenewalToken, error) {
	claims, err := uc.tokenSvc.Validate(tokenStr)
	if err != nil {
		return nil, nil, apperr.Unauthorized("invalid or expired session", err)
	}

	if claims.DeviceID != req.DeviceID {
		return nil, nil, apperr.Forbidden("session bound to different device", nil)
	}

	tokenID := valueobjects.ReconstituteTokenID(claims.TokenID)
	oldTokenEntity, err := uc.renewalRepo.FindByID(tokenID)
	if err != nil {
		return nil, nil, apperr.Map(err)
	}
	if oldTokenEntity == nil {
		return nil, nil, apperr.NotFound("Session", claims.TokenID)
	}
	if oldTokenEntity.IsRevoked() {
		req.Logger.Error("SECURITY ALERT: reuse detected", slog.String("jti", claims.TokenID))
		return nil, nil, apperr.Unauthorized("session has been invalidated", nil)
	}

	return &claims, oldTokenEntity, nil
}

func (uc *renewalTokenUseCase) rotateTokens(
	req *dto.RequestContext,
	user *aggregates.User,
	device *entities.Device,
	oldToken *entities.RenewalToken,
	roles []string,
	currentTime time.Time,
) (*dto.AuthResponse, error) {

	// 1. Revoke old token
	if err := oldToken.Revoke(currentTime); err != nil {
		return nil, apperr.Map(err)
	}
	if err := uc.renewalRepo.Save(oldToken); err != nil {
		return nil, apperr.Map(err)
	}

	// 2. Issue new access token
	newTokenIDStr := uc.idSvc.Generate()
	at, err := uc.tokenSvc.Issue(dto.IssueSessionToken{
		TokenID:   newTokenIDStr,
		UserID:    user.ID().Value(),
		DeviceID:  device.ID().Value(),
		Roles:     roles,
		IssuedAt:  currentTime,
		ExpiresAt: currentTime.Add(15 * time.Minute),
	})
	if err != nil {
		return nil, apperr.Internal("failed to issue access token", err)
	}

	// 3. Generate new renewal token
	rawRenewalToken, err := uc.tokenGenerator.Generate(32)
	if err != nil {
		return nil, apperr.Internal("failed to generate renewal token", err)
	}

	hashedToken, err := uc.tokenHasher.Hash(rawRenewalToken)
	if err != nil {
		return nil, apperr.Internal("failed to hash renewal token", err)
	}

	newTokenID := valueobjects.ReconstituteTokenID(newTokenIDStr)
	rtEntity, err := entities.NewRenewalToken(
		newTokenID,
		user.ID(),
		device.ID(),
		hashedToken,
		currentTime.Add(60*time.Minute),
		currentTime,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 4. Persist the new token
	if err := uc.renewalRepo.Save(rtEntity); err != nil {
		return nil, apperr.Map(err)
	}

	req.Logger.Info("Renewal token rotated successfully", slog.String("token_id", newTokenIDStr))

	return &dto.AuthResponse{
		AccessToken:  string(at.Raw),
		RefreshToken: rawRenewalToken, // deliver only raw token
	}, nil
}

// --- Helpers ---

func (uc *renewalTokenUseCase) fetchRequiredEntities(req *dto.RequestContext, userIDStr string) (*aggregates.User, *entities.Device, error) {
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

func (uc *renewalTokenUseCase) getRoleNames(req *dto.RequestContext, roleIDs []valueobjects.RoleID) ([]string, error) {
	roleNames := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := uc.roleRepo.GetByID(id)
		if err != nil {
			return nil, apperr.Map(err)
		}
		if role != nil {
			roleNames = append(roleNames, role.Name())
		}
	}
	return roleNames, nil
}
