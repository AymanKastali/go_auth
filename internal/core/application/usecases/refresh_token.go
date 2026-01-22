package usecases

import (
	"context"
	"log/slog"

	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/policies"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type refreshTokenUseCase struct {
	sessionSvc      dports.ISessionDomainService
	refreshRepo     dports.IRefreshTokenRepository
	userRepo        dports.IUserRepository
	roleRepo        dports.IRoleRepository
	deviceRepo      dports.IDeviceRepository
	sessionTokenSvc aports.ISessionTokenIssuerService
	clockSvc        dports.IClockService
	idSvc           dports.IIDService
	tokenHasher     dports.ITokenHasherService
	policy          policies.JWTPolicy
}

func NewRefreshTokenUseCase(
	sessionSvc dports.ISessionDomainService,
	refreshRepo dports.IRefreshTokenRepository,
	userRepo dports.IUserRepository,
	roleRepo dports.IRoleRepository,
	deviceRepo dports.IDeviceRepository,
	sessionTokenSvc aports.ISessionTokenIssuerService,
	clockSvc dports.IClockService,
	idSvc dports.IIDService,
	tokenHasher dports.ITokenHasherService,
	policy policies.JWTPolicy,
) *refreshTokenUseCase {
	return &refreshTokenUseCase{
		sessionSvc:      sessionSvc,
		refreshRepo:     refreshRepo,
		userRepo:        userRepo,
		roleRepo:        roleRepo,
		deviceRepo:      deviceRepo,
		sessionTokenSvc: sessionTokenSvc,
		clockSvc:        clockSvc,
		idSvc:           idSvc,
		tokenHasher:     tokenHasher,
		policy:          policy,
	}
}

func (uc *refreshTokenUseCase) Execute(c context.Context, rawToken string) (*dto.AuthResponse, error) {
	req := dto.FromContext(c)
	now, err := uc.clockSvc.Now()
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 1. Convert raw input to Value Object
	tokenVO, err := valueobjects.ParseRawRefreshToken(rawToken)
	if err != nil {
		return nil, apperr.Validation("Invalid refresh token", nil)
	}

	tokenID := tokenVO.TokenID()
	secret := tokenVO.Secret()

	// 2. Fetch the session from the database
	oldTokenEntity, err := uc.refreshRepo.FindByID(tokenID)
	if err != nil {
		return nil, apperr.Map(err)
	}

	if oldTokenEntity == nil {
		return nil, apperr.Unauthorized("Session not found", nil)
	}

	valid, err := uc.tokenHasher.Compare(secret, oldTokenEntity.HashedToken())
	if err != nil {
		return nil, apperr.Map(err)
	}
	if !valid {
		return nil, apperr.Unauthorized("Invalid refresh token", nil)
	}

	// 3. Security Check: Ensure device consistency
	fingerprintVO, err := valueobjects.NewDeviceFingerprint(req.DeviceFingerprint)
	if err != nil {
		return nil, apperr.Map(err)
	}
	currentDevice, err := uc.deviceRepo.GetByFingerprint(fingerprintVO)
	if err != nil {
		return nil, apperr.Map(err)
	}
	if currentDevice == nil {
		return nil, apperr.Forbidden("Device not recognized", nil)
	}

	if !oldTokenEntity.DeviceID().Equal(currentDevice.ID()) {
		return nil, apperr.Forbidden("Token does not belong to this device", nil)
	}

	// 4. Perform Rotation (Revocation & Reuse Detection)
	// Now returns only an error as per your new Domain Service logic
	if err := uc.sessionSvc.RotateSession(oldTokenEntity, now); err != nil {
		return nil, apperr.Map(err)
	}

	// 5. Create the New Session
	// We delegate the creation to the session service using the existing data
	newTokenEntity, rawSecret, err := uc.sessionSvc.CreateSession(
		oldTokenEntity.UserID(),
		oldTokenEntity.DeviceID(),
		now,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 6. Fetch User to get current roles for the new Access Token
	user, err := uc.userRepo.GetByID(oldTokenEntity.UserID())
	if err != nil || user == nil {
		return nil, apperr.Unauthorized("User context no longer valid", nil)
	}

	roleNames, err := uc.fetchRoleNames(user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 7. Issue the new Access Token (JWT)
	accessToken, err := uc.sessionTokenSvc.Issue(dto.SessionTokenMetadata{
		TokenID:   uc.idSvc.Generate(),
		SessionID: newTokenEntity.ID().Value(),
		UserID:    user.ID().Value(),
		DeviceID:  oldTokenEntity.DeviceID().Value(),
		Roles:     roleNames,
		IssuedAt:  now.Value(),
		ExpiresAt: now.Add(uc.policy.AccessTokenTTL).Value(),
	})
	if err != nil {
		return nil, apperr.Internal("Failed to issue access token", err)
	}

	// 8. Persistence: Atomic update
	// Ideally, these should be wrapped in a single database transaction
	if err := uc.refreshRepo.Save(oldTokenEntity); err != nil {
		return nil, apperr.Map(err)
	}
	if err := uc.refreshRepo.Save(newTokenEntity); err != nil {
		return nil, apperr.Map(err)
	}

	req.Logger.Info("Token rotation complete",
		slog.String("user_id", user.ID().Value()),
		slog.String("new_token_id", newTokenEntity.ID().Value()))

	return &dto.AuthResponse{
		AccessToken:  accessToken.Raw,
		RefreshToken: rawSecret.String(),
	}, nil
}

func (uc *refreshTokenUseCase) fetchRoleNames(ids []valueobjects.RoleID) ([]string, error) {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
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
