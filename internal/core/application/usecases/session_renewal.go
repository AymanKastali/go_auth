package usecases

import (
	"log/slog"

	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/policies"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type sessionRenewalTokenUseCase struct {
	sessionSvc         dports.ISessionDomainService
	sessionRenewalRepo dports.ISessionRenewalTokenRepository
	userRepo           dports.IUserRepository
	roleRepo           dports.IRoleRepository
	deviceRepo         dports.IDeviceRepository
	sessionTokenSvc    aports.ISessionTokenIssuerService
	clockSvc           dports.IClockService
	idSvc              dports.IIDService
	tokenHasher        dports.ITokenHasherService
	policy             policies.SessionTokenPolicy
}

func NewSessionRenewalTokenUseCase(
	sessionSvc dports.ISessionDomainService,
	sessionRenewalRepo dports.ISessionRenewalTokenRepository,
	userRepo dports.IUserRepository,
	roleRepo dports.IRoleRepository,
	deviceRepo dports.IDeviceRepository,
	sessionTokenSvc aports.ISessionTokenIssuerService,
	clockSvc dports.IClockService,
	idSvc dports.IIDService,
	tokenHasher dports.ITokenHasherService,
	policy policies.SessionTokenPolicy,
) *sessionRenewalTokenUseCase {
	return &sessionRenewalTokenUseCase{
		sessionSvc:         sessionSvc,
		sessionRenewalRepo: sessionRenewalRepo,
		userRepo:           userRepo,
		roleRepo:           roleRepo,
		deviceRepo:         deviceRepo,
		sessionTokenSvc:    sessionTokenSvc,
		clockSvc:           clockSvc,
		idSvc:              idSvc,
		tokenHasher:        tokenHasher,
		policy:             policy,
	}
}

// Execute handles the rotation of session renewal tokens (Refresh Tokens).
func (uc *sessionRenewalTokenUseCase) Execute(l *slog.Logger, input dto.SessionRenewalInput) (*dto.SessionTokens, error) {
	now, err := uc.clockSvc.Now()
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 1. Convert raw input to Value Object
	tokenVO, err := valueobjects.ParseSessionRenewalRawToken(input.RefreshToken)
	if err != nil {
		l.Warn("Invalid refresh token format provided")
		return nil, apperr.Validation("Invalid session renewal token", nil)
	}

	// 2. Fetch and Verify existing session
	oldTokenEntity, err := uc.sessionRenewalRepo.FindByID(tokenVO.ID())
	if err != nil {
		return nil, apperr.Map(err)
	}

	if oldTokenEntity == nil {
		l.Warn("Session token not found", slog.String("token_id", tokenVO.ID().String()))
		return nil, apperr.Unauthorized("Session not found", nil)
	}

	valid, err := uc.tokenHasher.Compare(tokenVO.Secret(), oldTokenEntity.SessionRenewalHashedToken())
	if err != nil {
		return nil, apperr.Map(err)
	}
	if !valid {
		l.Warn("Refresh token secret mismatch")
		return nil, apperr.Unauthorized("Invalid session renewal token", nil)
	}

	// 3. Security Check: Ensure device consistency
	fingerprintVO, err := valueobjects.NewDeviceFingerprint(input.DeviceFingerprint)
	if err != nil {
		return nil, apperr.Map(err)
	}
	currentDevice, err := uc.deviceRepo.GetByFingerprint(fingerprintVO)
	if err != nil {
		return nil, apperr.Map(err)
	}
	if currentDevice == nil {
		l.Warn("Device fingerprint not recognized", slog.String("fingerprint", input.DeviceFingerprint))
		return nil, apperr.Forbidden("Device not recognized", nil)
	}

	if !oldTokenEntity.DeviceID().Equal(currentDevice.ID()) {
		l.Warn("Security alert: token reuse attempted from different device",
			slog.String("original_device", oldTokenEntity.DeviceID().String()),
			slog.String("current_device", currentDevice.ID().String()))
		return nil, apperr.Forbidden("Token does not belong to this device", nil)
	}

	// 4. Perform Rotation (Revocation & Reuse Detection)
	if err := uc.sessionSvc.RotateSession(oldTokenEntity, now); err != nil {
		l.Error("Session rotation failed", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	// 5. Create the New Session
	newTokenEntity, rawSecret, err := uc.sessionSvc.CreateSession(
		oldTokenEntity.UserID(),
		oldTokenEntity.DeviceID(),
		now,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 6. Fetch User to get current roles
	user, err := uc.userRepo.GetByID(oldTokenEntity.UserID())
	if err != nil || user == nil {
		return nil, apperr.Unauthorized("User context no longer valid", nil)
	}

	roleNames, err := uc.fetchRoleNames(user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 7. Issue the new Session Token (JWT)
	sessionToken, err := uc.sessionTokenSvc.Issue(dto.SessionTokenMetadata{
		SessionRenewalTokenID: uc.idSvc.Generate(),
		SessionID:             newTokenEntity.ID().String(),
		UserID:                user.ID().String(),
		DeviceID:              oldTokenEntity.DeviceID().String(),
		Roles:                 roleNames,
		IssuedAt:              now.Time(),
		ExpiresAt:             now.Add(uc.policy.SessionTokenTTL).Time(),
	})
	if err != nil {
		return nil, apperr.Internal("Failed to issue session token", err)
	}

	// 8. Persistence
	if err := uc.sessionRenewalRepo.Save(oldTokenEntity); err != nil {
		return nil, apperr.Map(err)
	}
	if err := uc.sessionRenewalRepo.Save(newTokenEntity); err != nil {
		return nil, apperr.Map(err)
	}

	l.Info("Token rotation complete",
		slog.String("user_id", user.ID().String()),
		slog.String("new_token_id", newTokenEntity.ID().String()))

	return &dto.SessionTokens{
		SessionToken:        sessionToken.Raw,
		SessionRenewalToken: rawSecret.String(),
	}, nil
}

func (uc *sessionRenewalTokenUseCase) fetchRoleNames(ids []valueobjects.RoleID) ([]string, error) {
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
