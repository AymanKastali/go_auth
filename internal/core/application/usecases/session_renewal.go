package usecases

import (
	"log/slog"

	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/entities"
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
		policy:             policy,
	}
}

func (uc *sessionRenewalTokenUseCase) Execute(l *slog.Logger, input dto.SessionRenewalInput) (*dto.SessionTokens, error) {
	now, err := uc.clockSvc.Now()
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 1. VO Conversion (Gatekeeping)
	tokenVO, err := valueobjects.ParseSessionRenewalRawToken(input.RefreshToken)
	if err != nil {
		l.Warn("Invalid refresh token format provided")
		return nil, apperr.Map(err)
	}

	fingerprintVO, err := valueobjects.NewDeviceFingerprint(input.DeviceFingerprint)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 2. Data Retrieval
	oldTokenEntity, err := uc.sessionRenewalRepo.FindByID(tokenVO.ID())
	if err != nil {
		return nil, apperr.Map(err)
	}
	if oldTokenEntity == nil {
		l.Warn("Session token not found", slog.String("token_id", tokenVO.ID().String()))
		return nil, apperr.Unauthorized("Session not found", nil)
	}

	currentDevice, err := uc.deviceRepo.GetByFingerprint(fingerprintVO)
	if err != nil {
		return nil, apperr.Map(err)
	}
	if currentDevice == nil {
		l.Warn("Device fingerprint not recognized", slog.String("fingerprint", input.DeviceFingerprint))
		return nil, apperr.Forbidden("Device not recognized", nil)
	}

	// 3. Orchestrate Domain Logic via Service
	// This now handles Secret Verification, Device Check, and Rotation logic internally.
	newTokenEntity, rawToken, err := uc.sessionSvc.RefreshSession(
		oldTokenEntity,
		tokenVO.Secret(),
		currentDevice,
		now,
	)
	if err != nil {
		l.Warn("Session refresh rejected", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	// 4. Role hydration (Optimized batch fetch)
	user, err := uc.userRepo.GetByID(oldTokenEntity.UserID())
	if err != nil || user == nil {
		return nil, apperr.Unauthorized("User context no longer valid", nil)
	}

	roles, err := uc.roleRepo.GetByIDs(user.RoleIDs())
	if err != nil {
		return nil, apperr.Map(err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name()
	}

	// 5. Token Issuance
	sessionToken, err := uc.sessionTokenSvc.Issue(dto.SessionTokenMetadata{
		SessionRenewalRawTokenID: uc.idSvc.Generate(),
		SessionID:                newTokenEntity.ID().String(),
		UserID:                   user.ID().String(),
		DeviceID:                 oldTokenEntity.DeviceID().String(),
		Roles:                    roleNames,
		IssuedAt:                 now.Time(),
		ExpiresAt:                now.Add(uc.policy.SessionTokenTTL).Time(),
	})
	if err != nil {
		return nil, apperr.Internal("Failed to issue session token", err)
	}

	// 6. Persistence (Atomic Batch Save)
	allTokens := []*entities.SessionRenewalToken{oldTokenEntity, newTokenEntity}
	if err := uc.sessionRenewalRepo.SaveMany(allTokens); err != nil {
		l.Error("Failed to persist rotated tokens", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	l.Info("Token rotation complete",
		slog.String("user_id", user.ID().String()),
		slog.String("new_token_id", newTokenEntity.ID().String()),
	)

	return &dto.SessionTokens{
		SessionToken:        sessionToken.Raw,
		SessionRenewalToken: rawToken.String(),
	}, nil
}
