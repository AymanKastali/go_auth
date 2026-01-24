package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/policies"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type loginUseCase struct {
	authDomainService  dports.IAuthDomainService
	sessionRenewalRepo dports.ISessionRenewalTokenRepository
	roleRepo           dports.IRoleRepository
	idSvc              dports.IIDService
	clockSvc           dports.IClockService
	sessionTokenSvc    aports.ISessionTokenIssuerService
	sessionDomainSvc   dports.ISessionDomainService
	policy             policies.SessionTokenPolicy
}

func NewLoginUseCase(
	authDomainService dports.IAuthDomainService,
	sessionRenewalRepo dports.ISessionRenewalTokenRepository,
	roleRepo dports.IRoleRepository,
	sessionTokenSvc aports.ISessionTokenIssuerService,
	idSvc dports.IIDService,
	clockSvc dports.IClockService,
	sessionDomainSvc dports.ISessionDomainService,
	policy policies.SessionTokenPolicy,
) *loginUseCase {
	return &loginUseCase{
		authDomainService:  authDomainService,
		sessionRenewalRepo: sessionRenewalRepo,
		roleRepo:           roleRepo,
		idSvc:              idSvc,
		clockSvc:           clockSvc,
		sessionTokenSvc:    sessionTokenSvc,
		sessionDomainSvc:   sessionDomainSvc,
		policy:             policy,
	}
}

func (uc *loginUseCase) Execute(l *slog.Logger, input dto.LoginInput) (*dto.SessionTokens, error) {
	l.Info("Executing user login", slog.String("email", input.Email))

	now, err := uc.clockSvc.Now()
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 1. Authenticate
	user, err := uc.authDomainService.Authenticate(input.Email, input.Password)
	if err != nil {
		l.Warn("Authentication failed", slog.String("email", input.Email), slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	traits, err := valueobjects.NewDeviceFingerprintTraits(input.DeviceFingerprint)
	if err != nil {
		l.Warn("Invalid device traits provided", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	// 2. Resolve Device
	device, err := uc.authDomainService.ResolveDevice(
		traits,
		user.ID(),
		input.DeviceName,
		input.UserAgent,
		input.IPAddress,
		now,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 3. Session Management
	revoked, err := uc.sessionDomainSvc.InvalidateExistingSessions(user.ID(), device.ID(), now)
	if err != nil {
		return nil, apperr.Map(err)
	}

	sessionRenewalToken, rawToken, err := uc.sessionDomainSvc.CreateSession(
		user.ID(),
		device.ID(),
		now,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 4. Role hydration
	userRoleIDs := user.RoleIDs()
	l.Debug("Hydrating role names in batch", slog.Int("count", len(userRoleIDs)))

	roles, err := uc.roleRepo.GetByIDs(userRoleIDs)
	if err != nil {
		return nil, apperr.Map(err) // Wrap DB errors
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name()
	}

	// 5. Token Issuance
	sessionToken, err := uc.sessionTokenSvc.Issue(dto.SessionTokenMetadata{
		SessionRenewalRawTokenID: uc.idSvc.Generate(),
		SessionID:                sessionRenewalToken.ID().String(),
		UserID:                   user.ID().String(),
		DeviceID:                 device.ID().String(),
		Roles:                    roleNames,
		IssuedAt:                 now.Time(),
		ExpiresAt:                now.Add(uc.policy.SessionTokenTTL).Time(),
	})
	if err != nil {
		return nil, apperr.Internal("failed to issue session token", err)
	}

	// 6. Persistence (Batch Save)
	// Combine revoked tokens and the new token into one slice
	allTokens := make([]*entities.SessionRenewalToken, 0, len(revoked)+1)
	allTokens = append(allTokens, revoked...)
	allTokens = append(allTokens, sessionRenewalToken)

	if err := uc.sessionRenewalRepo.SaveMany(allTokens); err != nil {
		return nil, apperr.Map(err)
	}

	return &dto.SessionTokens{
		SessionToken:        sessionToken.Raw,
		SessionRenewalToken: rawToken.String(),
	}, nil
}
