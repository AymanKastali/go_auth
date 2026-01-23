package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
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
	sessionSvc         dports.ISessionDomainService
	policy             policies.SessionTokenPolicy
}

func NewLoginUseCase(
	authDomainService dports.IAuthDomainService,
	sessionRenewalRepo dports.ISessionRenewalTokenRepository,
	roleRepo dports.IRoleRepository,
	sessionTokenSvc aports.ISessionTokenIssuerService,
	idSvc dports.IIDService,
	clockSvc dports.IClockService,
	sessionSvc dports.ISessionDomainService,
	policy policies.SessionTokenPolicy,
) *loginUseCase {
	return &loginUseCase{
		authDomainService:  authDomainService,
		sessionRenewalRepo: sessionRenewalRepo,
		roleRepo:           roleRepo,
		idSvc:              idSvc,
		clockSvc:           clockSvc,
		sessionTokenSvc:    sessionTokenSvc,
		sessionSvc:         sessionSvc,
		policy:             policy,
	}
}

func (uc *loginUseCase) Execute(l *slog.Logger, input dto.LoginInput) (*dto.SessionTokens, error) {
	now, err := uc.clockSvc.Now()
	if err != nil {
		return nil, apperr.Map(err)
	}

	l.Info("Executing user login", slog.String("email", input.Email))

	// 1. Authenticate using data from input
	user, err := uc.authDomainService.Authenticate(input.Email, input.Password)
	if err != nil {
		l.Warn("Authentication failed", slog.String("email", input.Email), slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	// 2. Resolve Device using data from input
	fingerprint, err := valueobjects.NewDeviceFingerprint(input.DeviceFingerprint)
	if err != nil {
		return nil, apperr.Map(err)
	}

	device, err := uc.authDomainService.ResolveDevice(
		fingerprint,
		user.ID(),
		input.DeviceName, // These are *string in LoginInput
		input.UserAgent,
		input.IPAddress,
		now,
	)
	if err != nil {
		return nil, err
	}

	// 3. Session Management
	revoked, err := uc.sessionSvc.InvalidateExistingSessions(user.ID(), device.ID(), now)
	if err != nil {
		return nil, apperr.Map(err)
	}

	sessionRenewalToken, rawToken, err := uc.sessionSvc.CreateSession(
		user.ID(),
		device.ID(),
		now,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 4. Role hydration - pass the logger separately
	roles, err := uc.fetchRoleNames(l, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 5. Token Issuance
	sessionToken, err := uc.sessionTokenSvc.Issue(dto.SessionTokenMetadata{
		SessionRenewalTokenID: uc.idSvc.Generate(),
		SessionID:             sessionRenewalToken.ID().String(),
		UserID:                user.ID().String(),
		DeviceID:              device.ID().String(),
		Roles:                 roles,
		IssuedAt:              now.Time(),
		ExpiresAt:             now.Add(uc.policy.SessionTokenTTL).Time(),
	})
	if err != nil {
		return nil, apperr.Internal("failed to issue session token", err)
	}

	// 6. Persistence
	for _, ot := range revoked {
		_ = uc.sessionRenewalRepo.Save(ot)
	}
	if err := uc.sessionRenewalRepo.Save(sessionRenewalToken); err != nil {
		return nil, apperr.Map(err)
	}

	return &dto.SessionTokens{
		SessionToken:        sessionToken.Raw,
		SessionRenewalToken: rawToken.String(),
	}, nil
}

// Internal helper uses the passed logger instead of RequestContext
func (uc *loginUseCase) fetchRoleNames(l *slog.Logger, roleIDs []valueobjects.RoleID) ([]string, error) {
	l.Debug("Hydrating role names", slog.Int("count", len(roleIDs)))
	roleNames := make([]string, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		role, err := uc.roleRepo.GetByID(roleID)
		if err != nil {
			l.Error("Database error during role lookup",
				slog.String("role_id", roleID.String()),
				slog.Any("error", err),
			)
			return nil, apperr.Map(err)
		}
		if role != nil {
			roleNames = append(roleNames, role.Name())
		}
	}
	return roleNames, nil
}
