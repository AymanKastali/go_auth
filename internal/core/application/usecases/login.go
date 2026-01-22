package usecases

import (
	"context"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/policies"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type loginUseCase struct {
	authDomainService dports.IAuthDomainService
	refreshRepo       dports.IRefreshTokenRepository
	roleRepo          dports.IRoleRepository
	idSvc             dports.IIDService
	clockSvc          dports.IClockService
	sessionTokenSvc   aports.ISessionTokenIssuerService
	sessionSvc        dports.ISessionDomainService
	policy            policies.JWTPolicy
}

func NewLoginUseCase(
	authDomainService dports.IAuthDomainService,
	refreshRepo dports.IRefreshTokenRepository,
	roleRepo dports.IRoleRepository,
	sessionTokenSvc aports.ISessionTokenIssuerService,
	idSvc dports.IIDService,
	clockSvc dports.IClockService,
	sessionSvc dports.ISessionDomainService,
	policy policies.JWTPolicy,
) *loginUseCase {
	return &loginUseCase{
		authDomainService: authDomainService,
		refreshRepo:       refreshRepo,
		roleRepo:          roleRepo,
		idSvc:             idSvc,
		clockSvc:          clockSvc,
		sessionTokenSvc:   sessionTokenSvc,
		sessionSvc:        sessionSvc,
		policy:            policy,
	}
}

func (uc *loginUseCase) Execute(
	c context.Context,
	email, password string,
) (*dto.AuthResponse, error) {
	req := dto.FromContext(c)
	l := req.Logger
	now, err := uc.clockSvc.Now()
	if err != nil {
		return nil, apperr.Map(err)
	}

	l.Info("Executing user login", slog.String("email", email))

	user, err := uc.authDomainService.Authenticate(email, password)
	if err != nil {
		l.Warn("Authentication failed", slog.String("email", email), slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	fingerprint, err := valueobjects.NewDeviceFingerprint(req.DeviceFingerprint)
	if err != nil {
		return nil, apperr.Map(err)
	}

	device, err := uc.authDomainService.ResolveDevice(
		fingerprint,
		user.ID(),
		&req.DeviceName,
		&req.UserAgent,
		&req.IPAddress,
		now,
	)

	if err != nil {
		return nil, err
	}

	revoked, err := uc.sessionSvc.InvalidateExistingSessions(user.ID(), device.ID(), now)
	if err != nil {
		return nil, apperr.Map(err)
	}

	refreshToken, rawToken, err := uc.sessionSvc.CreateSession(
		user.ID(),
		device.ID(),
		now,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	roles, err := uc.fetchRoleNames(req, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	accessToken, err := uc.sessionTokenSvc.Issue(dto.SessionTokenMetadata{
		TokenID:   uc.idSvc.Generate(),
		SessionID: refreshToken.ID().Value(),
		UserID:    user.ID().Value(),
		DeviceID:  device.ID().Value(),
		Roles:     roles,
		IssuedAt:  now.Value(),
		ExpiresAt: now.Add(uc.policy.AccessTokenTTL).Value(),
	})
	if err != nil {
		return nil, apperr.Internal("failed to issue access token", err)
	}

	for _, ot := range revoked {
		_ = uc.refreshRepo.Save(ot)
	}
	if err := uc.refreshRepo.Save(refreshToken); err != nil {
		return nil, apperr.Map(err)
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Raw,
		RefreshToken: rawToken.String(),
	}, nil
}

func (uc *loginUseCase) fetchRoleNames(req *dto.RequestContext, roleIDs []valueobjects.RoleID) ([]string, error) {
	req.Logger.Debug("Hydrating role names", slog.Int("count", len(roleIDs)))
	roleNames := make([]string, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		role, err := uc.roleRepo.GetByID(roleID)
		if err != nil {
			req.Logger.Error("Database error during role lookup", slog.String("role_id", roleID.Value()), slog.Any("error", err))
			return nil, apperr.Map(err)
		}
		if role != nil {
			roleNames = append(roleNames, role.Name())
		}
	}
	return roleNames, nil
}
