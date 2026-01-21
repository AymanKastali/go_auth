package usecases

import (
	"context"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type loginUseCase struct {
	authDomainService ports.IAuthDomainService
	deviceFactory     ports.IDeviceFactory

	userRepo       dports.IUserRepository
	refreshRepo    dports.IRefreshTokenRepository
	deviceRepo     dports.IDeviceRepository
	roleRepo       dports.IRoleRepository
	passwordHasher dports.IPasswordHasherService
	tokenSvc       aports.ITokenService
	idSvc          dports.IIDService
	clockSvc       dports.IClockService
}

func NewLoginUseCase(
	authDomainService ports.IAuthDomainService,
	deviceFactory ports.IDeviceFactory,
	userRepo dports.IUserRepository,
	refreshRepo dports.IRefreshTokenRepository,
	deviceRepo dports.IDeviceRepository,
	roleRepo dports.IRoleRepository,
	passwordHasher dports.IPasswordHasherService,
	tokenSvc aports.ITokenService,
	idSvc dports.IIDService,
	clockSvc dports.IClockService,
) *loginUseCase {
	return &loginUseCase{
		authDomainService: authDomainService,
		deviceFactory:     deviceFactory,
		userRepo:          userRepo,
		refreshRepo:       refreshRepo,
		deviceRepo:        deviceRepo,
		roleRepo:          roleRepo,
		passwordHasher:    passwordHasher,
		tokenSvc:          tokenSvc,
		idSvc:             idSvc,
		clockSvc:          clockSvc,
	}
}

func (uc *loginUseCase) Execute(
	c context.Context,
	email, password string,
) (*dto.AuthResponse, error) {
	req := dto.FromContext(c)
	l := req.Logger
	now := uc.clockSvc.Now().UTC()

	l.Info("Executing user login", slog.String("email", email))

	user, err := uc.authDomainService.Authenticate(email, password)
	if err != nil {
		l.Warn("Authentication failed", slog.String("email", email), slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	device, err := uc.authDomainService.ResolveDevice(
		valueobjects.ReconstituteDeviceFingerprint(req.DeviceFingerprint),
		user.ID(),
		&req.DeviceName,
		&req.UserAgent,
		&req.IPAddress,
		now,
	)

	if err != nil {
		return nil, err
	}

	roleNames, err := uc.fetchRoleNames(req, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	tokenID := valueobjects.ReconstituteTokenID(uc.idSvc.Generate())

	return uc.issueTokensAndSaveSession(req, tokenID, user, device, roleNames, now)
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

func (uc *loginUseCase) issueTokensAndSaveSession(
	req *dto.RequestContext,
	tokenID valueobjects.TokenID,
	user *aggregates.User,
	device *entities.Device,
	roles []string,
	now time.Time,
) (*dto.AuthResponse, error) {

	// 1. Fetch existing active tokens for this specific User + Device
	// This allows the domain to decide what to do with them.
	oldTokens, err := uc.refreshRepo.GetActiveByUserIDAndDeviceID(user.ID(), device.ID())
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 2. Revoke old tokens via the Domain Entity
	for _, ot := range oldTokens {
		// Business logic lives here (e.g., setting RevokedAt, checking if already revoked)
		if err := ot.Revoke(now); err != nil {
			req.Logger.Warn("Could not revoke old token", slog.String("id", ot.ID().Value()))
			continue
		}

		// Persist the state change back to the DB
		if err := uc.refreshRepo.Save(ot); err != nil {
			return nil, apperr.Map(err)
		}
	}

	// 3. Issue new tokens via the Token Service
	at, _, err := uc.tokenSvc.IssueAccessToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), roles, now,
	)
	if err != nil {
		return nil, apperr.Internal("failed to issue access token", err)
	}

	rt, rtClaims, err := uc.tokenSvc.IssueRefreshToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), now,
	)
	if err != nil {
		return nil, apperr.Internal("failed to issue refresh token", err)
	}

	// 4. Create the NEW RefreshToken Entity (IMPORTANT: Do NOT call .Revoke() on this)
	rtEntity, err := entities.NewRefreshToken(
		tokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, now,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 5. Save the new active session
	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.Map(err)
	}

	req.Logger.Info("Login session established and old tokens cleared", slog.String("token_id", tokenID.Value()))

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
