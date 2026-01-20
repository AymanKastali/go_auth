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

type loginUseCase struct {
	userRepo         dports.IUserRepository
	renewalTokenRepo dports.IRenewalTokenRepository
	deviceRepo       dports.IDeviceRepository
	roleRepo         dports.IRoleRepository
	passwordHasher   dports.IPasswordHasherService
	sessionTokenSvc  aports.ISessionTokenIssuerService
	idSvc            dports.IIDService
	clockSvc         dports.IClockService
	tokenHasher      dports.ITokenHasherService
	// sessionRenewalSvc aports.ISessionRenewalTokenService
	tokenGenerator dports.IRandomTokenGenerator
}

func NewLoginUseCase(
	userRepo dports.IUserRepository,
	renewalTokenRepo dports.IRenewalTokenRepository,
	deviceRepo dports.IDeviceRepository,
	roleRepo dports.IRoleRepository,
	passwordHasher dports.IPasswordHasherService,
	sessionTokenSvc aports.ISessionTokenIssuerService,
	idSvc dports.IIDService,
	clockSvc dports.IClockService,
	tokenHasher dports.ITokenHasherService,
	// sessionRenewalSvc aports.ISessionRenewalTokenService,
	tokenGenerator dports.IRandomTokenGenerator,
) *loginUseCase {
	return &loginUseCase{
		userRepo:         userRepo,
		renewalTokenRepo: renewalTokenRepo,
		deviceRepo:       deviceRepo,
		roleRepo:         roleRepo,
		passwordHasher:   passwordHasher,
		sessionTokenSvc:  sessionTokenSvc,
		idSvc:            idSvc,
		clockSvc:         clockSvc,
		tokenHasher:      tokenHasher,
		// sessionRenewalSvc: sessionRenewalSvc,
		tokenGenerator: tokenGenerator,
	}
}

func (uc *loginUseCase) Execute(
	c context.Context,
	email, password string,
) (*dto.AuthResponse, error) {
	req := dto.FromContext(c)
	l := req.Logger
	currentTime := uc.clockSvc.Now().UTC()

	l.Info("Executing user login", slog.String("email", email))

	user, err := uc.authenticate(req, email, password)
	if err != nil {
		return nil, err
	}

	if !user.IsActive() {
		l.Warn("Login attempt by inactive user", slog.String("email", email))
		return nil, apperr.Forbidden("account is disabled", nil)
	}

	device, err := uc.resolveDevice(req, user.ID(), currentTime)
	if err != nil {
		return nil, err
	}

	roleNames, err := uc.fetchRoleNames(req, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	tokenID := valueobjects.ReconstituteTokenID(uc.idSvc.Generate())

	return uc.issueTokensAndSaveSession(req, tokenID, user, device, roleNames, currentTime)
}

func (uc *loginUseCase) authenticate(
	req *dto.RequestContext,
	email, password string,
) (*aggregates.User, error) {
	emailVO := valueobjects.ReconstituteEmail(email)
	user, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		req.Logger.Error("Database error during email lookup", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	if user == nil {
		req.Logger.Warn("Authentication failed: user not found", slog.String("email", email))
		return nil, apperr.Unauthorized("invalid credentials", nil)
	}

	if err := uc.passwordHasher.Compare(password, user.HashedPassword()); err != nil {
		req.Logger.Warn("Authentication failed: password mismatch", slog.String("email", email))
		return nil, apperr.Unauthorized("invalid credentials", nil)
	}

	return user, nil
}

func (uc *loginUseCase) resolveDevice(
	req *dto.RequestContext,
	userID valueobjects.UserID,
	currentTime time.Time,
) (*entities.Device, error) {
	deviceID := req.DeviceID

	if !uc.idSvc.IsValid(deviceID) {
		req.Logger.Warn("Device resolution failed: invalid ID format", slog.String("device_id", deviceID))
		return nil, apperr.Validation("invalid device id format", map[string]any{"device_id": deviceID})
	}

	deviceIDVO := valueobjects.ReconstituteDeviceID(deviceID)
	device, err := uc.deviceRepo.GetByID(deviceIDVO)
	if err != nil {
		req.Logger.Error("Database error during device lookup", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	if device == nil {
		req.Logger.Info("Registering new device context", slog.String("device_id", deviceID))
		device, err = entities.NewDevice(deviceIDVO, userID, &req.DeviceName, &req.UserAgent, &req.IPAddress, currentTime)
		if err != nil {
			req.Logger.Error("Failed to create new device entity", slog.Any("error", err))
			return nil, apperr.Map(err)
		}
		if err := device.Activate(currentTime); err != nil {
			req.Logger.Error("Failed to activate new device entity", slog.Any("error", err))
			return nil, apperr.Map(err)
		}
	} else {
		if err := device.BelongsTo(userID); err != nil {
			req.Logger.Warn("Device validation failed: ownership mismatch", slog.String("device_id", deviceID))
			return nil, apperr.Map(err)
		}
		if err := device.EnsureUsable(); err != nil {
			req.Logger.Warn("Device validation failed: unusable device", slog.String("device_id", deviceID))
			return nil, apperr.Map(err)
		}

		if err := device.MarkSeen(currentTime); err != nil {
			req.Logger.Error("Failed to update device last seen timestamp", slog.String("device_id", deviceID), slog.Any("error", err))
			return nil, apperr.Map(err)
		}
		if err := device.UpdateMetadata(currentTime, &req.DeviceName, &req.UserAgent, &req.IPAddress); err != nil {
			req.Logger.Error("Failed to update device metadata", slog.String("device_id", deviceID), slog.Any("error", err))
			return nil, apperr.Map(err)
		}
	}

	if err := uc.deviceRepo.Upsert(device); err != nil {
		req.Logger.Error("Database error during device upsert", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	return device, nil
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
	currentTime time.Time,
) (*dto.AuthResponse, error) {

	// 1. Fetch existing active tokens for this specific User + Device
	// This allows the domain to decide what to do with them.
	oldTokens, err := uc.renewalTokenRepo.FindByUserAndDevice(user.ID(), device.ID())
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 2. Revoke old tokens via the Domain Entity
	for _, ot := range oldTokens {
		// Business logic lives here (e.g., setting RevokedAt, checking if already revoked)
		if err := ot.Revoke(currentTime); err != nil {
			req.Logger.Warn("Could not revoke old token", slog.String("id", ot.ID().Value()))
			continue
		}

		// Persist the state change back to the DB
		if err := uc.renewalTokenRepo.Save(ot); err != nil {
			return nil, apperr.Map(err)
		}
	}

	// 3. Issue new tokens via the Token Service
	at, err := uc.sessionTokenSvc.Issue(dto.IssueSessionToken{
		TokenID:   tokenID.Value(),
		UserID:    user.ID().Value(),
		DeviceID:  device.ID().Value(),
		Roles:     roles,
		IssuedAt:  currentTime,
		ExpiresAt: currentTime.Add(15 * time.Minute),
	})
	if err != nil {
		return nil, apperr.Internal("failed to issue access token", err)
	}

	// 4. Create the NEW RefreshToken Entity
	rawToken, err := uc.tokenGenerator.Generate(32)
	if err != nil {
		return nil, apperr.Internal("failed to generate refresh token", err)
	}
	hashedToken, err := uc.tokenHasher.Hash(rawToken)
	if err != nil {
		return nil, apperr.Internal("failed to hash refresh token", err)
	}
	rtEntity, err := entities.NewRenewalToken(
		tokenID, user.ID(), device.ID(), hashedToken, currentTime.Add(60*time.Minute), currentTime,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	// 5. Save the new active session
	if err := uc.renewalTokenRepo.Save(rtEntity); err != nil {
		return nil, apperr.Map(err)
	}

	req.Logger.Info("Login session established and old tokens cleared", slog.String("token_id", tokenID.Value()))

	return &dto.AuthResponse{
		AccessToken:  string(at.Raw),
		RefreshToken: string(rtEntity.Hash().Value()),
	}, nil
}
