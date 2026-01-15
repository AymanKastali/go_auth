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

type loginUseCase struct {
	userRepo       dports.IUserRepository
	refreshRepo    dports.IRefreshTokenRepository
	deviceRepo     dports.IDeviceRepository
	roleRepo       dports.IRoleRepository
	passwordHasher dports.IPasswordService
	tokenService   aports.ITokenService
	idSvc          dports.IIDService
	clock          dports.IClockService
	logger         *slog.Logger
}

func NewLoginUseCase(
	userRepo dports.IUserRepository,
	refreshRepo dports.IRefreshTokenRepository,
	deviceRepo dports.IDeviceRepository,
	roleRepo dports.IRoleRepository,
	passwordHasher dports.IPasswordService,
	tokenService aports.ITokenService,
	idSvc dports.IIDService,
	clock dports.IClockService,
	logger *slog.Logger,
) *loginUseCase {
	return &loginUseCase{
		userRepo:       userRepo,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		idSvc:          idSvc,
		clock:          clock,
		logger:         logger,
	}
}

func (uc *loginUseCase) Execute(
	traceID string,
	email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
) (*dto.AuthResponse, error) {
	uc.logger.Info("Starting user login", "email", email, "trace_id", traceID)
	now := uc.clock.Now().UTC()

	// 1. Authenticate (Identify & Verify)
	user, err := uc.authenticate(traceID, email, password)
	if err != nil {
		return nil, err
	}

	// 2. Resolve Device (Identify/Create/Update device context)
	device, err := uc.resolveDevice(traceID, user.ID(), deviceIDStr, deviceName, userAgent, ipAddress, now)
	if err != nil {
		return nil, err
	}

	// 3. Fetch Permissions (Hydrate Claims)
	roleNames, err := uc.fetchRoleNames(traceID, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 4. Generate Token Identity
	tokenID := valueobjects.ReconstituteTokenID(uc.idSvc.Generate())

	// 5. Issue Tokens & Persist Session
	return uc.issueTokensAndSaveSession(traceID, tokenID, user, device, roleNames, now)
}

func (uc *loginUseCase) authenticate(traceID, email, password string) (*aggregates.User, error) {
	emailVO := valueobjects.ReconstituteEmail(email)
	user, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	// Security: Generic message for both account-not-found and wrong-password
	if user == nil || !uc.passwordHasher.Compare(password, user.HashedPassword().Value()) {
		uc.logger.Warn("Failed login attempt", "email", email, "trace_id", traceID)
		return nil, apperr.Unauthorized("invalid credentials", traceID, nil)
	}

	return user, nil
}

func (uc *loginUseCase) resolveDevice(
	traceID string,
	userID valueobjects.UserID,
	deviceIDStr, name, ua, ip string,
	currentTime time.Time,
) (*entities.Device, error) {
	if !uc.idSvc.IsValid(deviceIDStr) {
		return nil, apperr.Validation("invalid device id format", traceID, map[string]any{"device_id": deviceIDStr})
	}

	deviceIDVO := valueobjects.ReconstituteDeviceID(deviceIDStr)
	device, err := uc.deviceRepo.GetByID(deviceIDVO)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	if device == nil {
		// Create new device if first time seen
		device, err = entities.NewDevice(deviceIDVO, userID, &name, &ua, &ip, currentTime)
		if err != nil {
			return nil, apperr.Map(err, traceID)
		}
		device.Activate(currentTime)
	} else {
		// Validate existing device context
		if err := device.BelongsTo(userID); err != nil {
			return nil, apperr.Map(err, traceID)
		}
		if err := device.EnsureUsable(); err != nil {
			return nil, apperr.Map(err, traceID)
		}

		// Update metadata
		device.MarkSeen(currentTime)
		device.UpdateMetadata(currentTime, &name, &ua, &ip)
	}

	if err := uc.deviceRepo.Upsert(device); err != nil {
		return nil, apperr.Map(err, traceID)
	}

	return device, nil
}

func (uc *loginUseCase) fetchRoleNames(traceID string, roleIDs []valueobjects.RoleID) ([]string, error) {
	roleNames := make([]string, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		role, err := uc.roleRepo.GetByID(roleID)
		if err != nil {
			return nil, apperr.Map(err, traceID)
		}
		if role != nil {
			roleNames = append(roleNames, role.Name())
		}
	}
	return roleNames, nil
}

func (uc *loginUseCase) issueTokensAndSaveSession(
	traceID string,
	tokenID valueobjects.TokenID,
	user *aggregates.User,
	device *entities.Device,
	roles []string,
	currentTime time.Time,
) (*dto.AuthResponse, error) {

	// Issue JWTs via Application Port
	at, _, err := uc.tokenService.IssueAccessToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), roles, currentTime,
	)
	if err != nil {
		return nil, apperr.Internal("failed to issue access token", traceID, err)
	}

	rt, rtClaims, err := uc.tokenService.IssueRefreshToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), currentTime,
	)
	if err != nil {
		return nil, apperr.Internal("failed to issue refresh token", traceID, err)
	}

	// Reconstitute Refresh Token Entity for DB
	rtEntity, err := entities.NewRefreshToken(
		tokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, currentTime,
	)
	if err != nil {
		return nil, apperr.Map(err, traceID)
	}

	// Session Management: Revoke old tokens for this specific device (One session per device policy)
	if err := uc.refreshRepo.RevokeByDeviceID(user.ID(), device.ID(), currentTime); err != nil {
		return nil, apperr.Map(err, traceID)
	}

	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		return nil, apperr.Map(err, traceID)
	}

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
