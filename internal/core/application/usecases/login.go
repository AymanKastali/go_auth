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
	userRepo       dports.IUserRepository
	refreshRepo    dports.IRefreshTokenRepository
	deviceRepo     dports.IDeviceRepository
	roleRepo       dports.IRoleRepository
	passwordHasher dports.IPasswordHasherService
	tokenService   aports.ITokenService
	idSvc          dports.IIDService
	clock          dports.IClockService
}

func NewLoginUseCase(
	userRepo dports.IUserRepository,
	refreshRepo dports.IRefreshTokenRepository,
	deviceRepo dports.IDeviceRepository,
	roleRepo dports.IRoleRepository,
	passwordHasher dports.IPasswordHasherService,
	tokenService aports.ITokenService,
	idSvc dports.IIDService,
	clock dports.IClockService,
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
	}
}

func (uc *loginUseCase) Execute(
	c context.Context,
	email, password string,
) (*dto.AuthResponse, error) {
	req := dto.GetRequestContext(c)
	l := req.Logger
	now := uc.clock.Now().UTC()

	l.Info("Executing user login", slog.String("email", email))

	user, err := uc.authenticate(req, email, password)
	if err != nil {
		return nil, err
	}

	device, err := uc.resolveDevice(req, user.ID(), now)
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

func (uc *loginUseCase) authenticate(req *dto.RequestContext, email, password string) (*aggregates.User, error) {
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
	if !uc.idSvc.IsValid(req.DeviceID) {
		req.Logger.Warn("Device resolution failed: invalid ID format", slog.String("device_id", req.DeviceID))
		return nil, apperr.Validation("invalid device id format", map[string]any{"device_id": req.DeviceID})
	}

	deviceIDVO := valueobjects.ReconstituteDeviceID(req.DeviceID)
	device, err := uc.deviceRepo.GetByID(deviceIDVO)
	if err != nil {
		req.Logger.Error("Database error during device lookup", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	if device == nil {
		req.Logger.Info("Registering new device context", slog.String("device_id", req.DeviceID))
		device, err = entities.NewDevice(deviceIDVO, userID, &req.DeviceName, &req.UserAgent, &req.IPAddress, currentTime)
		if err != nil {
			return nil, apperr.Map(err)
		}
		if err := device.Activate(currentTime); err != nil {
			return nil, apperr.Map(err)
		}
	} else {
		if err := device.BelongsTo(userID); err != nil {
			req.Logger.Warn("Device validation failed: ownership mismatch", slog.String("device_id", req.DeviceID))
			return nil, apperr.Map(err)
		}
		if err := device.EnsureUsable(); err != nil {
			return nil, apperr.Map(err)
		}

		if err := device.MarkSeen(currentTime); err != nil {
			return nil, apperr.Map(err)
		}
		if err := device.UpdateMetadata(currentTime, &req.DeviceName, &req.UserAgent, &req.IPAddress); err != nil {
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

	at, _, err := uc.tokenService.IssueAccessToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), roles, currentTime,
	)
	if err != nil {
		req.Logger.Error("Token service failure: access token", slog.Any("error", err))
		return nil, apperr.Internal("failed to issue access token", err)
	}

	rt, rtClaims, err := uc.tokenService.IssueRefreshToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), currentTime,
	)
	if err != nil {
		req.Logger.Error("Token service failure: refresh token", slog.Any("error", err))
		return nil, apperr.Internal("failed to issue refresh token", err)
	}

	rtEntity, err := entities.NewRefreshToken(
		tokenID, user.ID(), device.ID(), rt, rtClaims.ExpiresAt, currentTime,
	)
	if err != nil {
		return nil, apperr.Map(err)
	}

	if err := uc.refreshRepo.RevokeByDeviceID(user.ID(), device.ID(), currentTime); err != nil {
		req.Logger.Error("Database error during session revocation", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	if err := uc.refreshRepo.Save(rtEntity); err != nil {
		req.Logger.Error("Database error during session persistence", slog.Any("error", err))
		return nil, apperr.Map(err)
	}

	req.Logger.Info("Login session established successfully", slog.String("token_id", tokenID.Value()))

	return &dto.AuthResponse{
		AccessToken:  at.Value(),
		RefreshToken: rt.Value(),
	}, nil
}
