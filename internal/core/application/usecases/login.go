package usecases

import (
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
	userRepo       dports.IUserRepository
	refreshRepo    dports.IRefreshTokenRepository
	deviceRepo     dports.IDeviceRepository
	roleRepo       dports.IRoleRepository
	passwordHasher dports.IPasswordService
	tokenService   aports.ITokenService
	idSvc          ports.IIDService
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
	idSvc ports.IIDService,
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
	requestID string, // Pass requestID as a string to keep the layer pure
	email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
) (*dto.AuthResponse, error) {
	uc.logger.Info("Starting user login", "email", email, "request_id", requestID)
	now := uc.clock.Now().UTC()

	// 1. Authenticate User
	user, err := uc.authenticate(requestID, email, password)
	if err != nil {
		return nil, err
	}

	// 2. Resolve Device
	device, err := uc.resolveDevice(requestID, user.ID(), deviceIDStr, deviceName, userAgent, ipAddress, now)
	if err != nil {
		return nil, err
	}

	// 3. Fetch Permissions
	roleNames, err := uc.fetchRoleNames(requestID, user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 4. Generate Token ID
	tokenID, err := valueobjects.NewTokenID(uc.idSvc.Generate())
	if err != nil {
		return nil, apperr.Internal("failed to generate unique token identifier", requestID, err)
	}

	// 5. Finalize Session
	return uc.issueTokensAndSaveSession(requestID, tokenID, user, device, roleNames, now)
}

func (uc *loginUseCase) authenticate(requestID, email, password string) (*aggregates.User, error) {
	emailVO := valueobjects.ReconstituteEmail(email)
	user, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	// Security: Use a generic error for both "user not found" and "wrong password"
	if user == nil || !uc.passwordHasher.Compare(password, user.HashedPassword().Value()) {
		return nil, apperr.Unauthorized("invalid credentials", requestID, nil)
	}

	return user, nil
}

func (uc *loginUseCase) resolveDevice(
	requestID string,
	userID valueobjects.UserID,
	deviceIDStr, name, ua, ip string,
	currentTime time.Time,
) (*entities.Device, error) {
	if !uc.idSvc.IsValid(deviceIDStr) {
		return nil, apperr.Invalid("invalid device id format", requestID, nil)
	}

	deviceIDVO := valueobjects.ReconstituteDeviceID(deviceIDStr)

	device, err := uc.deviceRepo.GetByID(deviceIDVO)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	if device == nil {
		device, err = entities.NewDevice(deviceIDVO, userID, &name, &ua, &ip, currentTime)
		if err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}
		device.Activate(currentTime)
	} else {
		if err := device.BelongsTo(userID); err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}

		if err := device.EnsureUsable(); err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}

		if err := device.MarkSeen(currentTime); err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}

		if err := device.UpdateMetadata(currentTime, &name, &ua, &ip); err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}
	}

	if err := uc.deviceRepo.Upsert(device); err != nil {
		return nil, apperr.Internal("storage error updating device", requestID, err)
	}

	return device, nil
}

func (uc *loginUseCase) fetchRoleNames(requestID string, roleIDs []valueobjects.RoleID) ([]string, error) {
	roleNames := make([]string, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		role, err := uc.roleRepo.GetByID(roleID)
		if err != nil {
			return nil, apperr.FromDomain(err, requestID)
		}
		if role != nil {
			roleNames = append(roleNames, role.Name())
		}
	}
	return roleNames, nil
}

func (uc *loginUseCase) issueTokensAndSaveSession(requestID string, tokenID valueobjects.TokenID, user *aggregates.User, device *entities.Device, roles []string, currentTime time.Time) (*dto.AuthResponse, error) {
	accessToken, _, err := uc.tokenService.IssueAccessToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), roles, currentTime,
	)
	if err != nil {
		return nil, apperr.Internal("access token generation failed", requestID, err)
	}

	refreshToken, refreshClaims, err := uc.tokenService.IssueRefreshToken(
		tokenID.Value(), user.ID().Value(), device.ID().Value(), currentTime,
	)
	if err != nil {
		return nil, apperr.Internal("refresh token generation failed", requestID, err)
	}

	refreshTokenEntity, err := entities.NewRefreshToken(
		tokenID, user.ID(), device.ID(), refreshToken, refreshClaims.ExpiresAt, currentTime,
	)
	if err != nil {
		return nil, apperr.FromDomain(err, requestID)
	}

	if err := uc.refreshRepo.RevokeByDeviceID(user.ID(), device.ID(), currentTime); err != nil {
		return nil, apperr.Internal("failed to revoke old sessions", requestID, err)
	}

	if err := uc.refreshRepo.Save(refreshTokenEntity); err != nil {
		return nil, apperr.Internal("failed to save new session", requestID, err)
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value(),
		RefreshToken: refreshToken.Value(),
	}, nil
}
