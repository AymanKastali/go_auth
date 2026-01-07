package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type loginUseCase struct {
	userRepo       ports.UserRepositoryPort
	refreshRepo    ports.RefreshTokenRepositoryPort
	deviceRepo     ports.DeviceRepositoryPort
	roleRepo       ports.RoleRepositoryPort
	passwordHasher ports.HashPasswordServicePort
	tokenService   ports.TokenServicePort
	logger         *slog.Logger
}

var _ ports.LoginUseCasePort = (*loginUseCase)(nil)

func NewLoginUseCase(
	userRepo ports.UserRepositoryPort,
	refreshRepo ports.RefreshTokenRepositoryPort,
	deviceRepo ports.DeviceRepositoryPort,
	roleRepo ports.RoleRepositoryPort,
	passwordHasher ports.HashPasswordServicePort,
	tokenService ports.TokenServicePort,
	logger *slog.Logger,
) ports.LoginUseCasePort {
	return &loginUseCase{
		userRepo:       userRepo,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		logger:         logger,
	}
}

func (h *loginUseCase) Execute(
	email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
) (*dto.AuthResponse, error) {
	h.logger.Info("Starting user login", "email", email)
	nowUTC := time.Now().UTC()

	// 1. Authentication
	user, err := h.authenticate(email, password)
	if err != nil {
		return nil, err
	}

	// 2. Device Identity Management
	device, err := h.resolveDevice(user.ID(), deviceIDStr, deviceName, userAgent, ipAddress, nowUTC)
	if err != nil {
		return nil, err
	}

	// 3. Authorization Context (Fetch Roles)
	roleNames, err := h.fetchRoleNames(user.RoleIDs())
	if err != nil {
		return nil, err
	}

	// 4. Token Issuance and Session Persistence
	return h.issueTokensAndSaveSession(user, device, roleNames, nowUTC)
}

// --- Internal Helper Methods ---

func (h *loginUseCase) authenticate(email, password string) (*aggregates.User, error) {
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	user, err := h.userRepo.GetByEmail(emailVO)
	if err != nil {
		return nil, err
	}
	if user == nil || !h.passwordHasher.Compare(password, user.HashedPassword().Value()) {
		return nil, apperr.NewUnauthorizedErr("invalid credentials")
	}

	return user, nil
}

func (h *loginUseCase) resolveDevice(userID valueobjects.UserID, dIDStr, name, ua, ip string, now time.Time) (*entities.Device, error) {
	deviceID, err := valueobjects.DeviceIDFromString(dIDStr)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		return nil, err
	}

	if device == nil {
		device, err = entities.NewDevice(deviceID, userID, &name, &ua, &ip, true, now)
		if err != nil {
			return nil, apperr.MapDomainErr(err)
		}
	} else {
		device.Update(now, &name, &ua, &ip)
	}

	if err := h.deviceRepo.Upsert(device); err != nil {
		return nil, apperr.NewInternalErr("failed to save device info")
	}

	return device, nil
}

func (h *loginUseCase) fetchRoleNames(roleIDs []valueobjects.RoleID) ([]string, error) {
	roleNames := make([]string, 0, len(roleIDs))
	// Optimization: If your repository supports GetByIDs([]RoleID), use it here.
	// Otherwise, this loop is acceptable if the number of roles per user is small.
	for _, roleID := range roleIDs {
		role, err := h.roleRepo.GetByID(roleID)
		if err != nil {
			return nil, err
		}
		if role != nil {
			roleNames = append(roleNames, role.Name())
		}
	}
	return roleNames, nil
}

func (h *loginUseCase) issueTokensAndSaveSession(user *aggregates.User, device *entities.Device, roles []string, now time.Time) (*dto.AuthResponse, error) {
	// 1. Generate Access Token
	accessToken, _, err := h.tokenService.IssueAccessToken(user.ID().String(), device.ID().String(), roles)
	if err != nil {
		return nil, err // JWT adapter now returns apperr.NewInternalErr or NewUnauthorizedErr
	}

	// 2. Generate Refresh Token
	refreshToken, refreshClaims, err := h.tokenService.IssueRefreshToken(user.ID().String(), device.ID().String())
	if err != nil {
		return nil, err
	}

	// 3. Persist Session
	tokenID, err := valueobjects.TokenIDFromString(refreshClaims.JTI)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	refreshTokenEntity, err := entities.NewRefreshToken(
		tokenID, user.ID(), device.ID(), refreshToken.Value(), refreshClaims.ExpiresAt, now,
	)
	if err != nil {
		return nil, apperr.MapDomainErr(err)
	}

	// Cleanup: Invalidate other sessions for this specific device (Rotate tokens)
	if err := h.refreshRepo.RevokeByDeviceID(user.ID(), device.ID(), now); err != nil {
		return nil, err
	}

	if err := h.refreshRepo.Save(refreshTokenEntity); err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value(),
		RefreshToken: refreshToken.Value(),
	}, nil
}
