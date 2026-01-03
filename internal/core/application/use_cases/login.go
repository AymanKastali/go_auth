package use_cases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/application/ports/use_cases"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports/repositories"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type loginUseCase struct {
	userRepository repositories.UserRepositoryPort
	refreshRepo    repositories.RefreshTokenRepositoryPort
	deviceRepo     repositories.DeviceRepositoryPort
	passwordHasher security.HashPasswordPort
	tokenService   security.TokenServicePort
	logger         *slog.Logger
}

var _ use_cases.LoginUseCasePort = (*loginUseCase)(nil)

func NewLoginUseCase(
	userRepository repositories.UserRepositoryPort,
	refreshRepo repositories.RefreshTokenRepositoryPort,
	deviceRepo repositories.DeviceRepositoryPort,
	passwordHasher security.HashPasswordPort,
	tokenService security.TokenServicePort,
	logger *slog.Logger,
) *loginUseCase {
	return &loginUseCase{
		userRepository: userRepository,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		logger:         logger,
	}
}

func (h *loginUseCase) Login(
	email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
) (*dto.AuthResponse, error) {
	h.logger.Info("Starting user login", "email", email)

	// 1. DOMAIN: Parse and validate email
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 2. INFRASTRUCTURE: Fetch user
	user, err := h.userRepository.GetByEmail(emailVO)
	if err != nil {
		h.logger.Error("User repository failure", "error", err)
		return nil, apperr.NewInternal("database connection failed")
	}

	// 3. APPLICATION: Logical check (Security: generic message)
	if user == nil {
		return nil, apperr.NewUnauthorized("invalid credentials")
	}

	// 4. APPLICATION: Password validation
	if !h.passwordHasher.Compare(password, user.HashedPassword().Value()) {
		return nil, apperr.NewUnauthorized("invalid credentials")
	}

	// 5. DOMAIN: Device ID parsing
	deviceID, err := valueobjects.DeviceIDFromString(deviceIDStr)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 6. INFRASTRUCTURE: Fetch device
	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		return nil, apperr.NewInternal("device lookup failed")
	}

	now := time.Now().UTC()
	if device == nil {
		device, err = entities.NewDevice(deviceID, user.ID(), &deviceName, &userAgent, &ipAddress, true, now)
		if err != nil {
			return nil, apperr.MapDomain(err)
		}
	} else {
		device.Update(now, &deviceName, &userAgent, &ipAddress)
	}

	// 7. INFRASTRUCTURE: Save device
	if err := h.deviceRepo.Upsert(device); err != nil {
		return nil, apperr.NewInternal("failed to update device info")
	}

	// 8. INFRASTRUCTURE: Token Issuance
	accessToken, err := h.tokenService.IssueAccessToken(user.ID().String(), deviceID.String(), nil)
	if err != nil {
		return nil, apperr.NewInternal("token generation failed")
	}

	refreshToken, err := h.tokenService.IssueRefreshToken(user.ID().String(), deviceID.String())
	if err != nil {
		return nil, apperr.NewInternal("refresh token generation failed")
	}

	// 9. DOMAIN: Token ID parsing
	rtClaims, _ := h.tokenService.ValidateRefreshToken(refreshToken.Value)
	tokenID, err := valueobjects.TokenIDFromString(rtClaims.JTI)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 10. DOMAIN: Entity creation
	refreshTokenEntity, err := entities.NewRefreshToken(tokenID, user.ID(), device.ID(), refreshToken.Value, rtClaims.ExpiresAt, now)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 11. INFRASTRUCTURE: Rotation
	if err := h.refreshRepo.RevokeByDeviceID(user.ID(), device.ID(), now); err != nil {
		return nil, apperr.NewInternal("failed to revoke old tokens")
	}

	if err := h.refreshRepo.Save(refreshTokenEntity); err != nil {
		return nil, apperr.NewInternal("failed to save session")
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}
