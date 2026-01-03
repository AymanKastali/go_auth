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
		h.logger.Error("Invalid email", "error", err)
		return nil, apperr.MapDomain(err) // Business rule violation
	}

	// 2. INFRASTRUCTURE: Fetch user
	user, err := h.userRepository.GetByEmail(emailVO)
	if err != nil {
		h.logger.Error("User repository failure", "error", err)
		return nil, apperr.ErrInternal // Securely hide DB specifics
	}

	// 3. APPLICATION: Logical check
	if user == nil {
		h.logger.Warn("Login attempt: User not found", "email", email)
		return nil, apperr.ErrInvalidCredentials
	}

	// 4. APPLICATION: Password validation
	if !h.passwordHasher.Compare(password, user.HashedPassword().Value()) {
		h.logger.Warn("Login attempt: Password mismatch", "email", email)
		return nil, apperr.ErrInvalidCredentials
	}

	// 5. DOMAIN: Device ID parsing
	deviceID, err := valueobjects.DeviceIDFromString(deviceIDStr)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 6. INFRASTRUCTURE: Fetch device
	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		h.logger.Error("Device repo failure", "error", err)
		return nil, apperr.ErrInternal
	}

	now := time.Now().UTC()
	if device == nil {
		// DOMAIN: Entity creation
		device, err = entities.NewDevice(deviceID, user.ID(), &deviceName, &userAgent, &ipAddress, true, now)
		if err != nil {
			return nil, apperr.MapDomain(err)
		}
	} else {
		device.Update(now, &deviceName, &userAgent, &ipAddress)
	}

	// 7. INFRASTRUCTURE: Save device
	if err := h.deviceRepo.Upsert(device); err != nil {
		h.logger.Error("Device upsert failure", "error", err)
		return nil, apperr.ErrInternal
	}

	// 8. INFRASTRUCTURE: Token Issuance
	accessToken, err := h.tokenService.IssueAccessToken(user.ID().String(), deviceID.String(), nil)
	if err != nil {
		h.logger.Error("Token service failure", "error", err)
		return nil, apperr.ErrInternal
	}

	refreshToken, err := h.tokenService.IssueRefreshToken(user.ID().String(), deviceID.String())
	if err != nil {
		return nil, apperr.ErrInternal
	}

	// 9. DOMAIN: Parsing token JTI
	rtClaims, _ := h.tokenService.ValidateRefreshToken(refreshToken.Value)
	tokenID, err := valueobjects.TokenIDFromString(rtClaims.JTI)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 10. DOMAIN: Create Refresh Token Entity
	refreshTokenEntity, err := entities.NewRefreshToken(tokenID, user.ID(), device.ID(), refreshToken.Value, rtClaims.ExpiresAt, now)
	if err != nil {
		return nil, apperr.MapDomain(err)
	}

	// 11. INFRASTRUCTURE: Final persistence
	if err := h.refreshRepo.RevokeByDeviceID(user.ID(), device.ID(), now); err != nil {
		h.logger.Error("Token revocation failure", "error", err)
		return nil, apperr.ErrInternal
	}

	if err := h.refreshRepo.Save(refreshTokenEntity); err != nil {
		h.logger.Error("Token save failure", "error", err)
		return nil, apperr.ErrInternal
	}

	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}
