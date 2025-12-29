package use_cases

import (
	"fmt"
	"go_auth/internal/application/dto"
	"go_auth/internal/application/ports/security"
	"go_auth/internal/application/ports/use_cases"
	"go_auth/internal/domain/domainerr"
	"go_auth/internal/domain/entities"
	"go_auth/internal/domain/factories"
	"go_auth/internal/domain/ports/repositories"
	"go_auth/internal/domain/valueobjects"
	"log/slog"
	"time"
)

type loginUseCase struct {
	userRepository repositories.UserRepositoryPort
	refreshRepo    repositories.RefreshTokenRepositoryPort
	deviceRepo     repositories.DeviceRepositoryPort
	passwordHasher security.HashPasswordPort
	tokenService   security.TokenServicePort
	emailFactory   factories.EmailFactory
	idFactory      factories.IDFactory
	deviceFactory  *factories.DeviceFactory
	logger         *slog.Logger
}

var _ use_cases.LoginUseCasePort = (*loginUseCase)(nil)

func NewLoginUseCase(
	userRepository repositories.UserRepositoryPort,
	refreshRepo repositories.RefreshTokenRepositoryPort,
	deviceRepo repositories.DeviceRepositoryPort,
	passwordHasher security.HashPasswordPort,
	tokenService security.TokenServicePort,
	emailFactory factories.EmailFactory,
	deviceFactory *factories.DeviceFactory,
	logger *slog.Logger,
) *loginUseCase {
	return &loginUseCase{
		userRepository: userRepository,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		emailFactory:   emailFactory,
		deviceFactory:  deviceFactory,
		logger:         logger,
	}
}

func (h *loginUseCase) Login(
	email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
) (*dto.AuthResponse, error) {

	h.logger.Info("Starting user login", "email", email, "deviceID", deviceIDStr)

	// --- Parse and validate email ---
	emailVO, err := h.emailFactory.New(email)
	if err != nil {
		h.logger.Error("Invalid email provided", "email", email, "error", err)
		return nil, domainerr.ErrInvalidCredentials
	}

	// --- Fetch user ---
	user, err := h.userRepository.GetByEmail(emailVO)
	if err != nil || user == nil {
		h.logger.Warn("User not found", "email", email)
		return nil, domainerr.ErrInvalidCredentials
	}

	// --- Validate password ---
	if !h.passwordHasher.Compare(password, user.PasswordHash.Value) {
		h.logger.Warn("Invalid password attempt", "email", email)
		return nil, domainerr.ErrInvalidCredentials
	}

	h.logger.Info("User authenticated successfully", "email", email, "userID", user.ID)

	// --- Convert IDs for JWT / repository ---
	userIDStr := user.ID.Value.String()
	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = string(r)
	}

	// --- DEVICE HANDLING ---
	deviceID, err := valueobjects.NewDeviceIdFromString(deviceIDStr)
	if err != nil {
		h.logger.Error("Invalid device ID", "deviceID", deviceIDStr, "error", err)
		return nil, domainerr.ErrInvalidCredentials
	}

	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		h.logger.Error("Failed to fetch device", "deviceID", deviceIDStr, "error", err)
		return nil, fmt.Errorf("device repo error: %w", err)
	}

	now := time.Now()
	if device == nil {
		device, err = h.deviceFactory.New(
			user.ID,
			deviceID,
			&deviceName,
			&userAgent,
			&ipAddress,
			now,
		)
		if err != nil {
			h.logger.Error("Failed to create device entity", "userID", user.ID, "error", err)
			return nil, fmt.Errorf("failed to create device entity: %w", err)
		}
		h.logger.Info("New device created", "userID", user.ID, "deviceID", device.ID)
	} else {
		device.UpdateLastSeen(now)
		device.Name = &deviceName
		device.UserAgent = &userAgent
		device.IPAddress = &ipAddress
		h.logger.Info("Existing device updated", "userID", user.ID, "deviceID", device.ID)
	}

	// Upsert device
	if err := h.deviceRepo.Upsert(device); err != nil {
		h.logger.Error("Failed to upsert device", "deviceID", device.ID, "error", err)
		return nil, fmt.Errorf("device repository: failed to upsert device: %w", err)
	}

	// --- ISSUE TOKENS ---
	accessToken, err := h.tokenService.IssueAccessToken(userIDStr, deviceIDStr, roles)
	if err != nil {
		h.logger.Error("Failed to issue access token", "userID", user.ID, "error", err)
		return nil, err
	}

	refreshToken, err := h.tokenService.IssueRefreshToken(userIDStr, deviceIDStr)
	if err != nil {
		h.logger.Error("Failed to issue refresh token", "userID", user.ID, "error", err)
		return nil, err
	}

	// --- SAVE REFRESH TOKEN IN DB ---
	rtClaims, err := h.tokenService.ValidateRefreshToken(refreshToken.Value)
	if err != nil {
		h.logger.Error("Failed to validate refresh token", "userID", user.ID, "error", err)
		return nil, err
	}

	tokenID, err := h.idFactory.TokenIDFromString(rtClaims.JTI)
	if err != nil {
		h.logger.Error("Failed to parse refresh token ID", "userID", user.ID, "error", err)
		return nil, err
	}

	refreshTokenEntity := &entities.RefreshToken{
		ID:        tokenID,
		UserID:    user.ID,
		DeviceID:  device.ID,
		Token:     refreshToken.Value,
		ExpiresAt: rtClaims.ExpiresAt,
		RevokedAt: nil,
	}

	if err := h.refreshRepo.RevokeByDeviceID(user.ID, device.ID, now); err != nil {
		h.logger.Error("Failed to rotate refresh tokens", "userID", user.ID, "deviceID", device.ID, "error", err)
		return nil, fmt.Errorf("failed to rotate session: %w", err)
	}

	if err := h.refreshRepo.Save(refreshTokenEntity); err != nil {
		h.logger.Error("Failed to save refresh token", "userID", user.ID, "deviceID", device.ID, "error", err)
		return nil, err
	}

	h.logger.Info("User login successful", "userID", user.ID, "deviceID", device.ID)

	// --- RETURN RESPONSE ---
	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}
