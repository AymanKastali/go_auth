package use_cases

import (
	"fmt"
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

	h.logger.Info("Starting user login", "email", email, "deviceID", deviceIDStr)

	// --- Parse and validate email ---
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		h.logger.Error("Invalid email provided", "email", email, "error", err)
		return nil, apperr.FromDomainError(err)
	}

	// --- Fetch user ---
	user, err := h.userRepository.GetByEmail(emailVO)
	if err != nil {
		h.logger.Error("User repository failed", "email", email, "error", err)
		return nil, apperr.ErrInternal
	}

	if user == nil {
		h.logger.Warn("User not found", "email", email)
		return nil, apperr.ErrInvalidCredentials
	}

	userIDVO := user.ID()

	// --- Validate password ---
	if !h.passwordHasher.Compare(password, user.HashedPassword().Value()) {
		h.logger.Warn("Invalid password attempt", "email", email)
		return nil, apperr.ErrInvalidCredentials
	}

	h.logger.Info("User authenticated successfully", "email", email, "userID", userIDVO)

	// --- Convert IDs for JWT / repository ---
	userIDStr := userIDVO.String()
	roles := make([]string, len(user.Roles()))
	for i, r := range user.Roles() {
		roles[i] = string(r)
	}

	// --- DEVICE HANDLING ---
	deviceID, err := valueobjects.DeviceIDFromString(deviceIDStr)
	if err != nil {
		h.logger.Error("Invalid device ID", "deviceID", deviceIDStr, "error", err)
		return nil, apperr.FromDomainError(err)
	}

	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		h.logger.Error("Failed to fetch device", "deviceID", deviceIDStr, "error", err)
		return nil, fmt.Errorf("device repo error: %w", err)
	}

	now := time.Now().UTC()
	if device == nil {
		device, err = entities.NewDevice(
			deviceID,
			userIDVO,
			&deviceName,
			&userAgent,
			&ipAddress,
			true,
			now,
		)
		if err != nil {
			h.logger.Error("Failed to create device entity", "userID", userIDVO, "error", err)
			return nil, fmt.Errorf("failed to create device entity: %w", err)
		}
		h.logger.Info("New device created", "userID", userIDVO, "deviceID", device.ID())
	} else {
		device.Update(
			now,
			&deviceName,
			&userAgent,
			&ipAddress,
		)
		h.logger.Info("Existing device updated", "userID", userIDVO, "deviceID", device.ID())
	}

	// Upsert device
	if err := h.deviceRepo.Upsert(device); err != nil {
		h.logger.Error("Failed to upsert device", "deviceID", device.ID(), "error", err)
		return nil, fmt.Errorf("device repository: failed to upsert device: %w", err)
	}

	deviceIDVO := device.ID()

	// --- ISSUE TOKENS ---
	accessToken, err := h.tokenService.IssueAccessToken(userIDStr, deviceIDStr, roles)
	if err != nil {
		h.logger.Error("Failed to issue access token", "userID", userIDVO, "error", err)
		return nil, err
	}

	refreshToken, err := h.tokenService.IssueRefreshToken(userIDStr, deviceIDStr)
	if err != nil {
		h.logger.Error("Failed to issue refresh token", "userID", userIDVO, "error", err)
		return nil, err
	}

	// --- SAVE REFRESH TOKEN IN DB ---
	rtClaims, err := h.tokenService.ValidateRefreshToken(refreshToken.Value)
	if err != nil {
		h.logger.Error("Failed to validate refresh token", "userID", userIDVO, "error", err)
		return nil, err
	}

	tokenID, err := valueobjects.TokenIDFromString(rtClaims.JTI)
	if err != nil {
		h.logger.Error("Failed to parse refresh token ID", "userID", userIDVO, "error", err)
		return nil, err
	}

	refreshTokenEntity, err := entities.NewRefreshToken(
		tokenID,
		userIDVO,
		deviceIDVO,
		refreshToken.Value,
		rtClaims.ExpiresAt,
		now,
	)
	if err != nil {
		h.logger.Error(
			"Failed to create refresh token entity",
			"userID", userIDVO,
			"deviceID", deviceIDVO,
			"error", err,
		)
		return nil, err
	}

	if err := h.refreshRepo.RevokeByDeviceID(userIDVO, deviceIDVO, now); err != nil {
		h.logger.Error("Failed to rotate refresh tokens", "userID", userIDVO, "deviceID", deviceIDVO, "error", err)
		return nil, fmt.Errorf("failed to rotate session: %w", err)
	}

	if err := h.refreshRepo.Save(refreshTokenEntity); err != nil {
		h.logger.Error("Failed to save refresh token", "userID", userIDVO, "deviceID", deviceIDVO, "error", err)
		return nil, err
	}

	h.logger.Info("User login successful", "userID", userIDVO, "deviceID", deviceIDVO)

	// --- RETURN RESPONSE ---
	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}
