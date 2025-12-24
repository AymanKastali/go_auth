package handlers

import (
	"fmt"
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/security"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	"time"
)

type LoginHandler struct {
	userRepository repositories.UserRepositoryPort
	refreshRepo    repositories.RefreshTokenRepositoryPort
	deviceRepo     repositories.DeviceRepositoryPort
	passwordHasher security.HashPasswordPort
	tokenService   security.TokenServicePort
	emailFactory   factories.EmailFactory
	idFactory      factories.IDFactory
}

func NewLoginHandler(
	userRepository repositories.UserRepositoryPort,
	refreshRepo repositories.RefreshTokenRepositoryPort,
	deviceRepo repositories.DeviceRepositoryPort,
	passwordHasher security.HashPasswordPort,
	tokenService security.TokenServicePort,
	emailFactory factories.EmailFactory,
	idFactory factories.IDFactory,
) *LoginHandler {
	return &LoginHandler{
		userRepository: userRepository,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		emailFactory:   emailFactory,
		idFactory:      idFactory,
	}
}

func (h *LoginHandler) Execute(
	email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
) (*dto.AuthResponse, error) {

	// --- Parse and validate email ---
	emailVO, err := h.emailFactory.New(email)
	if err != nil {
		return nil, err
	}

	// --- Fetch user ---
	user, err := h.userRepository.GetByEmail(emailVO)
	if err != nil || user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	// --- Validate password ---
	if !h.passwordHasher.Compare(password, user.PasswordHash.Value) {
		return nil, errors.ErrInvalidCredentials
	}

	// --- Convert IDs for JWT / repository ---
	userIDStr := user.ID.Value.String()
	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = string(r)
	}

	// --- DEVICE HANDLING (NEW) ---
	// Convert deviceId string to VO
	deviceID, err := h.idFactory.DeviceIDFromString(deviceIDStr)
	if err != nil {
		return nil, err
	}

	// Try to fetch existing device (new method could be added to repo)
	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if device == nil {
		// --- CREATE NEW DEVICE ---
		device = &entities.Device{
			ID:         deviceID,
			UserId:     user.ID,
			Name:       &deviceName,
			UserAgent:  &userAgent,
			IPAddress:  &ipAddress,
			IsActive:   true,
			CreatedAt:  now,
			LastSeenAt: &now,
		}
	} else {
		// --- UPDATE EXISTING DEVICE ---
		device.UpdateLastSeen(now)
		device.Name = &deviceName
		device.UserAgent = &userAgent
		device.IPAddress = &ipAddress
	}

	// Upsert device
	if err := h.deviceRepo.Upsert(device); err != nil {
		return nil, fmt.Errorf("device repository: failed to upsert device: %w", err)
	}

	// --- ISSUE TOKENS (CHANGED: pass deviceId) ---
	accessToken, err := h.tokenService.IssueAccessToken(userIDStr, deviceIDStr, roles)
	if err != nil {
		return nil, err
	}

	refreshToken, err := h.tokenService.IssueRefreshToken(userIDStr, deviceIDStr)
	if err != nil {
		return nil, err
	}

	// --- SAVE REFRESH TOKEN IN DB (CHANGED: create entity) ---
	rtClaims, err := h.tokenService.ValidateRefreshToken(refreshToken.Value)
	if err != nil {
		return nil, err
	}

	tokenID, err := h.idFactory.TokenIDFromString(rtClaims.JTI)
	if err != nil {
		return nil, err
	}

	refreshTokenEntity := &entities.RefreshToken{
		ID:        tokenID,
		UserId:    user.ID,
		DeviceId:  device.ID, // bind refresh token to device
		Token:     refreshToken.Value,
		ExpiresAt: rtClaims.ExpiresAt,
		RevokedAt: nil,
	}

	if err := h.refreshRepo.Save(refreshTokenEntity); err != nil {
		return nil, err
	}

	// --- RETURN RESPONSE ---
	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}
