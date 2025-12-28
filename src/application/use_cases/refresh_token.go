package use_cases

import (
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/security"
	"go_auth/src/application/ports/use_cases"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	"time"
)

type refreshTokenUseCase struct {
	userRepository repositories.UserRepositoryPort
	refreshRepo    repositories.RefreshTokenRepositoryPort
	deviceRepo     repositories.DeviceRepositoryPort
	tokenService   security.TokenServicePort
	idFactory      factories.IDFactory
}

var _ use_cases.RefreshTokenUseCasePort = (*refreshTokenUseCase)(nil)

func NewRefreshTokenUseCase(
	userRepository repositories.UserRepositoryPort,
	refreshRepo repositories.RefreshTokenRepositoryPort,
	deviceRepo repositories.DeviceRepositoryPort,
	tokenService security.TokenServicePort,
	idFactory factories.IDFactory,
) *refreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepository: userRepository,
		refreshRepo:    refreshRepo,
		deviceRepo:     deviceRepo,
		tokenService:   tokenService,
		idFactory:      idFactory,
	}
}

func (h *refreshTokenUseCase) RefreshToken(
	oldRefreshToken, deviceIdStr string,
) (*dto.AuthResponse, error) {

	claims, err := h.tokenService.ValidateRefreshToken(oldRefreshToken)
	if err != nil {
		return nil, errors.ErrRefreshTokenExpired
	}

	oldTokenID, err := h.idFactory.TokenIDFromString(claims.JTI)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	isRevoked, err := h.refreshRepo.IsRevoked(oldTokenID)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}
	if isRevoked {
		return nil, errors.ErrRefreshTokenRevoked
	}

	userIDVO, err := h.idFactory.UserIDFromString(claims.Subject)
	if err != nil {
		return nil, errors.ErrInvalidTokenUser
	}

	user, err := h.userRepository.GetByID(userIDVO)
	if err != nil || user == nil {
		return nil, errors.ErrUserNotFound
	}

	deviceID, err := h.idFactory.DeviceIDFromString(deviceIdStr)
	if err != nil {
		return nil, errors.ErrInvalidDeviceID
	}

	device, err := h.deviceRepo.GetByID(deviceID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, errors.ErrInvalidDeviceID
	}

	userIDStr := user.ID.Value.String()
	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = string(r)
	}

	newAccessToken, err := h.tokenService.IssueAccessToken(userIDStr, deviceIdStr, roles)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	newRefreshToken, err := h.tokenService.IssueRefreshToken(userIDStr, deviceIdStr)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	newClaims, err := h.tokenService.ValidateRefreshToken(newRefreshToken.Value)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	newTokenID, err := h.idFactory.TokenIDFromString(newClaims.JTI)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	now := time.Now()

	if err := h.refreshRepo.Revoke(oldTokenID, now); err != nil {
		return nil, errors.ErrRefreshTokenRevoked
	}

	rtEntity := &entities.RefreshToken{
		ID:        newTokenID,
		UserID:    user.ID,
		DeviceID:  deviceID,
		Token:     newRefreshToken.Value,
		ExpiresAt: newClaims.ExpiresAt,
		RevokedAt: nil,
	}

	if err := h.refreshRepo.Save(rtEntity); err != nil {
		return nil, errors.ErrInvalidToken
	}

	return &dto.AuthResponse{
		AccessToken:  newAccessToken.Value,
		RefreshToken: newRefreshToken.Value,
	}, nil
}
