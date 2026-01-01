package mappers

import (
	"fmt"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type RefreshTokenMapper struct{}

func NewRefreshTokenMapper() *RefreshTokenMapper {
	return &RefreshTokenMapper{}
}

// ToDomain converts a GORM model to a domain entity
func (m *RefreshTokenMapper) ToDomain(rt *models.RefreshToken) (*entities.RefreshToken, error) {
	if rt == nil {
		return nil, nil
	}

	tokenID, err := valueobjects.TokenIDFromString(rt.ID)
	if err != nil {
		return nil, fmt.Errorf("refresh token mapper: invalid ID '%s': %w", rt.ID, err)
	}

	userID, err := valueobjects.UserIDFromString(rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("refresh token mapper: invalid User ID '%s': %w", rt.UserID, err)
	}

	deviceID, err := valueobjects.DeviceIDFromString(rt.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("refresh token mapper: invalid Device ID '%s': %w", rt.DeviceID, err)
	}

	// Use CreatedAt or UpdatedAt as "now" for factory
	now := time.Now().UTC()

	refreshToken, err := entities.NewRefreshToken(
		tokenID,
		userID,
		deviceID,
		rt.Token,
		rt.ExpiresAt,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("refresh token mapper: failed to create domain entity: %w", err)
	}

	// Restore revoked time from DB
	if rt.RevokedAt != nil {
		refreshToken.Revoke(*rt.RevokedAt)
	}

	return refreshToken, nil
}

// ToModel converts a domain entity to a GORM model
func (m *RefreshTokenMapper) ToModel(rt *entities.RefreshToken) *models.RefreshToken {
	if rt == nil {
		return nil
	}

	return &models.RefreshToken{
		ID:        rt.ID().String(),
		UserID:    rt.UserID().String(),
		DeviceID:  rt.DeviceID().String(),
		Token:     rt.Token(),
		ExpiresAt: rt.ExpiresAt(),
		RevokedAt: rt.RevokedAt(),
		CreatedAt: rt.CreatedAt(),
		UpdatedAt: rt.UpdatedAt(),
	}
}
