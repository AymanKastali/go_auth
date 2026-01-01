package mappers

import (
	"fmt"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
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

	return &entities.RefreshToken{
		ID:        tokenID,
		UserID:    userID,
		DeviceID:  deviceID,
		Token:     rt.Token,
		CreatedAt: rt.CreatedAt,
		ExpiresAt: rt.ExpiresAt,
		RevokedAt: rt.RevokedAt,
	}, nil
}

// ToModel converts a domain entity to a GORM model
func (m *RefreshTokenMapper) ToModel(rt *entities.RefreshToken) *models.RefreshToken {
	if rt == nil {
		return nil
	}

	return &models.RefreshToken{
		ID:        rt.ID.String(),
		UserID:    rt.UserID.String(),
		DeviceID:  rt.DeviceID.String(),
		Token:     rt.Token,
		ExpiresAt: rt.ExpiresAt,
		RevokedAt: rt.RevokedAt,
	}
}
