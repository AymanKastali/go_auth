package mappers

import (
	"fmt"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/domain/entities"
)

type RefreshTokenMapper struct {
	uuidMapper *UUIDMapper
}

func NewRefreshTokenMapper(
	uuidMapper *UUIDMapper,
) *RefreshTokenMapper {
	return &RefreshTokenMapper{
		uuidMapper: uuidMapper,
	}
}

// ToDomain converts a GORM model to a domain entity
func (m *RefreshTokenMapper) ToDomain(rt *models.RefreshToken) (*entities.RefreshToken, error) {
	if rt == nil {
		return nil, nil
	}

	tokenID, err := m.uuidMapper.TokenIdFromString(rt.ID)
	if err != nil {
		return nil, fmt.Errorf("refresh token mapper: invalid ID '%s': %w", rt.ID, err)
	}

	userID, err := m.uuidMapper.UserIdFromString(rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("refresh token mapper: invalid User ID '%s': %w", rt.UserID, err)
	}

	deviceID, err := m.uuidMapper.DeviceIdFromString(rt.DeviceID)
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
		ID:        m.uuidMapper.TokenIdToString(rt.ID),
		UserID:    m.uuidMapper.UserIdToString(rt.UserID),
		DeviceID:  m.uuidMapper.DeviceIdToString(rt.DeviceID),
		Token:     rt.Token,
		ExpiresAt: rt.ExpiresAt,
		RevokedAt: rt.RevokedAt,
	}
}
