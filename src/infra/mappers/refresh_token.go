package mappers

import (
	"fmt"
	"go_auth/src/domain/entities"
	"go_auth/src/infra/persistence/postgres/models"
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

	tokenId, err := m.uuidMapper.TokenIdFromString(rt.ID)
	if err != nil {
		return nil, fmt.Errorf("refresh token mapper: invalid ID '%s': %w", rt.ID, err)
	}

	userId, err := m.uuidMapper.UserIdFromString(rt.UserId)
	if err != nil {
		return nil, fmt.Errorf("refresh token mapper: invalid User ID '%s': %w", rt.UserId, err)
	}

	deviceId, err := m.uuidMapper.DeviceIdFromString(rt.DeviceId)
	if err != nil {
		return nil, fmt.Errorf("refresh token mapper: invalid Device ID '%s': %w", rt.DeviceId, err)
	}

	return &entities.RefreshToken{
		ID:        tokenId,
		UserId:    userId,
		DeviceId:  deviceId,
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
		UserId:    m.uuidMapper.UserIdToString(rt.UserId),
		DeviceId:  m.uuidMapper.DeviceIdToString(rt.DeviceId),
		Token:     rt.Token,
		ExpiresAt: rt.ExpiresAt,
		RevokedAt: rt.RevokedAt,
	}
}
