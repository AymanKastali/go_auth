package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/interfaces"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type RefreshTokenMapper struct {
	uuidParser interfaces.IUUIDParserService
}

var _ IRefreshTokenMapper = (*RefreshTokenMapper)(nil)

func NewRefreshTokenMapper() IRefreshTokenMapper {
	return &RefreshTokenMapper{}
}

func (m *RefreshTokenMapper) ToDomain(rt *models.RefreshToken) (*entities.RefreshToken, error) {
	if rt == nil {
		return nil, pgerr.ErrNotFound
	}

	tokenID, err := m.uuidParser.ParseTokenID(rt.ID)
	if err != nil {
		return nil, err
	}

	userID, err := m.uuidParser.ParseUserID(rt.UserID)
	if err != nil {
		return nil, err
	}

	deviceID, err := m.uuidParser.ParseDeviceID(rt.DeviceID)
	if err != nil {
		return nil, err
	}

	tokenVO := valueobjects.ReconstituteToken(rt.Token)

	refreshToken := entities.ReconstituteRefreshToken(
		tokenID,
		userID,
		deviceID,
		tokenVO,
		rt.ExpiresAt,
		rt.RevokedAt,
		rt.CreatedAt,
		rt.UpdatedAt,
		rt.DeletedAt,
	)

	if rt.RevokedAt != nil {
		refreshToken.Revoke(*rt.RevokedAt)
	}

	return refreshToken, nil
}

func (m *RefreshTokenMapper) ToModel(e *entities.RefreshToken) *models.RefreshToken {
	if e == nil {
		return nil
	}

	return &models.RefreshToken{
		ID:        e.ID().Value(),
		UserID:    e.UserID().Value(),
		DeviceID:  e.DeviceID().Value(),
		Token:     e.Token().Value(),
		ExpiresAt: e.ExpiresAt(),
		RevokedAt: e.RevokedAt(),
		CreatedAt: e.CreatedAt(),
		UpdatedAt: e.UpdatedAt(),
	}
}
