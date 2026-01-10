package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/interfaces"
	"go_auth/internal/core/domain/entities"
)

type RefreshTokenMapper struct {
	uuidParser interfaces.IUUIDParserService
}

var _ IRefreshTokenMapper = (*RefreshTokenMapper)(nil)

func NewRefreshTokenMapper() IRefreshTokenMapper {
	return &RefreshTokenMapper{}
}

func (m *RefreshTokenMapper) ToDomain(rt *models.RefreshToken) (*entities.RefreshToken, error) {
	entity := "RefreshToken"
	if rt == nil {
		return nil, nil
	}

	tokenID, err := m.uuidParser.ParseTokenID(rt.ID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, rt.ID, err)
	}

	userID, err := m.uuidParser.ParseUserID(rt.UserID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, rt.UserID, err)
	}

	deviceID, err := m.uuidParser.ParseDeviceID(rt.DeviceID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, rt.DeviceID, err)
	}

	// Rehydrate the entity (using NewRefreshToken as a Reconstitutor here)
	refreshToken, err := entities.NewRefreshToken(
		tokenID,
		userID,
		deviceID,
		rt.Token,
		rt.ExpiresAt,
		rt.CreatedAt, // Use DB time for consistency
	)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, rt.ID, err)
	}

	if rt.RevokedAt != nil {
		refreshToken.Revoke(*rt.RevokedAt)
	}

	return refreshToken, nil
}

func (m *RefreshTokenMapper) ToModel(rt *entities.RefreshToken) *models.RefreshToken {
	if rt == nil {
		return nil
	}

	return &models.RefreshToken{
		ID:        rt.ID().Value(),
		UserID:    rt.UserID().Value(),
		DeviceID:  rt.DeviceID().Value(),
		Token:     rt.Token(),
		ExpiresAt: rt.ExpiresAt(),
		RevokedAt: rt.RevokedAt(),
		CreatedAt: rt.CreatedAt(),
		UpdatedAt: rt.UpdatedAt(),
	}
}
