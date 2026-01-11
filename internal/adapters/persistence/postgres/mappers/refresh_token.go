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

	tokenVO, err := valueobjects.NewToken(rt.Token)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, "token", err)
	}

	// Rehydrate the entity (using NewRefreshToken as a Reconstitutor here)
	refreshToken, err := entities.NewRefreshToken(
		tokenID,
		userID,
		deviceID,
		tokenVO,
		rt.ExpiresAt,
		rt.CreatedAt,
	)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, rt.ID, err)
	}

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
