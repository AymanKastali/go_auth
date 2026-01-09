package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type RefreshTokenMapper struct{}

func NewRefreshTokenMapper() *RefreshTokenMapper {
	return &RefreshTokenMapper{}
}

func (m *RefreshTokenMapper) ToDomain(rt *models.RefreshToken) (*entities.RefreshToken, error) {
	entity := "RefreshToken"
	if rt == nil {
		return nil, nil
	}

	tokenID, err := valueobjects.TokenIDFromString(rt.ID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, rt.ID, "ID", err)
	}

	userID, err := valueobjects.UserIDFromString(rt.UserID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, rt.ID, "UserID", err)
	}

	deviceID, err := valueobjects.DeviceIDFromString(rt.DeviceID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, rt.ID, "DeviceID", err)
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
		return nil, pgerr.NewDataCorruptionErr(entity, rt.ID, "Entity", err)
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
