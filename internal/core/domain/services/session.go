package services

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type sessionDomainService struct {
	refreshRepo         ports.IRefreshTokenRepository
	refreshTokenFactory ports.IRefreshTokenFactory
}

func NewSessionDomainService(
	refreshRepo ports.IRefreshTokenRepository,
	refreshTokenFactory ports.IRefreshTokenFactory,
) *sessionDomainService {
	return &sessionDomainService{
		refreshRepo:         refreshRepo,
		refreshTokenFactory: refreshTokenFactory,
	}
}

func (s *sessionDomainService) InvalidateExistingSessions(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	now valueobjects.Timepoint,
) ([]*entities.RefreshToken, error) {
	oldTokens, err := s.refreshRepo.FindByUserAndDevice(userID, deviceID)
	if err != nil {
		return nil, err
	}

	var revokedTokens []*entities.RefreshToken
	for _, ot := range oldTokens {
		// Business Rule: Skip if already revoked to avoid unnecessary DB writes
		if ot.IsRevoked() {
			continue
		}

		if err := ot.Revoke(now); err == nil {
			revokedTokens = append(revokedTokens, ot)
		}
	}

	return revokedTokens, nil
}

func (s *sessionDomainService) CreateSession(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	expiresAt valueobjects.Timepoint,
	now valueobjects.Timepoint,
) (*entities.RefreshToken, valueobjects.RawRefreshToken, error) {
	return s.refreshTokenFactory.New(
		userID,
		deviceID,
		expiresAt,
		now,
	)
}

func (s *sessionDomainService) RotateSession(
	oldToken *entities.RefreshToken,
	now valueobjects.Timepoint,
) error {
	// 1. Invariant Check: Is the token already revoked? (Reuse Detection)
	if oldToken.IsRevoked() {
		// Business Rule: If an old token is reused, it's a security breach.
		return derr.NewErrSessionCompromised(oldToken.UserID().Value())
	}

	// 2. Business Rule: Revoke the old token
	// This updates the entity state in memory
	return oldToken.Revoke(now)
}
