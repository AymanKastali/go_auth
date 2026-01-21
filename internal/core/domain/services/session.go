package services

import (
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type sessionDomainService struct {
	refreshRepo ports.IRefreshTokenRepository
}

func NewSessionDomainService(refreshRepo ports.IRefreshTokenRepository) *sessionDomainService {
	return &sessionDomainService{
		refreshRepo: refreshRepo,
	}
}

func (s *sessionDomainService) InvalidateExistingSessions(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	now time.Time,
) error {
	// 1. Fetch all active tokens for this specific User + Device
	oldTokens, err := s.refreshRepo.GetActiveByUserIDAndDeviceID(userID, deviceID)
	if err != nil {
		return err
	}

	// 2. Business Logic: Transition each token to 'Revoked' state
	for _, ot := range oldTokens {
		// The entity itself handles the state transition rules
		if err := ot.Revoke(now); err != nil {
			// We log and continue; failing to revoke one shouldn't
			// necessarily block the entire login flow unless specified.
			continue
		}

		// 3. Persist the domain state change
		if err := s.refreshRepo.Save(ot); err != nil {
			return err
		}
	}

	return nil
}
