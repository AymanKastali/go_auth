package services

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type sessionDomainSvc struct {
	repo      ports.ISessionRenewalTokenRepository
	factory   ports.ISessionRenewalTokenFactory
	hasher    ports.ITokenHasherService
	generator ports.IRandomTokenGenerator
}

func NewSessionDomainSvc(
	repo ports.ISessionRenewalTokenRepository,
	factory ports.ISessionRenewalTokenFactory,
	hasher ports.ITokenHasherService,
	generator ports.IRandomTokenGenerator,
) *sessionDomainSvc {
	return &sessionDomainSvc{
		repo:      repo,
		factory:   factory,
		hasher:    hasher,
		generator: generator,
	}
}

func (s *sessionDomainSvc) InvalidateExistingSessions(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	now valueobjects.Timepoint,
) ([]*entities.SessionRenewalToken, error) {
	oldTokens, err := s.repo.FindByUserAndDevice(userID, deviceID)
	if err != nil {
		return nil, err
	}

	var revokedTokens []*entities.SessionRenewalToken
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

func (s *sessionDomainSvc) CreateSession(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	now valueobjects.Timepoint,
) (*entities.SessionRenewalToken, valueobjects.SessionRenewalRawToken, error) {

	// 1. Generate Secret (Service responsibility)
	rawSecret, err := s.generator.Generate()
	if err != nil {
		return nil, valueobjects.SessionRenewalRawToken{}, err
	}

	// 2. Hash Secret (Service responsibility)
	hashed, err := s.hasher.Hash(rawSecret)
	if err != nil {
		return nil, valueobjects.SessionRenewalRawToken{}, err
	}

	// 3. Assemble Entity (Factory responsibility)
	sessionEntity, err := s.factory.New(userID, deviceID, hashed, now)
	if err != nil {
		return nil, valueobjects.SessionRenewalRawToken{}, err
	}

	// 4. Wrap for the UseCase
	rawToken, _ := valueobjects.NewSessionRenewalRawToken(sessionEntity.ID(), rawSecret)

	return sessionEntity, rawToken, nil
}

func (s *sessionDomainSvc) RotateSession(
	oldToken *entities.SessionRenewalToken,
	now valueobjects.Timepoint,
) error {
	// 1. Invariant Check: Is the token already revoked? (Reuse Detection)
	if oldToken.IsRevoked() {
		// Business Rule: If an old token is reused, it's a security breach.
		return derr.NewErrSessionCompromised(oldToken.UserID().String())
	}

	// 2. Business Rule: Revoke the old token
	// This updates the entity state in memory
	return oldToken.Revoke(now)
}

func (s *sessionDomainSvc) RevokeSession(
	token *entities.SessionRenewalToken,
	rawSecret valueobjects.SessionRenewalRawTokenSecret,
	now valueobjects.Timepoint,
) error {
	// 1. Verify integrity using the hasher
	valid, err := s.hasher.Compare(rawSecret, token.SessionRenewalHashedToken())
	if err != nil {
		return err
	}
	if !valid {
		// Return a domain error from your derr package
		return derr.NewErrInvalidCredentials()
	}

	// 2. Perform the domain state change
	if err := token.Revoke(now); err != nil {
		return err // e.g., ErrSessionRenewalTokenRevoked
	}

	return nil
}

func (s *sessionDomainSvc) RefreshSession(
	oldToken *entities.SessionRenewalToken,
	rawSecret valueobjects.SessionRenewalRawTokenSecret,
	currentDevice *entities.Device,
	now valueobjects.Timepoint,
) (*entities.SessionRenewalToken, valueobjects.SessionRenewalRawToken, error) {
	// 1. Security Check: Integrity
	valid, err := s.hasher.Compare(rawSecret, oldToken.SessionRenewalHashedToken())
	if err != nil {
		// Return empty VO instead of nil
		return nil, valueobjects.ZeroSessionRenewalRawToken, err
	}
	if !valid {
		return nil, valueobjects.ZeroSessionRenewalRawToken, derr.NewErrInvalidCredentials()
	}

	// 2. Security Check: Device Consistency
	if err := oldToken.BelongsToDevice(currentDevice.ID()); err != nil {
		return nil, valueobjects.ZeroSessionRenewalRawToken, err
	}

	// 3. Domain Logic: Rotate
	if err := oldToken.Rotate(now); err != nil {
		return nil, valueobjects.ZeroSessionRenewalRawToken, err
	}

	// 4. Create New Session
	return s.CreateSession(oldToken.UserID(), currentDevice.ID(), now)
}
