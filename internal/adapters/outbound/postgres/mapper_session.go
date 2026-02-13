package postgres

import (
	"go_auth/internal/domain"
)

func toSessionModel(s *domain.Session) SessionModel {
	identity := s.Identity()

	return SessionModel{
		ULID:                s.ID().String(),
		UserULID:            s.UserID().String(),
		HashedToken:         s.HashedToken().String(),
		PreviousHashedToken: s.PreviousHashedToken().String(),
		Fingerprint:         identity.Fingerprint().String(),
		IPAddress:           identity.IPAddress(),
		UserAgent:           identity.UserAgent(),
		OS:                  identity.OS(),
		Browser:             identity.Browser(),
		DeviceModel:         identity.Model(),
		AcceptLanguage:      identity.Language(),
		IsMobile:            identity.IsMobile(),
		ExpiresAt:           s.Expiry().Time(),
		LastActiveAt:        s.LastActiveAt(),
		IsRevoked:           s.IsRevoked(),
	}
}

func toSessionDomain(m SessionModel) *domain.Session {
	sid := domain.ReconstituteSessionID(m.ULID)
	userID := domain.ReconstituteUserID(m.UserULID)
	token := domain.ReconstituteHashedToken(m.HashedToken)
	previousToken := domain.ReconstituteHashedToken(m.PreviousHashedToken)

	identity := domain.ReconstituteDeviceIdentity(
		m.IPAddress,
		m.OS,
		m.Browser,
		m.DeviceModel,
		m.AcceptLanguage,
		m.UserAgent,
		m.IsMobile,
	)

	return domain.ReconstituteSession(
		sid,
		userID,
		token,
		previousToken,
		identity,
		m.ExpiresAt,
		m.LastActiveAt,
		m.IsRevoked,
	)
}
