package postgres

import (
	"go_auth/internal/domain"
)

func toSessionModel(s *domain.Session) SessionModel {
	identity := s.Identity()

	return SessionModel{
		ID:             s.ID().String(),
		UserID:         s.UserID().String(),
		HashedToken:    s.HashedToken().String(),
		Fingerprint:    identity.Fingerprint().String(),
		IPAddress:      identity.IPAddress(),
		UserAgent:      identity.UserAgent(),
		OS:             identity.OS(),
		Browser:        identity.Browser(),
		Model:          identity.Model(),
		AcceptLanguage: identity.Language(),
		IsMobile:       identity.IsMobile(),
		ExpiresAt:      s.ExpiresAt().Time(),
		LastActiveAt:   s.LastActiveAt().Time(),
		IsRevoked:      s.IsRevoked(),
	}
}

func toSessionDomain(m SessionModel) *domain.Session {
	sid := domain.ReconstituteSessionID(m.ID)
	userID := domain.ReconstituteUserID(m.UserID)
	token := domain.ReconstituteHashedToken(m.HashedToken)

	identity := domain.ReconstituteDeviceIdentity(
		m.IPAddress,
		m.OS,
		m.Browser,
		m.Model,
		m.AcceptLanguage,
		m.UserAgent,
		m.IsMobile,
	)

	return domain.ReconstituteSession(
		sid,
		userID,
		token,
		identity,
		domain.ReconstituteTimepoint(m.ExpiresAt),
		domain.ReconstituteTimepoint(m.LastActiveAt),
		m.IsRevoked,
	)
}
