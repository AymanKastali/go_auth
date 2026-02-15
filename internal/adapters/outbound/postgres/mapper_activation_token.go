package postgres

import (
	"go_auth/internal/domain"
)

func toActivationTokenModel(t *domain.ActivationToken) ActivationTokenModel {
	return ActivationTokenModel{
		ULID:        t.ID().String(),
		UserULID:    t.UserID().String(),
		HashedToken: t.HashedToken().String(),
		ExpiresAt:   t.ExpiresAt(),
		IsUsed:      t.IsUsed(),
	}
}

func toActivationTokenDomain(m ActivationTokenModel) *domain.ActivationToken {
	return domain.ReconstituteActivationToken(
		domain.ReconstituteActivationTokenID(m.ULID),
		domain.ReconstituteUserID(m.UserULID),
		domain.ReconstituteActivationTokenHash(m.HashedToken),
		m.ExpiresAt,
		m.IsUsed,
	)
}
