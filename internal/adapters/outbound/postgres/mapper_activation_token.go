package postgres

import (
	"go_auth/internal/domain"
)

// Activation Token
func toActivationTokenModel(t *domain.ActivationToken) ActivationTokenModel {
	return ActivationTokenModel{
		ID:          t.ID().String(),
		UserID:      t.UserID().String(),
		HashedToken: t.HashedToken().String(),
		ExpiresAt:   t.ExpiresAt().Time(),
		IsUsed:      t.IsUsed(),
	}
}

func toActivationTokenDomain(m ActivationTokenModel) *domain.ActivationToken {
	return domain.ReconstituteActivationToken(
		domain.ReconstituteActivationTokenID(m.ID),
		domain.ReconstituteUserID(m.UserID),
		domain.ReconstituteActivationTokenHash(m.HashedToken),
		domain.NewTimepoint(m.ExpiresAt),
		m.IsUsed,
	)
}
