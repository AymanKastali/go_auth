package postgres

import (
	"go_auth/internal/domain"
)

// Recovery Token
func toRecoveryTokenModel(t *domain.RecoveryToken) RecoveryTokenModel {
	return RecoveryTokenModel{
		ID:          t.ID().String(),
		UserID:      t.UserID().String(),
		HashedToken: t.HashedToken().String(),
		ExpiresAt:   t.ExpiresAt().Time(),
		IsUsed:      t.IsUsed(),
	}
}

func toRecoveryTokenDomain(m RecoveryTokenModel) *domain.RecoveryToken {
	return domain.ReconstituteRecoveryToken(
		domain.ReconstituteRecoveryTokenID(m.ID),
		domain.ReconstituteUserID(m.UserID),
		domain.ReconstituteRecoveryTokenHash(m.HashedToken),
		domain.NewTimepoint(m.ExpiresAt),
		m.IsUsed,
	)
}
