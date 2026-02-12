package postgres

import (
	"go_auth/internal/domain"
)

func toRecoveryTokenModel(t *domain.RecoveryToken) RecoveryTokenModel {
	return RecoveryTokenModel{
		ULID:        t.ID().String(),
		UserULID:    t.UserID().String(),
		HashedToken: t.HashedToken().String(),
		ExpiresAt:   t.ExpiresAt().Time(),
		IsUsed:      t.IsUsed(),
	}
}

func toRecoveryTokenDomain(m RecoveryTokenModel) *domain.RecoveryToken {
	return domain.ReconstituteRecoveryToken(
		domain.ReconstituteRecoveryTokenID(m.ULID),
		domain.ReconstituteUserID(m.UserULID),
		domain.ReconstituteRecoveryTokenHash(m.HashedToken),
		domain.NewTimepoint(m.ExpiresAt),
		m.IsUsed,
	)
}
