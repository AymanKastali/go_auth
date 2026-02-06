package postgres

import (
	"time"

	"go_auth/internal/core/domain"
)

// Recovery Token
func toRecoveryTokenModel(t *domain.RecoveryToken) RecoveryTokenModel {
	var usedAt *time.Time
	if t.IsUsed() {
		val := t.UsedAt().Time()
		usedAt = &val
	}

	return RecoveryTokenModel{
		ID:          t.ID().String(),
		UserID:      t.UserID().String(),
		HashedToken: t.HashedToken().String(),
		ExpiresAt:   t.ExpiresAt().Time(),
		UsedAt:      usedAt,
	}
}

func toRecoveryTokenDomain(m RecoveryTokenModel) *domain.RecoveryToken {
	var usedAt *domain.Timepoint
	if m.UsedAt != nil {
		tp := domain.NewTimepoint(*m.UsedAt)
		usedAt = &tp
	}

	return domain.ReconstituteRecoveryToken(
		domain.ReconstituteRecoveryTokenID(m.ID),
		domain.ReconstituteUserID(m.UserID),
		domain.ReconstituteRecoveryTokenHash(m.HashedToken),
		domain.NewTimepoint(m.ExpiresAt),
		usedAt,
	)
}
