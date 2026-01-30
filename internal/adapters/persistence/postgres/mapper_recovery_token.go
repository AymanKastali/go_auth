package postgres

import (
	"go_auth/internal/core/domain"
	"time"
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
		CreatedAt:   t.CreatedAt().Time(),
		UsedAt:      usedAt,
	}
}

func toRecoveryTokenDomain(m RecoveryTokenModel) *domain.RecoveryToken {
	// We use our Reconstitutor which handles the Timepoint conversions
	return domain.ReconstituteRecoveryToken(
		m.ID,
		m.UserID,
		m.HashedToken,
		m.ExpiresAt,
		m.CreatedAt,
		m.UsedAt,
	)
}
