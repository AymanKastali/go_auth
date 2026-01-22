package policies

import "time"

type RefreshTokenPolicy struct {
	Lifetime time.Duration
}

func NewDefaultRefreshTokenPolicy() RefreshTokenPolicy {
	return RefreshTokenPolicy{
		Lifetime: 7 * 24 * time.Hour, // 7 days
	}
}
