package policies

import "time"

type SessionRenewalTokenPolicy struct {
	Lifetime time.Duration
}

func NewDefaultSessionRenewalTokenPolicy() SessionRenewalTokenPolicy {
	return SessionRenewalTokenPolicy{
		Lifetime: 7 * 24 * time.Hour, // 7 days
	}
}
