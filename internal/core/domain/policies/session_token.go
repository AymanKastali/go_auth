package policies

import "time"

type SessionTokenPolicy struct {
	SessionTokenTTL time.Duration
}

func NewSessionTokenPolicy() SessionTokenPolicy {
	return SessionTokenPolicy{
		SessionTokenTTL: 5 * time.Minute,
	}
}
