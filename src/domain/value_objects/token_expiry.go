package valueobjects

import "time"

type TokenExpiry struct {
	value time.Time
}

func NewTokenExpiry(ttl time.Duration) TokenExpiry {
	return TokenExpiry{value: time.Now().Add(ttl)}
}

func (t TokenExpiry) Value() time.Time {
	return t.value
}

func (t TokenExpiry) IsExpired() bool {
	return time.Now().After(t.value)
}
