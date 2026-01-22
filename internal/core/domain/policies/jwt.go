package policies

import "time"

type JWTPolicy struct {
	AccessTokenTTL time.Duration
}

func NewDefaultJWTPolicy() JWTPolicy {
	return JWTPolicy{
		AccessTokenTTL: 5 * time.Minute,
	}
}
