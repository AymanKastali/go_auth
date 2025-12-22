package repositories

import (
	"time"
)

type BlacklistRepositoryPort interface {
	Blacklist(jti string, ttl time.Duration) error
	IsBlacklisted(jti string) (bool, error)
}
