package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisBlacklist struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisBlacklist(client *redis.Client) *RedisBlacklist {
	return &RedisBlacklist{
		client: client,
		ctx:    context.Background(),
	}
}

func (r *RedisBlacklist) Blacklist(jti string, ttl time.Duration) error {
	return r.client.Set(r.ctx, "jwt:blacklist:"+jti, "1", ttl).Err()
}

func (r *RedisBlacklist) IsBlacklisted(jti string) (bool, error) {
	res, err := r.client.Exists(r.ctx, "jwt:blacklist:"+jti).Result()
	return res == 1, err
}
