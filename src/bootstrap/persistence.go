package bootstrap

import (
	"go_auth/src/infra/persistence/cache"
	"go_auth/src/infra/persistence/postgres"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

func newDatabase() (*gorm.DB, error) {
	db, err := postgres.NewPostgresConnection()
	if err != nil {
		return nil, err
	}

	postgres.AutoMigrate(db)
	return db, nil
}

func newRedis() (*redis.Client, error) {
	redisConfig := cache.Load()

	// Match these to the field names in your RedisConfig struct
	rdb, err := cache.NewRedisClient(
		redisConfig.RedisAddr, // was .Addr
		redisConfig.RedisPass, // was .Password
		redisConfig.RedisDB,   // was .DB
	)
	if err != nil {
		return nil, err
	}

	return rdb, nil // changed 'err' to 'nil' for the second return
}
