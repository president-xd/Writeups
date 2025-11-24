package utils

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

var RedisClient *RedisClientConnection = nil
var ctx = context.Background()

type RedisClientConnection struct {
	client *redis.Client
}

func New() *RedisClientConnection {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	return &RedisClientConnection{client}
}

func (r *RedisClientConnection) Set(key string, value string, expirationTime time.Duration) error {
	res := r.client.Set(ctx, key, value, expirationTime)
	return res.Err()
}

func (r *RedisClientConnection) Get(key string) (string, error) {
	res := r.client.Get(ctx, key)
	return res.Result()
}

func init() {
	RedisClient = New()
}
