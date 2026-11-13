// Package redisx opens the Redis client (sessions cache, rate limits, short-lived challenges).
package redisx

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Open creates the client from a redis:// or rediss:// URL and checks Redis answers.
func Open(ctx context.Context, url string) (*redis.Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis: parse url: %w", err)
	}
	opt.DialTimeout = 2 * time.Second
	opt.ReadTimeout = time.Second
	opt.WriteTimeout = time.Second

	c := redis.NewClient(opt)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.Ping(pingCtx).Err(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return c, nil
}
