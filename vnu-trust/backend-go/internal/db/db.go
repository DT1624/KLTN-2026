// Package db mở kết nối Postgres dùng chung lược đồ db/schema.sql với backend TypeScript.
package db

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &DB{Pool: pool}, nil
}

// WaitReady thử lại nhiều lần để chịu được việc Postgres khởi động chậm hơn ứng dụng.
func (d *DB) WaitReady(ctx context.Context, retries int, delay time.Duration) error {
	var last error
	for i := 1; i <= retries; i++ {
		if err := d.Pool.Ping(ctx); err == nil {
			slog.Info("Đã kết nối Postgres")
			return nil
		} else {
			last = err
			slog.Warn("Postgres chưa sẵn sàng, thử lại", "lần", i, "tổng", retries)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return last
}

func (d *DB) Close() { d.Pool.Close() }
