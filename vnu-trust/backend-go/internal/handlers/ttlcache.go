package handlers

import (
	"context"
	"sync"
	"time"
)

// ttlCache là bộ nhớ đệm sống rất ngắn cho những giá trị tổng hợp đắt đỏ mà
// không cần tươi từng mili giây.
//
// Lý do có tệp này: tuyến /stats của trang chủ gọi bốn phép tổng hợp riêng biệt
// (số admin, số issuer, số DID, số VC). Ở chế độ on-chain đó là bốn vòng gọi
// fullnode cho MỖI lượt xem trang; ở chế độ đọc CSDL thì vẫn là nhiều lượt truy
// vấn lặp lại. Một bộ đếm trên trang chủ chậm vài giây không sao, nhưng làm
// fullnode nghẹn thì có.
//
// Giữ khoá trong suốt lúc tính để các lượt gọi song song gộp chung một lần
// tính: nếu 50 người mở trang cùng lúc lúc đệm vừa hết hạn thì chỉ đúng một
// phép tính chạy. Phải khớp hành vi với backend TypeScript (utils/ttl-cache.ts).
type ttlCache[T any] struct {
	mu        sync.Mutex
	ttl       time.Duration
	value     T
	expiresAt time.Time
	valid     bool
	compute   func(context.Context) (T, error)
}

func newTTLCache[T any](ttl time.Duration, compute func(context.Context) (T, error)) *ttlCache[T] {
	return &ttlCache[T]{ttl: ttl, compute: compute}
}

func (c *ttlCache[T]) Get(ctx context.Context) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.valid && time.Now().Before(c.expiresAt) {
		return c.value, nil
	}
	v, err := c.compute(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	c.value = v
	c.expiresAt = time.Now().Add(c.ttl)
	c.valid = true
	return v, nil
}
