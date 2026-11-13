// Package middleware cung cấp CORS, ghi log, giới hạn tần suất và kiểm quyền.
package middleware

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/vnu-trust/backend-go/internal/auth"
	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/httpx"
)

type ctxKey string

const claimsKey ctxKey = "claims"

func ClaimsFrom(ctx context.Context) *auth.Claims {
	c, _ := ctx.Value(claimsKey).(*auth.Claims)
	return c
}

// RequireAuth kiểm JWT và gắn claims vào context.
func RequireAuth(secret string, next httpx.Handler) httpx.Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			return httpx.Unauthorized("")
		}
		claims, err := auth.Verify(secret, strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
		if err != nil {
			return err
		}
		return next(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
	}
}

// RoleLookup trả vai trò hiện hành của một địa chỉ ("" nếu không còn tài khoản).
type RoleLookup func(ctx context.Context, address string) (string, error)

// RequireRole chặn theo vai trò hiện hành trong chỉ mục, không theo JWT: token
// sống tới 8 giờ, admin vừa bị thu hồi không được đọc tiếp dữ liệu.
func RequireRole(roleOf RoleLookup, next httpx.Handler, roles ...string) httpx.Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		c := ClaimsFrom(r.Context())
		if c == nil {
			return httpx.Unauthorized("")
		}
		current, err := roleOf(r.Context(), c.Address)
		if err != nil {
			return err
		}
		if current == "" {
			return httpx.Unauthorized("Tài khoản không còn trong hệ thống")
		}
		c.Role = current
		for _, role := range roles {
			if c.Role == role {
				return next(w, r)
			}
		}
		return httpx.Forbidden("Yêu cầu vai trò: %s", strings.Join(roles, " hoặc "))
	}
}

// RequireOnChainRole kiểm quyền THẬT trên chuỗi, không chỉ dựa vào JWT.
// JWT chỉ nói người dùng khai là gì; chuỗi mới nói họ thực sự có quyền gì.
func RequireOnChainRole(cc *chain.Client, kind string, next httpx.Handler) httpx.Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		c := ClaimsFrom(r.Context())
		if c == nil {
			return httpx.Unauthorized("")
		}
		ok := false
		if kind == "admin" {
			ok = cc.IsActiveAdmin(r.Context(), c.Address)
		} else {
			ok = cc.IsActiveIssuer(r.Context(), c.Address)
		}
		if !ok {
			if kind == "admin" {
				return httpx.Forbidden("Địa chỉ này không phải admin đang hoạt động trên chuỗi")
			}
			return httpx.Forbidden("Địa chỉ này chưa được cấp quyền issuer trên chuỗi hoặc quyền đã hết hiệu lực")
		}
		return next(w, r)
	}
}

// CORS chỉ cho phép đúng các origin đã cấu hình.
func CORS(allowed []string, next http.Handler) http.Handler {
	set := map[string]bool{}
	for _, o := range allowed {
		set[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if set[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders đặt các tiêu đề phòng thủ cơ bản, tương đương helmet.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// Như helmet bên TypeScript. Trình duyệt chỉ xét header này qua HTTPS (vd.
		// sau proxy TLS của Render), nên chạy máy nhà qua HTTP không ảnh hưởng.
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("request", "method", r.Method, "path", r.URL.Path,
			"status", rec.status, "ms", time.Since(start).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(c int) {
	r.status = c
	r.ResponseWriter.WriteHeader(c)
}

// RateLimiter giới hạn theo địa chỉ IP, dọn định kỳ để không rò bộ nhớ.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rps      rate.Limit
	burst    int
	// TrustProxyHops: số proxy tin cậy đứng trước server, xem ClientIP.
	TrustProxyHops int
}

type visitor struct {
	limiter *rate.Limiter
	seen    time.Time
}

func NewRateLimiter(perMinute, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: map[string]*visitor{},
		rps:      rate.Limit(float64(perMinute) / 60.0),
		burst:    burst,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) cleanup() {
	for range time.Tick(time.Minute) {
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.seen) > 10*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	v, ok := rl.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.visitors[ip] = v
	}
	v.seen = time.Now()
	return v.limiter.Allow()
}

func (rl *RateLimiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(ClientIP(r, rl.TrustProxyHops)) {
			httpx.Fail(w, http.StatusTooManyRequests, "Quá nhiều yêu cầu, thử lại sau")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP trả IP của người dùng thật. hops = 0: lấy từ kết nối TCP (chạy máy
// nhà, không có proxy). hops = N: tin N proxy đứng trước server và lấy phần tử
// thứ N tính từ cuối X-Forwarded-For — cùng quy tắc với `trust proxy` của
// Express. Không lấy phần tử đầu tiên vì client tự ghi được giá trị đó để né
// hạn mức.
func ClientIP(r *http.Request, hops int) string {
	if hops > 0 {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			i := len(parts) - hops
			if i < 0 {
				i = 0
			}
			if ip := strings.TrimSpace(parts[i]); ip != "" {
				return ip
			}
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
