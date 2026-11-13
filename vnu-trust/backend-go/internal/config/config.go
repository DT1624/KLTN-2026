// Package config nạp và kiểm tra cấu hình môi trường ngay lúc khởi động.
// Thiếu biến bắt buộc thì dừng ngay thay vì chết giữa chừng khi đã nhận request.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env            string
	Port           int
	FrontendOrigin []string

	DBHost, DBName, DBUser, DBPassword string
	DBPort                             int
	DBPoolMax                          int
	// DBSSLMode truyền thẳng cho pgx (disable | require | verify-full).
	// Postgres dịch vụ (Neon, Supabase) bắt buộc SSL nên khi triển khai đặt "require".
	DBSSLMode string

	JWTSecret string
	JWTExpiry time.Duration

	ChainFullnode   string
	ChainID         int
	RateLimitPerMin int
	AuthRateLimit   int
	// TrustProxyHops: số proxy tin cậy đứng trước server. 0 = lấy IP từ kết nối
	// TCP; 1 = lấy từ X-Forwarded-For do proxy của nhà cung cấp (vd. Render) thêm.
	// Sai số này thì mọi người dùng chung một IP và chung một hạn mức.
	TrustProxyHops  int
	ContractAddress string
	VerifyOnChain   bool

	IPFSProvider string
	PinataJWT    string
	IPFSGateway  string

	DIDMethod string
}

var addrRe = regexp.MustCompile(`^0x[0-9a-fA-F]{1,64}$`)

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	raw := env(key, "")
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s phải là số nguyên, nhận được %q", key, raw)
	}
	return n, nil
}

// Load đọc cấu hình từ biến môi trường và trả lỗi mô tả rõ chỗ sai.
func Load() (*Config, error) {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, "  - "+fmt.Sprintf(format, a...)) }

	port, err := envInt("PORT", 4001)
	if err != nil {
		add("%v", err)
	}
	dbPort, err := envInt("DB_PORT", 5432)
	if err != nil {
		add("%v", err)
	}
	poolMax, err := envInt("DB_POOL_MAX", 10)
	if err != nil {
		add("%v", err)
	}
	chainID, err := envInt("CHAIN_ID", 250)
	if err != nil {
		add("%v", err)
	}
	rateLimit, err := envInt("RATE_LIMIT_PER_MIN", 300)
	if err != nil {
		add("%v", err)
	}
	authRateLimit, err := envInt("AUTH_RATE_LIMIT_PER_MIN", 20)
	if err != nil {
		add("%v", err)
	}
	proxyHops, err := envInt("TRUST_PROXY_HOPS", 0)
	if err != nil || proxyHops < 0 {
		add("TRUST_PROXY_HOPS phải là số nguyên không âm")
	}
	sslMode := env("DB_SSLMODE", "disable")
	switch sslMode {
	case "disable", "require", "verify-full":
	default:
		add("DB_SSLMODE phải là disable, require hoặc verify-full, nhận %q", sslMode)
	}

	secret := env("JWT_SECRET", "")
	if len(secret) < 32 {
		add("JWT_SECRET phải dài ít nhất 32 ký tự (hiện %d)", len(secret))
	}

	contract := env("CONTRACT_ADDRESS", "")
	if !addrRe.MatchString(contract) {
		add("CONTRACT_ADDRESS không hợp lệ: %q", contract)
	}

	expiry, err := time.ParseDuration(env("JWT_EXPIRY", "8h"))
	if err != nil {
		add("JWT_EXPIRY không đúng định dạng thời lượng: %v", err)
	}

	provider := env("IPFS_PROVIDER", "mock")
	if provider != "mock" && provider != "pinata" {
		add("IPFS_PROVIDER phải là mock hoặc pinata, nhận %q", provider)
	}
	pinata := env("PINATA_JWT", "")
	if provider == "pinata" && pinata == "" {
		add("IPFS_PROVIDER=pinata nhưng thiếu PINATA_JWT")
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("cấu hình môi trường không hợp lệ:\n%s", strings.Join(errs, "\n"))
	}

	origins := strings.Split(env("FRONTEND_ORIGIN", "http://localhost:5173"), ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	c := &Config{
		Env:             env("NODE_ENV", "development"),
		Port:            port,
		FrontendOrigin:  origins,
		DBHost:          env("DB_HOST", "localhost"),
		DBPort:          dbPort,
		DBName:          env("DB_NAME", "vnu_trust"),
		DBUser:          env("DB_USER", "vnu_trust"),
		DBPassword:      env("DB_PASSWORD", "vnu_trust"),
		DBPoolMax:       poolMax,
		DBSSLMode:       sslMode,
		JWTSecret:       secret,
		JWTExpiry:       expiry,
		ChainFullnode:   strings.TrimRight(env("CHAIN_FULLNODE", "https://testnet.movementnetwork.xyz/v1"), "/"),
		ChainID:         chainID,
		ContractAddress: contract,
		VerifyOnChain:   env("VERIFY_ONCHAIN", "true") == "true",
		RateLimitPerMin: rateLimit,
		AuthRateLimit:   authRateLimit,
		TrustProxyHops:  proxyHops,
		IPFSProvider:    provider,
		PinataJWT:       pinata,
		IPFSGateway:     strings.TrimRight(env("IPFS_GATEWAY", "https://ipfs.io/ipfs"), "/"),
		DIDMethod:       env("DID_METHOD", "did:vnu"),
	}

	// VERIFY_ONCHAIN=false bỏ qua xác minh giao dịch VÀ đọc quyền từ CSDL thay vì
	// chuỗi — ai gọi API cũng tự khai được vai trò. Chỉ dùng để phát triển/kiểm
	// thử; chạy thật với cờ này là mở toang hệ thống, nên chặn ngay lúc khởi động.
	if !c.VerifyOnChain && c.Env == "production" {
		return nil, fmt.Errorf("VERIFY_ONCHAIN=false không được phép khi NODE_ENV=production " +
			"— cờ này tắt toàn bộ kiểm chứng on-chain")
	}
	// Contract (từ 13/11/2026) chỉ nhận chuỗi DID dạng "did:vnu:…<địa chỉ>". Đặt
	// phương thức khác thì mọi register_did bị chuỗi từ chối sau khi người dùng
	// đã ghi danh xong — báo ngay lúc khởi động. Phải khớp backend TypeScript.
	if c.VerifyOnChain && c.DIDMethod != "did:vnu" {
		return nil, fmt.Errorf("DID_METHOD=%s — contract chỉ chấp nhận \"did:vnu\" khi VERIFY_ONCHAIN=true", c.DIDMethod)
	}
	return c, nil
}

// DSN dựng chuỗi kết nối qua net/url để mật khẩu có ký tự đặc biệt
// (@, /, :, %) không làm vỡ cú pháp URL.
func (c *Config) DSN() string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.DBUser, c.DBPassword),
		Host:   net.JoinHostPort(c.DBHost, strconv.Itoa(c.DBPort)),
		Path:   "/" + c.DBName,
	}
	q := url.Values{}
	q.Set("sslmode", c.DBSSLMode)
	q.Set("pool_max_conns", strconv.Itoa(c.DBPoolMax))
	u.RawQuery = q.Encode()
	return u.String()
}
