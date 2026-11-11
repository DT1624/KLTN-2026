// Package config nạp và kiểm tra cấu hình môi trường ngay lúc khởi động.
// Thiếu biến bắt buộc thì dừng ngay thay vì chết giữa chừng khi đã nhận request.
package config

import (
	"fmt"
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

	JWTSecret string
	JWTExpiry time.Duration

	ChainFullnode   string
	ChainID         int
	RateLimitPerMin int
	AuthRateLimit   int
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
		JWTSecret:       secret,
		JWTExpiry:       expiry,
		ChainFullnode:   strings.TrimRight(env("CHAIN_FULLNODE", "https://testnet.movementnetwork.xyz/v1"), "/"),
		ChainID:         chainID,
		ContractAddress: contract,
		VerifyOnChain:   env("VERIFY_ONCHAIN", "true") == "true",
		RateLimitPerMin: rateLimit,
		AuthRateLimit:   authRateLimit,
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
	return c, nil
}

func (c *Config) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable&pool_max_conns=%d",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName, c.DBPoolMax)
}
