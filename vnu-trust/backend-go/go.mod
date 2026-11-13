module github.com/vnu-trust/backend-go

go 1.25.0

// Thư viện chuẩn go1.26.4 dính 18 lỗ hổng (govulncheck, SECURITY_REVIEW D-01); Go và Render
// tự tải đúng toolchain này khi build (GOTOOLCHAIN=auto).
toolchain go1.26.11

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.9.2
	golang.org/x/crypto v0.31.0
	golang.org/x/time v0.8.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
