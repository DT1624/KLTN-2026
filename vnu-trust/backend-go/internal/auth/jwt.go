package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vnu-trust/backend-go/internal/httpx"
)

type Claims struct {
	Address string `json:"address"`
	DID     string `json:"did"`
	Role    string `json:"role"`
	jwt.RegisteredClaims
}

func Sign(secret string, expiry time.Duration, address, did, role string) (string, error) {
	now := time.Now()
	c := Claims{
		Address: address, DID: did, Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(secret))
}

func Verify(secret, token string) (*Claims, error) {
	var c Claims
	// Chốt thuật toán HS256 để chặn tấn công đổi alg sang "none".
	_, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, httpx.Unauthorized("Thuật toán ký token không được chấp nhận")
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, httpx.Unauthorized("Token không hợp lệ hoặc đã hết hạn")
	}
	return &c, nil
}
