package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name string
		xff  string
		hops int
		want string
	}{
		{"không proxy thì bỏ qua X-Forwarded-For", "1.1.1.1", 0, "10.0.0.9"},
		{"một proxy: lấy phần tử cuối", "203.0.113.5", 1, "203.0.113.5"},
		{"client tự ghi giá trị giả phía trước", "6.6.6.6, 203.0.113.5", 1, "203.0.113.5"},
		{"hai proxy", "203.0.113.5, 198.51.100.7", 2, "203.0.113.5"},
		{"thiếu phần tử thì lấy phần tử đầu", "203.0.113.5", 3, "203.0.113.5"},
		{"không có tiêu đề thì dùng kết nối TCP", "", 1, "10.0.0.9"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.9:5555"
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := ClientIP(r, c.hops); got != c.want {
			t.Errorf("%s: ClientIP = %q, muốn %q", c.name, got, c.want)
		}
	}
}
