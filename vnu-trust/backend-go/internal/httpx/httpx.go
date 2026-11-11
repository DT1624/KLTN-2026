// Package httpx chứa kiểu lỗi có mã HTTP và các tiện ích ghi phản hồi,
// giữ đúng một định dạng phong bì JSON giống hệt backend TypeScript.
package httpx

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type Envelope struct {
	Success   bool    `json:"success"`
	Data      any     `json:"data"`
	Error     *string `json:"error"`
	Timestamp string  `json:"timestamp"`
}

// Error là lỗi nghiệp vụ mang theo mã HTTP.
type Error struct {
	Status  int
	Message string
	Code    string
}

func (e *Error) Error() string { return e.Message }

func BadRequest(format string, a ...any) *Error {
	return &Error{http.StatusBadRequest, fmt.Sprintf(format, a...), "BAD_REQUEST"}
}
func Unauthorized(msg string) *Error {
	if msg == "" {
		msg = "Chưa xác thực"
	}
	return &Error{http.StatusUnauthorized, msg, "UNAUTHORIZED"}
}
func Forbidden(format string, a ...any) *Error {
	return &Error{http.StatusForbidden, fmt.Sprintf(format, a...), "FORBIDDEN"}
}
func NotFound(format string, a ...any) *Error {
	return &Error{http.StatusNotFound, fmt.Sprintf(format, a...), "NOT_FOUND"}
}
func Conflict(format string, a ...any) *Error {
	return &Error{http.StatusConflict, fmt.Sprintf(format, a...), "CONFLICT"}
}
func Gone(format string, a ...any) *Error {
	return &Error{http.StatusGone, fmt.Sprintf(format, a...), "GONE"}
}
func Upstream(format string, a ...any) *Error {
	return &Error{http.StatusBadGateway, fmt.Sprintf(format, a...), "UPSTREAM_ERROR"}
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func OK(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Envelope{Success: true, Data: data, Timestamp: now()})
}

func Fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Envelope{Success: false, Error: &msg, Timestamp: now()})
}

// Handler là handler có thể trả lỗi, để không phải lặp lại việc ghi lỗi ở mọi nơi.
type Handler func(http.ResponseWriter, *http.Request) error

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h(w, r); err != nil {
		var he *Error
		if e, ok := err.(*Error); ok {
			he = e
		} else {
			slog.Error("lỗi không lường trước", "path", r.URL.Path, "err", err)
			he = &Error{http.StatusInternalServerError, "Lỗi máy chủ", "INTERNAL"}
		}
		if he.Status >= 500 {
			slog.Error(he.Message, "path", r.URL.Path)
		} else {
			slog.Debug("từ chối yêu cầu", "path", r.URL.Path, "msg", he.Message)
		}
		Fail(w, he.Status, he.Message)
	}
}

// DecodeJSON đọc thân yêu cầu, chặn trường lạ và giới hạn kích thước.
func DecodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 2<<20) // 2 MB
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return BadRequest("Thân yêu cầu không đọc được: %v", err)
	}
	return nil
}
