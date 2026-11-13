package httpx

import "testing"

func TestAddress(t *testing.T) {
	ok := []string{"0x1", "0xABCDEF", "0x" + repeat("a", 64)}
	for _, v := range ok {
		if _, err := Address(v, "f"); err != nil {
			t.Errorf("Address(%q) lẽ ra hợp lệ: %v", v, err)
		}
	}
	bad := []string{"", "1234", "0x", "0xzz", "0x" + repeat("a", 65), "khong-phai"}
	for _, v := range bad {
		if _, err := Address(v, "f"); err == nil {
			t.Errorf("Address(%q) lẽ ra bị từ chối", v)
		}
	}
	// Phải chuẩn hoá về DẠNG DUY NHẤT 0x + 64 hex chữ thường. Trước đây chỉ hạ
	// chữ thường, nên "0xede7…" (rút gọn của root 0x0ede7…) là một bản ghi khác
	// mà chuỗi lại coi là root (S-01, docs/SECURITY_REVIEW.md).
	got, _ := Address("0xABCDEF", "f")
	if got != "0x"+repeat("0", 58)+"abcdef" {
		t.Errorf("không chuẩn hoá về 0x + 64 hex chữ thường: %s", got)
	}
	a, _ := Address("0xede7", "f")
	b, _ := Address("0x0ede7", "f")
	if a != b {
		t.Errorf("hai dạng của cùng một địa chỉ cho hai chuỗi khác nhau: %s / %s", a, b)
	}
}

func TestHash32AddsPrefix(t *testing.T) {
	got, err := Hash32(repeat("A", 64), "f")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0x"+repeat("a", 64) {
		t.Errorf("Hash32 = %s", got)
	}
	if _, err := Hash32(repeat("a", 63), "f"); err == nil {
		t.Error("hash 63 ký tự lẽ ra bị từ chối")
	}
}

func TestCIDRejectsEmptyAndBadFormat(t *testing.T) {
	// Contract KHÔNG kiểm CID rỗng (xem F-06 trong CONTRACT_AUDIT.md),
	// nên backend bắt buộc phải chặn ở đây.
	if _, err := CID("", "f"); err == nil {
		t.Error("CID rỗng lẽ ra bị từ chối")
	}
	if _, err := CID("khong-phai-cid", "f"); err == nil {
		t.Error("CID sai định dạng lẽ ra bị từ chối")
	}
	valid := "bafkrei" + repeat("a", 52)
	if _, err := CID(valid, "f"); err != nil {
		t.Errorf("CIDv1 hợp lệ lại bị từ chối: %v", err)
	}
	if _, err := CID("Qm"+repeat("A", 44), "f"); err != nil {
		t.Errorf("CIDv0 hợp lệ lại bị từ chối: %v", err)
	}
}

func TestRoleAndVCType(t *testing.T) {
	for _, r := range []string{"root", "admin", "issuer", "holder", "verifier"} {
		if _, err := Role(r, "f"); err != nil {
			t.Errorf("vai trò %q lẽ ra hợp lệ", r)
		}
	}
	if _, err := Role("superuser", "f"); err == nil {
		t.Error("vai trò lạ lẽ ra bị từ chối")
	}
	// Hợp đồng nâng cấp 13/11/2026 đòi MỘT VC mang đúng một bit loại văn bằng;
	// 3 (cử nhân + thạc sĩ) và 63 (mọi bit) nay bị từ chối (E_INVALID_VC_TYPE).
	for _, n := range []int{0, -1, 3, 63, 64, 1000} {
		if _, err := VCType(n, "f"); err == nil {
			t.Errorf("vcType %d lẽ ra bị từ chối", n)
		}
	}
	for _, n := range []int{1, 2, 4, 8, 16, 32} {
		if _, err := VCType(n, "f"); err != nil {
			t.Errorf("vcType %d lẽ ra hợp lệ", n)
		}
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
