package chain

import "testing"

func TestNormalizeAddress(t *testing.T) {
	// Fullnode có thể trả địa chỉ đã rút gọn số 0 đầu (0x1) còn client gửi dạng
	// đầy đủ — so sánh chuỗi trực tiếp sẽ sai, nên phải chuẩn hoá trước.
	cases := []struct{ in, want string }{
		{"0x1", "0x" + pad("1")},
		{"0X1", "0x" + pad("1")},
		{"0xABC", "0x" + pad("abc")},
		{"0x" + pad("abc"), "0x" + pad("abc")},
		{"  0x1  ", "0x" + pad("1")},
	}
	for _, c := range cases {
		got, err := NormalizeAddress(c.in)
		if err != nil {
			t.Errorf("NormalizeAddress(%q) lỗi: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeAddress(%q) = %s, mong %s", c.in, got, c.want)
		}
	}
	// Dạng rút gọn và dạng đầy đủ của cùng một địa chỉ phải trùng nhau sau chuẩn hoá.
	a, _ := NormalizeAddress("0x1")
	b, _ := NormalizeAddress("0x0000000000000000000000000000000000000000000000000000000000000001")
	if a != b {
		t.Error("dạng rút gọn và dạng đầy đủ không quy về cùng một địa chỉ")
	}

	for _, bad := range []string{"", "0x", "zzz", "0x" + pad("1") + "1"} {
		if _, err := NormalizeAddress(bad); err == nil {
			t.Errorf("NormalizeAddress(%q) lẽ ra bị từ chối", bad)
		}
	}
}

func TestUTF8ToHexRoundTrip(t *testing.T) {
	// Fullnode nhận vector<u8> dưới dạng CHUỖI HEX; truyền mảng số sẽ bị từ chối
	// với "expect string<hex>".
	for _, s := range []string{"did:vnu:holder:0x1", "tiếng Việt có dấu", ""} {
		if got := HexToUTF8(UTF8ToHex(s)); got != s {
			t.Errorf("khứ hồi hỏng: %q -> %q", s, got)
		}
	}
	if got := UTF8ToHex("abc"); got != "0x616263" {
		t.Errorf("UTF8ToHex(abc) = %s", got)
	}
}
