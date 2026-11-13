package chain

import "testing"

// Fullnode Movement in địa chỉ module ở dạng RÚT GỌN. Chuỗi dưới đây chép nguyên
// văn từ phản hồi /transactions/simulate của gói 0x0ede7f… (S-04).
func TestNormalizeMoveIDShortForm(t *testing.T) {
	fromNode := "0xede7f6b38caab7ddfe757765fddbf07221f8b776c6395562faae571250708e3::did_registry::register_did"
	fromCfg := "0x0ede7f6b38caab7ddfe757765fddbf07221f8b776c6395562faae571250708e3::did_registry::register_did"
	if NormalizeMoveID(fromNode) != NormalizeMoveID(fromCfg) {
		t.Fatalf("hai dạng của cùng một hàm không khớp: %s / %s", NormalizeMoveID(fromNode), NormalizeMoveID(fromCfg))
	}
	if NormalizeMoveID(fromCfg) == NormalizeMoveID("0x0ede7f6b38caab7ddfe757765fddbf07221f8b776c6395562faae571250708e3::did_registry::update_did_document") {
		t.Fatal("hai hàm khác nhau lại khớp")
	}
}

func TestArgMatches(t *testing.T) {
	cases := []struct {
		actual any
		want   Arg
		ok     bool
	}{
		{"0xede7", ArgAddress("0x0ede7"), true},
		{"0xede7", ArgAddress("0x0ede8"), false},
		{"41", ArgU64(41), true},
		{"41", ArgU64(42), false},
		{"0xABcd", ArgBytes("0xabcd"), true},
		{"0xabcd", ArgBytes("0xabce"), false},
		{41.0, ArgU64(41), false}, // fullnode luôn trả u64 dạng chuỗi
		{nil, ArgBytes("0x"), false},
	}
	for i, c := range cases {
		if got := argMatches(c.actual, c.want); got != c.ok {
			t.Errorf("ca %d: argMatches(%v, %v) = %v, mong %v", i, c.actual, c.want, got, c.ok)
		}
	}
}
