package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestVerifySignatureRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := ChallengeMessage("0xabc", "nonce-123")
	sig := ed25519.Sign(priv, []byte(msg))

	pubHex := "0x" + hex.EncodeToString(pub)
	sigHex := "0x" + hex.EncodeToString(sig)

	if !VerifySignature(pubHex, msg, sigHex) {
		t.Error("chữ ký hợp lệ lại bị từ chối")
	}
	// Chấp nhận cả dạng không có tiền tố 0x, vì client có thể gửi kiểu nào cũng được.
	if !VerifySignature(hex.EncodeToString(pub), msg, hex.EncodeToString(sig)) {
		t.Error("không chấp nhận dạng hex không có tiền tố 0x")
	}
	if VerifySignature(pubHex, msg+"x", sigHex) {
		t.Error("thông điệp bị sửa mà chữ ký vẫn được chấp nhận")
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifySignature("0x"+hex.EncodeToString(otherPub), msg, sigHex) {
		t.Error("khoá công khai khác mà chữ ký vẫn được chấp nhận")
	}
}

func TestVerifySignatureRejectsMalformed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := "xin chao"
	sig := "0x" + hex.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	pubHex := "0x" + hex.EncodeToString(pub)

	cases := []struct{ name, pub, sig string }{
		{"khoá rỗng", "", sig},
		{"chữ ký rỗng", pubHex, ""},
		{"khoá sai độ dài", "0xdeadbeef", sig},
		{"chữ ký sai độ dài", pubHex, "0xdeadbeef"},
		{"khoá không phải hex", "0xzzzz", sig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if VerifySignature(c.pub, msg, c.sig) {
				t.Error("dữ liệu sai định dạng lại được chấp nhận")
			}
		})
	}
}

// Giá trị kỳ vọng lấy từ chính địa chỉ deployer trên chuỗi: khoá công khai
// trong frontend/scripts/chain-probe.mjs dẫn xuất ra đúng địa chỉ này
// (phép "Dẫn xuất địa chỉ từ khoá công khai đúng như ví làm").
func TestDeriveAddressMatchesChain(t *testing.T) {
	if got := DeriveAddress(probePublicKey); got != probeAddress {
		t.Errorf("DeriveAddress = %s, mong %s", got, probeAddress)
	}
	if DeriveAddress("0x1234") != "" {
		t.Error("khoá sai độ dài phải trả chuỗi rỗng")
	}
}

const (
	probePublicKey = "0x61ce325bb8fe57aa698412bfbe7b4ebc1f9c7673f44eae46d5595f7037679229"
	probeAddress   = "0x0ede7f6b38caab7ddfe757765fddbf07221f8b776c6395562faae571250708e3"
)
