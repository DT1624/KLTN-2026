// Package auth xử lý challenge, chữ ký Ed25519 và JWT.
package auth

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/sha3"
)

// CanonicalJSON và Hash phải cho kết quả GIỐNG HỆT hàm canonicalize/sha3_256Hex
// của backend TypeScript và của frontend, nếu không mọi phép kiểm tra toàn vẹn
// giữa ba bên sẽ thất bại.
func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"))
}

// VerifySignature kiểm chữ ký Ed25519 trên thông điệp UTF-8.
func VerifySignature(publicKeyHex, message, signatureHex string) bool {
	pub, err := decodeHex(publicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := decodeHex(signatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig)
}

// ChallengeMessage phải khớp từng ký tự với hàm cùng tên ở backend TypeScript
// và ở frontend, vì đây chính là chuỗi được ký.
func ChallengeMessage(address, nonce string) string {
	return strings.Join([]string{
		"VNU-Trust xac thuc dang nhap",
		"dia chi: " + address,
		"nonce: " + nonce,
	}, "\n")
}

// DeriveAddress — địa chỉ Aptos/Movement của khoá Ed25519 một chữ ký:
// SHA3-256(khoá công khai ‖ 0x00), dạng 0x + 64 hex. Trả "" nếu khoá không hợp lệ.
func DeriveAddress(publicKeyHex string) string {
	pub, err := decodeHex(publicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ""
	}
	h := sha3.Sum256(append(append(make([]byte, 0, len(pub)+1), pub...), 0x00))
	return "0x" + hex.EncodeToString(h[:])
}
