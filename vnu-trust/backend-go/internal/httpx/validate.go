package httpx

import (
	"regexp"
	"strings"
)

// Các biểu thức kiểm tra phải khớp với src/utils/validate.ts của backend TypeScript,
// để hai backend từ chối cùng một tập dữ liệu xấu.
var (
	reAddress   = regexp.MustCompile(`^0x[0-9a-fA-F]{1,64}$`)
	reHash32    = regexp.MustCompile(`^(0x)?[0-9a-fA-F]{64}$`)
	reTxHash    = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	reSignature = regexp.MustCompile(`^(0x)?[0-9a-fA-F]{128}$`)
	reCID       = regexp.MustCompile(`^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$`)
	reDID       = regexp.MustCompile(`^did:[a-zA-Z0-9]+:[\w.:%-]+$`)
)

func Address(v, field string) (string, error) {
	v = strings.TrimSpace(v)
	if !reAddress.MatchString(v) {
		return "", BadRequest("%s: địa chỉ ví không hợp lệ", field)
	}
	return strings.ToLower(v), nil
}

func Hash32(v, field string) (string, error) {
	v = strings.TrimSpace(v)
	if !reHash32.MatchString(v) {
		return "", BadRequest("%s: hash phải là 32 byte (64 ký tự hex)", field)
	}
	v = strings.ToLower(v)
	if !strings.HasPrefix(v, "0x") {
		v = "0x" + v
	}
	return v, nil
}

func TxHash(v, field string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if !reTxHash.MatchString(v) {
		return "", BadRequest("%s: txHash phải là 0x + 64 ký tự hex", field)
	}
	return v, nil
}

func PublicKey(v, field string) (string, error) { return Hash32(v, field) }

func Signature(v, field string) (string, error) {
	v = strings.TrimSpace(v)
	if !reSignature.MatchString(v) {
		return "", BadRequest("%s: chữ ký Ed25519 phải là 64 byte", field)
	}
	v = strings.ToLower(v)
	if !strings.HasPrefix(v, "0x") {
		v = "0x" + v
	}
	return v, nil
}

func CID(v, field string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", BadRequest("%s: CID không được rỗng", field)
	}
	if !reCID.MatchString(v) {
		return "", BadRequest("%s: CID không đúng định dạng IPFS", field)
	}
	return v, nil
}

func DID(v, field string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) == 0 || len(v) > 256 || !reDID.MatchString(v) {
		return "", BadRequest("%s: DID không đúng định dạng", field)
	}
	return v, nil
}

var validRoles = map[string]bool{"root": true, "admin": true, "issuer": true, "holder": true, "verifier": true}

func Role(v, field string) (string, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if !validRoles[v] {
		return "", BadRequest("%s: vai trò phải là root, admin, issuer, holder hoặc verifier", field)
	}
	return v, nil
}

// VCType kiểm bit mask 1..63 — 6 bit đã định nghĩa trong constants.move.
func VCType(v int, field string) (int, error) {
	if v < 1 || v > 63 {
		return 0, BadRequest("%s: vc_type phải trong khoảng 1..63", field)
	}
	return v, nil
}
