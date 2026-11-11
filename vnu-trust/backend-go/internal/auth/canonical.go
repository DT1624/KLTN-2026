package auth

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

// CanonicalJSON tuần tự hoá tất định: khoá đối tượng sắp xếp tăng dần, không
// khoảng trắng thừa. Phải khớp canonicalize() ở backend TypeScript và frontend.
func CanonicalJSON(v any) string {
	var sb strings.Builder
	writeCanonical(&sb, v)
	return sb.String()
}

func writeCanonical(sb *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	case float64:
		// JSON.stringify của JavaScript in số nguyên không có phần thập phân.
		if t == float64(int64(t)) {
			sb.WriteString(strconv.FormatInt(int64(t), 10))
		} else {
			sb.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
		}
	case string:
		b, _ := json.Marshal(t)
		sb.Write(b)
	case []any:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeCanonical(sb, e)
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			b, _ := json.Marshal(k)
			sb.Write(b)
			sb.WriteByte(':')
			writeCanonical(sb, t[k])
		}
		sb.WriteByte('}')
	default:
		b, _ := json.Marshal(t)
		sb.Write(b)
	}
}

// SHA3256Hex băm bản tuần tự hoá tất định, trả về "0x…".
func SHA3256Hex(v any) string {
	h := sha3.Sum256([]byte(CanonicalJSON(v)))
	return "0x" + hex.EncodeToString(h[:])
}

// SHA3256String băm trực tiếp một chuỗi (dùng cho vc_id_hash).
func SHA3256String(s string) string {
	h := sha3.Sum256([]byte(s))
	return "0x" + hex.EncodeToString(h[:])
}
