package auth

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/sha3"
)

// CanonicalJSON tuần tự hoá tất định: khoá đối tượng sắp xếp tăng dần, không
// khoảng trắng thừa. Phải khớp TỪNG BYTE với canonicalize() ở backend TypeScript
// và frontend — tức là với JSON.stringify của JavaScript. Ba chỗ dễ lệch, đều đã
// từng lệch thật (văn bằng có "Kinh tế & QTKD" bị bản Go từ chối):
//   - chuỗi: json.Marshal của Go escape <, >, & và U+2028/2029; JS thì không;
//   - số: JS in 1234567.5 và 1e-7, Go 'g' in 1.2345675e+06 và 1e-07;
//   - thứ tự khoá: JS sắp theo đơn vị UTF-16, Go sort.Strings theo byte UTF-8.
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
		sb.WriteString(jsNumber(t))
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			sb.WriteString("null")
			return
		}
		sb.WriteString(jsNumber(f))
	case string:
		writeJSString(sb, t)
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
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeJSString(sb, k)
			sb.WriteByte(':')
			writeCanonical(sb, t[k])
		}
		sb.WriteByte('}')
	default:
		b, _ := json.Marshal(t)
		sb.Write(b)
	}
}

// utf16Less so sánh theo đơn vị mã UTF-16, đúng như Array.prototype.sort() mặc định.
func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeJSString viết chuỗi giống JSON.stringify: chỉ escape ", \ và ký tự điều khiển.
func writeJSString(sb *strings.Builder, s string) {
	const hexd = "0123456789abcdef"
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				sb.WriteString(`\u00`)
				sb.WriteByte(hexd[r>>4])
				sb.WriteByte(hexd[r&0xf])
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// jsNumber định dạng số như Number.prototype.toString của ECMAScript (§6.1.6.1.20).
func jsNumber(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null" // JSON.stringify(NaN) === "null"
	}
	if f == 0 {
		return "0" // kể cả -0
	}
	neg := f < 0
	if neg {
		f = -f
	}
	// Chữ số ngắn nhất khứ hồi được + số mũ thập phân: "d.ddde±x".
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	k, n := len(digits), exp+1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		sign := "+"
		if n-1 < 0 {
			sign = "-"
		}
		ex := n - 1
		if ex < 0 {
			ex = -ex
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(ex)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(ex)
		}
	}
	if neg {
		return "-" + out
	}
	return out
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
