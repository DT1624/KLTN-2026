package auth

import (
	"encoding/json"
	"testing"
)

// Các giá trị kỳ vọng được sinh từ chính backend TypeScript và frontend.
// Nếu ba bên không tuần tự hoá giống hệt nhau thì mọi phép kiểm tra toàn vẹn
// và chữ ký giữa chúng đều sẽ thất bại, nên đây là bài kiểm quan trọng nhất.
func TestCanonicalJSONMatchesTypeScript(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"sắp xếp khoá", `{"b":2,"a":1}`, `{"a":1,"b":2}`},
		{"lồng nhau", `{"z":[3,{"y":1,"x":2}],"a":"x"}`, `{"a":"x","z":[3,{"x":2,"y":1}]}`},
		{"giá trị nguyên thuỷ", `{"n":null,"t":true,"f":false,"num":3.14}`,
			`{"f":false,"n":null,"num":3.14,"t":true}`},
		{"số nguyên không có phần thập phân", `{"a":1,"b":100}`, `{"a":1,"b":100}`},
		{"tiếng Việt có dấu", `{"ten":"Nguyễn Văn A"}`, `{"ten":"Nguyễn Văn A"}`},
		{"mảng rỗng và đối tượng rỗng", `{"a":[],"b":{}}`, `{"a":[],"b":{}}`},
		{"VC thật", `{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential"],"issuer":"did:vnu:issuer:0x2","credentialSubject":{"id":"did:vnu:holder:0x1","vnu:gpa":"3.4","vnu:degreeName":"CNTT"}}`,
			`{"@context":["https://www.w3.org/2018/credentials/v1"],"credentialSubject":{"id":"did:vnu:holder:0x1","vnu:degreeName":"CNTT","vnu:gpa":"3.4"},"issuer":"did:vnu:issuer:0x2","type":["VerifiableCredential"]}`},
		// Các ca dưới đây từng LỆCH với JavaScript (S-05): bản Go từ chối cấp văn bằng
		// có "Kinh tế & QTKD". Giá trị kỳ vọng sinh từ canonicalize() của backend TS.
		{"không escape & như JSON.stringify", `{"f":"Kinh tế & QTKD"}`, `{"f":"Kinh tế & QTKD"}`},
		{"không escape < >", `{"h":"<script>a>b</script>"}`, `{"h":"<script>a>b</script>"}`},
		{"không escape U+2028/2029", `{"u":"a\u2028b\u2029c"}`, "{\"u\":\"a\u2028b\u2029c\"}"},
		{"số thực thường", `{"n":1234567.5}`, `{"n":1234567.5}`},
		{"số nhỏ dạng thập phân", `{"n":0.00001}`, `{"n":0.00001}`},
		{"số nhỏ dạng mũ", `{"n":1e-7}`, `{"n":1e-7}`},
		{"số âm nhỏ dạng mũ", `{"n":-1e-7}`, `{"n":-1e-7}`},
		{"1e21 dạng mũ có dấu +", `{"n":1e21}`, `{"n":1e+21}`},
		{"số nguyên lớn hơn int64 vẫn in đủ", `{"n":123456789012345680000}`, `{"n":123456789012345680000}`},
		{"số mũ lớn", `{"n":1.5e300}`, `{"n":1.5e+300}`},
		{"số âm", `{"n":-0.5}`, `{"n":-0.5}`},
		{"vượt 2^53 làm tròn như double", `{"n":9007199254740993}`, `{"n":9007199254740992}`},
		{"thứ tự khoá theo UTF-16", `{"！":1,"😀":2,"a":0}`, `{"a":0,"😀":2,"！":1}`},
		{"ký tự điều khiển", `{"c":"tab\tnl\nq\"bs\\ctl\u0001"}`, `{"c":"tab\tnl\nq\"bs\\ctl\u0001"}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var v any
			if err := json.Unmarshal([]byte(c.in), &v); err != nil {
				t.Fatalf("dữ liệu vào không hợp lệ: %v", err)
			}
			if got := CanonicalJSON(v); got != c.want {
				t.Errorf("CanonicalJSON\n  nhận  = %s\n  mong  = %s", got, c.want)
			}
		})
	}
}

// Thứ tự khoá trong dữ liệu vào không được ảnh hưởng tới hash.
func TestCanonicalJSONKeyOrderIndependent(t *testing.T) {
	var a, b any
	_ = json.Unmarshal([]byte(`{"a":1,"b":{"c":2,"d":3}}`), &a)
	_ = json.Unmarshal([]byte(`{"b":{"d":3,"c":2},"a":1}`), &b)
	if SHA3256Hex(a) != SHA3256Hex(b) {
		t.Error("cùng nội dung nhưng khác thứ tự khoá lại cho hash khác nhau")
	}
}

// Hash của một VC có cả "&" lẫn số thực, lấy từ sha3_256Hex() của backend TS.
func TestSHA3256HexMixedMatchesTypeScript(t *testing.T) {
	var v any
	_ = json.Unmarshal([]byte(`{"f":"Kinh tế & QTKD","n":1234567.5}`), &v)
	const want = "0xff9341fc0c4a48aa39a99896cf735906f11f400008029e7f2f5fe1316e2d70f3"
	if got := SHA3256Hex(v); got != want {
		t.Errorf("SHA3256Hex = %s, mong đợi %s", got, want)
	}
}

func TestSHA3256HexMatchesTypeScript(t *testing.T) {
	// Giá trị đối chiếu chéo từ ba nguồn độc lập, tất cả đều cho cùng kết quả:
	//   node  : crypto.createHash("sha3-256").update('{"a":1}').digest("hex")
	//   noble : sha3_256(new TextEncoder().encode('{"a":1}'))   <- frontend dùng
	//   go    : golang.org/x/crypto/sha3.Sum256                  <- backend này dùng
	var v any
	_ = json.Unmarshal([]byte(`{"a":1}`), &v)
	const want = "0xa943baa087ebafbda2490731cbe9aa91708f0b66bd4055150e814fe74ce61c4a"
	if got := SHA3256Hex(v); got != want {
		t.Errorf("SHA3256Hex = %s, mong đợi %s", got, want)
	}
}

func TestChallengeMessageFormat(t *testing.T) {
	// Chuỗi này chính là thứ được ký, phải khớp từng ký tự với TypeScript và frontend.
	got := ChallengeMessage("0xabc", "n-1")
	want := "VNU-Trust xac thuc dang nhap\ndia chi: 0xabc\nnonce: n-1"
	if got != want {
		t.Errorf("ChallengeMessage\n  nhận = %q\n  mong = %q", got, want)
	}
}

// Vector vc_id_hash: SHA3-256 cua byte UTF-8 THO cua chuoi (khong qua canonicalize).
// Gia tri sinh tu @noble/hashes va node:crypto (hai nguon doc lap, bang nhau) ngay 17/11.
func TestSHA3256StringVcIdVectors(t *testing.T) {
	cases := map[string]string{
		"x": "0x741efa311f97686956946758e0d95f70f11ff2da4f2feb7c54314f44134ac49f",
		"urn:uuid:00000000-0000-4000-8000-000000000000": "0xf618bc0a0c3e9391cd60c27430da73a3cd434ff1cce8685ff4dca1a3907519f3",
	}
	for in, want := range cases {
		if got := SHA3256String(in); got != want {
			t.Errorf("SHA3256String(%q) = %s, want %s", in, got, want)
		}
	}
}
