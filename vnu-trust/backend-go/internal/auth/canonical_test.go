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
