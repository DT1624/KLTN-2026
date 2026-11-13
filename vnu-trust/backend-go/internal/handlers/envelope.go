package handlers

import (
	"context"
	"encoding/base64"
	"regexp"
	"sort"
	"strings"

	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/httpx"
)

// Kiểm CẤU TRÚC phong bì văn bằng và bản trình bày đã mã hoá (P3, 13/11/2026).
// Máy chủ không còn thấy bản rõ nên không kiểm được contentHash lúc cấp; rào thay
// thế: ví holder tự kiểm sau khi giải mã, bước xác minh 7, và ở đây — phong bì đúng
// định dạng, gắn với đúng văn bằng, đúng holder + issuer là người nhận, KHÔNG mang
// trường lạ. Phải giống hệt backend TypeScript (services/envelope.service.ts).

var reB64 = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

const (
	maxEnvelopeCT = 64 * 1024
	maxShareCT    = 1024 * 1024
)

func b64len(v any, field string) (int, error) {
	s, ok := v.(string)
	if !ok || !reB64.MatchString(s) || len(s)%4 != 0 {
		return 0, httpx.BadRequest("Phong bì không hợp lệ: %s phải là base64", field)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return 0, httpx.BadRequest("Phong bì không hợp lệ: %s phải là base64", field)
	}
	return len(b), nil
}

func exactKeys(o any, keys []string, what string) (map[string]any, error) {
	m, ok := o.(map[string]any)
	if !ok {
		return nil, httpx.BadRequest("Phong bì không hợp lệ: %s phải là đối tượng", what)
	}
	got := make([]string, 0, len(m))
	for k := range m {
		got = append(got, k)
	}
	want := append([]string{}, keys...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		return nil, httpx.BadRequest("Phong bì không hợp lệ: %s chỉ được có các trường %s", what, strings.Join(keys, ", "))
	}
	return m, nil
}

func (a *API) loadPinned(ctx context.Context, cid, what string) (any, error) {
	v, err := a.IPFS.FetchJSON(ctx, cid)
	if err != nil {
		return nil, httpx.BadRequest("Không đọc được %s tại CID %s", what, cid)
	}
	return v, nil
}

func isOne(v any) bool { f, ok := v.(float64); return ok && f == 1 }

// assertEnvelope: phong bì văn bằng tại cid gắn với vcIDHash, người nhận đúng là holder + issuer.
func (a *API) assertEnvelope(ctx context.Context, cid, vcIDHash, holder, issuer string) error {
	raw, err := a.loadPinned(ctx, cid, "phong bì văn bằng")
	if err != nil {
		return err
	}
	env, err := exactKeys(raw, []string{"v", "alg", "aad", "iv", "ct", "recipients"}, "phong bì")
	if err != nil {
		return err
	}
	if !isOne(env["v"]) || env["alg"] != "A256GCM" {
		return httpx.BadRequest("Phong bì không hợp lệ: chỉ hỗ trợ v=1, alg=A256GCM")
	}
	if env["aad"] != "vnu-vc:"+strings.ToLower(vcIDHash) {
		return httpx.BadRequest("Phong bì không hợp lệ: aad không gắn với văn bằng này")
	}
	if n, err := b64len(env["iv"], "iv"); err != nil {
		return err
	} else if n != 12 {
		return httpx.BadRequest("Phong bì không hợp lệ: iv phải 12 byte")
	}
	if n, err := b64len(env["ct"], "ct"); err != nil {
		return err
	} else if n < 16 || n > maxEnvelopeCT {
		return httpx.BadRequest("Phong bì không hợp lệ: kích thước bản mã ngoài khoảng cho phép")
	}
	recipients, ok := env["recipients"].([]any)
	if !ok || len(recipients) < 2 || len(recipients) > 4 {
		return httpx.BadRequest("Phong bì không hợp lệ: cần 2..4 người nhận")
	}
	holderAddr, _ := chain.NormalizeAddress(holder)
	issuerAddr, _ := chain.NormalizeAddress(issuer)
	kids := map[string]bool{}
	holders, issuers := 0, 0
	for _, raw := range recipients {
		r, err := exactKeys(raw, []string{"kid", "role", "epk", "iv", "wk"}, "người nhận")
		if err != nil {
			return err
		}
		s, _ := r["kid"].(string)
		kid, kerr := chain.NormalizeAddress(s)
		if kerr != nil {
			return httpx.BadRequest("Phong bì không hợp lệ: kid phải là địa chỉ")
		}
		if kids[kid] {
			return httpx.BadRequest("Phong bì không hợp lệ: người nhận trùng lặp")
		}
		kids[kid] = true
		role := r["role"]
		if role != "holder" && role != "issuer" {
			return httpx.BadRequest("Phong bì không hợp lệ: role phải là holder hoặc issuer")
		}
		// Ngắt sớm theo đúng thứ tự epk → iv → wk như biểu thức `||` bên TypeScript,
		// để cùng một phong bì sai cho cùng một thông điệp lỗi (bài học #8).
		for _, f := range []struct {
			key  string
			want int
		}{{"epk", 32}, {"iv", 12}, {"wk", 48}} {
			n, err := b64len(r[f.key], f.key)
			if err != nil {
				return err
			}
			if n != f.want {
				return httpx.BadRequest("Phong bì không hợp lệ: khoá bọc sai kích thước")
			}
		}
		if role == "holder" && kid == holderAddr {
			holders++
		}
		if role == "issuer" && kid == issuerAddr {
			issuers++
		}
	}
	if holders != 1 {
		return httpx.BadRequest("Phong bì không hợp lệ: holder không nằm trong danh sách người nhận")
	}
	if issuers != 1 {
		return httpx.BadRequest("Phong bì không hợp lệ: issuer không nằm trong danh sách người nhận")
	}
	return nil
}

// assertShareBlob: bản trình bày đã mã hoá tại cid (khoá nằm trong fragment liên kết).
func (a *API) assertShareBlob(ctx context.Context, cid string) error {
	raw, err := a.loadPinned(ctx, cid, "bản trình bày đã mã hoá")
	if err != nil {
		return err
	}
	blob, err := exactKeys(raw, []string{"v", "alg", "iv", "ct"}, "bản trình bày")
	if err != nil {
		return err
	}
	if !isOne(blob["v"]) || blob["alg"] != "A256GCM" {
		return httpx.BadRequest("Phong bì không hợp lệ: chỉ hỗ trợ v=1, alg=A256GCM")
	}
	if n, err := b64len(blob["iv"], "iv"); err != nil {
		return err
	} else if n != 12 {
		return httpx.BadRequest("Phong bì không hợp lệ: iv phải 12 byte")
	}
	if n, err := b64len(blob["ct"], "ct"); err != nil {
		return err
	} else if n < 16 || n > maxShareCT {
		return httpx.BadRequest("Phong bì không hợp lệ: kích thước bản mã ngoài khoảng cho phép")
	}
	return nil
}

// isPublicPinned: tuyến công khai GET /api/ipfs/{cid} chỉ phục vụ DID Document, phong
// bì văn bằng và bản trình bày đã mã hoá — JSON khác (vd. văn bằng dạng rõ một client
// cẩu thả ghim) không được phát lại công khai. Giống bản TypeScript.
func isPublicPinned(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if j := strings.Join(keys, ","); j == "aad,alg,ct,iv,recipients,v" || j == "alg,ct,iv,v" {
		return true
	}
	id, _ := m["id"].(string)
	_, hasCtx := m["@context"]
	return strings.HasPrefix(id, "did:") && hasCtx
}
