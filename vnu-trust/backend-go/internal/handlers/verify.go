package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vnu-trust/backend-go/internal/auth"
	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/middleware"
)

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
	// Advisory: bước CẢNH BÁO — hiện cho người xác minh nhưng không quyết định
	// overallValid. Hiện chỉ có bước 6 (quyết định 13/11/2026, C2) — giống bản TS.
	Advisory bool `json:"advisory"`
}

func newCheck(name string, passed bool, detail string) Check {
	return Check{Name: name, Passed: passed, Detail: detail}
}

type CredSummary struct {
	VCID      string `json:"vcId"`
	Status    string `json:"status"`
	IssuerDID string `json:"issuerDid"`
	TypeLabel string `json:"typeLabel"`
	// ReplacedBy (C3): vc_id của văn bằng thay thế — chỉ khi chuỗi xác nhận liên kết.
	ReplacedBy *string `json:"replacedBy"`
}

type Report struct {
	VPID         string        `json:"vpId"`
	HolderDID    string        `json:"holderDid"`
	OverallValid bool          `json:"overallValid"`
	Checks       []Check       `json:"checks"`
	Credentials  []CredSummary `json:"credentials"`
	VerifiedAt   time.Time     `json:"verifiedAt"`
}

func (a *API) OpenShare(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	st, err := a.Store.OpenShareToken(r.Context(), token)
	if err != nil {
		return err
	}
	vp, err := a.Store.VPByID(r.Context(), st.VPID)
	if err != nil {
		return err
	}
	ids := []string{}
	if vp != nil {
		ids = vp.VCIDs
	}
	httpx.OK(w, http.StatusOK, map[string]any{
		"vpId": st.VPID, "holderDid": st.HolderDID, "ipfsCid": st.IPFSCid,
		"expiresAt": st.ExpiresAt, "viewCount": st.ViewCount, "vcIds": ids,
	})
	return nil
}

// verify chạy 7 bước kiểm tra độc lập; mỗi bước trả kết quả riêng để giao diện
// chỉ rõ chỗ nào hỏng thay vì chỉ một chữ "không hợp lệ".
//
// P3 (13/11/2026): IPFS chỉ giữ bản trình bày ĐÃ MÃ HOÁ; khoá nằm trong fragment liên
// kết mà máy chủ không bao giờ nhận. Trình duyệt người xác minh giải mã rồi gửi bản rõ
// vpDoc lên; máy chủ chạy 7 bước trên chính bản đó và KHÔNG lưu nó — giống bản TS.
func (a *API) verify(r *http.Request, token string, vpDoc map[string]any) (*Report, error) {
	ctx := r.Context()
	st, err := a.Store.OpenShareToken(ctx, token)
	if err != nil {
		return nil, err
	}
	checks := []Check{}

	// 1. Bản trình bày đã mã hoá còn nằm trên IPFS, đúng định dạng.
	if ferr := a.assertShareBlob(ctx, st.IPFSCid); ferr == nil {
		checks = append(checks, newCheck("Tải VP từ IPFS", true, "Bản mã tại CID "+st.IPFSCid))
	} else {
		checks = append(checks, newCheck("Tải VP từ IPFS", false, ferr.Error()))
	}

	vp, err := a.Store.VPByID(ctx, st.VPID)
	if err != nil {
		return nil, err
	}

	// 2. Toàn vẹn nội dung VP
	if vpDoc != nil && vp != nil {
		got := auth.SHA3256Hex(vpDoc)
		ok := got == vp.VPHash
		detail := "Hash khớp"
		if !ok {
			detail = "Hash lệch: " + got + " ≠ " + vp.VPHash
		}
		checks = append(checks, newCheck("Toàn vẹn nội dung VP", ok, detail))
	}

	// 3. Chữ ký của holder trên VP
	if vpDoc != nil && vp != nil {
		holder, err := a.Store.EntityByDID(ctx, vp.HolderDID)
		if err != nil {
			return nil, err
		}
		ok, detail := false, "Không tìm thấy khoá công khai của holder"
		if holder != nil {
			unsigned := make(map[string]any, len(vpDoc))
			for k, v := range vpDoc {
				if k != "proof" {
					unsigned[k] = v
				}
			}
			ok = auth.VerifySignature(holder.PublicKeyHex, auth.CanonicalJSON(unsigned), vp.ProofValue)
			detail = "Chữ ký hợp lệ"
			if !ok {
				detail = "Chữ ký không khớp khoá công khai của holder"
			}
		}
		checks = append(checks, newCheck("Chữ ký của người trình bày", ok, detail))
	}

	// 4. DID của holder còn hoạt động
	if vp != nil {
		res, derr := a.resolve(r, vp.HolderDID)
		if derr != nil {
			checks = append(checks, newCheck("DID người trình bày còn hiệu lực", false, derr.Error()))
		} else {
			checks = append(checks, newCheck("DID người trình bày còn hiệu lực",
				res.Status == "active", "Trạng thái \""+res.Status+"\" (nguồn: "+res.Source+")"))
		}
	}

	// 5. Từng VC còn hiệu lực
	creds := []CredSummary{}
	allValid := vp != nil && len(vp.VCIDs) > 0
	activeCount := 0
	// Giữ lại hàng đã đọc để bước 5b dùng lại: đọc hai lần cùng một VC là nhân
	// đôi số truy vấn CSDL cho mỗi văn bằng trong bản trình bày.
	// P5: MỘT câu truy vấn cho mọi VC và MỘT lần đọc lô trên chuỗi (trạng thái + hash),
	// dùng chung cho bước 5 và 7 — trước đây là 2 view mỗi văn bằng. Giống bản TS.
	fetched := []*db.Credential{}
	var recs map[int64]chain.VCLite
	if vp != nil {
		rows, err := a.Store.VCsByIDs(ctx, vp.VCIDs)
		if err != nil {
			return nil, err
		}
		byID := map[string]*db.Credential{}
		for i := range rows {
			byID[rows[i].VCID] = &rows[i]
		}
		for _, id := range vp.VCIDs {
			fetched = append(fetched, byID[id])
		}
		recs = a.Chain.VCRecords(ctx, onChainIDs(fetched))
		for i, id := range vp.VCIDs {
			vc := fetched[i]
			if vc == nil {
				allValid = false
				creds = append(creds, CredSummary{id, "không tìm thấy", "-", "-", nil})
				continue
			}
			stt, _ := a.effectiveFrom(vc, recs)
			if stt != "active" {
				allValid = false
			} else {
				activeCount++
			}
			creds = append(creds, CredSummary{id, stt, vc.IssuerDID, vcTypeLabel(vc.VCType), a.confirmedReplacement(ctx, vc)})
		}
	}
	checks = append(checks, newCheck("Tất cả chứng chỉ còn hiệu lực", allValid,
		strconv.Itoa(activeCount)+"/"+strconv.Itoa(len(creds))+" còn hiệu lực"))

	// 5b. Nội dung văn bằng vẫn khớp bản đã neo trên chuỗi.
	//
	// Bước 5 mới chỉ hỏi "văn bằng này còn hiệu lực không". Nó KHÔNG phát hiện
	// được việc nội dung bị sửa sau khi cấp: đổi điểm trong văn bằng rồi trình bày
	// thì trạng thái vẫn "active". Ở đây ta băm lại CHÍNH nội dung có trong bản
	// trình bày rồi hỏi chuỗi xem có đúng hash đã neo không (P3: máy chủ không còn
	// giữ bản rõ — dùng bản người xác minh nhận được, đúng thứ cần kiểm).
	presented := map[string]any{}
	if list, ok := vpDoc["verifiableCredential"].([]any); ok {
		for _, v := range list {
			if m, ok := v.(map[string]any); ok {
				if id, ok := m["id"].(string); ok {
					presented[id] = m
				}
			}
		}
	}
	allIntact := len(creds) > 0
	intactCount := 0
	// Các VC độc lập với nhau nên hỏi chuỗi song song: tuần tự thì một bản trình
	// bày 5 văn bằng phải chờ 5 vòng mạng nối tiếp.
	intact := make([]bool, len(fetched))
	var wg sync.WaitGroup
	for i, vc := range fetched {
		doc, ok := presented[vp.VCIDs[i]] // fetched song song với vp.VCIDs
		if vc == nil || vc.OnChainVCID == nil || !ok {
			continue
		}
		wg.Add(1)
		go func(i int, vc *db.Credential, doc any) {
			defer wg.Done()
			// Bản ghi lô đã có content_hash: so tại chỗ, cùng ngữ nghĩa verify_integrity
			// (online: ACTIVE và hash khớp; offline giữ đúng hành vi cũ: chỉ so hash).
			if rec, ok := recs[*vc.OnChainVCID]; ok && rec.ContentHash != "" {
				intact[i] = (a.Chain.Offline() || rec.Status == "active") && rec.ContentHash == strings.ToLower(auth.SHA3256Hex(doc))
				return
			}
			intact[i] = a.Chain.VerifyIntegrity(ctx, *vc.OnChainVCID, auth.SHA3256Hex(doc))
		}(i, vc, doc)
	}
	wg.Wait()
	for _, ok := range intact {
		if ok {
			intactCount++
		} else {
			allIntact = false
		}
	}
	checks = append(checks, newCheck("Nội dung văn bằng khớp bản neo trên chuỗi", allIntact,
		strconv.Itoa(intactCount)+"/"+strconv.Itoa(len(creds))+" khớp hash đã neo"))

	// 6. Issuer còn được tin cậy trên chuỗi — P5: hỏi mỗi issuer MỘT lần, song song.
	trust := map[string]bool{}
	var tmu sync.Mutex
	for _, vc := range fetched {
		if vc == nil {
			continue
		}
		if _, dup := trust[vc.IssuerAddress]; dup {
			continue
		}
		trust[vc.IssuerAddress] = false
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			ok := a.Chain.IsActiveIssuer(ctx, addr)
			tmu.Lock()
			trust[addr] = ok
			tmu.Unlock()
		}(vc.IssuerAddress)
	}
	wg.Wait()
	allTrusted := len(creds) > 0
	for _, vc := range fetched {
		allTrusted = allTrusted && vc != nil && trust[vc.IssuerAddress]
	}
	detail := "Tất cả issuer đang hoạt động trên chuỗi"
	if !allTrusted {
		detail = "Có issuer đã bị thu hồi/tạm ngưng — văn bằng vẫn hiệu lực cho tới khi cấp trên xem xét"
	}
	// C2 (13/11/2026): thu hồi / tạm ngưng một đơn vị KHÔNG làm văn bằng họ đã cấp mất
	// hiệu lực. Cấp trên xem xét rồi thu hồi theo lô; khi đó bước 5 mới đỏ. Bước này
	// vì vậy chỉ là CẢNH BÁO — giống hệt bản TypeScript.
	step6 := newCheck("Đơn vị cấp còn được tin cậy", allTrusted, detail)
	step6.Advisory = true
	checks = append(checks, step6)

	overall := true
	for _, c := range checks {
		if !c.Passed && !c.Advisory {
			overall = false
		}
	}
	return &Report{
		VPID: st.VPID, HolderDID: st.HolderDID, OverallValid: overall,
		Checks: checks, Credentials: creds, VerifiedAt: time.Now().UTC(),
	}, nil
}

// verifyBody: bản trình bày trình duyệt người xác minh vừa giải mã (P3) — giống zVerifyBody bên TS.
func verifyBody(r *http.Request) (map[string]any, error) {
	var body struct {
		VP map[string]any `json:"vp"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return nil, err
	}
	if body.VP == nil {
		return nil, httpx.BadRequest("vp: bắt buộc — bản trình bày đã giải mã")
	}
	return body.VP, nil
}

func (a *API) VerifyShare(w http.ResponseWriter, r *http.Request) error {
	vpDoc, err := verifyBody(r)
	if err != nil {
		return err
	}
	rep, err := a.verify(r, r.PathValue("token"), vpDoc)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rep)
	return nil
}

func (a *API) VerifyAndRecord(w http.ResponseWriter, r *http.Request) error {
	vpDoc, err := verifyBody(r)
	if err != nil {
		return err
	}
	rep, err := a.verify(r, r.PathValue("token"), vpDoc)
	if err != nil {
		return err
	}
	c := middleware.ClaimsFrom(r.Context())
	if err := a.Store.SaveVerification(r.Context(), rep.VPID, c.Address, rep.OverallValid, rep); err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rep)
	return nil
}

func (a *API) VerifyHistory(w http.ResponseWriter, r *http.Request) error {
	c := middleware.ClaimsFrom(r.Context())
	limit, err := queryInt(r, "limit", 50, 1, 200)
	if err != nil {
		return err
	}
	rows, err := a.Store.VerificationHistory(r.Context(), c.Address, limit)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rows)
	return nil
}

// confirmedReplacement: văn bằng thay thế cho vc (C3), chỉ khi chuỗi xác nhận đúng
// liên kết đó — giống bản TypeScript (vp.service.ts confirmedReplacement).
func (a *API) confirmedReplacement(ctx context.Context, vc *db.Credential) *string {
	if vc.ReplacedByVCID == nil {
		return nil
	}
	if a.Chain.Offline() {
		return vc.ReplacedByVCID
	}
	repl, err := a.Store.VCByID(ctx, *vc.ReplacedByVCID)
	if err != nil || repl == nil || repl.OnChainVCID == nil || vc.OnChainVCID == nil {
		return nil
	}
	if linked, ok := a.Chain.VCReplacement(ctx, *vc.OnChainVCID); ok && linked == *repl.OnChainVCID {
		return &repl.VCID
	}
	return nil
}
