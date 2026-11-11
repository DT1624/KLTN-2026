package handlers

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vnu-trust/backend-go/internal/auth"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/middleware"
)

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type CredSummary struct {
	VCID      string `json:"vcId"`
	Status    string `json:"status"`
	IssuerDID string `json:"issuerDid"`
	TypeLabel string `json:"typeLabel"`
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
func (a *API) verify(r *http.Request, token string) (*Report, error) {
	ctx := r.Context()
	st, err := a.Store.OpenShareToken(ctx, token)
	if err != nil {
		return nil, err
	}
	checks := []Check{}

	// 1. Tải VP từ IPFS
	vpDoc, ferr := a.IPFS.FetchJSON(ctx, st.IPFSCid)
	if ferr == nil {
		checks = append(checks, Check{"Tải VP từ IPFS", true, "CID " + st.IPFSCid})
	} else {
		checks = append(checks, Check{"Tải VP từ IPFS", false, ferr.Error()})
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
		checks = append(checks, Check{"Toàn vẹn nội dung VP", ok, detail})
	}

	// 3. Chữ ký của holder trên VP
	if vpDoc != nil && vp != nil {
		holder, err := a.Store.EntityByDID(ctx, vp.HolderDID)
		if err != nil {
			return nil, err
		}
		ok, detail := false, "Không tìm thấy khoá công khai của holder"
		if holder != nil {
			unsigned := vpDoc
			if m, isMap := vpDoc.(map[string]any); isMap {
				cp := make(map[string]any, len(m))
				for k, v := range m {
					if k != "proof" {
						cp[k] = v
					}
				}
				unsigned = cp
			}
			ok = auth.VerifySignature(holder.PublicKeyHex, auth.CanonicalJSON(unsigned), vp.ProofValue)
			detail = "Chữ ký hợp lệ"
			if !ok {
				detail = "Chữ ký không khớp khoá công khai của holder"
			}
		}
		checks = append(checks, Check{"Chữ ký của người trình bày", ok, detail})
	}

	// 4. DID của holder còn hoạt động
	if vp != nil {
		res, derr := a.resolve(r, vp.HolderDID)
		if derr != nil {
			checks = append(checks, Check{"DID người trình bày còn hiệu lực", false, derr.Error()})
		} else {
			checks = append(checks, Check{"DID người trình bày còn hiệu lực",
				res.Status == "active", "Trạng thái \"" + res.Status + "\" (nguồn: " + res.Source + ")"})
		}
	}

	// 5. Từng VC còn hiệu lực
	creds := []CredSummary{}
	allValid := vp != nil && len(vp.VCIDs) > 0
	activeCount := 0
	// Giữ lại hàng đã đọc để bước 5b dùng lại: đọc hai lần cùng một VC là nhân
	// đôi số truy vấn CSDL cho mỗi văn bằng trong bản trình bày.
	fetched := []*db.Credential{}
	if vp != nil {
		for _, id := range vp.VCIDs {
			vc, err := a.Store.VCByID(ctx, id)
			if err != nil {
				return nil, err
			}
			fetched = append(fetched, vc)
			if vc == nil {
				allValid = false
				creds = append(creds, CredSummary{id, "không tìm thấy", "-", "-"})
				continue
			}
			stt, _ := a.effectiveStatus(r, vc)
			if stt != "active" {
				allValid = false
			} else {
				activeCount++
			}
			creds = append(creds, CredSummary{id, stt, vc.IssuerDID, vcTypeLabel(vc.VCType)})
		}
	}
	checks = append(checks, Check{"Tất cả chứng chỉ còn hiệu lực", allValid,
		strconv.Itoa(activeCount) + "/" + strconv.Itoa(len(creds)) + " còn hiệu lực"})

	// 5b. Nội dung văn bằng vẫn khớp bản đã neo trên chuỗi.
	//
	// Bước 5 mới chỉ hỏi "văn bằng này còn hiệu lực không". Nó KHÔNG phát hiện
	// được việc nội dung bị sửa sau khi cấp: đổi điểm trong vc_json rồi ghim lại
	// IPFS thì trạng thái vẫn "active". Ở đây ta băm lại chính nội dung đang giữ
	// rồi hỏi chuỗi xem có đúng hash đã neo không.
	allIntact := len(creds) > 0
	intactCount := 0
	// Các VC độc lập với nhau nên hỏi chuỗi song song: tuần tự thì một bản trình
	// bày 5 văn bằng phải chờ 5 vòng mạng nối tiếp.
	intact := make([]bool, len(fetched))
	var wg sync.WaitGroup
	for i, vc := range fetched {
		if vc == nil || vc.OnChainVCID == nil {
			continue
		}
		wg.Add(1)
		go func(i int, vc *db.Credential) {
			defer wg.Done()
			intact[i] = a.Chain.VerifyIntegrity(ctx, *vc.OnChainVCID, auth.SHA3256Hex(vc.VCJSON))
		}(i, vc)
	}
	wg.Wait()
	for _, ok := range intact {
		if ok {
			intactCount++
		} else {
			allIntact = false
		}
	}
	checks = append(checks, Check{"Nội dung văn bằng khớp bản neo trên chuỗi", allIntact,
		strconv.Itoa(intactCount) + "/" + strconv.Itoa(len(creds)) + " khớp hash đã neo"})

	// 6. Issuer còn được tin cậy trên chuỗi — hỏi song song theo issuer_address đã lưu.
	trusted := make([]bool, len(fetched))
	for i, vc := range fetched {
		if vc == nil {
			continue
		}
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			trusted[i] = a.Chain.IsActiveIssuer(ctx, addr)
		}(i, vc.IssuerAddress)
	}
	wg.Wait()
	allTrusted := len(creds) > 0
	for _, ok := range trusted {
		allTrusted = allTrusted && ok
	}
	detail := "Tất cả issuer đang hoạt động trên chuỗi"
	if !allTrusted {
		detail = "Có issuer đã bị thu hồi/tạm ngưng"
	}
	checks = append(checks, Check{"Đơn vị cấp còn được tin cậy", allTrusted, detail})

	overall := true
	for _, c := range checks {
		if !c.Passed {
			overall = false
		}
	}
	return &Report{
		VPID: st.VPID, HolderDID: st.HolderDID, OverallValid: overall,
		Checks: checks, Credentials: creds, VerifiedAt: time.Now().UTC(),
	}, nil
}

func (a *API) VerifyShare(w http.ResponseWriter, r *http.Request) error {
	rep, err := a.verify(r, r.PathValue("token"))
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rep)
	return nil
}

func (a *API) VerifyAndRecord(w http.ResponseWriter, r *http.Request) error {
	rep, err := a.verify(r, r.PathValue("token"))
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
	rows, err := a.Store.VerificationHistory(r.Context(), c.Address, queryInt(r, "limit", 50, 1, 200))
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rows)
	return nil
}
