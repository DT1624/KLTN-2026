package handlers

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/vnu-trust/backend-go/internal/httpx"
)

var (
	reLookupDID  = regexp.MustCompile(`^did:`)
	reLookupCID  = regexp.MustCompile(`^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$`)
	reLookupAddr = regexp.MustCompile(`^0x[0-9a-fA-F]{1,64}$`)
	reLookupFull = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
)

// Lookup là ô tra cứu hợp nhất ở trang chủ.
//
// Lưu ý: địa chỉ ví đầy đủ và mã giao dịch ĐỀU là "0x" + 64 ký tự hex, không
// phân biệt được bằng hình thức. Với trường hợp đó thì thử resolve DID trước,
// không có mới tra sang giao dịch.
func (a *API) Lookup(w http.ResponseWriter, r *http.Request) error {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 3 || len(q) > 300 {
		return httpx.BadRequest("q: chuỗi tra cứu phải dài 3..300 ký tự")
	}

	switch {
	case reLookupDID.MatchString(strings.ToLower(q)):
		res, err := a.resolve(r, q)
		if err != nil {
			return err
		}
		httpx.OK(w, http.StatusOK, map[string]any{"kind": "did", "result": res})
		return nil

	case reLookupCID.MatchString(q):
		// Chỉ trả nội dung khi CID là DID Document đã ghi nhận. Nội dung văn bằng
		// là dữ liệu cá nhân, mà CID của mọi văn bằng nằm công khai trên chuỗi (S-03).
		isDidDoc, err := a.Store.IsDIDDocumentCID(r.Context(), q)
		if err != nil {
			return err
		}
		if !isDidDoc {
			httpx.OK(w, http.StatusOK, map[string]any{
				"kind": "cid", "result": map[string]any{"cid": q, "content": nil, "private": true}})
			return nil
		}
		content, err := a.IPFS.FetchJSON(r.Context(), q)
		if err != nil {
			return err
		}
		httpx.OK(w, http.StatusOK, map[string]any{
			"kind": "cid", "result": map[string]any{"cid": q, "content": content, "private": false}})
		return nil

	case strings.HasPrefix(strings.ToLower(q), "urn:uuid:"):
		vc, err := a.Store.VCByID(r.Context(), q)
		if err != nil {
			return err
		}
		if vc == nil {
			return httpx.BadRequest("Không tìm thấy VC %s", q)
		}
		status, source := a.effectiveStatus(r, vc)
		// Chỉ công bố thông tin không nhạy cảm — không trả nội dung VC.
		httpx.OK(w, http.StatusOK, map[string]any{"kind": "vcId", "result": map[string]any{
			"vcId": vc.VCID, "status": status, "statusSource": source, "issuerDid": vc.IssuerDID,
			"holderDid": vc.HolderDID, "typeLabel": vcTypeLabel(vc.VCType),
			"issuedAt": vc.IssuedAt, "expiresAt": vc.ExpiresAt,
			"ipfsCid": vc.IPFSCid, "txHash": vc.TxHash,
		}})
		return nil

	case reLookupAddr.MatchString(q):
		res, err := a.resolveByAddress(r, strings.ToLower(q))
		if err == nil {
			httpx.OK(w, http.StatusOK, map[string]any{"kind": "address", "result": res})
			return nil
		}
		if !reLookupFull.MatchString(q) {
			return err
		}
		tx, txErr := a.Chain.GetTransaction(r.Context(), strings.ToLower(q))
		if txErr != nil || tx == nil {
			return httpx.BadRequest("Chuỗi này không phải địa chỉ ví có DID, cũng không phải mã giao dịch có thật")
		}
		httpx.OK(w, http.StatusOK, map[string]any{"kind": "txHash", "result": map[string]any{
			"hash": tx.Hash, "success": tx.Success, "vmStatus": tx.VMStatus,
			"sender": tx.Sender, "function": tx.Payload.Function, "version": tx.Version,
		}})
		return nil
	}

	return httpx.BadRequest("Không nhận diện được định danh — hãy nhập DID, địa chỉ ví, CID hoặc mã VC")
}

var vcTypeLabels = map[int]string{
	1: "Bằng cử nhân", 2: "Bằng thạc sĩ", 4: "Bằng tiến sĩ",
	8: "Bảng điểm", 16: "Chứng chỉ ngắn hạn", 32: "Chứng chỉ ủy quyền",
}

func vcTypeLabel(t int) string {
	if l, ok := vcTypeLabels[t]; ok {
		return l
	}
	var parts []string
	for _, bit := range []int{1, 2, 4, 8, 16, 32} {
		if t&bit != 0 {
			parts = append(parts, vcTypeLabels[bit])
		}
	}
	if len(parts) == 0 {
		return "Loại " + strconv.Itoa(t)
	}
	return strings.Join(parts, ", ")
}
