package handlers

import (
	"net/http"
	"strings"

	"github.com/vnu-trust/backend-go/internal/auth"
	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/middleware"
	"github.com/vnu-trust/backend-go/internal/services"
)

type ResolvedDID struct {
	DID          string `json:"did"`
	Source       string `json:"source"`
	Status       string `json:"status"`
	DocumentCID  string `json:"documentCid"`
	DocumentHash string `json:"documentHash"`
	Version      int    `json:"version"`
	Document     any    `json:"document"`
	IntegrityOK  *bool  `json:"integrityOk"`
}

// resolve lấy chuỗi làm nguồn sự thật, chỉ lùi về CSDL khi chuỗi không có dữ liệu.
func (a *API) resolve(r *http.Request, did string) (*ResolvedDID, error) {
	ctx := r.Context()
	if oc := a.Chain.ResolveDID(ctx, did); oc != nil {
		// Không được nói dối là "chain" khi VERIFY_ONCHAIN=false và dữ liệu
		// thực ra đọc từ chỉ mục CSDL. Phải khớp backend TypeScript.
		src := "chain"
		if a.Chain.Offline() {
			src = "db-index"
		}
		out := &ResolvedDID{
			DID: did, Source: src, Status: oc.Status,
			DocumentCID: oc.DocumentCID, DocumentHash: oc.DocumentHash, Version: oc.Version,
		}
		if doc, err := a.IPFS.FetchJSON(ctx, oc.DocumentCID); err == nil {
			out.Document = doc
			ok := auth.SHA3256Hex(doc) == oc.DocumentHash
			out.IntegrityOK = &ok
		}
		return out, nil
	}

	cached, err := a.Store.DIDByDID(ctx, did)
	if err != nil {
		return nil, err
	}
	if cached == nil {
		return nil, httpx.NotFound("Không tìm thấy DID %s", did)
	}
	ok := auth.SHA3256Hex(cached.DocJSON) == cached.DocumentHash
	return &ResolvedDID{
		DID: did, Source: "cache", Status: cached.Status,
		DocumentCID: cached.DocumentCID, DocumentHash: cached.DocumentHash,
		Version: cached.Version, Document: cached.DocJSON, IntegrityOK: &ok,
	}, nil
}

func (a *API) ResolveDIDHandler(w http.ResponseWriter, r *http.Request) error {
	did, err := httpx.DID(r.URL.Query().Get("did"), "did")
	if err != nil {
		return err
	}
	res, err := a.resolve(r, did)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, res)
	return nil
}

func (a *API) resolveByAddress(r *http.Request, address string) (*ResolvedDID, error) {
	if oc := a.Chain.ResolveDIDByOwner(r.Context(), address); oc != nil {
		return a.resolve(r, oc.DID)
	}
	row, err := a.Store.DIDByAddress(r.Context(), address)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, httpx.NotFound("Địa chỉ %s chưa có DID", address)
	}
	return a.resolve(r, row.DID)
}

// ResolveDIDByAddressHandler resolve DID theo địa chỉ chủ sở hữu.
func (a *API) ResolveDIDByAddressHandler(w http.ResponseWriter, r *http.Request) error {
	address, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	res, err := a.resolveByAddress(r, address)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, res)
	return nil
}

// SaveDID ghi nhận DID sau khi giao dịch register_did đã lên chuỗi.
// Ba lớp kiểm tra: giao dịch có thật, hash khớp nội dung, CID khớp bản ghi trên chuỗi.
func (a *API) SaveDID(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		DID          string         `json:"did"`
		DocumentCID  string         `json:"documentCid"`
		DocumentHash string         `json:"documentHash"`
		DocJSON      map[string]any `json:"docJson"`
		TxHash       string         `json:"txHash"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	did, err := httpx.DID(body.DID, "did")
	if err != nil {
		return err
	}
	cid, err := httpx.CID(body.DocumentCID, "documentCid")
	if err != nil {
		return err
	}
	hash, err := httpx.Hash32(body.DocumentHash, "documentHash")
	if err != nil {
		return err
	}
	txHash, err := httpx.TxHash(body.TxHash, "txHash")
	if err != nil {
		return err
	}
	if body.DocJSON == nil {
		return httpx.BadRequest("docJson: bắt buộc")
	}

	c := middleware.ClaimsFrom(r.Context())
	e, err := a.Store.RequireEntity(r.Context(), c.Address)
	if err != nil {
		return err
	}
	if did != e.DID {
		return httpx.BadRequest("DID không khớp với tài khoản đang đăng nhập")
	}

	// Thứ tự kiểm tra: rẻ trước, đắt sau — và phải GIỐNG HỆT backend TypeScript,
	// nếu không cùng một yêu cầu sai sẽ nhận hai mã lỗi khác nhau tuỳ backend nào
	// phục vụ. (Đúng loại lệch này từng lọt qua vì ở chế độ nghiêm ngặt cả hai
	// đều dừng sớm ở bước xác minh giao dịch.)

	// (1) Hash phải khớp nội dung. Không tốn I/O nên kiểm trước.
	if got := auth.SHA3256Hex(body.DocJSON); got != hash {
		return httpx.BadRequest("Hash tài liệu không khớp nội dung (tính được %s, khai %s)", got, hash)
	}
	// (2) Đã ghi rồi thì dừng — một lượt truy vấn CSDL, rẻ hơn gọi fullnode.
	if existing, err := a.Store.DIDByDID(r.Context(), did); err != nil {
		return err
	} else if existing != nil {
		return httpx.Conflict("DID này đã được ghi nhận")
	}
	// (3) Giao dịch phải có thật và do chính chủ gửi — đắt nhất, để cuối.
	//     Tham số của chính giao dịch đó phải là DID/CID/hash đang ghi (S-02).
	if _, err := a.Chain.VerifyTransactionArgs(r.Context(), txHash, a.Chain.EntryRegisterDID(), e.Address,
		[]chain.Arg{chain.ArgBytes(chain.UTF8ToHex(did)), chain.ArgBytes(chain.UTF8ToHex(cid)), chain.ArgBytes(hash)}); err != nil {
		return err
	}
	// (4) Đối chiếu với bản ghi trên chuỗi. Ở chế độ nghiêm ngặt, KHÔNG đọc được
	//     bản ghi thì dừng — trước đây bước này bị bỏ qua lặng lẽ (P-10). Chế độ
	//     offline đọc từ chỉ mục, DID mới thì chưa có, nên vẫn cho qua như cũ.
	oc := a.Chain.ResolveDID(r.Context(), did)
	if oc == nil && !a.Chain.Offline() {
		return httpx.BadRequest("Không đọc được DID này trên chuỗi — giao dịch register_did chưa ghi đúng DID của tài khoản")
	}
	if oc != nil {
		if oc.DocumentCID != cid {
			return httpx.BadRequest("CID khai báo không khớp CID đã ghi trên chuỗi")
		}
		if !a.Chain.Offline() && strings.ToLower(oc.DocumentHash) != hash {
			return httpx.BadRequest("Hash tài liệu khai báo không khớp hash đã ghi trên chuỗi")
		}
		if oc.Status != "active" {
			return httpx.BadRequest("DID trên chuỗi đang ở trạng thái %q", oc.Status)
		}
	}

	row, err := a.Store.SaveDID(r.Context(), services.SaveDIDInput{
		EntityID: e.ID, DID: did, DocumentCID: cid, DocumentHash: hash,
		DocJSON: body.DocJSON, TxHash: txHash,
	})
	if err != nil {
		return err
	}
	a.Store.Audit(r.Context(), e.Address, services.AuditDIDSave, &did,
		map[string]any{"documentCid": cid, "txHash": txHash})
	httpx.OK(w, http.StatusCreated, row)
	return nil
}
