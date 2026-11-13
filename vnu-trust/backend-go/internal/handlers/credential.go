package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/vnu-trust/backend-go/internal/auth"
	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/middleware"
	"github.com/vnu-trust/backend-go/internal/services"
)

// effectiveStatus kết hợp trạng thái trên chuỗi, trong CSDL và hạn dùng; chuỗi
// được ưu tiên khi lệch. Trả kèm nguồn ("chain" | "db-index" | "db") như bản TS.
func (a *API) effectiveStatus(r *http.Request, c *db.Credential) (status, source string) {
	if c.ExpiresAt != nil && !c.ExpiresAt.After(time.Now()) {
		return "expired", "db"
	}
	if c.OnChainVCID != nil {
		if st := a.Chain.VCStatus(r.Context(), *c.OnChainVCID); st != "" {
			return st, a.chainSource()
		}
	}
	return c.Status, "db"
}

// effectiveFrom: cùng luật effectiveStatus nhưng dùng bản ghi đã đọc theo lô (P5).
func (a *API) effectiveFrom(c *db.Credential, recs map[int64]chain.VCLite) (status, source string) {
	if c.ExpiresAt != nil && !c.ExpiresAt.After(time.Now()) {
		return "expired", "db"
	}
	if c.OnChainVCID != nil {
		if rec, ok := recs[*c.OnChainVCID]; ok {
			return rec.Status, a.chainSource()
		}
	}
	return c.Status, "db"
}

func onChainIDs(rows []*db.Credential) []int64 {
	ids := []int64{}
	for _, c := range rows {
		if c != nil && c.OnChainVCID != nil {
			ids = append(ids, *c.OnChainVCID)
		}
	}
	return ids
}

func (a *API) withStatus(r *http.Request, c *db.Credential) credentialWithStatus {
	st, src := a.effectiveStatus(r, c)
	return credentialWithStatus{Credential: c,
		Effective: map[string]any{"status": st, "source": src, "drift": src != "db" && st != c.Status}}
}

// withTypeLabels gắn nhãn tiếng Việt cho từng loại văn bằng trong số liệu biểu đồ.
func withTypeLabels(m map[string]any) map[string]any {
	if types, ok := m["byType"].([]services.TypeCount); ok {
		for i := range types {
			types[i].Label = vcTypeLabel(types[i].VCType)
		}
	}
	return m
}

func (a *API) IssuerStats(w http.ResponseWriter, r *http.Request) error {
	c := middleware.ClaimsFrom(r.Context())
	stats, err := a.Store.CredentialBreakdown(r.Context(), c.DID)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, withTypeLabels(stats))
	return nil
}

func (a *API) IssuerCredentials(w http.ResponseWriter, r *http.Request) error {
	c := middleware.ClaimsFrom(r.Context())
	// Bộ lọc ?status trước đây bị BỎ QUA ở bản Go (bản TS có lọc) — L-05.
	status := r.URL.Query().Get("status")
	switch status {
	case "", "active", "suspended", "expired", "revoked":
	default:
		return httpx.BadRequest("status: phải là active, suspended, expired hoặc revoked")
	}
	rows, err := a.Store.VCsByIssuer(r.Context(), c.DID, status)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rows)
	return nil
}

// IssuerCredential — một VC do chính issuer này cấp.
func (a *API) IssuerCredential(w http.ResponseWriter, r *http.Request) error {
	c := middleware.ClaimsFrom(r.Context())
	vc, err := a.Store.RequireVC(r.Context(), r.PathValue("vcId"))
	if err != nil {
		return err
	}
	if vc.IssuerDID != c.DID {
		return httpx.Forbidden("VC này không do bạn cấp")
	}
	httpx.OK(w, http.StatusOK, vc)
	return nil
}

// AdminCredential — một VC theo mã, cho màn hình quản trị.
//
// Admin cần số hiệu on-chain (OnChainVCID) để ký được admin_revoke_vc /
// admin_reinstate_vc: hàm trên chuỗi nhận u64 chứ không nhận chuỗi urn:uuid.
func (a *API) AdminCredential(w http.ResponseWriter, r *http.Request) error {
	vc, err := a.Store.RequireVC(r.Context(), r.PathValue("vcId"))
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, vc)
	return nil
}

// issueBody là thân yêu cầu ghi một VC vừa lên chuỗi — dùng chung cho cấp mới
// và cấp lại (C3), giống zIssueBody bên TypeScript.
type issueBody struct {
	VCID          string `json:"vcId"`
	OnChainVCID   int64  `json:"onChainVcId"`
	HolderDID     string `json:"holderDid"`
	HolderAddress string `json:"holderAddress"`
	VCType        int    `json:"vcType"`
	IPFSCid       string `json:"ipfsCid"`
	VCIDHash      string `json:"vcIdHash"`
	ContentHash   string `json:"contentHash"`
	ProofValue    string `json:"proofValue"`
	// P3: KHÔNG còn vcJson — nội dung nằm trong phong bì mã hoá tại ipfsCid.
	IssuedAt  string  `json:"issuedAt"`
	ExpiresAt *string `json:"expiresAt"`
	TxHash    string  `json:"txHash"`
}

// issueInput là issueBody đã qua kiểm định dạng.
type issueInput struct {
	body                                         issueBody
	holderDID, holderAddr, cid, vcIDHash, txHash string
	contentHash                                  string
	vcType                                       int
	issuedAt                                     time.Time
	expiresAt                                    *time.Time
}

func parseIssueBody(r *http.Request) (*issueInput, error) {
	var in issueInput
	body := &in.body
	if err := httpx.DecodeJSON(r, body); err != nil {
		return nil, err
	}
	if len(body.VCID) < 8 || len(body.VCID) > 200 {
		return nil, httpx.BadRequest("vcId: phải dài 8..200 ký tự")
	}
	var err error
	if in.holderDID, err = httpx.DID(body.HolderDID, "holderDid"); err != nil {
		return nil, err
	}
	if in.holderAddr, err = httpx.Address(body.HolderAddress, "holderAddress"); err != nil {
		return nil, err
	}
	if in.vcType, err = httpx.VCType(body.VCType, "vcType"); err != nil {
		return nil, err
	}
	if in.cid, err = httpx.CID(body.IPFSCid, "ipfsCid"); err != nil {
		return nil, err
	}
	if in.vcIDHash, err = httpx.Hash32(body.VCIDHash, "vcIdHash"); err != nil {
		return nil, err
	}
	if in.contentHash, err = httpx.Hash32(body.ContentHash, "contentHash"); err != nil {
		return nil, err
	}
	if in.txHash, err = httpx.TxHash(body.TxHash, "txHash"); err != nil {
		return nil, err
	}
	if len(body.ProofValue) < 16 {
		return nil, httpx.BadRequest("proofValue: chữ ký quá ngắn")
	}
	issuedAt, perr := time.Parse(time.RFC3339, body.IssuedAt)
	if perr != nil {
		return nil, httpx.BadRequest("issuedAt: phải theo định dạng RFC3339")
	}
	in.issuedAt = issuedAt
	if body.ExpiresAt != nil && *body.ExpiresAt != "" {
		t, perr := time.Parse(time.RFC3339, *body.ExpiresAt)
		if perr != nil {
			return nil, httpx.BadRequest("expiresAt: phải theo định dạng RFC3339")
		}
		if !t.After(issuedAt) {
			return nil, httpx.BadRequest("Thời điểm hết hạn phải sau thời điểm cấp")
		}
		in.expiresAt = &t
	}
	return &in, nil
}

// assertIssueInput: các phép kiểm trước khi chạm chuỗi, đúng thứ tự bên TypeScript
// (vc.service.ts assertIssueInput): tự cấp → hash vcId → trùng → phong bì.
// P3: máy chủ không còn thấy nội dung nên không tính lại contentHash (envelope.go).
func (a *API) assertIssueInput(ctx context.Context, in *issueInput, issuerAddr string) error {
	if in.holderAddr == issuerAddr {
		return httpx.BadRequest("Đơn vị cấp không được tự cấp văn bằng cho chính mình")
	}
	if got := auth.SHA3256String(in.body.VCID); got != in.vcIDHash {
		return httpx.BadRequest("Hash của vcId không khớp (tính được %s)", got)
	}
	if existing, err := a.Store.VCByID(ctx, in.body.VCID); err != nil {
		return err
	} else if existing != nil {
		return httpx.Conflict("VC này đã được ghi nhận")
	}
	return a.assertEnvelope(ctx, in.cid, in.vcIDHash, in.holderAddr, issuerAddr)
}

// issueArgs: sáu tham số của issue_vc sau signer (S-02); reissue_vc dùng đúng sáu
// tham số này sau old_vc_id.
func (a *API) issueArgs(in *issueInput) []chain.Arg {
	var expUnix int64
	if in.expiresAt != nil {
		expUnix = in.expiresAt.Unix()
	}
	return []chain.Arg{
		chain.ArgAddress(in.holderAddr), chain.ArgU64(int64(in.vcType)), chain.ArgBytes(in.vcIDHash),
		chain.ArgBytes(chain.UTF8ToHex(in.cid)), chain.ArgBytes(in.contentHash), chain.ArgU64(expUnix),
	}
}

// assertIssuedEvent: số hiệu on-chain và DID holder lấy từ sự kiện của CHÍNH giao dịch.
func (a *API) assertIssuedEvent(tx *chain.Transaction, in *issueInput) error {
	if a.Chain.Offline() {
		return nil
	}
	ev := chain.FindEvent(tx, a.Chain.Module("vc_registry")+"::VCIssuedEvent")
	if ev == nil {
		return httpx.BadRequest("Giao dịch không phát VCIssuedEvent")
	}
	if fmt.Sprint(ev["id"]) != strconv.FormatInt(in.body.OnChainVCID, 10) {
		return httpx.BadRequest("onChainVcId không khớp sự kiện trên chuỗi (chuỗi ghi %v)", ev["id"])
	}
	if hd, _ := ev["holder_did"].(string); chain.HexToUTF8(hd) != in.holderDID {
		return httpx.BadRequest("holderDid không khớp DID của người nhận ghi trên chuỗi")
	}
	return nil
}

func (in *issueInput) saveInput(issuer *db.Entity) services.SaveVCInput {
	return services.SaveVCInput{
		VCID: in.body.VCID, OnChainVCID: in.body.OnChainVCID,
		IssuerDID: issuer.DID, IssuerAddress: issuer.Address,
		HolderDID: in.holderDID, HolderAddress: in.holderAddr,
		VCType: in.vcType, IPFSCid: in.cid, VCIDHash: in.vcIDHash, ContentHash: in.contentHash,
		ProofValue: in.body.ProofValue,
		IssuedAt:   in.issuedAt, ExpiresAt: in.expiresAt, TxHash: in.txHash,
	}
}

func (a *API) IssueCredential(w http.ResponseWriter, r *http.Request) error {
	in, err := parseIssueBody(r)
	if err != nil {
		return err
	}
	claims := middleware.ClaimsFrom(r.Context())
	// Rẻ trước, đắt sau — giống hệt thứ tự bên TypeScript.
	if err := a.assertIssueInput(r.Context(), in, claims.Address); err != nil {
		return err
	}
	issuer, err := a.Store.RequireEntity(r.Context(), claims.Address)
	if err != nil {
		return err
	}
	tx, err := a.Chain.VerifyTransactionArgs(r.Context(), in.txHash, a.Chain.EntryIssueVC(), issuer.Address, a.issueArgs(in))
	if err != nil {
		return err
	}
	if err := a.assertIssuedEvent(tx, in); err != nil {
		return err
	}
	row, err := a.Store.SaveVC(r.Context(), in.saveInput(issuer))
	if err != nil {
		return err
	}
	a.Store.Audit(r.Context(), issuer.Address, services.AuditVCIssue, &in.body.VCID,
		map[string]any{"holderDid": in.holderDID, "vcType": in.vcType, "txHash": in.txHash})
	httpx.OK(w, http.StatusCreated, row)
	return nil
}

// ChangeVCStatus kiểm lại ràng buộc chuyển trạng thái cho khớp contract.
func (a *API) ChangeVCStatus(next string) httpx.Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		vcID := r.PathValue("vcId")
		if vcID == "" {
			return httpx.BadRequest("Thiếu mã VC trên đường dẫn")
		}
		var body struct {
			Reason string `json:"reason"`
			TxHash string `json:"txHash"`
		}
		if err := httpx.DecodeJSON(r, &body); err != nil {
			return err
		}
		if len(body.Reason) < 2 || len(body.Reason) > 500 {
			return httpx.BadRequest("reason: lý do phải dài 2..500 ký tự")
		}
		txHash, err := httpx.TxHash(body.TxHash, "txHash")
		if err != nil {
			return err
		}

		claims := middleware.ClaimsFrom(r.Context())
		actor, err := a.Store.RequireEntity(r.Context(), claims.Address)
		if err != nil {
			return err
		}
		vc, err := a.Store.RequireVC(r.Context(), vcID)
		if err != nil {
			return err
		}

		// Hai đường, khớp contract và backend TypeScript (vc.service.ts):
		// admin/root luôn dùng hàm admin_*; issuer đã cấp VC dùng suspend_vc /
		// revoke_vc và không kích hoạt lại được.
		isAdmin := actor.Role == "admin" || actor.Role == "root"
		isIssuer := vc.IssuerAddress == actor.Address
		if !isIssuer && !isAdmin {
			return httpx.Forbidden("Chỉ issuer đã cấp hoặc admin mới đổi được trạng thái")
		}
		if vc.Status == "revoked" {
			return httpx.Conflict("VC đã bị thu hồi, không đổi được nữa")
		}
		switch next {
		case "suspended":
			if vc.Status != "active" {
				return httpx.Conflict("Chỉ tạm ngưng được VC đang hoạt động")
			}
		case "active":
			if vc.Status != "suspended" {
				return httpx.Conflict("Chỉ kích hoạt lại được VC đang tạm ngưng")
			}
			// Contract chỉ cho admin kích hoạt lại, tránh issuer tự ngưng/bật né kiểm toán.
			if !isAdmin {
				return httpx.Forbidden("Chỉ admin mới kích hoạt lại được VC đã tạm ngưng")
			}
		}
		// M-06 do contract chặn khi nối chuỗi; issuer bị thu hồi đã bị RequireRole
		// chặn ở tuyến. Offline không mô hình hoá DID/tạm ngưng của vai trò.

		var expectedFn string
		switch {
		case isAdmin && next == "revoked":
			expectedFn = a.Chain.EntryAdminRevokeVC()
		case isAdmin && next == "suspended":
			expectedFn = a.Chain.EntryAdminSuspendVC()
		case isAdmin:
			expectedFn = a.Chain.EntryAdminReinstateVC()
		case next == "revoked":
			expectedFn = a.Chain.EntryRevokeVC()
		default:
			expectedFn = a.Chain.EntrySuspendVC()
		}
		// Giao dịch phải nhắm đúng VC này (S-02).
		if !a.Chain.Offline() && vc.OnChainVCID == nil {
			return httpx.BadRequest("VC này chưa có số hiệu on-chain — không đối chiếu được giao dịch")
		}
		var args []chain.Arg
		if vc.OnChainVCID != nil {
			args = []chain.Arg{chain.ArgU64(*vc.OnChainVCID)}
		}
		if _, err := a.Chain.VerifyTransactionArgs(r.Context(), txHash, expectedFn, actor.Address, args); err != nil {
			return err
		}
		// Chống phát lại: giao dịch có thật nhưng CŨ vẫn qua mọi phép kiểm trên.
		// Chuỗi hiện tại phải đúng là trạng thái sắp ghi.
		if !a.Chain.Offline() && vc.OnChainVCID != nil {
			if onChain := a.Chain.VCStatus(r.Context(), *vc.OnChainVCID); onChain != next {
				if onChain == "" {
					onChain = "không đọc được"
				}
				return httpx.Conflict("Trên chuỗi VC đang \"%s\", không phải \"%s\" — giao dịch đã cũ", onChain, next)
			}
		}

		row, err := a.Store.UpdateVCStatus(r.Context(), vcID, next, body.Reason, txHash)
		if err != nil {
			return err
		}
		action := services.AuditVCReinstate
		switch next {
		case "revoked":
			action = services.AuditVCRevoke
		case "suspended":
			action = services.AuditVCSuspend
		}
		a.Store.Audit(r.Context(), actor.Address, action, &vcID,
			map[string]any{"reason": body.Reason, "txHash": txHash, "byAdmin": isAdmin})
		httpx.OK(w, http.StatusOK, row)
		return nil
	}
}

// ---------- Holder ----------

type credentialWithStatus struct {
	*db.Credential
	Effective map[string]any `json:"effective"`
}

func (a *API) HolderCredentials(w http.ResponseWriter, r *http.Request) error {
	c := middleware.ClaimsFrom(r.Context())
	rows, err := a.Store.VCsByHolder(r.Context(), c.DID)
	if err != nil {
		return err
	}
	// P5: một lần đọc lô thay cho N lần get_vc_status (trước đây còn gọi TUẦN TỰ).
	ptrs := make([]*db.Credential, len(rows))
	for i := range rows {
		ptrs[i] = &rows[i]
	}
	recs := a.Chain.VCRecords(r.Context(), onChainIDs(ptrs))
	out := make([]credentialWithStatus, 0, len(rows))
	for _, c := range ptrs {
		st, src := a.effectiveFrom(c, recs)
		out = append(out, credentialWithStatus{Credential: c,
			Effective: map[string]any{"status": st, "source": src, "drift": src != "db" && st != c.Status}})
	}
	httpx.OK(w, http.StatusOK, out)
	return nil
}

// HolderCredential — một VC của chính người sở hữu đang đăng nhập.
func (a *API) HolderCredential(w http.ResponseWriter, r *http.Request) error {
	c := middleware.ClaimsFrom(r.Context())
	vc, err := a.Store.RequireVC(r.Context(), r.PathValue("vcId"))
	if err != nil {
		return err
	}
	if vc.HolderDID != c.DID {
		return httpx.Forbidden("VC này không thuộc về bạn")
	}
	httpx.OK(w, http.StatusOK, a.withStatus(r, vc))
	return nil
}

func (a *API) HolderPresentations(w http.ResponseWriter, r *http.Request) error {
	c := middleware.ClaimsFrom(r.Context())
	rows, err := a.Store.VPsByHolder(r.Context(), c.DID)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rows)
	return nil
}

func (a *API) CreatePresentation(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		VPID        string   `json:"vpId"`
		VerifierDID *string  `json:"verifierDid"`
		VCIDs       []string `json:"vcIds"`
		IPFSCid     string   `json:"ipfsCid"`
		VPHash      string   `json:"vpHash"`
		ProofValue  string   `json:"proofValue"`
		Challenge   *string  `json:"challenge"`
		TTLSeconds  int      `json:"ttlSeconds"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	if len(body.VPID) < 8 || len(body.VPID) > 200 {
		return httpx.BadRequest("vpId: phải dài 8..200 ký tự")
	}
	if len(body.VCIDs) == 0 || len(body.VCIDs) > 20 {
		return httpx.BadRequest("vcIds: phải có 1..20 chứng chỉ")
	}
	cid, err := httpx.CID(body.IPFSCid, "ipfsCid")
	if err != nil {
		return err
	}
	vpHash, err := httpx.Hash32(body.VPHash, "vpHash")
	if err != nil {
		return err
	}
	if len(body.ProofValue) < 16 {
		return httpx.BadRequest("proofValue: chữ ký quá ngắn")
	}
	if body.TTLSeconds == 0 {
		body.TTLSeconds = 3600
	}
	if body.TTLSeconds < 60 || body.TTLSeconds > 604800 {
		return httpx.BadRequest("ttlSeconds: thời hạn phải trong khoảng 60..604800 giây")
	}

	claims := middleware.ClaimsFrom(r.Context())

	// Mọi VC đưa vào VP phải thuộc về chính holder và còn hiệu lực.
	for _, id := range body.VCIDs {
		vc, err := a.Store.VCByID(r.Context(), id)
		if err != nil {
			return err
		}
		if vc == nil {
			return httpx.NotFound("Không tìm thấy VC %s", id)
		}
		if vc.HolderDID != claims.DID {
			return httpx.Forbidden("VC %s không thuộc về bạn", id)
		}
		if st, _ := a.effectiveStatus(r, vc); st != "active" {
			return httpx.BadRequest("VC %s đang ở trạng thái %q, không thể đưa vào VP", id, st)
		}
	}
	// P3: IPFS chỉ giữ bản trình bày ĐÃ MÃ HOÁ (khoá nằm trong fragment liên kết).
	if err := a.assertShareBlob(r.Context(), cid); err != nil {
		return err
	}

	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)

	vp, share, err := a.Store.CreateVP(r.Context(), services.CreateVPInput{
		VPID: body.VPID, HolderDID: claims.DID, VerifierDID: body.VerifierDID,
		VCIDs: body.VCIDs, IPFSCid: cid, VPHash: vpHash, ProofValue: body.ProofValue,
		Challenge: body.Challenge, TTL: time.Duration(body.TTLSeconds) * time.Second,
		ShareToken: token,
	})
	if err != nil {
		return err
	}
	a.Store.Audit(r.Context(), claims.Address, services.AuditShareCreate, &body.VPID,
		map[string]any{"vcIds": body.VCIDs, "ttlSeconds": body.TTLSeconds})
	httpx.OK(w, http.StatusCreated, map[string]any{
		"vp":    vp,
		"share": map[string]any{"token": share.Token, "expiresAt": share.ExpiresAt},
	})
	return nil
}

func (a *API) HolderShares(w http.ResponseWriter, r *http.Request) error {
	c := middleware.ClaimsFrom(r.Context())
	rows, err := a.Store.SharesByHolder(r.Context(), c.DID)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rows)
	return nil
}

func (a *API) RevokeShare(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return httpx.BadRequest("Thiếu mã chia sẻ trên đường dẫn")
	}
	c := middleware.ClaimsFrom(r.Context())
	vpID, err := a.Store.RevokeShareToken(r.Context(), token, c.DID)
	if err != nil {
		return err
	}
	a.Store.Audit(r.Context(), c.Address, services.AuditShareRevoke, &vpID, nil)
	httpx.OK(w, http.StatusOK, map[string]any{"revoked": true})
	return nil
}
