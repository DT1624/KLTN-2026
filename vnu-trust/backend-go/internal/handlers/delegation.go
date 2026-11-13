package handlers

import (
	"net/http"

	"time"

	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/services"
)

// Uỷ quyền (M-02, R-04) và kiểm duyệt DID (M-01, M-08).
// Mọi hành vi và hình dạng phản hồi phải khớp backend/src/services/authority.service.ts.

// delegationBit là bit VC_DELEGATION — chỉ root cấp, sub-issuer không được nhận.
const delegationBit = 32

type subIssuer struct {
	Address    string  `json:"address"`
	Label      *string `json:"label"`
	VCTypeMask int     `json:"vcTypeMask"`
	ExpiresAt  int64   `json:"expiresAt"`
	Status     string  `json:"status"`
}

// IssuerDelegation — quyền uỷ quyền của chính mình và các sub-issuer mình đã cấp.
func (a *API) IssuerDelegation(w http.ResponseWriter, r *http.Request) error {
	actor, err := a.actor(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	me, err := chain.NormalizeAddress(actor.Address)
	if err != nil {
		return err
	}
	mask, expires := 0, int64(0)
	if info := a.Chain.RoleInfo(ctx, me); info != nil {
		mask, expires = info.VCTypeMask, info.ExpiresAt
	}
	targets, err := a.Store.AuditTargets(ctx, me, services.AuditApproveIssuer)
	if err != nil {
		return err
	}
	subs := []subIssuer{}
	for _, t := range targets {
		if a.Chain.GetDelegator(ctx, t) != me {
			continue // đã được root/admin cấp lại
		}
		item := subIssuer{Address: t, Status: "unknown"}
		if info := a.Chain.RoleInfo(ctx, t); info != nil {
			item.VCTypeMask, item.ExpiresAt, item.Status = info.VCTypeMask, info.ExpiresAt, info.Status
		}
		if e, _ := a.Store.EntityByAddress(ctx, t); e != nil {
			label := e.Label
			item.Label = &label
		}
		subs = append(subs, item)
	}
	httpx.OK(w, http.StatusOK, map[string]any{
		"canDelegate":   a.Chain.CanDelegate(ctx, me),
		"delegableMask": mask &^ delegationBit,
		"expiresAt":     expires,
		"subIssuers":    subs,
		"source":        a.chainSource(),
	})
	return nil
}

// ApproveSubIssuer — issuer uỷ quyền cấp sub-issuer (approve_issuer do issuer ký).
func (a *API) ApproveSubIssuer(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Address    string `json:"address"`
		VCTypeMask int    `json:"vcTypeMask"`
		ExpiresAt  int64  `json:"expiresAt"`
		TxHash     string `json:"txHash"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	address, err := httpx.Address(body.Address, "address")
	if err != nil {
		return err
	}
	if body.VCTypeMask < 1 || body.VCTypeMask > 31 {
		return httpx.BadRequest("vcTypeMask: phải trong khoảng 1..31 (sub-issuer không nhận bit uỷ quyền)")
	}
	if body.ExpiresAt < 0 {
		return httpx.BadRequest("expiresAt: không được âm")
	}
	txHash, err := httpx.TxHash(body.TxHash, "txHash")
	if err != nil {
		return err
	}
	actor, err := a.actor(r)
	if err != nil {
		return err
	}
	if a.Chain.Offline() {
		return httpx.Forbidden("Chế độ không nối chuỗi không xác định được quyền uỷ quyền")
	}
	// Thứ tự khớp TypeScript (approveSubIssuer → approveIssuer): quyền uỷ quyền
	// trước, hạn ở tương lai sau.
	if !a.Chain.CanDelegate(r.Context(), actor.Address) {
		return httpx.Forbidden("Quyền issuer của bạn không có bit uỷ quyền, hoặc đã hết hiệu lực")
	}
	if body.ExpiresAt != 0 && body.ExpiresAt <= time.Now().Unix() {
		return httpx.BadRequest("Thời điểm hết hạn phải ở tương lai (0 = vĩnh viễn)")
	}
	res, err := a.approveIssuer(r, actor, address, body.VCTypeMask, body.ExpiresAt, txHash)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusCreated, res)
	return nil
}

// SubIssuerStatus — issuer cha tạm ngưng / thu hồi sub-issuer do chính mình cấp.
// Không kích hoạt lại được: tự ngưng rồi tự bật là né kiểm soát.
func (a *API) SubIssuerStatus(w http.ResponseWriter, r *http.Request) error {
	address, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	var body statusReasonTxBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	if body.Status != "suspended" && body.Status != "revoked" {
		return httpx.BadRequest("status: phải là suspended hoặc revoked")
	}
	reason, err := validReason(body.Reason)
	if err != nil {
		return err
	}
	txHash, err := httpx.TxHash(body.TxHash, "txHash")
	if err != nil {
		return err
	}
	actor, err := a.actor(r)
	if err != nil {
		return err
	}
	if a.Chain.Offline() {
		return httpx.Forbidden("Chế độ không nối chuỗi không xác định được quan hệ uỷ quyền")
	}
	me, err := chain.NormalizeAddress(actor.Address)
	if err != nil {
		return err
	}
	if a.Chain.GetDelegator(r.Context(), address) != me {
		return httpx.Forbidden("Địa chỉ này không phải sub-issuer do bạn cấp")
	}
	res, err := a.setIssuerStatus(r, actor, address, body.Status, reason, txHash)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, res)
	return nil
}

// AdminDIDStatus — admin khoá / mở / thu hồi DID của một địa chỉ. Thu hồi DID
// trên chuỗi thu hồi luôn vai trò admin/issuer (M-01), nên chỉ mục hạ về holder.
func (a *API) AdminDIDStatus(w http.ResponseWriter, r *http.Request) error {
	address, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	var body statusReasonTxBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	reason, err := validReason(body.Reason)
	if err != nil {
		return err
	}
	txHash, err := httpx.TxHash(body.TxHash, "txHash")
	if err != nil {
		return err
	}
	var expectedFn, action string
	switch body.Status {
	case "suspended":
		expectedFn, action = a.Chain.EntryAdminSuspendDID(), services.AuditDIDSuspend
	case "active":
		expectedFn, action = a.Chain.EntryAdminReactivateDID(), services.AuditDIDReactivate
	case "revoked":
		expectedFn, action = a.Chain.EntryAdminRevokeDID(), services.AuditDIDRevoke
	default:
		return httpx.BadRequest("status: phải là suspended, active hoặc revoked")
	}
	actor, err := a.actor(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	entity, _ := a.Store.EntityByAddress(ctx, address)
	if a.Chain.Offline() && entity != nil {
		if entity.Role == "root" {
			return httpx.Forbidden("Không được tác động lên DID của root")
		}
		if actor.Role != "root" && entity.Role == "admin" {
			return httpx.Forbidden("Chỉ root mới tác động được lên DID của admin khác")
		}
	}
	args := []chain.Arg{chain.ArgAddress(address), chain.ArgBytes(chain.UTF8ToHex(reason))}
	if _, err := a.Chain.VerifyTransactionArgs(ctx, txHash, expectedFn, actor.Address, args); err != nil {
		return err
	}
	// Chống phát lại: DID trên chuỗi hiện tại phải đúng trạng thái sắp ghi.
	if !a.Chain.Offline() {
		onChain := a.Chain.ResolveDIDByOwner(ctx, address)
		if onChain == nil || onChain.Status != body.Status {
			got := "không có"
			if onChain != nil {
				got = onChain.Status
			}
			return httpx.Conflict("Trên chuỗi DID đang \"%s\", không khớp thao tác — giao dịch đã cũ", got)
		}
	}
	if err := a.Store.SetDIDStatusByAddress(ctx, address, body.Status); err != nil {
		return err
	}
	var appRole *string
	if entity != nil {
		role := entity.Role
		if body.Status == "revoked" && (role == "admin" || role == "issuer") {
			if role, err = a.Store.UpdateEntityRole(ctx, address, "holder"); err != nil {
				return err
			}
		}
		appRole = &role
	}
	a.Store.Audit(ctx, actor.Address, action, &address, map[string]any{"reason": reason, "txHash": txHash})
	httpx.OK(w, http.StatusOK, map[string]any{
		"address":            address,
		"txHash":             txHash,
		"status":             body.Status,
		"appRole":            appRole,
		"notRegisteredInApp": entity == nil,
	})
	return nil
}
