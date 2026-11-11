package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/middleware"
	"github.com/vnu-trust/backend-go/internal/services"
)

// Quản trị vai trò TRÊN CHUỖI.
//
// Mô hình giống hệt phần còn lại của hệ thống: ví phi lưu ký nên chính người
// dùng ký và gửi giao dịch, backend chỉ XÁC MINH giao dịch đó có thật rồi cập
// nhật chỉ mục trong CSDL. Quyền hạn do contract quyết định — backend không tự
// ý phong ai làm gì.
//
// Màn hình này từng bị hoãn vì contract dính F-00 (root đóng băng ở địa chỉ
// không ai giữ khoá) và F-01 (approve_issuer luôn đòi hash 32 byte). Cả hai đã
// sửa nên tuyến này mới có ý nghĩa.
//
// Mọi hành vi phải khớp backend/src/services/authority.service.ts.

type authorityResult struct {
	Address            string  `json:"address"`
	TxHash             string  `json:"txHash"`
	AppRole            *string `json:"appRole"`
	NotRegisteredInApp bool    `json:"notRegisteredInApp"`
}

// assertRootAuthority chặn các thao tác chỉ root mới được làm.
//
// Khi còn nối chuỗi thì VerifyTransaction đã là bằng chứng mạnh nhất: giao dịch
// thành công nghĩa là chính contract đã chấp nhận người gửi là root. Rào này
// chủ yếu để chế độ VERIFY_ONCHAIN=false không trở thành cửa sau — lúc đó không
// có giao dịch nào để xác minh cả.
func (a *API) assertRootAuthority(ctx context.Context, actor *db.Entity) error {
	if a.Chain.Offline() {
		if actor.Role != "root" {
			return httpx.Forbidden("Chỉ tài khoản root mới thực hiện được thao tác này")
		}
		return nil
	}
	root := a.Chain.GetRootAdmin(ctx)
	if root == "" {
		return httpx.Forbidden("Chỉ root_admin trên chuỗi mới thực hiện được thao tác này")
	}
	got, err1 := chain.NormalizeAddress(root)
	want, err2 := chain.NormalizeAddress(actor.Address)
	if err1 != nil || err2 != nil || got != want {
		return httpx.Forbidden("Chỉ root_admin trên chuỗi mới thực hiện được thao tác này")
	}
	return nil
}

// applyAuthorityTx xác minh giao dịch rồi đồng bộ vai trò trong chỉ mục.
// newRole rỗng nghĩa là thao tác không đổi vai trò phía ứng dụng.
func (a *API) applyAuthorityTx(
	r *http.Request, actor *db.Entity,
	target, txHash, expectedFn, newRole, auditAction string,
	detail map[string]any,
) (*authorityResult, error) {
	ctx := r.Context()
	addr, err := chain.NormalizeAddress(target)
	if err != nil {
		return nil, err
	}
	if err := a.Chain.VerifyTransaction(ctx, txHash, expectedFn, actor.Address); err != nil {
		return nil, err
	}

	entity, _ := a.Store.EntityByAddress(ctx, addr)
	var appRole *string
	if entity != nil {
		role := entity.Role
		if newRole != "" {
			updated, err := a.Store.UpdateEntityRole(ctx, addr, newRole)
			if err != nil {
				return nil, err
			}
			role = updated
		}
		appRole = &role
	}

	if detail == nil {
		detail = map[string]any{}
	}
	detail["txHash"] = txHash
	a.Store.Audit(ctx, actor.Address, auditAction, &addr, detail)

	return &authorityResult{
		Address:            addr,
		TxHash:             txHash,
		AppRole:            appRole,
		NotRegisteredInApp: entity == nil,
	}, nil
}

func (a *API) actor(r *http.Request) (*db.Entity, error) {
	claims := middleware.ClaimsFrom(r.Context())
	return a.Store.RequireEntity(r.Context(), claims.Address)
}

// --- Ảnh chụp trạng thái ---

// AuthorityRoot trả quyền root hiện tại và đề cử đang chờ ký nhận.
func (a *API) AuthorityRoot(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	claims := middleware.ClaimsFrom(ctx)
	caller, err := chain.NormalizeAddress(claims.Address)
	if err != nil {
		return err
	}

	// Trả null (không phải chuỗi rỗng) khi chưa đọc được, để khớp đúng backend
	// TypeScript — đây là loại lệch mà bộ parity từng bắt được.
	var rootOut, pendingOut any
	callerIsRoot, callerIsPending := false, false
	if root := a.Chain.GetRootAdmin(ctx); root != "" {
		rootOut = root
		if n, err := chain.NormalizeAddress(root); err == nil && n == caller {
			callerIsRoot = true
		}
	}
	if pending := a.Chain.PendingRoot(ctx); pending != "" {
		pendingOut = pending
		callerIsPending = pending == caller
	}

	httpx.OK(w, http.StatusOK, map[string]any{
		"rootAdmin":           rootOut,
		"pendingRoot":         pendingOut,
		"callerIsRoot":        callerIsRoot,
		"callerIsPendingRoot": callerIsPending,
		"source":              a.chainSource(),
	})
	return nil
}

func (a *API) chainSource() string {
	if a.Chain.Offline() {
		return "db-index"
	}
	return "chain"
}

// AuthorityRole trả toàn bộ những gì chuỗi biết về quyền hạn của một địa chỉ.
func (a *API) AuthorityRole(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	address, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}

	entity, _ := a.Store.EntityByAddress(ctx, address)
	var appRole, appLabel any
	if entity != nil {
		appRole = entity.Role
		appLabel = entity.Label
	}
	var role any
	if info := a.Chain.RoleInfo(ctx, address); info != nil {
		role = info
	}

	// Cùng một địa chỉ ở cả hai vế: "đã cấp bao nhiêu" và "đang giữ bao nhiêu"
	// trong một lượt gọi.
	issued, held := a.Chain.LiveCounts(ctx, address, address)

	httpx.OK(w, http.StatusOK, map[string]any{
		"address":        address,
		"isActiveAdmin":  a.Chain.IsActiveAdmin(ctx, address),
		"isActiveIssuer": a.Chain.IsActiveIssuer(ctx, address),
		"canDelegate":    a.Chain.CanDelegate(ctx, address),
		"role":           role,
		"appRole":        appRole,
		"appLabel":       appLabel,
		// Số văn bằng còn hiệu lực — cận trên, vì bộ đếm on-chain không trừ VC hết hạn.
		"liveCredentials": map[string]any{"issued": issued, "held": held},
		"source":          a.chainSource(),
	})
	return nil
}

// --- Thao tác ghi ---

type addressTxBody struct {
	Address string `json:"address"`
	TxHash  string `json:"txHash"`
}

type reasonTxBody struct {
	Reason string `json:"reason"`
	TxHash string `json:"txHash"`
	Status string `json:"status"`
}

func validReason(v string) (string, error) {
	s := strings.TrimSpace(v)
	if len(s) < 2 || len(s) > 500 {
		return "", httpx.BadRequest("reason: phải dài 2..500 ký tự")
	}
	return s, nil
}

// AuthorityGrantAdmin — root cấp quyền admin.
func (a *API) AuthorityGrantAdmin(w http.ResponseWriter, r *http.Request) error {
	var body addressTxBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	address, err := httpx.Address(body.Address, "address")
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
	if err := a.assertRootAuthority(r.Context(), actor); err != nil {
		return err
	}
	res, err := a.applyAuthorityTx(r, actor, address, txHash,
		a.Chain.EntryGrantAdmin(), "admin", services.AuditGrantAdmin, nil)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusCreated, res)
	return nil
}

// AuthorityRevokeAdmin — root thu hồi quyền admin.
func (a *API) AuthorityRevokeAdmin(w http.ResponseWriter, r *http.Request) error {
	address, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	var body reasonTxBody
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
	actor, err := a.actor(r)
	if err != nil {
		return err
	}
	if err := a.assertRootAuthority(r.Context(), actor); err != nil {
		return err
	}
	self, err := chain.NormalizeAddress(actor.Address)
	if err != nil {
		return err
	}
	if address == self {
		return httpx.BadRequest("Root không thể tự thu hồi quyền admin của chính mình")
	}
	// Mất quyền admin thì quay về holder — vẫn giữ DID và văn bằng của mình.
	res, err := a.applyAuthorityTx(r, actor, address, txHash,
		a.Chain.EntryRevokeAdmin(), "holder", services.AuditRevokeAdmin,
		map[string]any{"reason": reason})
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, res)
	return nil
}

// AuthorityApproveIssuer — root hoặc admin phê duyệt issuer.
func (a *API) AuthorityApproveIssuer(w http.ResponseWriter, r *http.Request) error {
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
	if body.VCTypeMask < 1 || body.VCTypeMask > 63 {
		return httpx.BadRequest("vcTypeMask: phải trong khoảng 1..63")
	}
	if body.ExpiresAt < 0 {
		return httpx.BadRequest("expiresAt: không được âm")
	}
	if body.ExpiresAt != 0 && body.ExpiresAt <= time.Now().Unix() {
		return httpx.BadRequest("Thời điểm hết hạn phải ở tương lai (0 = vĩnh viễn)")
	}
	txHash, err := httpx.TxHash(body.TxHash, "txHash")
	if err != nil {
		return err
	}
	actor, err := a.actor(r)
	if err != nil {
		return err
	}
	res, err := a.applyAuthorityTx(r, actor, address, txHash,
		a.Chain.EntryApproveIssuer(), "issuer", services.AuditApproveIssuer,
		map[string]any{"vcTypeMask": body.VCTypeMask, "expiresAt": body.ExpiresAt})
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusCreated, res)
	return nil
}

// AuthorityIssuerStatus — tạm ngưng / kích hoạt lại / thu hồi quyền issuer.
func (a *API) AuthorityIssuerStatus(w http.ResponseWriter, r *http.Request) error {
	address, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	var body reasonTxBody
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

	var expectedFn, newRole, action string
	switch body.Status {
	case "suspended":
		// Tạm ngưng thì vẫn là issuer: quyền còn đó, chỉ bị khoá.
		expectedFn, newRole, action = a.Chain.EntrySuspendIssuer(), "", services.AuditIssuerSuspended
	case "active":
		expectedFn, newRole, action = a.Chain.EntryReactivateIssuer(), "", services.AuditIssuerActive
	case "revoked":
		expectedFn, newRole, action = a.Chain.EntryRevokeIssuer(), "holder", services.AuditIssuerRevoked
	default:
		return httpx.BadRequest("status: phải là suspended, active hoặc revoked")
	}

	actor, err := a.actor(r)
	if err != nil {
		return err
	}
	res, err := a.applyAuthorityTx(r, actor, address, txHash, expectedFn, newRole, action,
		map[string]any{"reason": reason})
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, res)
	return nil
}

// AuthorityProposeRoot — bước 1 của chuyển quyền root.
func (a *API) AuthorityProposeRoot(w http.ResponseWriter, r *http.Request) error {
	var body addressTxBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	address, err := httpx.Address(body.Address, "address")
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
	if err := a.assertRootAuthority(r.Context(), actor); err != nil {
		return err
	}
	self, err := chain.NormalizeAddress(actor.Address)
	if err != nil {
		return err
	}
	if address == self {
		return httpx.BadRequest("Đề cử chính mình làm root là thao tác vô nghĩa")
	}
	// Đề cử một địa chỉ chưa ghi danh là cách nhanh nhất để mất quyền root:
	// không ai chứng minh được có người giữ khoá của địa chỉ đó.
	if e, _ := a.Store.EntityByAddress(r.Context(), address); e == nil {
		return httpx.BadRequest(
			"Địa chỉ được đề cử chưa đăng ký trong hệ thống — hãy để họ đăng ký DID trước khi đề cử")
	}
	res, err := a.applyAuthorityTx(r, actor, address, txHash,
		a.Chain.EntryProposeRoot(), "", services.AuditProposeRoot, nil)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, res)
	return nil
}

// AuthorityCancelRootTransfer — root huỷ đề cử đang chờ.
func (a *API) AuthorityCancelRootTransfer(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		TxHash string `json:"txHash"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
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
	if err := a.assertRootAuthority(r.Context(), actor); err != nil {
		return err
	}
	res, err := a.applyAuthorityTx(r, actor, actor.Address, txHash,
		a.Chain.EntryCancelRootTransfer(), "", services.AuditCancelRootTransfer, nil)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, res)
	return nil
}

// AuthorityAcceptRoot — bước 2: người được đề cử tự ký nhận quyền root.
//
// Tuyến này KHÔNG đòi vai trò admin. Người được đề cử, tại thời điểm ký nhận,
// vẫn chưa phải root trong CSDL — chặn theo vai trò ở đây sẽ khoá đúng bước duy
// nhất chứng minh được họ giữ khoá. Quyền thật vẫn do contract quyết định:
// accept_root chỉ thành công trên chuỗi nếu người ký đúng là địa chỉ đang được
// đề cử.
func (a *API) AuthorityAcceptRoot(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		TxHash string `json:"txHash"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
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
	res, err := a.applyAuthorityTx(r, actor, actor.Address, txHash,
		a.Chain.EntryAcceptRoot(), "root", services.AuditAcceptRoot, nil)
	if err != nil {
		return err
	}

	// Chỉ có MỘT root. Chuỗi chỉ giữ đúng một root_admin, nên để hai hàng
	// role='root' trong chỉ mục là nói dối về chính thứ vừa thay đổi. Root cũ
	// xuống admin — họ vẫn là người có thẩm quyền, chỉ không còn là gốc.
	if err := a.Store.DemoteOtherRoots(r.Context(), res.Address); err != nil {
		return err
	}

	httpx.OK(w, http.StatusOK, res)
	return nil
}
