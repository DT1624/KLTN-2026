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
// Tham số đầu của giao dịch phải là địa chỉ đích (S-02).
func (a *API) applyAuthorityTx(
	r *http.Request, actor *db.Entity,
	target, txHash, expectedFn, newRole, auditAction string,
	detail map[string]any,
) (*authorityResult, error) {
	return a.applyAuthorityTxArgs(r, actor, target, txHash, expectedFn, newRole, auditAction, detail, nil, nil)
}

// applyAuthorityTxArgs: args nil = mặc định [địa chỉ đích]. Thiếu phép đối chiếu
// này thì một giao dịch approve_issuer thật phong được issuer cho địa chỉ BẤT KỲ,
// dùng lại bao nhiêu lần cũng được. beforeSync chạy sau khi giao dịch đã xác minh,
// trước khi đổi chỉ mục.
func (a *API) applyAuthorityTxArgs(
	r *http.Request, actor *db.Entity,
	target, txHash, expectedFn, newRole, auditAction string,
	detail map[string]any, args []chain.Arg, beforeSync func() error,
) (*authorityResult, error) {
	ctx := r.Context()
	addr, err := chain.NormalizeAddress(target)
	if err != nil {
		return nil, err
	}
	if args == nil {
		args = []chain.Arg{chain.ArgAddress(addr)}
	}
	if _, err := a.Chain.VerifyTransactionArgs(ctx, txHash, expectedFn, actor.Address, args); err != nil {
		return nil, err
	}
	if beforeSync != nil {
		if err := beforeSync(); err != nil {
			return nil, err
		}
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
}

// statusReasonTxBody dành cho tuyến đổi trạng thái. Tách khỏi reasonTxBody để
// tuyến KHÔNG nhận "status" (thu hồi admin) từ chối trường thừa như TypeScript.
type statusReasonTxBody struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
	TxHash string `json:"txHash"`
}

// expectRoleStatus chống phát lại: sau khi giao dịch đã xác minh, trạng thái vai
// trò HIỆN TẠI trên chuỗi phải đúng là trạng thái sắp ghi. mask < 0 = không kiểm
// mask. Offline không có giao dịch để phát lại nên bỏ qua. Khớp TypeScript.
func (a *API) expectRoleStatus(ctx context.Context, target, status string, mask int) func() error {
	return func() error {
		if a.Chain.Offline() {
			return nil
		}
		info := a.Chain.RoleInfo(ctx, target)
		if info == nil || info.Status != status || (mask >= 0 && info.VCTypeMask != mask) {
			got := "không có"
			if info != nil {
				got = info.Status
			}
			return httpx.Conflict("Trên chuỗi vai trò của địa chỉ này đang \"%s\", không khớp thao tác — giao dịch đã cũ", got)
		}
		return nil
	}
}

// assertNoRoleConflictOffline: offline không có contract chặn xung đột vai trò
// (M-04, R-05) nên chặn ở đây — mỗi địa chỉ tối đa MỘT vai trò. Khớp TypeScript.
func (a *API) assertNoRoleConflictOffline(ctx context.Context, target, wanted string) error {
	if !a.Chain.Offline() {
		return nil
	}
	e, _ := a.Store.EntityByAddress(ctx, target)
	if e == nil {
		return nil
	}
	switch {
	case e.Role == "root":
		return httpx.Conflict("Root không được giữ thêm vai trò admin hay issuer")
	case wanted == "admin" && e.Role == "issuer":
		return httpx.Conflict("Địa chỉ đang là issuer — thu hồi quyền issuer trước")
	case wanted == "issuer" && e.Role == "admin":
		return httpx.Conflict("Địa chỉ đang là admin — thu hồi quyền admin trước")
	case e.Role == wanted:
		return httpx.Conflict("Địa chỉ đã là %s", wanted)
	}
	return nil
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
	if err := a.assertNoRoleConflictOffline(r.Context(), address, "admin"); err != nil {
		return err
	}
	res, err := a.applyAuthorityTxArgs(r, actor, address, txHash,
		a.Chain.EntryGrantAdmin(), "admin", services.AuditGrantAdmin, nil,
		nil, a.expectRoleStatus(r.Context(), address, "active", -1))
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
	res, err := a.applyAuthorityTxArgs(r, actor, address, txHash,
		a.Chain.EntryRevokeAdmin(), "holder", services.AuditRevokeAdmin,
		map[string]any{"reason": reason}, nil, a.expectRoleStatus(r.Context(), address, "revoked", -1))
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
	res, err := a.approveIssuer(r, actor, address, body.VCTypeMask, body.ExpiresAt, txHash)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusCreated, res)
	return nil
}

// approveIssuer xác minh giao dịch approve_issuer rồi ghi chỉ mục. Dùng chung
// cho root/admin và cho issuer uỷ quyền cấp sub-issuer.
func (a *API) approveIssuer(r *http.Request, actor *db.Entity, address string, mask int, expiresAt int64, txHash string) (*authorityResult, error) {
	if err := a.assertNoRoleConflictOffline(r.Context(), address, "issuer"); err != nil {
		return nil, err
	}
	return a.applyAuthorityTxArgs(r, actor, address, txHash,
		a.Chain.EntryApproveIssuer(), "issuer", services.AuditApproveIssuer,
		map[string]any{"vcTypeMask": mask, "expiresAt": expiresAt},
		[]chain.Arg{chain.ArgAddress(address), chain.ArgU64(int64(mask)), {}, {}, chain.ArgU64(expiresAt)},
		a.expectRoleStatus(r.Context(), address, "active", mask))
}

// AuthorityIssuerStatus — tạm ngưng / kích hoạt lại / thu hồi quyền issuer.
func (a *API) AuthorityIssuerStatus(w http.ResponseWriter, r *http.Request) error {
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
	actor, err := a.actor(r)
	if err != nil {
		return err
	}
	res, err := a.setIssuerStatus(r, actor, address, body.Status, reason, txHash)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, res)
	return nil
}

// setIssuerStatus xác minh giao dịch đổi trạng thái issuer rồi ghi chỉ mục.
// Dùng chung cho admin và cho issuer cha quản lý sub-issuer.
func (a *API) setIssuerStatus(r *http.Request, actor *db.Entity, address, status, reason, txHash string) (*authorityResult, error) {
	var expectedFn, newRole, action string
	switch status {
	case "suspended":
		// Tạm ngưng thì vẫn là issuer: quyền còn đó, chỉ bị khoá.
		expectedFn, newRole, action = a.Chain.EntrySuspendIssuer(), "", services.AuditIssuerSuspended
	case "active":
		expectedFn, newRole, action = a.Chain.EntryReactivateIssuer(), "", services.AuditIssuerActive
	case "revoked":
		expectedFn, newRole, action = a.Chain.EntryRevokeIssuer(), "holder", services.AuditIssuerRevoked
	default:
		return nil, httpx.BadRequest("status: phải là suspended, active hoặc revoked")
	}
	return a.applyAuthorityTxArgs(r, actor, address, txHash, expectedFn, newRole, action,
		map[string]any{"reason": reason}, nil, a.expectRoleStatus(r.Context(), address, status, -1))
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
	res, err := a.applyAuthorityTxArgs(r, actor, actor.Address, txHash,
		a.Chain.EntryCancelRootTransfer(), "", services.AuditCancelRootTransfer, nil, []chain.Arg{}, nil)
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
	// accept_root không có tham số nên giao dịch CŨ cũng hợp lệ: root trước đây
	// gửi lại hash accept_root của mình là giành lại "root" trong chỉ mục và hạ
	// root thật xuống admin. Phải hỏi chuỗi: root HIỆN TẠI là ai.
	stillRoot := func() error {
		if a.Chain.Offline() {
			return nil
		}
		root, err1 := chain.NormalizeAddress(a.Chain.GetRootAdmin(r.Context()))
		me, err2 := chain.NormalizeAddress(actor.Address)
		if err1 != nil || err2 != nil || root != me {
			return httpx.Forbidden("Trên chuỗi, tài khoản này hiện không phải root_admin — giao dịch accept_root đã cũ")
		}
		return nil
	}
	res, err := a.applyAuthorityTxArgs(r, actor, actor.Address, txHash,
		a.Chain.EntryAcceptRoot(), "root", services.AuditAcceptRoot, nil, []chain.Arg{}, stillRoot)
	if err != nil {
		return err
	}

	// Chỉ có MỘT root. Chuỗi chỉ giữ đúng một root_admin, nên để hai hàng
	// role='root' trong chỉ mục là nói dối về chính thứ vừa thay đổi. Root cũ về
	// holder: trên chuỗi họ không có bản ghi admin nào.
	if err := a.Store.DemoteOtherRoots(r.Context(), res.Address); err != nil {
		return err
	}

	httpx.OK(w, http.StatusOK, res)
	return nil
}
