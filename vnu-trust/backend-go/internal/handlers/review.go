package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/middleware"
	"github.com/vnu-trust/backend-go/internal/services"
)

// Nâng cấp hợp đồng 13/11/2026 — C2 (xử lý theo lô), C3 (cấp lại có liên kết),
// P4.1 (tự khoá DID), P4.2 (chuyển ví khi mất khoá). Mọi handler ở đây phải
// giống hệt backend TypeScript (backend/src/services/review.service.ts): cùng
// thứ tự kiểm, cùng mã lỗi.

const maxBatch = 100

// BatchResult giống hệt bản TypeScript.
type BatchResult struct {
	Changed []string `json:"changed"`
	Skipped []string `json:"skipped"`
	Stale   []string `json:"stale"`
}

type batchBody struct {
	Action string   `json:"action"`
	VCIDs  []string `json:"vcIds"`
	Reason string   `json:"reason"`
	TxHash string   `json:"txHash"`
}

func parseBatchBody(r *http.Request) (*batchBody, string, error) {
	var b batchBody
	if err := httpx.DecodeJSON(r, &b); err != nil {
		return nil, "", err
	}
	if b.Action != "suspend" && b.Action != "revoke" {
		return nil, "", httpx.BadRequest("action: phải là suspend hoặc revoke")
	}
	if len(b.VCIDs) < 1 || len(b.VCIDs) > maxBatch {
		return nil, "", httpx.BadRequest("vcIds: cần 1..%d văn bằng", maxBatch)
	}
	for _, id := range b.VCIDs {
		if n := len(strings.TrimSpace(id)); n < 8 || n > 200 {
			return nil, "", httpx.BadRequest("vcIds: mỗi mã phải dài 8..200 ký tự")
		}
	}
	b.Reason = strings.TrimSpace(b.Reason)
	if len(b.Reason) < 2 || len(b.Reason) > 500 {
		return nil, "", httpx.BadRequest("reason: lý do phải dài 2..500 ký tự")
	}
	txHash, err := httpx.TxHash(b.TxHash, "txHash")
	if err != nil {
		return nil, "", err
	}
	return &b, txHash, nil
}

// canApply là luật bỏ qua của hợp đồng (vc_registry::batch_can_apply), dùng khi offline.
func canApply(vc *db.Credential, target string) bool {
	if vc.Status == "revoked" {
		return false
	}
	if target == "revoked" {
		return true
	}
	expired := vc.ExpiresAt != nil && !vc.ExpiresAt.After(time.Now())
	return vc.Status == "active" && !expired
}

func (a *API) batchFunction(parent bool, action string) string {
	switch {
	case !parent && action == "revoke":
		return a.Chain.EntryAdminRevokeVCs()
	case !parent:
		return a.Chain.EntryAdminSuspendVCs()
	case action == "revoke":
		return a.Chain.EntryDelegatorRevokeVCs()
	default:
		return a.Chain.EntryDelegatorSuspendVCs()
	}
}

// batchChange: hình dạng lô → VC tồn tại → số hiệu on-chain → quyền (issuer cha)
// → giao dịch → sự kiện của chính giao dịch → trạng thái hiện tại → ghi.
func (a *API) batchChange(parent bool) httpx.Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		b, txHash, err := parseBatchBody(r)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, id := range b.VCIDs {
			if seen[id] {
				return httpx.BadRequest("vcIds: có mã văn bằng trùng lặp")
			}
			seen[id] = true
		}
		ctx := r.Context()
		actor, err := a.Store.RequireEntity(ctx, middleware.ClaimsFrom(ctx).Address)
		if err != nil {
			return err
		}
		rows, err := a.Store.VCsByIDs(ctx, b.VCIDs)
		if err != nil {
			return err
		}
		if len(rows) != len(b.VCIDs) {
			found := map[string]bool{}
			for _, row := range rows {
				found[row.VCID] = true
			}
			for _, id := range b.VCIDs {
				if !found[id] {
					return httpx.NotFound("Không tìm thấy VC %s", id)
				}
			}
		}
		missingOnChain := false
		for _, row := range rows {
			if row.OnChainVCID == nil {
				missingOnChain = true
			}
		}
		if !a.Chain.Offline() && missingOnChain {
			return httpx.BadRequest("Có VC chưa có số hiệu on-chain — không đối chiếu được giao dịch")
		}
		if parent {
			for _, row := range rows {
				if a.Chain.GetDelegator(ctx, row.IssuerAddress) != actor.Address {
					return httpx.Forbidden("VC %s không do sub-issuer của bạn cấp", row.VCID)
				}
			}
		}

		// Hợp đồng đòi id TĂNG DẦN NGHIÊM NGẶT; giao diện sắp xếp giống hệt.
		sort.SliceStable(rows, func(i, j int) bool { return onChainOrZero(&rows[i]) < onChainOrZero(&rows[j]) })
		target := map[string]string{"suspend": "suspended", "revoke": "revoked"}[b.Action]
		var args []chain.Arg
		if !missingOnChain {
			ids := make([]int64, len(rows))
			for i := range rows {
				ids[i] = *rows[i].OnChainVCID
			}
			args = []chain.Arg{chain.ArgU64s(ids), chain.ArgBytes(chain.UTF8ToHex(b.Reason))}
		}
		tx, err := a.Chain.VerifyTransactionArgs(ctx, txHash, a.batchFunction(parent, b.Action), actor.Address, args)
		if err != nil {
			return err
		}

		var changedOnChain map[int64]bool
		if !a.Chain.Offline() {
			ev := chain.FindEvent(tx, a.Chain.Module("vc_registry")+"::VCBatchProcessedEvent")
			list, ok := ev["changed"].([]any)
			if ev == nil || !ok {
				return httpx.BadRequest("Giao dịch không phát VCBatchProcessedEvent")
			}
			changedOnChain = map[int64]bool{}
			for _, v := range list {
				if n, err := strconv.ParseInt(fmt.Sprint(v), 10, 64); err == nil {
					changedOnChain[n] = true
				}
			}
		}
		res := BatchResult{Changed: []string{}, Skipped: []string{}, Stale: []string{}}
		for i := range rows {
			row := &rows[i]
			changed := canApply(row, target)
			if changedOnChain != nil {
				changed = changedOnChain[*row.OnChainVCID]
			}
			if !changed {
				res.Skipped = append(res.Skipped, row.VCID)
				continue
			}
			// Chống phát lại (quyết định #19), áp từng VC.
			if !a.Chain.Offline() && a.Chain.VCStatus(ctx, *row.OnChainVCID) != target {
				res.Stale = append(res.Stale, row.VCID)
				continue
			}
			res.Changed = append(res.Changed, row.VCID)
		}
		if len(res.Changed) == 0 && len(res.Stale) > 0 {
			return httpx.Conflict("Trạng thái trên chuỗi đã khác trạng thái giao dịch này đặt — giao dịch đã cũ")
		}
		if len(res.Changed) > 0 {
			if err := a.Store.SetVCsStatus(ctx, res.Changed, target, b.Reason, txHash); err != nil {
				return err
			}
		}
		action := services.AuditVCSuspend
		if b.Action == "revoke" {
			action = services.AuditVCRevoke
		}
		for _, id := range res.Changed {
			id := id
			a.Store.Audit(ctx, actor.Address, action, &id, map[string]any{
				"reason": b.Reason, "txHash": txHash, "batch": true, "byAdmin": !parent, "byParent": parent,
			})
		}
		httpx.OK(w, http.StatusOK, res)
		return nil
	}
}

func onChainOrZero(c *db.Credential) int64 {
	if c.OnChainVCID == nil {
		return 0
	}
	return *c.OnChainVCID
}

// AdminBatch: admin_suspend_vcs / admin_revoke_vcs.
func (a *API) AdminBatch(w http.ResponseWriter, r *http.Request) error {
	return a.batchChange(false)(w, r)
}

// ParentBatch: delegator_suspend_vcs / delegator_revoke_vcs.
func (a *API) ParentBatch(w http.ResponseWriter, r *http.Request) error {
	return a.batchChange(true)(w, r)
}

// AdminIssuerCredentials: mọi VC do một issuer cấp — để xem xét (C2).
func (a *API) AdminIssuerCredentials(w http.ResponseWriter, r *http.Request) error {
	addr, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	rows, err := a.Store.VCsByIssuerAddress(r.Context(), addr)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rows)
	return nil
}

// ParentReviewCredentials: issuer cha xem VC của sub-issuer của mình.
func (a *API) ParentReviewCredentials(w http.ResponseWriter, r *http.Request) error {
	addr, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	ctx := r.Context()
	actor, err := a.Store.RequireEntity(ctx, middleware.ClaimsFrom(ctx).Address)
	if err != nil {
		return err
	}
	if a.Chain.GetDelegator(ctx, addr) != actor.Address {
		return httpx.Forbidden("Địa chỉ này không phải sub-issuer do bạn cấp")
	}
	rows, err := a.Store.VCsByIssuerAddress(ctx, addr)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rows)
	return nil
}

// assertLinkedOnChain: chống phát lại cho C3 — chuỗi phải đang ghi đúng liên kết.
func (a *API) assertLinkedOnChain(ctx context.Context, oldID, newID int64) error {
	linked, ok := a.Chain.VCReplacement(ctx, oldID)
	if !ok || linked != newID {
		got := "không có"
		if ok {
			got = strconv.FormatInt(linked, 10)
		}
		return httpx.Conflict("Trên chuỗi văn bằng cũ đang được thay bằng \"%s\", không phải %d", got, newID)
	}
	return nil
}

// ReissueCredential (reissue_vc). Thứ tự: phép kiểm rẻ của cấp mới → VC cũ → quyền
// → VC cũ đang hoạt động → chưa bị thay → cùng loại → holder cũ (nếu đổi ví)
// → giao dịch → sự kiện → trạng thái chuỗi → ghi hai bản ghi trong một giao dịch CSDL.
func (a *API) ReissueCredential(w http.ResponseWriter, r *http.Request) error {
	oldID := r.PathValue("vcId")
	in, err := parseIssueBody(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	claims := middleware.ClaimsFrom(ctx)
	if err := a.assertIssueInput(ctx, in, claims.Address); err != nil {
		return err
	}
	old, err := a.Store.RequireVC(ctx, oldID)
	if err != nil {
		return err
	}
	isOwner := old.IssuerAddress == claims.Address
	if !isOwner && a.Chain.GetDelegator(ctx, old.IssuerAddress) != claims.Address {
		return httpx.Forbidden("Chỉ issuer đã cấp văn bằng cũ (hoặc issuer cha của họ) mới cấp lại được")
	}
	if old.Status == "revoked" {
		return httpx.Conflict("Văn bằng cũ đã bị thu hồi — chỉ admin nối liên kết được")
	}
	if old.Status != "active" {
		return httpx.Conflict("Chỉ cấp lại được văn bằng đang hoạt động (kể cả đã hết hạn)")
	}
	if old.ReplacedByVCID != nil {
		return httpx.Conflict("Văn bằng cũ đã có bản thay thế")
	}
	if in.vcType != old.VCType {
		return httpx.BadRequest("Văn bằng thay thế phải cùng loại với văn bằng cũ")
	}
	if in.holderAddr != old.HolderAddress && a.Chain.HasActiveDID(ctx, old.HolderAddress) {
		return httpx.Conflict("Holder cũ vẫn có DID hoạt động — admin phải khoá/thu hồi DID cũ trước khi cấp sang ví mới")
	}
	if !a.Chain.Offline() && old.OnChainVCID == nil {
		return httpx.BadRequest("Văn bằng cũ chưa có số hiệu on-chain — không đối chiếu được giao dịch")
	}
	issuer, err := a.Store.RequireEntity(ctx, claims.Address)
	if err != nil {
		return err
	}
	oldArg := chain.Arg{}
	if old.OnChainVCID != nil {
		oldArg = chain.ArgU64(*old.OnChainVCID)
	}
	tx, err := a.Chain.VerifyTransactionArgs(ctx, in.txHash, a.Chain.EntryReissueVC(), issuer.Address,
		append([]chain.Arg{oldArg}, a.issueArgs(in)...))
	if err != nil {
		return err
	}
	if err := a.assertIssuedEvent(tx, in); err != nil {
		return err
	}
	if !a.Chain.Offline() {
		ev := chain.FindEvent(tx, a.Chain.Module("vc_registry")+"::VCReplacedEvent")
		if ev == nil || fmt.Sprint(ev["old_id"]) != strconv.FormatInt(*old.OnChainVCID, 10) ||
			fmt.Sprint(ev["new_id"]) != strconv.FormatInt(in.body.OnChainVCID, 10) {
			return httpx.BadRequest("Giao dịch không phát VCReplacedEvent khớp văn bằng cũ và mới")
		}
		if err := a.assertLinkedOnChain(ctx, *old.OnChainVCID, in.body.OnChainVCID); err != nil {
			return err
		}
	}
	row, err := a.Store.ReissueVC(ctx, in.saveInput(issuer), old.VCID)
	if err != nil {
		return err
	}
	a.Store.Audit(ctx, issuer.Address, services.AuditVCReissue, &in.body.VCID, map[string]any{
		"replaces": old.VCID, "holderDid": in.holderDID, "vcType": in.vcType, "txHash": in.txHash,
		"byParent": !isOwner,
	})
	httpx.OK(w, http.StatusCreated, row)
	return nil
}

// AdminLinkReplacement (admin_link_replacement): issuer gốc đã mất quyền, issuer
// khác cấp mới bằng issue_vc, admin nối liên kết.
func (a *API) AdminLinkReplacement(w http.ResponseWriter, r *http.Request) error {
	oldID := r.PathValue("vcId")
	var body struct {
		NewVCID string `json:"newVcId"`
		TxHash  string `json:"txHash"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	body.NewVCID = strings.TrimSpace(body.NewVCID)
	if n := len(body.NewVCID); n < 8 || n > 200 {
		return httpx.BadRequest("newVcId: phải dài 8..200 ký tự")
	}
	txHash, err := httpx.TxHash(body.TxHash, "txHash")
	if err != nil {
		return err
	}
	if oldID == body.NewVCID {
		return httpx.BadRequest("Văn bằng không thể thay cho chính nó")
	}
	ctx := r.Context()
	old, err := a.Store.RequireVC(ctx, oldID)
	if err != nil {
		return err
	}
	neu, err := a.Store.RequireVC(ctx, body.NewVCID)
	if err != nil {
		return err
	}
	if old.ReplacedByVCID != nil {
		return httpx.Conflict("Văn bằng cũ đã có bản thay thế")
	}
	if neu.ReplacesVCID != nil {
		return httpx.Conflict("Văn bằng mới đã thay cho một văn bằng khác")
	}
	if neu.VCType != old.VCType {
		return httpx.BadRequest("Văn bằng thay thế phải cùng loại với văn bằng cũ")
	}
	if neu.Status != "active" {
		return httpx.Conflict("Văn bằng thay thế phải đang hoạt động")
	}
	if !a.Chain.Offline() {
		if old.OnChainVCID == nil || neu.OnChainVCID == nil {
			return httpx.BadRequest("Có văn bằng chưa có số hiệu on-chain — không đối chiếu được giao dịch")
		}
		if *neu.OnChainVCID <= *old.OnChainVCID {
			return httpx.BadRequest("Văn bằng thay thế phải được cấp sau văn bằng cũ")
		}
	}
	if neu.HolderAddress != old.HolderAddress && a.Chain.HasActiveDID(ctx, old.HolderAddress) {
		return httpx.Conflict("Holder cũ vẫn có DID hoạt động — khoá/thu hồi DID cũ trước khi nối sang ví mới")
	}
	actor, err := a.Store.RequireEntity(ctx, middleware.ClaimsFrom(ctx).Address)
	if err != nil {
		return err
	}
	var args []chain.Arg
	if old.OnChainVCID != nil && neu.OnChainVCID != nil {
		args = []chain.Arg{chain.ArgU64(*old.OnChainVCID), chain.ArgU64(*neu.OnChainVCID)}
	}
	if _, err := a.Chain.VerifyTransactionArgs(ctx, txHash, a.Chain.EntryAdminLinkReplacement(), actor.Address, args); err != nil {
		return err
	}
	if !a.Chain.Offline() {
		if err := a.assertLinkedOnChain(ctx, *old.OnChainVCID, *neu.OnChainVCID); err != nil {
			return err
		}
	}
	o, n, err := a.Store.LinkReplacement(ctx, old.VCID, neu.VCID, txHash)
	if err != nil {
		return err
	}
	a.Store.Audit(ctx, actor.Address, services.AuditVCLink, &old.VCID,
		map[string]any{"replacement": neu.VCID, "txHash": txHash})
	httpx.OK(w, http.StatusOK, map[string]any{"old": o, "replacement": n})
	return nil
}

// AdminRecordMigration (P4.2): ghi liên kết ví cũ → ví mới sau khi đã xác minh
// danh tính ngoài hệ thống. Không có giao dịch: đây là hồ sơ hành chính.
func (a *API) AdminRecordMigration(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		OldAddress string `json:"oldAddress"`
		NewAddress string `json:"newAddress"`
		Note       string `json:"note"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	oldAddr, err := httpx.Address(body.OldAddress, "oldAddress")
	if err != nil {
		return err
	}
	newAddr, err := httpx.Address(body.NewAddress, "newAddress")
	if err != nil {
		return err
	}
	note := strings.TrimSpace(body.Note)
	if len(note) < 2 || len(note) > 500 {
		return httpx.BadRequest("note: ghi chú phải dài 2..500 ký tự")
	}
	if oldAddr == newAddr {
		return httpx.BadRequest("Ví mới phải khác ví cũ")
	}
	ctx := r.Context()
	oldEnt, err := a.Store.EntityByAddress(ctx, oldAddr)
	if err != nil {
		return err
	}
	newEnt, err := a.Store.EntityByAddress(ctx, newAddr)
	if err != nil {
		return err
	}
	if oldEnt == nil {
		return httpx.NotFound("Không tìm thấy ví cũ")
	}
	if newEnt == nil {
		return httpx.NotFound("Không tìm thấy ví mới")
	}
	if m, err := a.Store.MigrationOf(ctx, oldAddr); err != nil {
		return err
	} else if m != nil {
		return httpx.Conflict("Ví cũ này đã được chuyển sang một ví khác")
	}
	if a.Chain.HasActiveDID(ctx, oldAddr) {
		return httpx.Conflict("Ví cũ vẫn có DID hoạt động — khoá hoặc thu hồi DID cũ trước")
	}
	if !a.Chain.HasActiveDID(ctx, newAddr) {
		return httpx.Conflict("Ví mới chưa có DID hoạt động")
	}
	actor, err := a.Store.RequireEntity(ctx, middleware.ClaimsFrom(ctx).Address)
	if err != nil {
		return err
	}
	m, err := a.Store.InsertMigration(ctx, services.Migration{
		OldAddress: oldAddr, NewAddress: newAddr, OldDID: oldEnt.DID, NewDID: newEnt.DID,
		RecordedBy: actor.Address, Note: note,
	})
	if err != nil {
		return err
	}
	a.Store.Audit(ctx, actor.Address, services.AuditDIDMigrate, &oldEnt.DID,
		map[string]any{"newDid": newEnt.DID, "note": note})
	httpx.OK(w, http.StatusCreated, m)
	return nil
}

// AdminMigration: ví mới của một ví cũ (null nếu chưa có).
func (a *API) AdminMigration(w http.ResponseWriter, r *http.Request) error {
	addr, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	m, err := a.Store.MigrationOf(r.Context(), addr)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, m)
	return nil
}

// IssuerHolderMigration: chỉ issuer đã cấp văn bằng cho ví cũ mới xem được.
func (a *API) IssuerHolderMigration(w http.ResponseWriter, r *http.Request) error {
	addr, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	ctx := r.Context()
	ok, err := a.Store.IssuedToHolder(ctx, middleware.ClaimsFrom(ctx).Address, addr)
	if err != nil {
		return err
	}
	if !ok {
		return httpx.Forbidden("Bạn chưa cấp văn bằng nào cho ví này")
	}
	m, err := a.Store.MigrationOf(ctx, addr)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, m)
	return nil
}

// SelfDIDStatus (P4.1): chủ DID tự khoá (suspend_own_did) / tự mở (reactivate_own_did).
func (a *API) SelfDIDStatus(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Status string `json:"status"`
		TxHash string `json:"txHash"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	if body.Status != "suspended" && body.Status != "active" {
		return httpx.BadRequest("status: phải là suspended hoặc active")
	}
	txHash, err := httpx.TxHash(body.TxHash, "txHash")
	if err != nil {
		return err
	}
	ctx := r.Context()
	actor, err := a.Store.RequireEntity(ctx, middleware.ClaimsFrom(ctx).Address)
	if err != nil {
		return err
	}
	cur, err := a.Store.LatestDIDStatus(ctx, actor.Address)
	if err != nil {
		return err
	}
	switch {
	case cur == "":
		return httpx.NotFound("Bạn chưa có DID")
	case cur == "revoked":
		return httpx.Conflict("DID đã bị thu hồi vĩnh viễn")
	case body.Status == "suspended" && cur != "active":
		return httpx.Conflict("Chỉ khoá được DID đang hoạt động")
	case body.Status == "active" && cur != "suspended":
		return httpx.Conflict("Chỉ mở được DID đang bị khoá")
	}
	fn := a.Chain.EntrySuspendOwnDID()
	if body.Status == "active" {
		fn = a.Chain.EntryReactivateOwnDID()
	}
	if _, err := a.Chain.VerifyTransactionArgs(ctx, txHash, fn, actor.Address, nil); err != nil {
		return err
	}
	if !a.Chain.Offline() {
		d := a.Chain.ResolveDIDByOwner(ctx, actor.Address)
		if d == nil || d.Status != body.Status {
			st := "không có"
			if d != nil {
				st = d.Status
			}
			return httpx.Conflict("Trên chuỗi DID đang \"%s\", không khớp thao tác — giao dịch đã cũ", st)
		}
	}
	if err := a.Store.SetOwnDIDStatus(ctx, actor.Address, body.Status); err != nil {
		return err
	}
	action := services.AuditDIDSuspend
	if body.Status == "active" {
		action = services.AuditDIDReactivate
	}
	a.Store.Audit(ctx, actor.Address, action, &actor.Address, map[string]any{"txHash": txHash, "self": true})
	httpx.OK(w, http.StatusOK, map[string]any{"address": actor.Address, "status": body.Status, "txHash": txHash})
	return nil
}
