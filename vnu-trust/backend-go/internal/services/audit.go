package services

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// Nhật ký kiểm toán cho các thao tác làm thay đổi trạng thái tin cậy.
//
// Bảng audit_log có sẵn trong lược đồ nhưng trước đây KHÔNG backend nào ghi
// vào — tuyến GET /admin/audit luôn trả rỗng. Một hệ thống văn bằng mà không
// ghi lại được "ai thu hồi cái gì, lúc nào" thì mất đúng thứ nó hứa hẹn.
//
// Tên hành động phải giống hệt backend TypeScript
// (backend/src/services/audit.service.ts), nếu không lịch sử sẽ vỡ thành hai
// loại tuỳ theo backend nào xử lý yêu cầu.
const (
	AuditDIDSave     = "did.save"
	AuditVCIssue     = "vc.issue"
	AuditVCRevoke    = "vc.revoke"
	AuditVCSuspend   = "vc.suspend"
	AuditVCReinstate = "vc.reinstate"
	AuditShareCreate = "share.create"
	AuditShareRevoke = "share.revoke"

	// Quản trị quyền hạn trên chuỗi
	AuditGrantAdmin         = "authority.grant_admin"
	AuditRevokeAdmin        = "authority.revoke_admin"
	AuditApproveIssuer      = "authority.approve_issuer"
	AuditIssuerSuspended    = "authority.issuer_suspended"
	AuditIssuerActive       = "authority.issuer_active"
	AuditIssuerRevoked      = "authority.issuer_revoked"
	AuditProposeRoot        = "authority.propose_root"
	AuditAcceptRoot         = "authority.accept_root"
	AuditCancelRootTransfer = "authority.cancel_root_transfer"
)

// Audit ghi một dòng nhật ký. Lỗi ghi KHÔNG được làm hỏng thao tác chính:
// người dùng đã thu hồi xong văn bằng rồi, không thể báo họ là thất bại chỉ
// vì phần ghi chép phụ trợ gặp sự cố — chỉ log lại rồi đi tiếp.
func (s *Store) Audit(ctx context.Context, actor, action string, target *string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		slog.Error("không dựng được detail nhật ký kiểm toán", "err", err, "action", action)
		return
	}
	if _, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO audit_log (actor, action, target, detail) VALUES ($1,$2,$3,$4)`,
		actor, action, target, raw); err != nil {
		slog.Error("không ghi được nhật ký kiểm toán", "err", err, "actor", actor, "action", action)
	}
}

// AuditEntry là một dòng nhật ký trả về cho tuyến quản trị. Tên trường giữ
// nguyên dạng snake_case của bảng để khớp `SELECT *` bên backend TypeScript.
type AuditEntry struct {
	ID        int64           `json:"id"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	Target    *string         `json:"target"`
	Detail    json.RawMessage `json:"detail"`
	CreatedAt time.Time       `json:"created_at"`
}

func (s *Store) AuditList(ctx context.Context, limit, offset int) ([]AuditEntry, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT id, actor, action, target, detail, created_at
		   FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var detail []byte
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Detail = json.RawMessage(detail)
		out = append(out, e)
	}
	return out, rows.Err()
}
