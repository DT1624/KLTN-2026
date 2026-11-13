package services

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/vnu-trust/backend-go/internal/db"
)

// Nâng cấp hợp đồng 13/11/2026 — phần lưu trữ của C2 (xử lý theo lô), C3 (cấp
// lại có liên kết) và P4.2 (chuyển ví khi mất khoá). Câu SQL phải cho kết quả
// giống hệt backend TypeScript (backend/src/services/review.service.ts).

// ReasonReplaced là lý do hợp đồng ghi vào VC cũ khi nó bị thay (REASON_REPLACED).
const ReasonReplaced = "replaced"

// VCsByIssuerAddress liệt kê VC do một issuer cấp, theo số hiệu on-chain tăng dần.
func (s *Store) VCsByIssuerAddress(ctx context.Context, address string) ([]db.Credential, error) {
	return s.listVCsOrdered(ctx, "issuer_address = $1", "on_chain_vc_id NULLS LAST, issued_at", address)
}

// VCsByIDs trả các VC có vc_id trong danh sách (thứ tự không xác định).
func (s *Store) VCsByIDs(ctx context.Context, ids []string) ([]db.Credential, error) {
	return s.listVCsOrdered(ctx, "vc_id = ANY($1)", "vc_id", ids)
}

// SetVCsStatus ghi cùng một trạng thái cho nhiều VC (sau giao dịch theo lô).
func (s *Store) SetVCsStatus(ctx context.Context, ids []string, status, reason, txHash string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE credentials SET status = $2, status_reason = $3, status_tx_hash = $4, updated_at = now()
		  WHERE vc_id = ANY($1)`, ids, status, reason, txHash)
	return err
}

// ReissueVC chèn VC mới (thay cho oldVCID) và thu hồi VC cũ trong MỘT giao dịch CSDL.
func (s *Store) ReissueVC(ctx context.Context, in SaveVCInput, oldVCID string) (*db.Credential, error) {
	var out *db.Credential
	err := pgx.BeginFunc(ctx, s.DB.Pool, func(tx pgx.Tx) error {
		in.ReplacesVCID = &oldVCID
		c, err := saveVC(ctx, tx, in)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE credentials SET status = 'revoked', status_reason = $2, status_tx_hash = $3,
			        replaced_by_vc_id = $4, updated_at = now()
			  WHERE vc_id = $1`, oldVCID, ReasonReplaced, in.TxHash, in.VCID); err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
}

// LinkReplacement ghi liên kết cũ → mới do admin nối. Lý do thu hồi cũ (nếu VC cũ
// đã bị thu hồi từ trước) được giữ nguyên, giống hợp đồng.
func (s *Store) LinkReplacement(ctx context.Context, oldVCID, newVCID, txHash string) (old, repl *db.Credential, err error) {
	err = pgx.BeginFunc(ctx, s.DB.Pool, func(tx pgx.Tx) error {
		o, err := scanVC(tx.QueryRow(ctx,
			`UPDATE credentials
			    SET status_reason = CASE WHEN status = 'revoked' THEN status_reason ELSE $2 END,
			        status_tx_hash = CASE WHEN status = 'revoked' THEN status_tx_hash ELSE $3 END,
			        status = 'revoked', replaced_by_vc_id = $4, updated_at = now()
			  WHERE vc_id = $1 RETURNING `+vcCols, oldVCID, ReasonReplaced, txHash, newVCID))
		if err != nil {
			return err
		}
		n, err := scanVC(tx.QueryRow(ctx,
			`UPDATE credentials SET replaces_vc_id = $2, updated_at = now() WHERE vc_id = $1 RETURNING `+vcCols,
			newVCID, oldVCID))
		if err != nil {
			return err
		}
		old, repl = o, n
		return nil
	})
	return old, repl, err
}

// IssuedToHolder: issuer đã từng cấp VC cho ví này chưa.
func (s *Store) IssuedToHolder(ctx context.Context, issuer, holder string) (bool, error) {
	var one int
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT 1 FROM credentials WHERE issuer_address = $1 AND holder_address = $2 LIMIT 1`,
		issuer, holder).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Migration là một liên kết ví cũ → ví mới do admin ghi nhận (P4.2).
type Migration struct {
	ID         int64     `json:"id"`
	OldAddress string    `json:"old_address"`
	NewAddress string    `json:"new_address"`
	OldDID     string    `json:"old_did"`
	NewDID     string    `json:"new_did"`
	RecordedBy string    `json:"recorded_by"`
	Note       string    `json:"note"`
	CreatedAt  time.Time `json:"created_at"`
}

const migrationCols = `id, old_address, new_address, old_did, new_did, recorded_by, note, created_at`

func scanMigration(row pgx.Row) (*Migration, error) {
	var m Migration
	err := row.Scan(&m.ID, &m.OldAddress, &m.NewAddress, &m.OldDID, &m.NewDID, &m.RecordedBy, &m.Note, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// MigrationOf trả liên kết của một ví cũ, hoặc nil.
func (s *Store) MigrationOf(ctx context.Context, oldAddress string) (*Migration, error) {
	return scanMigration(s.DB.Pool.QueryRow(ctx,
		`SELECT `+migrationCols+` FROM identity_migrations WHERE old_address = $1`, oldAddress))
}

// InsertMigration ghi một liên kết ví cũ → ví mới.
func (s *Store) InsertMigration(ctx context.Context, m Migration) (*Migration, error) {
	return scanMigration(s.DB.Pool.QueryRow(ctx,
		`INSERT INTO identity_migrations (old_address, new_address, old_did, new_did, recorded_by, note)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+migrationCols,
		m.OldAddress, m.NewAddress, m.OldDID, m.NewDID, m.RecordedBy, m.Note))
}

// LatestDIDStatus là trạng thái DID gần nhất của một địa chỉ trong chỉ mục ("" nếu chưa có).
func (s *Store) LatestDIDStatus(ctx context.Context, address string) (string, error) {
	var st string
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT d.status FROM did_documents d JOIN entities e ON e.id = d.entity_id
		  WHERE e.address = $1 ORDER BY d.created_at DESC LIMIT 1`, address).Scan(&st)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return st, err
}

// SetOwnDIDStatus ghi trạng thái DID (không đụng DID đã thu hồi).
func (s *Store) SetOwnDIDStatus(ctx context.Context, address, status string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE did_documents d SET status = $2, updated_at = now()
		   FROM entities e WHERE e.id = d.entity_id AND e.address = $1 AND d.status <> 'revoked'`,
		address, status)
	return err
}
