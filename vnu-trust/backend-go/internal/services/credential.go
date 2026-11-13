package services

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/httpx"
)

const didCols = `id, entity_id, did, document_cid, document_hash, doc_json, version, status, tx_hash, created_at, updated_at`

func scanDID(row pgx.Row) (*db.DIDDocument, error) {
	var d db.DIDDocument
	err := row.Scan(&d.ID, &d.EntityID, &d.DID, &d.DocumentCID, &d.DocumentHash,
		&d.DocJSON, &d.Version, &d.Status, &d.TxHash, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) DIDByDID(ctx context.Context, did string) (*db.DIDDocument, error) {
	return scanDID(s.DB.Pool.QueryRow(ctx, `SELECT `+didCols+` FROM did_documents WHERE did = $1`, did))
}

// IsDIDDocumentCID — CID này có phải tài liệu của một DID đã ghi nhận không.
func (s *Store) IsDIDDocumentCID(ctx context.Context, cid string) (bool, error) {
	var ok bool
	err := s.DB.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM did_documents WHERE document_cid = $1)`, cid).Scan(&ok)
	return ok, err
}

func (s *Store) DIDByAddress(ctx context.Context, address string) (*db.DIDDocument, error) {
	return scanDID(s.DB.Pool.QueryRow(ctx,
		`SELECT d.`+`id, d.entity_id, d.did, d.document_cid, d.document_hash, d.doc_json,
		        d.version, d.status, d.tx_hash, d.created_at, d.updated_at
		   FROM did_documents d JOIN entities e ON e.id = d.entity_id
		  WHERE e.address = $1`, address))
}

type SaveDIDInput struct {
	EntityID, DID, DocumentCID, DocumentHash, TxHash string
	DocJSON                                          map[string]any
}

func (s *Store) SaveDID(ctx context.Context, in SaveDIDInput) (*db.DIDDocument, error) {
	d, err := scanDID(s.DB.Pool.QueryRow(ctx,
		`INSERT INTO did_documents (entity_id, did, document_cid, document_hash, doc_json, tx_hash)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+didCols,
		in.EntityID, in.DID, in.DocumentCID, in.DocumentHash, in.DocJSON, in.TxHash))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, httpx.Conflict("DID này đã được ghi nhận")
		}
		return nil, err
	}
	return d, nil
}

const vcCols = `id, vc_id, on_chain_vc_id, issuer_did, issuer_address, holder_did, holder_address,
	vc_type, ipfs_cid, vc_id_hash, content_hash, proof_value, vc_json, status, status_reason,
	issued_at, expires_at, tx_hash, status_tx_hash, created_at, updated_at`

func scanVC(row pgx.Row) (*db.Credential, error) {
	var c db.Credential
	err := row.Scan(&c.ID, &c.VCID, &c.OnChainVCID, &c.IssuerDID, &c.IssuerAddress,
		&c.HolderDID, &c.HolderAddress, &c.VCType, &c.IPFSCid, &c.VCIDHash, &c.ContentHash,
		&c.ProofValue, &c.VCJSON, &c.Status, &c.StatusReason, &c.IssuedAt, &c.ExpiresAt,
		&c.TxHash, &c.StatusTxHash, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) VCByID(ctx context.Context, vcID string) (*db.Credential, error) {
	return scanVC(s.DB.Pool.QueryRow(ctx, `SELECT `+vcCols+` FROM credentials WHERE vc_id = $1`, vcID))
}

func (s *Store) RequireVC(ctx context.Context, vcID string) (*db.Credential, error) {
	c, err := s.VCByID(ctx, vcID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, httpx.NotFound("Không tìm thấy VC")
	}
	return c, nil
}

func (s *Store) listVCs(ctx context.Context, where string, args ...any) ([]db.Credential, error) {
	rows, err := s.DB.Pool.Query(ctx, `SELECT `+vcCols+` FROM credentials WHERE `+where+` ORDER BY issued_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []db.Credential{}
	for rows.Next() {
		var c db.Credential
		if err := rows.Scan(&c.ID, &c.VCID, &c.OnChainVCID, &c.IssuerDID, &c.IssuerAddress,
			&c.HolderDID, &c.HolderAddress, &c.VCType, &c.IPFSCid, &c.VCIDHash, &c.ContentHash,
			&c.ProofValue, &c.VCJSON, &c.Status, &c.StatusReason, &c.IssuedAt, &c.ExpiresAt,
			&c.TxHash, &c.StatusTxHash, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) VCsByHolder(ctx context.Context, did string) ([]db.Credential, error) {
	return s.listVCs(ctx, "holder_did = $1", did)
}

// VCsByIssuer — status rỗng là mọi trạng thái.
func (s *Store) VCsByIssuer(ctx context.Context, did, status string) ([]db.Credential, error) {
	if status != "" {
		return s.listVCs(ctx, "issuer_did = $1 AND status = $2", did, status)
	}
	return s.listVCs(ctx, "issuer_did = $1", did)
}

type SaveVCInput struct {
	VCID                                       string
	OnChainVCID                                int64
	IssuerDID, IssuerAddress                   string
	HolderDID, HolderAddress                   string
	VCType                                     int
	IPFSCid, VCIDHash, ContentHash, ProofValue string
	VCJSON                                     map[string]any
	IssuedAt                                   time.Time
	ExpiresAt                                  *time.Time
	TxHash                                     string
}

func (s *Store) SaveVC(ctx context.Context, in SaveVCInput) (*db.Credential, error) {
	c, err := scanVC(s.DB.Pool.QueryRow(ctx,
		`INSERT INTO credentials
		   (vc_id, on_chain_vc_id, issuer_did, issuer_address, holder_did, holder_address,
		    vc_type, ipfs_cid, vc_id_hash, content_hash, proof_value, vc_json,
		    issued_at, expires_at, tx_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING `+vcCols,
		in.VCID, in.OnChainVCID, in.IssuerDID, in.IssuerAddress, in.HolderDID, in.HolderAddress,
		in.VCType, in.IPFSCid, in.VCIDHash, in.ContentHash, in.ProofValue, in.VCJSON,
		in.IssuedAt, in.ExpiresAt, in.TxHash))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, httpx.Conflict("VC này đã được ghi nhận")
		}
		return nil, err
	}
	return c, nil
}

func (s *Store) UpdateVCStatus(ctx context.Context, vcID, status, reason, txHash string) (*db.Credential, error) {
	return scanVC(s.DB.Pool.QueryRow(ctx,
		`UPDATE credentials SET status = $2, status_reason = $3, status_tx_hash = $4, updated_at = now()
		  WHERE vc_id = $1 RETURNING `+vcCols, vcID, status, reason, txHash))
}

// MonthCount và TypeCount là các điểm dữ liệu cho biểu đồ.
type MonthCount struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}

type TypeCount struct {
	VCType int    `json:"vcType"`
	Label  string `json:"label"`
	Count  int    `json:"count"`
}

type IssuerCount struct {
	DID   string  `json:"did"`
	Label *string `json:"label"`
	Count int     `json:"count"`
}

// CredentialBreakdown đếm VC theo trạng thái, theo tháng (12 tháng gần nhất) và
// theo loại; issuerDID rỗng nghĩa là toàn hệ thống. Nhãn loại do tầng handler gắn.
func (s *Store) CredentialBreakdown(ctx context.Context, issuerDID string) (map[string]any, error) {
	where, args := "", []any{}
	if issuerDID != "" {
		where, args = "WHERE issuer_did = $1", []any{issuerDID}
	}
	monthWhere := "WHERE"
	if where != "" {
		monthWhere = where + " AND"
	}

	status := map[string]int{"active": 0, "suspended": 0, "expired": 0, "revoked": 0}
	total := 0
	if err := s.scanCounts(ctx, `SELECT status::text, count(*) FROM credentials `+where+` GROUP BY status`,
		args, func(k string, n int) { status[k] = n; total += n }); err != nil {
		return nil, err
	}
	byMonth := []MonthCount{}
	if err := s.scanCounts(ctx, `SELECT to_char(date_trunc('month', issued_at), 'YYYY-MM'), count(*)
		  FROM credentials `+monthWhere+` issued_at >= date_trunc('month', now()) - interval '11 months'
		 GROUP BY 1 ORDER BY 1`, args, func(k string, n int) { byMonth = append(byMonth, MonthCount{k, n}) }); err != nil {
		return nil, err
	}
	byType := []TypeCount{}
	if err := s.scanCounts(ctx, `SELECT vc_type::text, count(*) FROM credentials `+where+` GROUP BY vc_type ORDER BY vc_type`,
		args, func(k string, n int) {
			t, _ := strconv.Atoi(k)
			byType = append(byType, TypeCount{VCType: t, Count: n})
		}); err != nil {
		return nil, err
	}

	out := map[string]any{"total": total, "byMonth": byMonth, "byType": byType}
	for k, v := range status {
		out[k] = v
	}
	return out, nil
}

// TopIssuers trả 5 đơn vị cấp nhiều văn bằng nhất.
func (s *Store) TopIssuers(ctx context.Context) ([]IssuerCount, error) {
	rows, err := s.DB.Pool.Query(ctx, `SELECT c.issuer_did, e.label, count(*)
		  FROM credentials c LEFT JOIN entities e ON e.did = c.issuer_did
		 GROUP BY c.issuer_did, e.label ORDER BY count(*) DESC, c.issuer_did LIMIT 5`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IssuerCount{}
	for rows.Next() {
		var ic IssuerCount
		if err := rows.Scan(&ic.DID, &ic.Label, &ic.Count); err != nil {
			return nil, err
		}
		out = append(out, ic)
	}
	return out, rows.Err()
}

// VerificationCounts trả tổng số lượt xác minh và số lượt hợp lệ.
func (s *Store) VerificationCounts(ctx context.Context) (total, valid int, err error) {
	err = s.DB.Pool.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE overall_valid) FROM verifications`).Scan(&total, &valid)
	return
}

func (s *Store) scanCounts(ctx context.Context, sql string, args []any, fn func(string, int)) error {
	rows, err := s.DB.Pool.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		fn(k, n)
	}
	return rows.Err()
}
