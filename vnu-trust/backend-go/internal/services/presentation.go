package services

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/httpx"
)

const vpCols = `id, vp_id, holder_did, verifier_did, vc_ids, ipfs_cid, vp_hash, proof_value, challenge, created_at`

func scanVP(row pgx.Row) (*db.Presentation, error) {
	var p db.Presentation
	err := row.Scan(&p.ID, &p.VPID, &p.HolderDID, &p.VerifierDID, &p.VCIDs,
		&p.IPFSCid, &p.VPHash, &p.ProofValue, &p.Challenge, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) VPByID(ctx context.Context, vpID string) (*db.Presentation, error) {
	return scanVP(s.DB.Pool.QueryRow(ctx, `SELECT `+vpCols+` FROM presentations WHERE vp_id = $1`, vpID))
}

func (s *Store) VPsByHolder(ctx context.Context, did string) ([]db.Presentation, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+vpCols+` FROM presentations WHERE holder_did = $1 ORDER BY created_at DESC`, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []db.Presentation{}
	for rows.Next() {
		var p db.Presentation
		if err := rows.Scan(&p.ID, &p.VPID, &p.HolderDID, &p.VerifierDID, &p.VCIDs,
			&p.IPFSCid, &p.VPHash, &p.ProofValue, &p.Challenge, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type CreateVPInput struct {
	VPID, HolderDID string
	VerifierDID     *string
	VCIDs           []string
	IPFSCid         string
	VPHash          string
	ProofValue      string
	Challenge       *string
	TTL             time.Duration
	ShareToken      string
}

// CreateVP ghi VP và liên kết chia sẻ trong CÙNG một giao dịch CSDL, để không
// bao giờ tồn tại VP mồ côi khi bước sau lỗi.
func (s *Store) CreateVP(ctx context.Context, in CreateVPInput) (*db.Presentation, *db.ShareToken, error) {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	vp, err := scanVP(tx.QueryRow(ctx,
		`INSERT INTO presentations (vp_id, holder_did, verifier_did, vc_ids, ipfs_cid, vp_hash, proof_value, challenge)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+vpCols,
		in.VPID, in.HolderDID, in.VerifierDID, in.VCIDs, in.IPFSCid, in.VPHash, in.ProofValue, in.Challenge))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, nil, httpx.Conflict("VP này đã tồn tại")
		}
		return nil, nil, err
	}

	var st db.ShareToken
	if err := tx.QueryRow(ctx,
		`INSERT INTO share_tokens (token, vp_id, holder_did, ipfs_cid, expires_at)
		 VALUES ($1,$2,$3,$4,$5)
		 RETURNING token, vp_id, holder_did, ipfs_cid, expires_at, revoked_at, view_count, created_at`,
		in.ShareToken, in.VPID, in.HolderDID, in.IPFSCid, time.Now().Add(in.TTL),
	).Scan(&st.Token, &st.VPID, &st.HolderDID, &st.IPFSCid, &st.ExpiresAt,
		&st.RevokedAt, &st.ViewCount, &st.CreatedAt); err != nil {
		return nil, nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return vp, &st, nil
}

const shareCols = `token, vp_id, holder_did, ipfs_cid, expires_at, revoked_at, view_count, created_at`

func scanShare(row pgx.Row) (*db.ShareToken, error) {
	var t db.ShareToken
	err := row.Scan(&t.Token, &t.VPID, &t.HolderDID, &t.IPFSCid, &t.ExpiresAt,
		&t.RevokedAt, &t.ViewCount, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// OpenShareToken kiểm hiệu lực và tăng bộ đếm lượt xem trong một câu lệnh,
// nên bộ đếm không sai khi có nhiều lượt xem đồng thời.
func (s *Store) OpenShareToken(ctx context.Context, token string) (*db.ShareToken, error) {
	t, err := scanShare(s.DB.Pool.QueryRow(ctx,
		`UPDATE share_tokens SET view_count = view_count + 1
		  WHERE token = $1 AND revoked_at IS NULL AND expires_at > now()
		 RETURNING `+shareCols, token))
	if err != nil {
		return nil, err
	}
	if t != nil {
		return t, nil
	}

	// Không cập nhật được: phân biệt rõ nguyên nhân để báo lỗi cho đúng.
	existing, err := scanShare(s.DB.Pool.QueryRow(ctx, `SELECT `+shareCols+` FROM share_tokens WHERE token = $1`, token))
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, httpx.NotFound("Liên kết chia sẻ không tồn tại")
	}
	if existing.RevokedAt != nil {
		return nil, httpx.Gone("Liên kết đã bị chủ sở hữu thu hồi")
	}
	return nil, httpx.Gone("Liên kết đã hết hạn")
}

func (s *Store) SharesByHolder(ctx context.Context, did string) ([]db.ShareToken, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+shareCols+` FROM share_tokens WHERE holder_did = $1 ORDER BY created_at DESC`, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []db.ShareToken{}
	for rows.Next() {
		var t db.ShareToken
		if err := rows.Scan(&t.Token, &t.VPID, &t.HolderDID, &t.IPFSCid, &t.ExpiresAt,
			&t.RevokedAt, &t.ViewCount, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeShareToken thu hồi liên kết và trả vp_id để ghi nhật ký.
func (s *Store) RevokeShareToken(ctx context.Context, token, holderDID string) (string, error) {
	var vpID string
	err := s.DB.Pool.QueryRow(ctx,
		`UPDATE share_tokens SET revoked_at = now()
		  WHERE token = $1 AND holder_did = $2 AND revoked_at IS NULL RETURNING vp_id`, token, holderDID).Scan(&vpID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if vpID == "" {
		// Phân biệt "không tồn tại/không phải của bạn" với "đã thu hồi rồi".
		existing, err := scanShare(s.DB.Pool.QueryRow(ctx, `SELECT `+shareCols+` FROM share_tokens WHERE token = $1`, token))
		if err != nil {
			return "", err
		}
		if existing == nil {
			return "", httpx.NotFound("Liên kết chia sẻ không tồn tại")
		}
		if existing.HolderDID != holderDID {
			return "", httpx.Forbidden("Liên kết này không thuộc về bạn")
		}
		vpID = existing.VPID
	}
	return vpID, nil
}

func (s *Store) SaveVerification(ctx context.Context, vpID, verifier string, valid bool, report any) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO verifications (vp_id, verifier_address, overall_valid, report) VALUES ($1,$2,$3,$4)`,
		vpID, verifier, valid, report)
	return err
}

type VerificationRow struct {
	ID           string    `json:"id"`
	VPID         string    `json:"vp_id"`
	OverallValid bool      `json:"overall_valid"`
	Report       any       `json:"report"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s *Store) VerificationHistory(ctx context.Context, verifier string, limit int) ([]VerificationRow, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT id, vp_id, overall_valid, report, created_at FROM verifications
		  WHERE verifier_address = $1 ORDER BY created_at DESC LIMIT $2`, verifier, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []VerificationRow{}
	for rows.Next() {
		var v VerificationRow
		if err := rows.Scan(&v.ID, &v.VPID, &v.OverallValid, &v.Report, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
