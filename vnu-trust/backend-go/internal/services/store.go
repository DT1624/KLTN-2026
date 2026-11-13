// Package services chứa tầng nghiệp vụ, dùng chung CSDL với backend TypeScript.
package services

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/httpx"
)

type Store struct{ DB *db.DB }

func NewStore(d *db.DB) *Store { return &Store{DB: d} }

// isUniqueViolation nhận diện lỗi trùng khoá của Postgres (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

const entityCols = `id, address, public_key_hex, did, role, label, email, created_at, updated_at`

func scanEntity(row pgx.Row) (*db.Entity, error) {
	var e db.Entity
	err := row.Scan(&e.ID, &e.Address, &e.PublicKeyHex, &e.DID, &e.Role, &e.Label,
		&e.Email, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) EntityByAddress(ctx context.Context, address string) (*db.Entity, error) {
	return scanEntity(s.DB.Pool.QueryRow(ctx,
		`SELECT `+entityCols+` FROM entities WHERE address = $1`, address))
}

func (s *Store) EntityByDID(ctx context.Context, did string) (*db.Entity, error) {
	return scanEntity(s.DB.Pool.QueryRow(ctx,
		`SELECT `+entityCols+` FROM entities WHERE did = $1`, did))
}

func (s *Store) RequireEntity(ctx context.Context, address string) (*db.Entity, error) {
	e, err := s.EntityByAddress(ctx, address)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, httpx.NotFound("Không tìm thấy thực thể")
	}
	return e, nil
}

type RegisterEntityInput struct {
	Address, PublicKeyHex, DID, Role, Label string
	Email                                   *string
}

func (s *Store) RegisterEntity(ctx context.Context, in RegisterEntityInput) (*db.Entity, error) {
	e, err := scanEntity(s.DB.Pool.QueryRow(ctx,
		`INSERT INTO entities (address, public_key_hex, did, role, label, email)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+entityCols,
		in.Address, in.PublicKeyHex, in.DID, in.Role, in.Label, in.Email))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, httpx.Conflict("Địa chỉ ví hoặc DID này đã được đăng ký")
		}
		return nil, err
	}
	return e, nil
}

// UpdateEntityRole đổi vai trò trong chỉ mục sau khi giao dịch đã lên chuỗi.
// Trả về vai trò mới để người gọi không phải đọc lại.
func (s *Store) UpdateEntityRole(ctx context.Context, address, role string) (string, error) {
	var out string
	err := s.DB.Pool.QueryRow(ctx,
		`UPDATE entities SET role = $2, updated_at = now() WHERE address = $1 RETURNING role::text`,
		address, role).Scan(&out)
	if err != nil {
		return "", err
	}
	return out, nil
}

// DemoteOtherRoots hạ mọi hàng role='root' khác xuống 'holder'. Chuỗi chỉ giữ
// đúng một root_admin nên chỉ mục cũng chỉ được có một root. Root cũ về holder
// vì trên chuỗi họ KHÔNG có bản ghi admin nào — trước đây chỉ mục ghi "admin",
// và ở chế độ offline điều đó để root cũ giữ nguyên quyền quản trị.
func (s *Store) DemoteOtherRoots(ctx context.Context, keep string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE entities SET role = 'holder', updated_at = now()
		  WHERE role = 'root' AND address <> $1`, keep)
	return err
}

func (s *Store) ListEntitiesByRole(ctx context.Context, role string, limit, offset int) ([]db.Entity, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+entityCols+` FROM entities WHERE role = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		role, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []db.Entity{}
	for rows.Next() {
		var e db.Entity
		if err := rows.Scan(&e.ID, &e.Address, &e.PublicKeyHex, &e.DID, &e.Role, &e.Label,
			&e.Email, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) CountEntitiesByRole(ctx context.Context) (map[string]int, error) {
	rows, err := s.DB.Pool.Query(ctx, `SELECT role::text, count(*) FROM entities GROUP BY role`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var r string
		var n int
		if err := rows.Scan(&r, &n); err != nil {
			return nil, err
		}
		out[r] = n
	}
	return out, rows.Err()
}

// ---------- Challenge ----------

func (s *Store) CreateChallenge(ctx context.Context, address, nonce string, ttl time.Duration) (time.Time, error) {
	expires := time.Now().Add(ttl)
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO auth_challenges (address, nonce, expires_at) VALUES ($1,$2,$3)`,
		address, nonce, expires)
	return expires, err
}

// ConsumeChallenge lấy challenge còn hiệu lực VÀ đánh dấu đã dùng trong cùng một
// câu lệnh, nên hai yêu cầu song song không thể cùng dùng một nonce.
func (s *Store) ConsumeChallenge(ctx context.Context, nonce string) (address string, err error) {
	err = s.DB.Pool.QueryRow(ctx,
		`UPDATE auth_challenges SET used = TRUE
		  WHERE nonce = $1 AND used = FALSE AND expires_at > now()
		  RETURNING address`, nonce).Scan(&address)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", httpx.Unauthorized("Challenge không tồn tại, đã dùng hoặc đã hết hạn")
	}
	return address, err
}

func (s *Store) PurgeExpiredChallenges(ctx context.Context) (int64, error) {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM auth_challenges WHERE expires_at < now() - interval '1 day'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// AuditTargets trả các đích (không trùng) của một hành động do một người thực
// hiện, đọc từ nhật ký kiểm toán. Dùng để liệt kê sub-issuer mà issuer đã cấp,
// vì chuỗi không có view liệt kê theo cha.
func (s *Store) AuditTargets(ctx context.Context, actor, action string) ([]string, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT DISTINCT target FROM audit_log
		  WHERE actor = $1 AND action = $2 AND target IS NOT NULL`, actor, action)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetDIDStatusByAddress đổi trạng thái DID hiện hành (chưa bị thu hồi) của một
// địa chỉ trong chỉ mục, sau khi giao dịch kiểm duyệt của admin đã xác minh.
func (s *Store) SetDIDStatusByAddress(ctx context.Context, address, status string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE did_documents d SET status = $2, updated_at = now()
		   FROM entities e
		  WHERE e.id = d.entity_id AND e.address = $1 AND d.status <> 'revoked'`, address, status)
	return err
}
