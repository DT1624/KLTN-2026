package chain

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Chế độ không phụ thuộc chuỗi (VERIFY_ONCHAIN=false).
//
// Chỉ dùng khi phát triển hoặc chạy kiểm thử tự động, lúc chưa có chuỗi thật
// hoặc chuỗi bị dựng lại. Khi đó các câu hỏi "địa chỉ này có phải issuer đang
// hoạt động không" được trả lời bằng CHỈ MỤC TRONG CSDL thay vì view function.
//
// Cố ý KHÔNG trả true vô điều kiện: luồng phân quyền vẫn phải có ý nghĩa —
// một holder vẫn bị chặn khỏi tuyến issuer — nếu không bài kiểm thử chẳng
// chứng minh được điều gì. Phải khớp từng hành vi với backend TypeScript
// (backend/src/chain/offline.ts), nếu không bộ đối chiếu parity sẽ báo lệch.
type offlineDB struct {
	pool *pgxpool.Pool
	once sync.Once
}

// UseOfflineSource trỏ client sang CSDL khi chạy không có chuỗi. Gọi sau khi
// đã mở kết nối Postgres; không gọi thì client vẫn hỏi fullnode như thường.
func (c *Client) UseOfflineSource(pool *pgxpool.Pool) {
	if c.cfg.VerifyOnChain {
		return
	}
	c.offline = &offlineDB{pool: pool}
}

// Offline cho biết client đang trả lời bằng CSDL thay vì chuỗi.
func (c *Client) Offline() bool { return c.offline != nil }

func (o *offlineDB) warnOnce() {
	o.once.Do(func() {
		slog.Warn("VERIFY_ONCHAIN=false — quyền và trạng thái DID đọc từ CSDL thay vì chuỗi. " +
			"TUYỆT ĐỐI không bật cấu hình này ở môi trường thật.")
	})
}

func (o *offlineDB) role(ctx context.Context, address string) string {
	o.warnOnce()
	addr, err := NormalizeAddress(address)
	if err != nil {
		return ""
	}
	var role string
	if o.pool.QueryRow(ctx, `SELECT role FROM entities WHERE address = $1`, addr).
		Scan(&role) != nil {
		return ""
	}
	return role
}

// rootFromDB trả hàng duy nhất có role='root' (accept_root giữ bất biến đó).
func (o *offlineDB) rootFromDB(ctx context.Context) string {
	o.warnOnce()
	var addr string
	_ = o.pool.QueryRow(ctx,
		`SELECT address FROM entities WHERE role = 'root' ORDER BY updated_at DESC LIMIT 1`).Scan(&addr)
	return addr
}

func (o *offlineDB) isAdmin(ctx context.Context, a string) bool {
	r := o.role(ctx, a)
	return r == "admin" || r == "root"
}

func (o *offlineDB) isIssuer(ctx context.Context, a string) bool {
	return o.role(ctx, a) == "issuer"
}

func (o *offlineDB) hasActiveDID(ctx context.Context, address string) bool {
	o.warnOnce()
	addr, err := NormalizeAddress(address)
	if err != nil {
		return false
	}
	var n int
	err = o.pool.QueryRow(ctx, `SELECT 1 FROM did_documents d
		  JOIN entities e ON e.id = d.entity_id
		 WHERE e.address = $1 AND d.status = 'active'`, addr).Scan(&n)
	return err == nil
}

const offlineDIDCols = `did, document_cid, document_hash, status, version`

func (o *offlineDB) scanDID(ctx context.Context, sql string, arg any) *OnChainDID {
	o.warnOnce()
	var d OnChainDID
	if o.pool.QueryRow(ctx, sql, arg).
		Scan(&d.DID, &d.DocumentCID, &d.DocumentHash, &d.Status, &d.Version) != nil {
		return nil
	}
	return &d
}

func (o *offlineDB) resolveDID(ctx context.Context, did string) *OnChainDID {
	return o.scanDID(ctx, `SELECT `+offlineDIDCols+` FROM did_documents WHERE did = $1`, did)
}

func (o *offlineDB) resolveDIDByOwner(ctx context.Context, address string) *OnChainDID {
	addr, err := NormalizeAddress(address)
	if err != nil {
		return nil
	}
	return o.scanDID(ctx, `SELECT d.did, d.document_cid, d.document_hash, d.status, d.version
		  FROM did_documents d JOIN entities e ON e.id = d.entity_id
		 WHERE e.address = $1`, addr)
}

func (o *offlineDB) vcStatus(ctx context.Context, id int64) string {
	o.warnOnce()
	var s string
	if o.pool.QueryRow(ctx, `SELECT status FROM credentials WHERE on_chain_vc_id = $1`, id).
		Scan(&s) != nil {
		return ""
	}
	return s
}

func (o *offlineDB) vcRecords(ctx context.Context, ids []int64) map[int64]VCLite {
	o.warnOnce()
	out := map[int64]VCLite{}
	rows, err := o.pool.Query(ctx,
		`SELECT on_chain_vc_id, status, content_hash FROM credentials WHERE on_chain_vc_id = ANY($1)`, ids)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var st, h string
		if rows.Scan(&id, &st, &h) == nil {
			out[id] = VCLite{Status: st, ContentHash: strings.ToLower(h)}
		}
	}
	return out
}

func (o *offlineDB) replacement(ctx context.Context, id int64) (int64, bool) {
	o.warnOnce()
	var n *int64
	if o.pool.QueryRow(ctx,
		`SELECT n.on_chain_vc_id FROM credentials o
		   JOIN credentials n ON n.vc_id = o.replaced_by_vc_id
		  WHERE o.on_chain_vc_id = $1`, id).Scan(&n) != nil || n == nil {
		return 0, false
	}
	return *n, true
}

func (o *offlineDB) vcIntegrity(ctx context.Context, id int64, hash string) bool {
	o.warnOnce()
	var stored string
	if o.pool.QueryRow(ctx, `SELECT content_hash FROM credentials WHERE on_chain_vc_id = $1`, id).
		Scan(&stored) != nil {
		return false
	}
	norm := func(h string) string {
		h = strings.ToLower(strings.TrimSpace(h))
		if !strings.HasPrefix(h, "0x") {
			h = "0x" + h
		}
		return h
	}
	return norm(stored) == norm(hash)
}

type offlineCounts struct{ admins, issuers, dids, vcs int }

func (o *offlineDB) counts(ctx context.Context) offlineCounts {
	o.warnOnce()
	var c offlineCounts
	_ = o.pool.QueryRow(ctx, `SELECT
		  (SELECT count(*) FROM entities WHERE role IN ('admin','root')),
		  (SELECT count(*) FROM entities WHERE role = 'issuer'),
		  (SELECT count(*) FROM did_documents),
		  (SELECT count(*) FROM credentials)`).
		Scan(&c.admins, &c.issuers, &c.dids, &c.vcs)
	return c
}

// roleInfo — bản đối ứng ngoài chuỗi của authority::get_info. Không bịa ra
// vc_type_mask hay hạn uỷ quyền: những thứ đó chỉ tồn tại trên chuỗi, và trả
// về số liệu tưởng tượng còn tệ hơn trả về rỗng. Phải khớp hành vi của
// backend/src/chain/offline.ts, nếu không bộ đối chiếu parity sẽ báo lệch.
func (o *offlineDB) roleInfo(ctx context.Context, address string) *OnChainRole {
	r := o.role(ctx, address)
	if r != "admin" && r != "root" && r != "issuer" {
		return nil
	}
	return &OnChainRole{Status: "active"}
}

func (o *offlineDB) liveCounts(ctx context.Context, issuer, holder string) (issued, held int) {
	o.warnOnce()
	ia, err1 := NormalizeAddress(issuer)
	ha, err2 := NormalizeAddress(holder)
	if err1 != nil || err2 != nil {
		return 0, 0
	}
	// Khớp bộ đếm "sống" của contract: chỉ VC đang ACTIVE (tạm ngưng không tính).
	_ = o.pool.QueryRow(ctx, `SELECT
		  (SELECT count(*) FROM credentials WHERE issuer_address = $1 AND status = 'active'),
		  (SELECT count(*) FROM credentials WHERE holder_address = $2 AND status = 'active')`,
		ia, ha).Scan(&issued, &held)
	return
}
