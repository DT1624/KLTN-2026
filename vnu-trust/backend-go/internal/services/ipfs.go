package services

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/sha3"

	"github.com/vnu-trust/backend-go/internal/auth"
	"github.com/vnu-trust/backend-go/internal/config"
	"github.com/vnu-trust/backend-go/internal/httpx"
)

type IPFS struct {
	cfg  *config.Config
	http *http.Client
	// Nguồn thật của kho mock là bảng ipfs_objects trong CSDL dùng chung; xem
	// chú thích ở db/schema.sql. Giữ nội dung ghim trong bộ nhớ tiến trình làm
	// mất nó sau mỗi lần khởi động lại, và làm nội dung ghim qua backend này vô
	// hình với backend kia.
	pool  *pgxpool.Pool
	mu    sync.RWMutex
	mock  map[string]any // tầng đệm trong tiến trình
	cache map[string]cacheEntry
}

type cacheEntry struct {
	at   time.Time
	body any
}

const cacheTTL = 5 * time.Minute

func NewIPFS(cfg *config.Config, pool *pgxpool.Pool) *IPFS {
	return &IPFS{
		cfg:   cfg,
		http:  &http.Client{Timeout: 20 * time.Second},
		pool:  pool,
		mock:  map[string]any{},
		cache: map[string]cacheEntry{},
	}
}

// persistMock ghi nội dung mock vào CSDL dùng chung. Trùng CID thì bỏ qua —
// cùng CID nghĩa là cùng nội dung, đó chính là ý nghĩa của định địa chỉ theo
// nội dung. Lỗi ghi KHÔNG làm hỏng thao tác chính: nội dung vẫn còn trong bộ
// nhớ tiến trình nên lần đọc ngay sau đó vẫn chạy.
func (s *IPFS) persistMock(ctx context.Context, cid string, content any) {
	if s.pool == nil {
		return
	}
	raw, err := json.Marshal(content)
	if err != nil {
		return
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO ipfs_objects (cid, content) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING`,
		cid, raw); err != nil {
		slog.Error("không lưu được nội dung mock vào CSDL", "err", err, "cid", cid)
	}
}

type PinResult struct {
	CID  string `json:"cid"`
	URL  string `json:"url"`
	Size int    `json:"size"`
}

const base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"

// mockCID sinh CID tất định có ĐÚNG hình dạng CIDv1 base32 (b + 58 ký tự),
// nếu không sẽ bị chính bộ kiểm tra CID của backend từ chối.
func mockCID(raw []byte) string {
	h1 := sha3.Sum256(raw)
	// Không dùng append(raw, ...) trực tiếp: nếu raw còn dư sức chứa thì append
	// sẽ ghi đè lên mảng nền của chính raw. Tạo lát mới cho chắc chắn.
	suffixed := make([]byte, 0, len(raw)+2)
	suffixed = append(suffixed, raw...)
	suffixed = append(suffixed, '#', '2')
	h2 := sha3.Sum256(suffixed)

	seed := make([]byte, 0, 64)
	seed = append(seed, h1[:]...)
	seed = append(seed, h2[:]...)
	var sb strings.Builder
	sb.WriteString("bafkrei")
	for i := 0; i < 52; i++ {
		sb.WriteByte(base32Alphabet[int(seed[i])%32])
	}
	return sb.String()
}

func (s *IPFS) PinJSON(ctx context.Context, content any, name string) (*PinResult, error) {
	raw, err := json.Marshal(content)
	if err != nil {
		return nil, httpx.BadRequest("Nội dung không tuần tự hoá được: %v", err)
	}

	if s.cfg.IPFSProvider == "mock" {
		// Dùng bản tuần tự hoá TẤT ĐỊNH chứ không phải json.Marshal, để CID sinh
		// ra trùng với backend TypeScript cho cùng một nội dung.
		cid := mockCID([]byte(auth.CanonicalJSON(content)))
		s.mu.Lock()
		s.mock[cid] = content
		s.mu.Unlock()
		s.persistMock(ctx, cid, content)
		return &PinResult{CID: cid, URL: s.cfg.IPFSGateway + "/" + cid, Size: len(raw)}, nil
	}

	body, _ := json.Marshal(map[string]any{
		"pinataContent":  content,
		"pinataMetadata": map[string]any{"name": name},
		"pinataOptions":  map[string]any{"cidVersion": 1},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.pinata.cloud/pinning/pinJSONToIPFS", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.PinataJWT)

	res, err := s.http.Do(req)
	if err != nil {
		return nil, httpx.Upstream("Không gọi được Pinata: %v", err)
	}
	defer res.Body.Close()

	out, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 400 {
		return nil, httpx.Upstream("Pinata trả %d: %s", res.StatusCode, string(out))
	}
	var pr struct {
		IpfsHash string `json:"IpfsHash"`
		PinSize  int    `json:"PinSize"`
	}
	if err := json.Unmarshal(out, &pr); err != nil {
		return nil, httpx.Upstream("Phản hồi Pinata không đọc được")
	}
	return &PinResult{CID: pr.IpfsHash, URL: s.cfg.IPFSGateway + "/" + pr.IpfsHash, Size: pr.PinSize}, nil
}

func (s *IPFS) FetchJSON(ctx context.Context, cid string) (any, error) {
	s.mu.RLock()
	if e, ok := s.cache[cid]; ok && time.Since(e.at) < cacheTTL {
		s.mu.RUnlock()
		return e.body, nil
	}
	if v, ok := s.mock[cid]; ok && s.cfg.IPFSProvider == "mock" {
		s.mu.RUnlock()
		return v, nil
	}
	s.mu.RUnlock()

	if s.cfg.IPFSProvider == "mock" {
		// Không có trong bộ nhớ tiến trình -> đọc từ CSDL dùng chung. Đây là
		// đường đi thường gặp nhất sau một lần khởi động lại, hoặc khi nội dung
		// được backend kia ghim.
		if s.pool == nil {
			return nil, httpx.BadRequest("Không tìm thấy CID %s trong kho mock", cid)
		}
		var raw []byte
		if err := s.pool.QueryRow(ctx,
			`SELECT content FROM ipfs_objects WHERE cid = $1`, cid).Scan(&raw); err != nil {
			return nil, httpx.BadRequest("Không tìm thấy CID %s trong kho mock", cid)
		}
		var body any
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, httpx.BadRequest("Nội dung CID %s trong kho mock không đọc được", cid)
		}
		s.mu.Lock()
		s.mock[cid] = body
		s.mu.Unlock()
		return body, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.IPFSGateway+"/"+cid, nil)
	if err != nil {
		return nil, err
	}
	res, err := s.http.Do(req)
	if err != nil {
		return nil, httpx.Upstream("Không gọi được gateway IPFS: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return nil, httpx.Upstream("Gateway IPFS trả %d cho CID %s", res.StatusCode, cid)
	}

	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	var body any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, httpx.Upstream("Nội dung CID %s không phải JSON hợp lệ", cid)
	}

	s.mu.Lock()
	s.cache[cid] = cacheEntry{at: time.Now(), body: body}
	s.mu.Unlock()
	return body, nil
}
