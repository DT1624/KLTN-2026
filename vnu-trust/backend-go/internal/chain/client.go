// Package chain đọc dữ liệu từ fullnode Movement/Aptos và xác minh giao dịch.
package chain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vnu-trust/backend-go/internal/config"
	"github.com/vnu-trust/backend-go/internal/httpx"
)

type Client struct {
	cfg     *config.Config
	http    *http.Client
	offline *offlineDB
}

func New(cfg *config.Config) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 20 * time.Second}}
}

func (c *Client) Module(name string) string { return c.cfg.ContractAddress + "::" + name }

func (c *Client) rpc(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.ChainFullnode+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, httpx.Upstream("Không gọi được fullnode: %v", err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, httpx.Upstream("Không đọc được phản hồi fullnode: %v", err)
	}
	if res.StatusCode >= 400 {
		return raw, httpx.Upstream("Fullnode trả %d", res.StatusCode)
	}
	return raw, nil
}

type viewReq struct {
	Function      string   `json:"function"`
	TypeArguments []string `json:"type_arguments"`
	Arguments     []any    `json:"arguments"`
}

// View gọi một hàm #[view] của contract.
func (c *Client) View(ctx context.Context, fn string, args ...any) ([]json.RawMessage, error) {
	if args == nil {
		args = []any{}
	}
	raw, err := c.rpc(ctx, http.MethodPost, "/view", viewReq{Function: fn, TypeArguments: []string{}, Arguments: args})
	if err != nil {
		return nil, err
	}
	var out []json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, httpx.Upstream("Phản hồi view không đúng định dạng: %s", truncate(string(raw), 200))
	}
	return out, nil
}

// ViewOrNil nuốt lỗi abort của contract — nhiều view abort khi không tìm thấy,
// trong khi tầng nghiệp vụ chỉ cần biết "không có".
func (c *Client) ViewOrNil(ctx context.Context, fn string, args ...any) []json.RawMessage {
	out, err := c.View(ctx, fn, args...)
	if err != nil {
		slog.Debug("view trả lỗi, coi như không có dữ liệu", "fn", fn, "err", err)
		return nil
	}
	return out
}

type Transaction struct {
	Hash     string `json:"hash"`
	Success  bool   `json:"success"`
	VMStatus string `json:"vm_status"`
	Sender   string `json:"sender"`
	Version  string `json:"version"`
	Payload  struct {
		Function  string `json:"function"`
		Arguments []any  `json:"arguments"`
	} `json:"payload"`
	Events []struct {
		Type string         `json:"type"`
		Data map[string]any `json:"data"`
	} `json:"events"`
}

// Arg là kỳ vọng cho một tham số của hàm entry (bỏ qua signer). Kind rỗng = không kiểm.
// Fullnode trả address dạng rút gọn, u64 dạng chuỗi thập phân, vector<u8> dạng hex.
type Arg struct{ Kind, Val string }

func ArgAddress(a string) Arg { return Arg{"address", a} }
func ArgU64(n int64) Arg      { return Arg{"u64", strconv.FormatInt(n, 10)} }
func ArgBytes(h string) Arg   { return Arg{"bytes", h} }

func argMatches(actual any, want Arg) bool {
	s, ok := actual.(string)
	if !ok {
		return false
	}
	switch want.Kind {
	case "address":
		a, err1 := NormalizeAddress(s)
		b, err2 := NormalizeAddress(want.Val)
		return err1 == nil && err2 == nil && a == b
	case "u64":
		return s == want.Val
	default:
		return strings.EqualFold(s, want.Val)
	}
}

// NormalizeMoveID đưa "địa_chỉ::module::tên" về địa chỉ đầy đủ 64 hex. Fullnode in
// địa chỉ module ở dạng RÚT GỌN — gói tại 0x0ede7f… hiện ra là
// "0xede7f…::did_registry::register_did" — nên so chuỗi trực tiếp với tên dựng từ
// CONTRACT_ADDRESS đầy đủ thì mọi giao dịch thật đều bị từ chối (S-04).
func NormalizeMoveID(id string) string {
	parts := strings.Split(id, "::")
	if len(parts) < 2 {
		return id
	}
	a, err := NormalizeAddress(parts[0])
	if err != nil {
		return id
	}
	parts[0] = a
	return strings.Join(parts, "::")
}

// FindEvent trả dữ liệu của sự kiện đầu tiên có kiểu khớp (sau chuẩn hoá địa chỉ).
func FindEvent(tx *Transaction, typ string) map[string]any {
	if tx == nil {
		return nil
	}
	want := NormalizeMoveID(typ)
	for _, e := range tx.Events {
		if NormalizeMoveID(e.Type) == want {
			return e.Data
		}
	}
	return nil
}

var reTx = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)

func (c *Client) GetTransaction(ctx context.Context, hash string) (*Transaction, error) {
	if !reTx.MatchString(hash) {
		return nil, httpx.BadRequest("txHash không đúng định dạng (cần 0x + 64 ký tự hex)")
	}
	raw, err := c.rpc(ctx, http.MethodGet, "/transactions/by_hash/"+hash, nil)
	if err != nil {
		return nil, nil // fullnode chưa thấy giao dịch
	}
	var tx Transaction
	if err := json.Unmarshal(raw, &tx); err != nil {
		return nil, nil
	}
	return &tx, nil
}

// VerifyTransaction kiểm giao dịch có thật, thành công, đúng hàm và đúng người gửi.
//
// Đây là điểm khác biệt quan trọng so với các backend cũ: trước đây client gửi
// txHash nào thì backend ghi thẳng, nên có thể bịa ra bản ghi không hề tồn tại
// trên chuỗi.
func (c *Client) VerifyTransaction(ctx context.Context, hash, expectedFn, expectedSender string) error {
	_, err := c.VerifyTransactionArgs(ctx, hash, expectedFn, expectedSender, nil)
	return err
}

// VerifyTransactionArgs như VerifyTransaction, thêm: tham số giao dịch phải khớp
// đúng bản ghi đang ghi (S-02). Trả về giao dịch để đọc sự kiện; trả nil khi
// VERIFY_ONCHAIN=false (không có giao dịch nào được đọc).
func (c *Client) VerifyTransactionArgs(ctx context.Context, hash, expectedFn, expectedSender string, args []Arg) (*Transaction, error) {
	if !c.cfg.VerifyOnChain {
		slog.Warn("VERIFY_ONCHAIN=false — BỎ QUA xác minh giao dịch", "hash", hash)
		return nil, nil
	}
	tx, err := c.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, httpx.BadRequest("Không tìm thấy giao dịch này trên chuỗi")
	}
	if !tx.Success {
		return nil, httpx.BadRequest("Giao dịch thất bại trên chuỗi: %s", tx.VMStatus)
	}
	if tx.Payload.Function == "" || NormalizeMoveID(tx.Payload.Function) != NormalizeMoveID(expectedFn) {
		return nil, httpx.BadRequest("Giao dịch gọi hàm %q, cần %q", tx.Payload.Function, expectedFn)
	}
	got, err := NormalizeAddress(tx.Sender)
	if err != nil {
		return nil, err
	}
	want, err := NormalizeAddress(expectedSender)
	if err != nil {
		return nil, err
	}
	if got != want {
		return nil, httpx.BadRequest("Người gửi giao dịch không khớp với tài khoản đang đăng nhập")
	}
	for i, a := range args {
		if a.Kind == "" {
			continue
		}
		var actual any
		if i < len(tx.Payload.Arguments) {
			actual = tx.Payload.Arguments[i]
		}
		if !argMatches(actual, a) {
			return nil, httpx.BadRequest("Tham số thứ %d của giao dịch không khớp dữ liệu đang ghi", i+1)
		}
	}
	return tx, nil
}

// NormalizeAddress đưa địa chỉ về dạng 0x + 64 hex chữ thường.
// Fullnode có thể trả dạng đã rút gọn số 0 đầu (0x1) còn client gửi dạng đầy đủ,
// nên so sánh chuỗi trực tiếp sẽ sai.
func NormalizeAddress(addr string) (string, error) {
	// Hạ chữ thường TRƯỚC rồi mới cắt tiền tố, nếu không "0X1" sẽ lọt qua với
	// tiền tố còn nguyên và hỏng ở bước giải mã hex. Bản TypeScript cũng làm
	// theo thứ tự này, hai backend phải hành xử giống nhau.
	h := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(addr)), "0x")
	if h == "" || len(h) > 64 {
		return "", httpx.BadRequest("Địa chỉ không hợp lệ: %s", addr)
	}
	if _, err := hex.DecodeString(pad(h)); err != nil {
		return "", httpx.BadRequest("Địa chỉ không hợp lệ: %s", addr)
	}
	return "0x" + pad(h), nil
}

func pad(h string) string {
	if len(h)%2 == 1 {
		h = "0" + h
	}
	return strings.Repeat("0", 64-len(h)) + h
}

// UTF8ToHex — fullnode nhận tham số vector<u8> dưới dạng CHUỖI HEX, không phải
// mảng số. Truyền mảng sẽ bị từ chối với "expect string<hex>".
func UTF8ToHex(s string) string { return "0x" + hex.EncodeToString([]byte(s)) }

func HexToUTF8(h string) string {
	b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
	if err != nil {
		return ""
	}
	return string(b)
}

type Health struct {
	ChainID       int    `json:"chain_id"`
	LedgerVersion string `json:"ledger_version"`
}

func (c *Client) Health(ctx context.Context) (*Health, error) {
	raw, err := c.rpc(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return nil, err
	}
	var h Health
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, httpx.Upstream("Không đọc được thông tin fullnode")
	}
	if h.ChainID != c.cfg.ChainID {
		slog.Warn("CHAIN_ID trong cấu hình không khớp fullnode — giao dịch sẽ bị từ chối BAD_CHAIN_ID",
			"expected", c.cfg.ChainID, "actual", h.ChainID)
	}
	return &h, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
