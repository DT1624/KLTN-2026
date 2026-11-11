// Package handlers cài đặt các tuyến API, giữ đúng hợp đồng với backend TypeScript.
package handlers

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/config"
	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/services"
)

type API struct {
	Cfg   *config.Config
	Store *services.Store
	Chain *chain.Client
	IPFS  *services.IPFS

	// Đệm cho /stats, dựng lười ở lần gọi đầu để New() giữ nguyên chữ ký.
	statsOnce sync.Once
	stats     *ttlCache[map[string]any]
}

func New(cfg *config.Config, st *services.Store, cc *chain.Client, ip *services.IPFS) *API {
	return &API{Cfg: cfg, Store: st, Chain: cc, IPFS: ip}
}

func queryInt(r *http.Request, key string, def, min, max int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		return def
	}
	return n
}

// Health báo trạng thái máy chủ. verifyOnChain nói rõ có đang kiểm chứng trên
// chuỗi hay không: công khai ra để giao diện cảnh báo được và để bộ kiểm thử
// biết đang ở chế độ nào — chạy không kiểm chứng mà im lặng là chỗ dễ nhầm nhất.
func (a *API) Health(w http.ResponseWriter, _ *http.Request) error {
	httpx.OK(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"backend":       "go",
		"verifyOnChain": a.Cfg.VerifyOnChain,
	})
	return nil
}

// Stats trả số liệu tổng quan cho trang chủ, đệm 5 giây — xem ttlcache.go.
func (a *API) Stats(w http.ResponseWriter, r *http.Request) error {
	a.statsOnce.Do(func() {
		a.stats = newTTLCache(5*time.Second, a.computeStats)
	})
	data, err := a.stats.Get(r.Context())
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, data)
	return nil
}

func (a *API) computeStats(ctx context.Context) (map[string]any, error) {
	admins, issuers := a.Chain.AuthorityStats(ctx)

	// Chế độ VERIFY_ONCHAIN=false không gọi fullnode: không có chuỗi thì không
	// có ledger version, và không nên tốn một vòng mạng cho mỗi lần xem trang chủ.
	chainID := a.Cfg.ChainID
	var ledgerVersion any
	if !a.Chain.Offline() {
		health, err := a.Chain.Health(ctx)
		if err != nil {
			return nil, err
		}
		chainID = health.ChainID
		ledgerVersion = health.LedgerVersion
	}

	// Trả null (không phải chuỗi rỗng) khi chưa đọc được root admin, để khớp
	// đúng backend TypeScript — đây là loại lệch mà bộ parity từng bắt được.
	var rootAdmin any
	if s := a.Chain.GetRootAdmin(ctx); s != "" {
		rootAdmin = s
	}

	return map[string]any{
		"admins":        admins,
		"issuers":       issuers,
		"dids":          a.Chain.TotalDIDs(ctx),
		"credentials":   a.Chain.TotalVCs(ctx),
		"chainId":       chainID,
		"ledgerVersion": ledgerVersion,
		"rootAdmin":     rootAdmin,
		"contract":      a.Cfg.ContractAddress,
	}, nil
}

// PinIPFS ghim JSON lên IPFS. Cần đăng nhập để không bị lạm dụng làm kho lưu trữ.
func (a *API) PinIPFS(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		JSON map[string]any `json:"json"`
		Name string         `json:"name"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	if body.JSON == nil {
		return httpx.BadRequest("json: nội dung cần ghim phải là một đối tượng")
	}
	if len(body.Name) == 0 || len(body.Name) > 120 {
		return httpx.BadRequest("name: tên phải dài 1..120 ký tự")
	}
	res, err := a.IPFS.PinJSON(r.Context(), body.JSON, body.Name)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusCreated, res)
	return nil
}
