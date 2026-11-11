package handlers

import (
	"context"
	"net/http"

	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/middleware"
)

// Routes dựng bộ định tuyến bằng http.ServeMux của thư viện chuẩn (Go 1.22+
// đã hỗ trợ mẫu có phương thức và tham số đường dẫn, nên không cần thư viện ngoài).
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	secret := a.Cfg.JWTSecret

	// Tuyến xác thực bị giới hạn chặt hơn nhiều so với giới hạn chung, để chặn
	// việc dò địa chỉ và thử chữ ký hàng loạt. Phải khớp backend TypeScript:
	// 20 yêu cầu mỗi phút cho mỗi địa chỉ IP.
	authLimiter := middleware.NewRateLimiter(a.Cfg.AuthRateLimit, a.Cfg.AuthRateLimit)
	limited := func(h httpx.Handler) http.Handler { return authLimiter.Wrap(h) }

	roleOf := func(ctx context.Context, address string) (string, error) {
		e, err := a.Store.EntityByAddress(ctx, address)
		if err != nil || e == nil {
			return "", err
		}
		return e.Role, nil
	}
	authed := func(h httpx.Handler) httpx.Handler { return middleware.RequireAuth(secret, h) }
	role := func(h httpx.Handler, roles ...string) httpx.Handler {
		return middleware.RequireAuth(secret, middleware.RequireRole(roleOf, h, roles...))
	}
	onchain := func(h httpx.Handler, kind string, roles ...string) httpx.Handler {
		return middleware.RequireAuth(secret,
			middleware.RequireRole(roleOf, middleware.RequireOnChainRole(a.Chain, kind, h), roles...))
	}

	// --- Công khai ---
	// /health cho hạ tầng, /api/health cho giao diện vì proxy của frontend chỉ
	// chuyển tiếp các đường dẫn dưới /api.
	mux.Handle("GET /health", httpx.Handler(a.Health))
	mux.Handle("GET /api/health", httpx.Handler(a.Health))
	mux.Handle("GET /api/stats", httpx.Handler(a.Stats))
	mux.Handle("GET /api/lookup", httpx.Handler(a.Lookup))
	mux.Handle("GET /api/did/resolve", httpx.Handler(a.ResolveDIDHandler))
	mux.Handle("GET /api/did/by-address/{address}", httpx.Handler(a.ResolveDIDByAddressHandler))
	mux.Handle("POST /api/entities/register", httpx.Handler(a.RegisterEntity))
	mux.Handle("GET /api/entities/by-address/{address}", httpx.Handler(a.EntityByAddressPublic))
	mux.Handle("POST /api/auth/challenge", limited(a.AuthChallenge))
	mux.Handle("POST /api/auth/verify", limited(a.AuthVerify))
	mux.Handle("GET /api/verify/share/{token}", httpx.Handler(a.OpenShare))
	mux.Handle("POST /api/verify/share/{token}", httpx.Handler(a.VerifyShare))

	// --- Cần đăng nhập ---
	mux.Handle("GET /api/auth/me", authed(a.AuthMe))
	mux.Handle("POST /api/ipfs/pin", authed(a.PinIPFS))
	mux.Handle("POST /api/did/save", authed(a.SaveDID))

	// --- Issuer ---
	mux.Handle("GET /api/issuer/stats", role(a.IssuerStats, "issuer"))
	mux.Handle("GET /api/issuer/credentials", role(a.IssuerCredentials, "issuer"))
	mux.Handle("GET /api/issuer/credentials/{vcId}", role(a.IssuerCredential, "issuer"))
	mux.Handle("POST /api/issuer/credentials", onchain(a.IssueCredential, "issuer", "issuer"))
	mux.Handle("POST /api/issuer/credentials/{vcId}/revoke", role(a.ChangeVCStatus("revoked"), "issuer"))
	mux.Handle("POST /api/issuer/credentials/{vcId}/suspend", role(a.ChangeVCStatus("suspended"), "issuer"))

	// --- Holder ---
	mux.Handle("GET /api/holder/credentials", role(a.HolderCredentials, "holder"))
	mux.Handle("GET /api/holder/credentials/{vcId}", role(a.HolderCredential, "holder"))
	mux.Handle("GET /api/holder/presentations", role(a.HolderPresentations, "holder"))
	mux.Handle("POST /api/holder/presentations", role(a.CreatePresentation, "holder"))
	mux.Handle("GET /api/holder/shares", role(a.HolderShares, "holder"))
	mux.Handle("DELETE /api/holder/shares/{token}", role(a.RevokeShare, "holder"))

	// --- Verifier ---
	mux.Handle("POST /api/verify/share/{token}/record",
		role(a.VerifyAndRecord, "verifier", "admin", "root"))
	mux.Handle("GET /api/verify/history", role(a.VerifyHistory, "verifier", "admin", "root"))

	// --- Admin ---
	mux.Handle("GET /api/admin/overview", role(a.AdminOverview, "admin", "root"))
	mux.Handle("GET /api/admin/analytics", role(a.AdminAnalytics, "admin", "root"))
	mux.Handle("GET /api/admin/issuers", role(a.AdminIssuers(), "admin", "root"))
	mux.Handle("GET /api/admin/admins", role(a.AdminAdmins(), "admin", "root"))
	mux.Handle("GET /api/admin/check/{address}", role(a.AdminCheckAddress, "admin", "root"))
	mux.Handle("GET /api/admin/credentials/{vcId}", role(a.AdminCredential, "admin", "root"))
	mux.Handle("POST /api/admin/credentials/{vcId}/revoke",
		onchain(a.ChangeVCStatus("revoked"), "admin", "admin", "root"))
	mux.Handle("POST /api/admin/credentials/{vcId}/reinstate",
		onchain(a.ChangeVCStatus("active"), "admin", "admin", "root"))
	mux.Handle("GET /api/admin/audit", role(a.AdminAudit, "admin", "root"))

	// --- Quản trị quyền hạn trên chuỗi ---
	// Đường dẫn phải khớp từng ký tự với backend TypeScript
	// (backend/src/routes/admin.routes.ts), nếu không bộ chọn backend ở thanh
	// trên sẽ đổi được máy chủ mà màn hình lại gãy.
	mux.Handle("GET /api/admin/authority/root", role(a.AuthorityRoot, "admin", "root"))
	mux.Handle("GET /api/admin/authority/role/{address}", role(a.AuthorityRole, "admin", "root"))
	mux.Handle("POST /api/admin/authority/admins", role(a.AuthorityGrantAdmin, "admin", "root"))
	mux.Handle("POST /api/admin/authority/admins/{address}/revoke",
		role(a.AuthorityRevokeAdmin, "admin", "root"))
	mux.Handle("POST /api/admin/authority/issuers",
		onchain(a.AuthorityApproveIssuer, "admin", "admin", "root"))
	mux.Handle("POST /api/admin/authority/issuers/{address}/status",
		onchain(a.AuthorityIssuerStatus, "admin", "admin", "root"))
	mux.Handle("POST /api/admin/authority/root/propose", role(a.AuthorityProposeRoot, "admin", "root"))
	mux.Handle("POST /api/admin/authority/root/cancel",
		role(a.AuthorityCancelRootTransfer, "admin", "root"))

	// Tuyến nhận quyền root KHÔNG chặn theo vai trò: người được đề cử lúc này
	// vẫn chưa phải root trong CSDL. Xem chú thích ở AuthorityAcceptRoot.
	mux.Handle("GET /api/authority/root", authed(a.AuthorityRoot))
	mux.Handle("POST /api/authority/root/accept", authed(a.AuthorityAcceptRoot))

	// Tuyến không khớp -> 404 theo đúng định dạng phong bì JSON.
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.Fail(w, http.StatusNotFound, "Không có tuyến "+r.Method+" "+r.URL.Path)
	}))

	return mux
}
