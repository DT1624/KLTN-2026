package handlers

import (
	"math"
	"net/http"

	"github.com/vnu-trust/backend-go/internal/httpx"
)

func (a *API) AdminOverview(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	admins, issuers := a.Chain.AuthorityStats(ctx)
	inApp, err := a.Store.CountEntitiesByRole(ctx)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, map[string]any{
		"onChain": map[string]any{
			"admins": admins, "issuers": issuers, "rootAdmin": a.Chain.GetRootAdmin(ctx),
		},
		"inApp":       inApp,
		"issuerDrift": issuers - inApp["issuer"],
	})
	return nil
}

// AdminAnalytics trả số liệu cho biểu đồ của màn hình quản trị.
func (a *API) AdminAnalytics(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	creds, err := a.Store.CredentialBreakdown(ctx, "")
	if err != nil {
		return err
	}
	top, err := a.Store.TopIssuers(ctx)
	if err != nil {
		return err
	}
	total, valid, err := a.Store.VerificationCounts(ctx)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, map[string]any{
		"credentials":   withTypeLabels(creds),
		"topIssuers":    top,
		"verifications": map[string]int{"total": total, "valid": valid},
	})
	return nil
}

func (a *API) listRoleWithChain(role string) httpx.Handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		limit, err := queryInt(r, "limit", 20, 1, 100)
		if err != nil {
			return err
		}
		offset, err := queryInt(r, "offset", 0, 0, math.MaxInt32)
		if err != nil {
			return err
		}
		rows, err := a.Store.ListEntitiesByRole(r.Context(), role, limit, offset)
		if err != nil {
			return err
		}
		out := make([]map[string]any, 0, len(rows))
		for _, e := range rows {
			active := a.Chain.IsActiveIssuer(r.Context(), e.Address)
			if role == "admin" {
				active = a.Chain.IsActiveAdmin(r.Context(), e.Address)
			}
			out = append(out, map[string]any{
				"address": e.Address, "did": e.DID, "label": e.Label,
				"createdAt": e.CreatedAt, "activeOnChain": active,
			})
		}
		httpx.OK(w, http.StatusOK, out)
		return nil
	}
}

func (a *API) AdminIssuers() httpx.Handler { return a.listRoleWithChain("issuer") }
func (a *API) AdminAdmins() httpx.Handler  { return a.listRoleWithChain("admin") }

func (a *API) AdminCheckAddress(w http.ResponseWriter, r *http.Request) error {
	address, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, map[string]any{
		"address":        address,
		"isActiveAdmin":  a.Chain.IsActiveAdmin(r.Context(), address),
		"isActiveIssuer": a.Chain.IsActiveIssuer(r.Context(), address),
	})
	return nil
}

// AdminAudit trả nhật ký kiểm toán, mới nhất trước. Tuyến này trước đây chỉ có
// ở backend TypeScript — thiếu ở Go là một lệch thật mà bộ parity chưa chạm tới
// vì nó đối chiếu bằng tài khoản holder.
func (a *API) AdminAudit(w http.ResponseWriter, r *http.Request) error {
	limit, err := queryInt(r, "limit", 20, 1, 100)
	if err != nil {
		return err
	}
	offset, err := queryInt(r, "offset", 0, 0, math.MaxInt32)
	if err != nil {
		return err
	}
	rows, err := a.Store.AuditList(r.Context(), limit, offset)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, rows)
	return nil
}
