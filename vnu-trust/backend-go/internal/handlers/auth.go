package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/google/uuid"

	"github.com/vnu-trust/backend-go/internal/auth"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/httpx"
	"github.com/vnu-trust/backend-go/internal/middleware"
	"github.com/vnu-trust/backend-go/internal/services"
)

const challengeTTL = 5 * 60 * 1e9 // 5 phút

func (a *API) AuthChallenge(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Address string `json:"address"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	address, err := httpx.Address(body.Address, "address")
	if err != nil {
		return err
	}

	// Chỉ phát challenge cho địa chỉ đã đăng ký, tránh để kẻ lạ dò địa chỉ.
	e, err := a.Store.EntityByAddress(r.Context(), address)
	if err != nil {
		return err
	}
	if e == nil {
		return httpx.Unauthorized("Tài khoản chưa đăng ký trong hệ thống")
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	nonce := uuid.NewString() + "." + hex.EncodeToString(buf)

	expires, err := a.Store.CreateChallenge(r.Context(), address, nonce, challengeTTL)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, map[string]any{
		"nonce":     nonce,
		"message":   auth.ChallengeMessage(address, nonce),
		"expiresAt": expires.UTC(),
	})
	return nil
}

func (a *API) AuthVerify(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Address   string `json:"address"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}
	address, err := httpx.Address(body.Address, "address")
	if err != nil {
		return err
	}
	signature, err := httpx.Signature(body.Signature, "signature")
	if err != nil {
		return err
	}
	if len(body.Nonce) < 8 {
		return httpx.BadRequest("nonce: không hợp lệ")
	}

	// Lấy và đánh dấu đã dùng trong CÙNG một câu lệnh — hai yêu cầu song song
	// không thể cùng dùng một nonce.
	challengeAddr, err := a.Store.ConsumeChallenge(r.Context(), body.Nonce)
	if err != nil {
		return err
	}
	if challengeAddr != address {
		return httpx.Unauthorized("Challenge không thuộc về địa chỉ này")
	}

	e, err := a.Store.EntityByAddress(r.Context(), address)
	if err != nil {
		return err
	}
	if e == nil {
		return httpx.Unauthorized("Tài khoản chưa đăng ký trong hệ thống")
	}

	if !auth.VerifySignature(e.PublicKeyHex, auth.ChallengeMessage(address, body.Nonce), signature) {
		return httpx.Unauthorized("Chữ ký không hợp lệ")
	}

	token, err := auth.Sign(a.Cfg.JWTSecret, a.Cfg.JWTExpiry, e.Address, e.DID, e.Role)
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusOK, map[string]any{
		"token": token,
		"entity": map[string]any{
			"address": e.Address, "did": e.DID, "role": e.Role, "label": e.Label,
		},
	})
	return nil
}

// EntityByAddressPublic — hồ sơ công khai của một địa chỉ (không lộ email),
// dùng khi khôi phục ví bằng cụm từ ghi nhớ trên máy khác.
func (a *API) EntityByAddressPublic(w http.ResponseWriter, r *http.Request) error {
	address, err := httpx.Address(r.PathValue("address"), "address")
	if err != nil {
		return err
	}
	e, err := a.Store.EntityByAddress(r.Context(), address)
	if err != nil {
		return err
	}
	if e == nil {
		return httpx.NotFound("Không tìm thấy thực thể")
	}
	// Không lộ email và tên hiển thị (thường là họ tên thật) ra tuyến công khai —
	// ghép với sự kiện VCIssuedEvent công khai là biết "ai có bằng gì" (P-05).
	httpx.OK(w, http.StatusOK, struct {
		*db.Entity
		Label *string `json:"label"`
		Email *string `json:"email"`
	}{Entity: e})
	return nil
}

func (a *API) AuthMe(w http.ResponseWriter, r *http.Request) error {
	c := middleware.ClaimsFrom(r.Context())
	e, err := a.Store.RequireEntity(r.Context(), c.Address)
	if err != nil {
		return err
	}
	ctx := r.Context()
	hasDID := a.Chain.HasActiveDID(ctx, e.Address)
	isAdmin := a.Chain.IsActiveAdmin(ctx, e.Address)
	isIssuer := a.Chain.IsActiveIssuer(ctx, e.Address)
	canDelegate := a.Chain.CanDelegate(ctx, e.Address)

	consistent := hasDID
	switch e.Role {
	case "issuer":
		consistent = isIssuer
	case "admin":
		consistent = isAdmin
	}

	httpx.OK(w, http.StatusOK, map[string]any{
		"entity": e,
		"onChain": map[string]any{
			"hasActiveDid": hasDID, "isActiveAdmin": isAdmin, "isActiveIssuer": isIssuer,
			// Được phép cấp quyền cho issuer khác (root, admin, hoặc issuer có bit uỷ quyền — F-02).
			"canDelegate": canDelegate,
		},
		"consistent": consistent,
	})
	return nil
}

func (a *API) RegisterEntity(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Address      string  `json:"address"`
		PublicKeyHex string  `json:"publicKeyHex"`
		DID          string  `json:"did"`
		Role         string  `json:"role"`
		Label        string  `json:"label"`
		Email        *string `json:"email"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return err
	}

	address, err := httpx.Address(body.Address, "address")
	if err != nil {
		return err
	}
	pub, err := httpx.PublicKey(body.PublicKeyHex, "publicKeyHex")
	if err != nil {
		return err
	}
	did, err := httpx.DID(body.DID, "did")
	if err != nil {
		return err
	}
	role, err := httpx.Role(body.Role, "role")
	if err != nil {
		return err
	}
	if len(body.Label) < 2 || len(body.Label) > 120 {
		return httpx.BadRequest("label: tên hiển thị phải dài 2..120 ký tự")
	}
	if role == "root" {
		return httpx.BadRequest("Không thể tự đăng ký vai trò root — root do contract quy định lúc publish")
	}

	// Địa chỉ phải là địa chỉ của CHÍNH khoá công khai được khai (S-01). Thiếu
	// bước này thì ai cũng ghi danh được địa chỉ của người khác — kể cả admin hay
	// root trên chuỗi chưa ghi danh — bằng khoá của mình, rồi ký challenge mà đăng nhập.
	if auth.DeriveAddress(pub) != address {
		return httpx.BadRequest("Địa chỉ ví không khớp khoá công khai (địa chỉ = SHA3-256(khoá công khai ‖ 0x00))")
	}

	// DID phải bám theo địa chỉ ví để không thể mạo danh DID của người khác.
	want := a.Cfg.DIDMethod + ":" + role + ":"
	if len(did) <= len(want) || did[:len(want)] != want || did[len(did)-len(address):] != address {
		return httpx.BadRequest("DID phải có dạng %s<địa chỉ ví>", want)
	}

	if e, err := a.Store.EntityByAddress(r.Context(), address); err != nil {
		return err
	} else if e != nil {
		return httpx.Conflict("Địa chỉ ví này đã được đăng ký")
	}
	if e, err := a.Store.EntityByDID(r.Context(), did); err != nil {
		return err
	} else if e != nil {
		return httpx.Conflict("DID này đã được đăng ký")
	}

	// Chế độ nghiêm ngặt: admin/issuer phải được chuỗi công nhận trước, nếu không
	// ai cũng tự khai admin để đọc văn bằng và nhật ký của người khác.
	if !a.Chain.Offline() && (role == "admin" || role == "issuer") {
		ok := a.Chain.IsActiveIssuer(r.Context(), address)
		if role == "admin" {
			ok = a.Chain.IsActiveAdmin(r.Context(), address)
		}
		if !ok {
			return httpx.Forbidden("Địa chỉ này chưa được cấp quyền %s trên chuỗi — hãy đăng ký với vai trò holder, "+
				"vai trò sẽ tự nâng khi được cấp quyền", role)
		}
	}

	e, err := a.Store.RegisterEntity(r.Context(), services.RegisterEntityInput{
		Address: address, PublicKeyHex: pub, DID: did, Role: role, Label: body.Label, Email: body.Email,
	})
	if err != nil {
		return err
	}
	httpx.OK(w, http.StatusCreated, e)
	return nil
}
