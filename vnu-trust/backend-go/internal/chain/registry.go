package chain

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Tên hàm entry và view — đối chiếu đúng ABI đã deploy. Gom về một chỗ vì đây
// chính là nơi đã sinh lỗi ở backend cũ: gọi vc_registry::issuer_vc trong khi
// contract tên là issue_vc.
func (c *Client) EntryRegisterDID() string { return c.Module("did_registry") + "::register_did" }
func (c *Client) EntryIssueVC() string     { return c.Module("vc_registry") + "::issue_vc" }
func (c *Client) EntryRevokeVC() string    { return c.Module("vc_registry") + "::revoke_vc" }
func (c *Client) EntrySuspendVC() string   { return c.Module("vc_registry") + "::suspend_vc" }
func (c *Client) EntryAdminRevokeVC() string {
	return c.Module("vc_registry") + "::admin_revoke_vc"
}
func (c *Client) EntryAdminReinstateVC() string {
	return c.Module("vc_registry") + "::admin_reinstate_vc"
}
func (c *Client) EntryAdminSuspendVC() string {
	return c.Module("vc_registry") + "::admin_suspend_vc"
}

// Admin kiểm duyệt DID — nằm ở module authority vì cần kiểm quyền admin.
func (c *Client) EntryAdminSuspendDID() string { return c.Module("authority") + "::admin_suspend_did" }
func (c *Client) EntryAdminReactivateDID() string {
	return c.Module("authority") + "::admin_reactivate_did"
}
func (c *Client) EntryAdminRevokeDID() string { return c.Module("authority") + "::admin_revoke_did" }

// Quản trị quyền hạn. Tên phải khớp từng chữ với backend TypeScript
// (backend/src/chain/abi.ts), nếu không cùng một giao dịch sẽ được một bên
// chấp nhận và bên kia từ chối.
func (c *Client) EntryGrantAdmin() string    { return c.Module("authority") + "::grant_admin" }
func (c *Client) EntryRevokeAdmin() string   { return c.Module("authority") + "::revoke_admin" }
func (c *Client) EntryApproveIssuer() string { return c.Module("authority") + "::approve_issuer" }
func (c *Client) EntrySuspendIssuer() string { return c.Module("authority") + "::suspend_issuer" }
func (c *Client) EntryReactivateIssuer() string {
	return c.Module("authority") + "::reactivate_issuer"
}
func (c *Client) EntryRevokeIssuer() string { return c.Module("authority") + "::revoke_issuer" }

// Chuyển quyền root là HAI BƯỚC: root đề cử, người nhận tự ký chấp nhận. Hàm
// transfer_root một bước đã bị bỏ — chuyển nhầm sang địa chỉ không ai giữ khoá
// là khoá chết toàn bộ cây quyền lực (F-00).
func (c *Client) EntryProposeRoot() string { return c.Module("authority") + "::propose_root" }
func (c *Client) EntryAcceptRoot() string  { return c.Module("authority") + "::accept_root" }

// C2 (nâng cấp 13/11): xử lý theo lô — admin mọi VC, issuer cha VC của sub-issuer.
func (c *Client) EntryAdminSuspendVCs() string {
	return c.Module("vc_registry") + "::admin_suspend_vcs"
}
func (c *Client) EntryAdminRevokeVCs() string { return c.Module("vc_registry") + "::admin_revoke_vcs" }
func (c *Client) EntryDelegatorSuspendVCs() string {
	return c.Module("vc_registry") + "::delegator_suspend_vcs"
}
func (c *Client) EntryDelegatorRevokeVCs() string {
	return c.Module("vc_registry") + "::delegator_revoke_vcs"
}

// C3: cấp lại có liên kết cũ → mới.
func (c *Client) EntryReissueVC() string { return c.Module("vc_registry") + "::reissue_vc" }
func (c *Client) EntryAdminLinkReplacement() string {
	return c.Module("vc_registry") + "::admin_link_replacement"
}

// P4.1: chủ DID tự khoá / tự mở.
func (c *Client) EntrySuspendOwnDID() string { return c.Module("did_registry") + "::suspend_own_did" }
func (c *Client) EntryReactivateOwnDID() string {
	return c.Module("did_registry") + "::reactivate_own_did"
}

func (c *Client) EntryCancelRootTransfer() string {
	return c.Module("authority") + "::cancel_root_transfer"
}

// NoPendingRoot là địa chỉ rỗng contract dùng cho "không có đề cử nào".
const NoPendingRoot = "0x0000000000000000000000000000000000000000000000000000000000000000"

var roleStatus = map[int]string{1: "active", 2: "revoked", 3: "suspended"}

type OnChainDID struct {
	DID          string `json:"did"`
	DocumentCID  string `json:"documentCid"`
	DocumentHash string `json:"documentHash"`
	Status       string `json:"status"`
	Version      int    `json:"version"`
}

var didStatus = map[int]string{1: "active", 2: "suspended", 3: "revoked"}
var vcStatus = map[int]string{1: "active", 2: "suspended", 3: "expired", 4: "revoked"}

// resolve_did trả về (did_string, document_cid, document_hash, status, version)
func parseDID(raw []json.RawMessage) *OnChainDID {
	if len(raw) < 5 {
		return nil
	}
	var didHex, cidHex, hashHex string
	var status int
	var version string
	if json.Unmarshal(raw[0], &didHex) != nil ||
		json.Unmarshal(raw[1], &cidHex) != nil ||
		json.Unmarshal(raw[2], &hashHex) != nil ||
		json.Unmarshal(raw[3], &status) != nil ||
		json.Unmarshal(raw[4], &version) != nil {
		return nil
	}
	st, ok := didStatus[status]
	if !ok {
		st = "revoked"
	}
	v, _ := strconv.Atoi(version)
	return &OnChainDID{DID: HexToUTF8(didHex), DocumentCID: HexToUTF8(cidHex),
		DocumentHash: hashHex, Status: st, Version: v}
}

func (c *Client) ResolveDID(ctx context.Context, did string) *OnChainDID {
	if c.offline != nil {
		return c.offline.resolveDID(ctx, did)
	}
	return parseDID(c.ViewOrNil(ctx, c.Module("did_registry")+"::resolve_did", UTF8ToHex(did)))
}

func (c *Client) ResolveDIDByOwner(ctx context.Context, address string) *OnChainDID {
	if c.offline != nil {
		return c.offline.resolveDIDByOwner(ctx, address)
	}
	addr, err := NormalizeAddress(address)
	if err != nil {
		return nil
	}
	return parseDID(c.ViewOrNil(ctx, c.Module("did_registry")+"::resolve_did_by_owner", addr))
}

func (c *Client) boolView(ctx context.Context, fn, address string) bool {
	addr, err := NormalizeAddress(address)
	if err != nil {
		return false
	}
	raw := c.ViewOrNil(ctx, fn, addr)
	if len(raw) == 0 {
		return false
	}
	var b bool
	return json.Unmarshal(raw[0], &b) == nil && b
}

func (c *Client) HasActiveDID(ctx context.Context, a string) bool {
	if c.offline != nil {
		return c.offline.hasActiveDID(ctx, a)
	}
	return c.boolView(ctx, c.Module("did_registry")+"::has_active_did", a)
}
func (c *Client) IsActiveAdmin(ctx context.Context, a string) bool {
	if c.offline != nil {
		return c.offline.isAdmin(ctx, a)
	}
	return c.boolView(ctx, c.Module("authority")+"::is_active_admin", a)
}
func (c *Client) IsActiveIssuer(ctx context.Context, a string) bool {
	if c.offline != nil {
		return c.offline.isIssuer(ctx, a)
	}
	return c.boolView(ctx, c.Module("authority")+"::is_active_issuer", a)
}

func (c *Client) GetRootAdmin(ctx context.Context) string {
	if c.offline != nil {
		return c.offline.rootFromDB(ctx)
	}
	raw := c.ViewOrNil(ctx, c.Module("authority")+"::get_root_admin")
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw[0], &s) != nil {
		return ""
	}
	return s
}

func (c *Client) VCStatus(ctx context.Context, onChainVCID int64) string {
	if c.offline != nil {
		return c.offline.vcStatus(ctx, onChainVCID)
	}
	raw := c.ViewOrNil(ctx, c.Module("vc_registry")+"::get_vc_status", strconv.FormatInt(onChainVCID, 10))
	if len(raw) == 0 {
		return ""
	}
	var n int
	if json.Unmarshal(raw[0], &n) != nil {
		return ""
	}
	return vcStatus[n]
}

// VCLite là trạng thái hiệu lực + content_hash của một VC; ContentHash rỗng khi chỉ
// đọc được trạng thái (đường dự phòng từng VC).
type VCLite struct{ Status, ContentHash string }

// VCRecords đọc trạng thái hiệu lực + content_hash của NHIỀU VC trong MỘT lần gọi view
// (P5, 13/11): get_vcs_paginated(min, span) khi các id nằm trong khoảng ≤ 200 — thay cho
// cả get_vc_status lẫn verify_integrity. Khoảng rộng hơn / view lỗi thì quay về gọi từng
// VC (song song, trần 8). Khớp backend TypeScript (registry.ts vcRecordsOnChain).
func (c *Client) VCRecords(ctx context.Context, ids []int64) map[int64]VCLite {
	out := map[int64]VCLite{}
	seen := map[int64]bool{}
	uniq := []int64{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}
	if len(uniq) == 0 {
		return out
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i] < uniq[j] })
	if c.offline != nil {
		return c.offline.vcRecords(ctx, uniq)
	}
	if span := uniq[len(uniq)-1] - uniq[0] + 1; span <= 200 {
		raw := c.ViewOrNil(ctx, c.Module("vc_registry")+"::get_vcs_paginated",
			strconv.FormatInt(uniq[0], 10), strconv.FormatInt(span, 10))
		var recs []struct {
			ID          string `json:"id"`
			Status      int    `json:"status"`
			ContentHash string `json:"content_hash"`
		}
		if len(raw) > 0 && json.Unmarshal(raw[0], &recs) == nil {
			for _, rec := range recs {
				id, err := strconv.ParseInt(rec.ID, 10, 64)
				if st := vcStatus[rec.Status]; err == nil && seen[id] && st != "" {
					out[id] = VCLite{Status: st, ContentHash: strings.ToLower(rec.ContentHash)}
				}
			}
			return out
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, id := range uniq {
		wg.Add(1)
		sem <- struct{}{}
		go func(id int64) {
			defer wg.Done()
			defer func() { <-sem }()
			if st := c.VCStatus(ctx, id); st != "" {
				mu.Lock()
				out[id] = VCLite{Status: st}
				mu.Unlock()
			}
		}(id)
	}
	wg.Wait()
	return out
}

// VCReplacement trả số hiệu on-chain của VC thay thế cho onChainVCID (C3) và
// true, hoặc (0, false) nếu chưa bị thay. Offline đọc chỉ mục CSDL.
func (c *Client) VCReplacement(ctx context.Context, onChainVCID int64) (int64, bool) {
	if c.offline != nil {
		return c.offline.replacement(ctx, onChainVCID)
	}
	raw := c.ViewOrNil(ctx, c.Module("vc_registry")+"::get_replacement", strconv.FormatInt(onChainVCID, 10))
	if len(raw) < 2 {
		return 0, false
	}
	var has bool
	var id string
	if json.Unmarshal(raw[0], &has) != nil || !has || json.Unmarshal(raw[1], &id) != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(id, 10, 64)
	return n, err == nil
}

func (c *Client) countView(ctx context.Context, fn string) int {
	raw := c.ViewOrNil(ctx, fn)
	if len(raw) == 0 {
		return 0
	}
	var s string
	if json.Unmarshal(raw[0], &s) != nil {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func (c *Client) TotalDIDs(ctx context.Context) int {
	if c.offline != nil {
		return c.offline.counts(ctx).dids
	}
	return c.countView(ctx, c.Module("did_registry")+"::total_dids")
}
func (c *Client) TotalVCs(ctx context.Context) int {
	if c.offline != nil {
		return c.offline.counts(ctx).vcs
	}
	return c.countView(ctx, c.Module("vc_registry")+"::total_vcs")
}

func (c *Client) AuthorityStats(ctx context.Context) (admins, issuers int) {
	if c.offline != nil {
		n := c.offline.counts(ctx)
		return n.admins, n.issuers
	}
	raw := c.ViewOrNil(ctx, c.Module("authority")+"::stats")
	if len(raw) < 2 {
		return 0, 0
	}
	var a, i string
	_ = json.Unmarshal(raw[0], &a)
	_ = json.Unmarshal(raw[1], &i)
	admins, _ = strconv.Atoi(a)
	issuers, _ = strconv.Atoi(i)
	return
}

// CanDelegate — địa chỉ này có được phép cấp quyền cho issuer khác không (F-02)?
func (c *Client) CanDelegate(ctx context.Context, a string) bool {
	if c.offline != nil {
		return c.offline.isAdmin(ctx, a)
	}
	return c.boolView(ctx, c.Module("authority")+"::can_delegate", a)
}

// GetDelegator trả issuer cha đã cấp issuer này qua uỷ quyền, hoặc "" nếu do
// root/admin cấp. Chế độ offline không biết quan hệ uỷ quyền (chỉ có trên chuỗi)
// nên trả "" — không ai được coi là cha, thay vì đoán bừa.
func (c *Client) GetDelegator(ctx context.Context, issuer string) string {
	if c.offline != nil {
		return ""
	}
	addr, err := NormalizeAddress(issuer)
	if err != nil {
		return ""
	}
	raw := c.ViewOrNil(ctx, c.Module("authority")+"::get_delegator", addr)
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw[0], &s) != nil {
		return ""
	}
	parent, err := NormalizeAddress(s)
	if err != nil || parent == NoPendingRoot {
		return ""
	}
	return parent
}

// PendingRoot trả địa chỉ đang được đề cử làm root nhưng chưa ký nhận.
// Chuỗi rỗng nghĩa là không có đề cử nào.
func (c *Client) PendingRoot(ctx context.Context) string {
	if c.offline != nil {
		return ""
	}
	raw := c.ViewOrNil(ctx, c.Module("authority")+"::get_pending_root")
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw[0], &s) != nil {
		return ""
	}
	addr, err := NormalizeAddress(s)
	if err != nil || addr == NoPendingRoot {
		return ""
	}
	return addr
}

// OnChainRole là bản ghi vai trò trả về từ authority::get_info.
type OnChainRole struct {
	ApprovedBy       string `json:"approvedBy"`
	VCTypeMask       int    `json:"vcTypeMask"`
	DelegationVCCID  string `json:"delegationVcCid"`
	DelegationVCHash string `json:"delegationVcHash"`
	ExpiresAt        int64  `json:"expiresAt"`
	Status           string `json:"status"`
}

// RoleInfo đọc bản ghi vai trò on-chain. get_info abort khi địa chỉ chưa từng
// được cấp vai trò nào — ở đây coi đó là "không có vai trò" thay vì lỗi.
func (c *Client) RoleInfo(ctx context.Context, address string) *OnChainRole {
	if c.offline != nil {
		return c.offline.roleInfo(ctx, address)
	}
	addr, err := NormalizeAddress(address)
	if err != nil {
		return nil
	}
	raw := c.ViewOrNil(ctx, c.Module("authority")+"::get_info", addr)
	if len(raw) < 6 {
		return nil
	}
	var approvedBy, mask, cidHex, hashHex, expires string
	var status int
	if json.Unmarshal(raw[0], &approvedBy) != nil ||
		json.Unmarshal(raw[1], &mask) != nil ||
		json.Unmarshal(raw[2], &cidHex) != nil ||
		json.Unmarshal(raw[3], &hashHex) != nil ||
		json.Unmarshal(raw[4], &expires) != nil ||
		json.Unmarshal(raw[5], &status) != nil {
		return nil
	}
	m, _ := strconv.Atoi(mask)
	e, _ := strconv.ParseInt(expires, 10, 64)
	st, ok := roleStatus[status]
	if !ok {
		st = "unknown"
	}
	return &OnChainRole{
		ApprovedBy:       approvedBy,
		VCTypeMask:       m,
		DelegationVCCID:  HexToUTF8(cidHex),
		DelegationVCHash: hashHex,
		ExpiresAt:        e,
		Status:           st,
	}
}

// LiveCounts trả số VC đang còn hiệu lực (đã trừ phần bị thu hồi) — F-11e.
func (c *Client) LiveCounts(ctx context.Context, issuer, holder string) (issued, held int) {
	if c.offline != nil {
		return c.offline.liveCounts(ctx, issuer, holder)
	}
	ia, err1 := NormalizeAddress(issuer)
	ha, err2 := NormalizeAddress(holder)
	if err1 != nil || err2 != nil {
		return 0, 0
	}
	raw := c.ViewOrNil(ctx, c.Module("vc_registry")+"::get_live_counts", ia, ha)
	if len(raw) < 2 {
		return 0, 0
	}
	var a, b string
	_ = json.Unmarshal(raw[0], &a)
	_ = json.Unmarshal(raw[1], &b)
	issued, _ = strconv.Atoi(a)
	held, _ = strconv.Atoi(b)
	return
}

// VerifyIntegrity hỏi chuỗi xem `claimedHash` có đúng là content_hash đã neo
// cho VC này không. Dùng để phát hiện nội dung văn bằng bị sửa sau khi cấp:
// trạng thái vẫn "active" nhưng hash thì không còn khớp.
func (c *Client) VerifyIntegrity(ctx context.Context, onChainVCID int64, claimedHash string) bool {
	if c.offline != nil {
		return c.offline.vcIntegrity(ctx, onChainVCID, claimedHash)
	}
	h := claimedHash
	if !strings.HasPrefix(h, "0x") {
		h = "0x" + h
	}
	raw := c.ViewOrNil(ctx, c.Module("vc_registry")+"::verify_integrity",
		strconv.FormatInt(onChainVCID, 10), h)
	if len(raw) == 0 {
		return false
	}
	var b bool
	return json.Unmarshal(raw[0], &b) == nil && b
}
