# Hợp đồng API — VNU-Trust

Hai backend cài đặt **cùng một hợp đồng** trên **cùng lược đồ CSDL** (`db/schema.sql`):

| | TypeScript | Go |
|---|---|---|
| Thư mục | `backend/` | `backend-go/` |
| Cổng mặc định | 4000 | 4001 |
| Nền tảng | Express + `pg` | `net/http` + `pgx` |

Frontend trỏ vào cái nào cũng chạy được — đổi `VITE_API_BASE` là xong.

## Định dạng phản hồi

Mọi phản hồi đều dùng chung một phong bì:

```json
{ "success": true,  "data": { }, "error": null,       "timestamp": "2026-09-14T…" }
{ "success": false, "data": null, "error": "Mô tả",   "timestamp": "2026-09-14T…" }
```

## Mã trạng thái

| Mã | Khi nào |
|---|---|
| `400` | Dữ liệu vào không hợp lệ, hash không khớp, giao dịch không tồn tại trên chuỗi |
| `401` | Chưa đăng nhập, JWT hỏng/hết hạn, chữ ký sai, challenge đã dùng |
| `403` | Sai vai trò, hoặc không có quyền thật trên chuỗi |
| `404` | Không tìm thấy |
| `409` | Trùng dữ liệu, hoặc chuyển trạng thái không hợp lệ |
| `410` | Liên kết chia sẻ đã hết hạn hoặc bị thu hồi |
| `429` | Vượt giới hạn tần suất |
| `502` | Fullnode hoặc IPFS gateway lỗi |

## Bảng tuyến

### Công khai

| Phương thức | Đường dẫn | Mô tả |
|---|---|---|
| `GET` | `/health` | Kiểm tra sống |
| `GET` | `/api/stats` | Số liệu đọc trực tiếp từ chuỗi |
| `GET` | `/api/lookup?q=` | Tra cứu hợp nhất: DID, địa chỉ ví, CID, mã VC, mã giao dịch |
| `GET` | `/api/did/resolve?did=` | Resolve DID (chuỗi là nguồn sự thật) |
| `GET` | `/api/did/by-address/{address}` | Resolve DID theo địa chỉ chủ sở hữu |
| `POST` | `/api/entities/register` | Ghi danh thực thể mới. Chế độ nghiêm ngặt: vai trò `admin`/`issuer` phải đã có trên chuỗi, nếu không trả 403 |
| `GET` | `/api/entities/by-address/{address}` | Hồ sơ công khai (email luôn `null`) — dùng khi khôi phục ví trên máy khác |
| `POST` | `/api/auth/challenge` | Xin nonce để ký — *giới hạn 20/phút* |
| `POST` | `/api/auth/verify` | Nộp chữ ký, nhận JWT — *giới hạn 20/phút* |
| `GET` | `/api/verify/share/{token}` | Xem nhanh liên kết chia sẻ |
| `POST` | `/api/verify/share/{token}` | Chạy đủ 7 bước xác minh |

### Cần đăng nhập

| Phương thức | Đường dẫn | Vai trò |
|---|---|---|
| `GET` | `/api/auth/me` | mọi vai trò |
| `POST` | `/api/ipfs/pin` | mọi vai trò |
| `POST` | `/api/did/save` | mọi vai trò |
| `GET` | `/api/issuer/stats` · `/api/issuer/credentials` · `/api/issuer/credentials/{vcId}` | issuer — `stats` gồm số theo trạng thái, `byMonth` (12 tháng), `byType` |
| `POST` | `/api/issuer/credentials` | issuer **+ quyền thật trên chuỗi** |
| `POST` | `/api/issuer/credentials/{vcId}/revoke` · `/suspend` | issuer |
| `GET` | `/api/holder/credentials` · `/credentials/{vcId}` · `/presentations` · `/shares` | holder |
| `POST` | `/api/holder/presentations` | holder |
| `DELETE` | `/api/holder/shares/{token}` | holder |
| `POST` | `/api/verify/share/{token}/record` | verifier, admin, root |
| `GET` | `/api/verify/history` | verifier, admin, root |
| `GET` | `/api/admin/overview` · `/analytics` · `/issuers` · `/admins` · `/check/{address}` · `/audit` | admin, root — `analytics` là số liệu biểu đồ: `credentials` (như `issuer/stats`), `topIssuers`, `verifications` |
| `GET` | `/api/admin/credentials/{vcId}` | admin, root |
| `POST` | `/api/admin/credentials/{vcId}/revoke` · `/reinstate` | admin, root **+ quyền thật trên chuỗi** |

### Quản trị quyền hạn trên chuỗi

Cấp và thu hồi vai trò **không phải** là thao tác của backend: chính người quản
trị ký giao dịch từ ví của mình, backend chỉ **xác minh giao dịch đó có thật**
rồi cập nhật chỉ mục. Contract mới là bên quyết định ai được làm gì.

| Phương thức | Đường dẫn | Vai trò | Hàm entry được xác minh |
|---|---|---|---|
| `GET` | `/api/admin/authority/root` | admin, root | — |
| `GET` | `/api/admin/authority/role/{address}` | admin, root | — |
| `POST` | `/api/admin/authority/admins` | admin, root **+ là root trên chuỗi** | `authority::grant_admin` |
| `POST` | `/api/admin/authority/admins/{address}/revoke` | admin, root **+ là root trên chuỗi** | `authority::revoke_admin` |
| `POST` | `/api/admin/authority/issuers` | admin, root **+ quyền thật trên chuỗi** | `authority::approve_issuer` |
| `POST` | `/api/admin/authority/issuers/{address}/status` | admin, root **+ quyền thật trên chuỗi** | `suspend_issuer` / `reactivate_issuer` / `revoke_issuer` |
| `POST` | `/api/admin/authority/root/propose` | admin, root **+ là root trên chuỗi** | `authority::propose_root` |
| `POST` | `/api/admin/authority/root/cancel` | admin, root **+ là root trên chuỗi** | `authority::cancel_root_transfer` |
| `GET` | `/api/authority/root` | **mọi vai trò đã đăng nhập** | — |
| `POST` | `/api/authority/root/accept` | **mọi vai trò đã đăng nhập** | `authority::accept_root` |

Hai tuyến cuối **cố ý không chặn theo vai trò**: người được đề cử làm root, tại
đúng thời điểm ký nhận, vẫn chưa phải root trong CSDL. Chặn theo vai trò ở đó sẽ
khoá đúng bước duy nhất chứng minh được họ giữ khoá riêng. Rào chắn thật vẫn còn
nguyên — `accept_root` chỉ thành công trên chuỗi nếu người ký đúng là địa chỉ
đang được đề cử, và backend từ chối nếu không xác minh được giao dịch.

**Ảnh hưởng tới vai trò trong CSDL** (chỉ mục, không phải nguồn sự thật):

| Thao tác | Vai trò sau đó |
|---|---|
| `grant_admin` | `admin` |
| `revoke_admin` | `holder` — vẫn giữ DID và văn bằng của mình |
| `approve_issuer` | `issuer` |
| `issuer status = suspended` / `active` | **không đổi** — quyền còn đó, chỉ bị khoá |
| `issuer status = revoked` | `holder` |
| `accept_root` | `root`, và mọi hàng `root` khác hạ xuống `admin` |

## Ba bất biến phải giữ giữa các cài đặt

Đây là những chỗ mà chỉ cần một bên lệch là cả hệ thống hỏng, nên đều có test riêng.

**1. Chuỗi được ký khi đăng nhập** — phải giống nhau từng ký tự ở cả ba nơi
(backend TS, backend Go, frontend):

```
VNU-Trust xac thuc dang nhap
dia chi: <địa chỉ ví>
nonce: <nonce>
```

**2. Tuần tự hoá tất định** — khoá đối tượng sắp xếp tăng dần, không khoảng trắng
thừa, số nguyên in không có phần thập phân. Đây là đầu vào của mọi phép băm.
Kiểm bằng `backend-go/internal/auth/canonical_test.go` (7 trường hợp, có tiếng
Việt và cấu trúc lồng sâu).

**3. Hàm băm** — SHA3-256 trên bản tuần tự hoá tất định, trả về `0x` + 64 hex.
Ba cài đặt đã được đối chiếu cho cùng kết quả:
`node:crypto` (TS) ≡ `@noble/hashes` (frontend) ≡ `golang.org/x/crypto/sha3` (Go).

## Xác minh giao dịch on-chain

Mọi tuyến ghi có tham chiếu on-chain đều yêu cầu `txHash`, và backend kiểm bốn
điều trước khi ghi CSDL:

1. Giao dịch **tồn tại** trên fullnode
2. `success == true`
3. `payload.function` **đúng hàm entry** mong đợi
4. `sender` **khớp** tài khoản đang đăng nhập (sau khi chuẩn hoá địa chỉ)

Đặt `VERIFY_ONCHAIN=false` sẽ bỏ qua bước này — **chỉ dùng cho test tự động**,
cả hai backend đều ghi cảnh báo mức WARN khi cờ này tắt.

### `txHash` đến từ đâu

Từ chính giao diện. Trình duyệt giữ khoá riêng nên nó **tự ký và tự gửi** giao
dịch tới fullnode (`frontend/src/lib/chain.ts`), chờ xác nhận, rồi đưa mã giao
dịch nhận được vào thân yêu cầu gửi lên backend. Người dùng không nhập gì cả.

Trước đây mọi biểu mẫu đều có ô "Mã giao dịch" bắt người dùng tự gọi hàm bằng ví
ngoài rồi chép hash dán vào — đẩy phần khó nhất sang cho người dùng, và vì giao
diện không đọc được phản hồi giao dịch nên `onChainVcId` bị ghi cứng bằng 0.

Khi backend chạy `VERIFY_ONCHAIN=false`, giao diện **không** gửi giao dịch lên
chuỗi (gói trên chuỗi có thể là bản cũ hoặc chưa có): ví vẫn ký đúng nội dung
giao dịch đó, và tham chiếu gửi lên backend là băm SHA3-256 của bản đã ký. Giao
diện hiển thị rõ đây là *tham chiếu cục bộ*, không phải mã giao dịch.

## Thông số chuỗi dùng chung

`CONTRACT_ADDRESS` và các thông số chuỗi khác có **một nguồn duy nhất**:
`chain.env` ở gốc dự án. `./scripts/sync-chain-env.sh` đẩy chúng sang
`backend/.env`, `backend-go/.env` và `frontend/.env` (dưới tiền tố `VITE_`).
`./scripts/deploy.sh` publish gói Move rồi tự cập nhật `chain.env` và gọi script
đồng bộ. Sửa địa chỉ ở ba tệp `.env` bằng tay là cách chắc chắn nhất để hai
backend nói chuyện với hai gói khác nhau mà không ai báo lỗi.

## Chạy kiểm thử

```bash
cd backend    && node scripts/e2e.mjs                            # 19 phép kiểm
cd backend    && API_BASE=http://localhost:4001/api node scripts/e2e.mjs   # cùng bộ, chạy lên Go
cd backend-go && go test ./...
cd frontend   && node scripts/wallet-e2e.mjs                     # 17 phép kiểm
node scripts/abi-check.mjs                                       # tên hàm contract ↔ hai backend
```

Bộ E2E ở `backend/scripts/e2e.mjs` nhận biến `API_BASE`, nên dùng **chính nó** để
kiểm cả hai backend — đây là cách bảo đảm hai bên thực sự tương đương.

## Sửa một backend mà không làm lệch backend kia

Ba thứ phải sửa **cùng lúc** ở cả hai bên, và mỗi thứ đều có bài kiểm thử bắt lỗi:

| Sửa gì | Bên TypeScript | Bên Go | Bài kiểm bắt lỗi |
|---|---|---|---|
| Thêm/đổi tuyến | `src/routes/*.ts` + `src/app.ts` | `internal/handlers/*.go` + `router.go` | `scripts/parity.mjs` |
| Tên hàm on-chain | `src/chain/abi.ts` | `internal/chain/registry.go` | `scripts/abi-check.mjs` |
| Tên hành động kiểm toán | `src/services/audit.service.ts` | `internal/services/audit.go` | `full-flow.mjs` mục 8 |

Thứ tự kiểm tra đầu vào cũng là một phần của hợp đồng: cùng một yêu cầu sai phải
cho **cùng một mã lỗi** ở hai bên. Nguyên tắc đã chốt là **rẻ trước, đắt sau** —
kiểm định dạng và dữ liệu trong bộ nhớ trước, truy vấn CSDL sau, gọi fullnode
sau cùng. `parity.mjs` đối chiếu đúng điều này bằng cách gửi dữ liệu sai vào cả
hai rồi so mã trạng thái.
