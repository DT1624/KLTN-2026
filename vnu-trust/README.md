# VNU-Trust

Hệ thống **danh tính tự chủ (SSI)** và **văn bằng khả kiểm** của ĐHQGHN, chạy trên
Movement Network theo chuẩn W3C DID / Verifiable Credentials.

```
vnu-trust/
├── contracts/     Move — 3 module: did_registry, authority, vc_registry
├── backend/       TypeScript (Express + Postgres)   — cổng 4000
├── backend-go/    Go (net/http + Postgres)          — cổng 4001
├── frontend/      React + Vite + Tailwind           — cổng 5173
├── db/schema.sql  Lược đồ CSDL DÙNG CHUNG cho cả hai backend
├── chain.env      Nguồn duy nhất của địa chỉ hợp đồng và thông số chuỗi
├── scripts/       dev.sh · test.sh · bench.sh · clean.sh · deploy.sh · sync-chain-env.sh
├── docs/          API, rà soát hợp đồng
├── deploy/        Triển khai lên host free (Render, Vercel, Neon) — xem deploy/README.md
└── Makefile       `make` để xem mọi lệnh
```

Hai backend cài đặt **cùng một hợp đồng API** trên **cùng một lược đồ CSDL**, nên
frontend trỏ vào cái nào cũng chạy được. Xem [docs/API.md](docs/API.md).

## Chạy nhanh

```bash
make install      # lần đầu: cài phụ thuộc
make up           # Postgres + backend TS + backend Go + giao diện → http://localhost:5173
make status       # cái gì đang chạy
make down         # tắt (giữ dữ liệu)
make test         # toàn bộ kiểm thử trên CSDL + cổng riêng, xong tự dọn
make clean        # tắt hết, xoá log/tệp tạm/build (giữ dữ liệu, image Docker, node_modules)
```

Lần đầu cần `backend/.env` và `backend-go/.env` (chép từ `.env.example`, điền
`JWT_SECRET` ≥ 32 ký tự — **giống nhau ở hai bên** để token dùng chéo được).

## Chọn backend nào?

Không bắt buộc chạy cả hai. Giao diện có bộ chọn **TS / Go** ở thanh trên, đổi ngay
lúc chạy (proxy `/api-ts` → 4000, `/api-go` → 4001); bên nào không chạy sẽ báo đỏ.

| Tình huống | Dùng |
|---|---|
| Phát triển hằng ngày, sửa nghiệp vụ | **TS** (`make up-ts`) — tự nạp lại khi sửa mã, cùng ngôn ngữ với giao diện |
| Triển khai thật / chịu tải | **Go** (`make up-go`) — một tệp nhị phân, ít phụ thuộc; đo được `/auth/me` nhanh hơn bản TS 2,4–3,2× |
| Đối chiếu, kiểm thử tương đương | **cả hai** (`make up`) — `make test` chạy bộ parity giữa hai bên |

Triển khai một backend duy nhất: đặt `VITE_API_BASE=/api` trong `frontend/.env` để
ghim cứng và ẩn bộ chọn.

---

## Nguyên tắc thiết kế

**1. Blockchain là nguồn sự thật, CSDL chỉ là chỉ mục.**
Mọi bản ghi tham chiếu on-chain đều phải kèm `tx_hash`, và backend **xác minh giao
dịch đó với fullnode** trước khi ghi: có thật, thành công, đúng hàm entry, đúng người
gửi. Backend cũ trong các repo trước nhận `txHash` nào thì ghi thẳng cái đó, nên
client hoàn toàn có thể bịa một chuỗi hex và tạo ra văn bằng giả mà không hề có giao
dịch nào trên chuỗi.

**2. Khoá riêng không bao giờ rời khỏi trình duyệt.**
Xem mục bên dưới.

**3. Không tin dữ liệu client.**
Hash do client khai đều được băm lại từ chính nội dung để đối chiếu. Quyền issuer
được kiểm trực tiếp trên chuỗi chứ không chỉ dựa vào vai trò ghi trong JWT.

---

## Mô hình bảo mật của ví người dùng

Câu hỏi đặt ra là làm sao để người sở hữu văn bằng an toàn nhất. Lời giải ở đây là
**ví phi lưu ký** — máy chủ không giữ khoá, nên có bị chiếm quyền cũng không ký thay
người dùng được.

| Lớp | Cách làm |
|---|---|
| Sinh khoá | Ed25519, sinh trong trình duyệt bằng `crypto.getRandomValues` |
| Lưu trữ | Chỉ lưu **bản mã** trong IndexedDB của chính máy đó |
| Mã hoá | AES-256-GCM; khoá dẫn xuất bằng PBKDF2-SHA256 **600.000 vòng** (khuyến nghị OWASP 2023), muối 16 byte riêng cho mỗi ví |
| Toàn vẹn | AES-GCM có xác thực: sửa 1 byte bản mã là phát hiện được ngay |
| Bộ nhớ | Khoá riêng dạng rõ chỉ tồn tại khi ví đang mở; tự khoá sau 15 phút không thao tác |
| Đăng nhập | Thách thức – đáp ứng: máy chủ gửi nonce dùng một lần, trình duyệt ký, máy chủ kiểm bằng khoá công khai. **Không có mật khẩu nào truyền qua mạng** |
| Phiên | JWT lưu trong `sessionStorage`, mất khi đóng tab |
| Sao lưu | Xuất tệp keystore **vẫn ở dạng đã mã hoá**, an toàn để cất giữ ngoài |

Đánh đổi phải chấp nhận: **mất mật khẩu là mất ví**, không có cơ chế đặt lại. Giao
diện cảnh báo rõ điều này và nhắc tải bản sao lưu ngay khi tạo ví.

Kiểm chứng: `cd frontend && node scripts/wallet-e2e.mjs` — 17 phép kiểm, trong đó có
kiểm rằng **không gói tin nào gửi lên máy chủ chứa khoá riêng hoặc mật khẩu**.

---

## Tài liệu

- [docs/CONTRACT_AUDIT.md](docs/CONTRACT_AUDIT.md) — rà soát smart contract, 10 phát hiện
  (đã sửa hết, mỗi cái có test chống quay lại).
- [docs/API.md](docs/API.md) — hợp đồng API dùng chung cho hai backend.
- [docs/TOMTAT.md](docs/TOMTAT.md) — tóm tắt những gì đã làm.
- [docs/VNU-TRUST-CHECKLIST.md](docs/VNU-TRUST-CHECKLIST.md) — checklist hoàn thiện khoá luận.
