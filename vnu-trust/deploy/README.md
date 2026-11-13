# Triển khai VNU-Trust lên host miễn phí

```
                 ┌─► vnu-trust-ts  (Render, Node) ─┐
vnu-trust-web ───┤                                 ├─► Postgres (Neon) 
(Render/Vercel)  └─► vnu-trust-go  (Render, Go)  ──┘   Movement testnet (đã có sẵn)
```

| Phần | Host | Gói free |
|---|---|---|
| Frontend | Render Static Site **hoặc** Vercel | Không ngủ, có HTTPS (ví trong trình duyệt bắt buộc HTTPS) |
| 2 backend | Render Web Service | Ngủ sau 15 phút không dùng; lần gọi đầu chờ ~30–60 giây |
| Postgres | Neon (hoặc Supabase) | 0,5 GB, không hết hạn. **Không** dùng Postgres của Render: bị xoá sau 30 ngày |
| IPFS | Chế độ `mock` (lưu trong Postgres) | Không cần tài khoản Pinata |

## Thư mục này có gì

| Tệp | Dùng để |
|---|---|
| `render.yaml` | Blueprint: tạo cả 2 backend + frontend trên Render trong một lần |
| `vercel/vercel.json` | Phương án thay thế: frontend lên Vercel |
| `init-db.sh` | Nạp `db/schema.sql` vào Postgres trên host (chạy một lần) |
| `check.sh` | Kiểm tra sau khi triển khai: backend sống, đúng chế độ chuỗi, CORS, frontend |
| `.env.example` | Mẫu `deploy/.env` cho hai tập lệnh trên (không đẩy lên GitHub) |

## Các bước

### 1. Tạo Postgres trên Neon

1. Đăng ký <https://neon.tech> → **New project** → region **Singapore**.
2. Vào **Connection details**, **tắt** "Connection pooling" để lấy host trực tiếp
   (không có `-pooler`). Ghi lại host, database, user, password.
3. Nạp lược đồ từ máy bạn:

```bash
cd vnu-trust
cp deploy/.env.example deploy/.env      # điền DB_HOST, DB_NAME, DB_USER, DB_PASSWORD
./deploy/init-db.sh                     # in "9 bảng" là đúng
```

### 2. Tạo 2 backend + frontend trên Render

1. Đăng ký <https://render.com> bằng tài khoản GitHub, cấp quyền repo.
2. **New → Blueprint** → chọn repo → **Blueprint Path**: `vnu-trust/deploy/render.yaml`.
3. Render hỏi `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` cho **từng** backend:
   nhập đúng giá trị Neon ở bước 1 (hai bên giống nhau).
4. **Apply**. Chờ ba dịch vụ build xong (lần đầu ~5 phút).

`JWT_SECRET` được Render tự sinh trong nhóm biến `vnu-trust-shared` và dùng
chung cho cả hai backend, không phải nhập.

### 3. Kiểm tra lại URL

Nếu tên dịch vụ đã có người dùng, Render thêm hậu tố, vd. `vnu-trust-go-a1b2.onrender.com`.
Khi đó sửa trong bảng điều khiển Render (hoặc sửa `render.yaml` rồi push):

| Ở đâu | Biến | Giá trị |
|---|---|---|
| Env group `vnu-trust-shared` | `FRONTEND_ORIGIN` | URL frontend, không có `/` cuối |
| `vnu-trust-web` | `VITE_API_TS_URL` | URL backend TS + `/api` |
| `vnu-trust-web` | `VITE_API_GO_URL` | URL backend Go + `/api` |

Biến `VITE_*` được nhúng lúc build, nên sửa xong phải **Manual Deploy** lại frontend.

### 4. Kiểm tra

```bash
# điền WEB_URL, TS_URL, GO_URL trong deploy/.env
./deploy/check.sh                       # phải "7 đạt, 0 hỏng"
```

Rồi mở frontend → tạo ví → nhận token thử nghiệm → đăng ký DID. Ở bộ chọn backend
trên thanh trên, đổi TS ↔ Go phải dùng được cả hai.

## Phương án: frontend lên Vercel

Giữ hai backend trên Render, chỉ thay phần frontend:

1. <https://vercel.com> → **Add New → Project** → chọn repo.
2. **Root Directory**: `vnu-trust/deploy/vercel` (Vercel tự đọc `vercel.json` ở đó;
   lệnh build đi sang `vnu-trust/frontend`).
3. **Environment Variables**: thêm đủ các biến `VITE_*` giống khối `vnu-trust-web`
   trong `render.yaml`.
4. Deploy, rồi thêm URL Vercel vào `FRONTEND_ORIGIN` trên Render (phân cách bằng dấu phẩy):
   `https://vnu-trust-web.onrender.com,https://vnu-trust.vercel.app`
5. `WEB_URL=https://vnu-trust.vercel.app ./deploy/check.sh`

Có thể xoá dịch vụ `vnu-trust-web` trên Render nếu chỉ dùng Vercel.

## Lưu ý

- **Giới hạn 750 giờ/tháng của Render** tính chung cho cả tài khoản. Hai backend
  thức 24/7 cần ~1.488 giờ, nhưng chúng ngủ khi không ai dùng nên demo bình thường
  vẫn đủ. Nếu thiếu, xoá `vnu-trust-ts` và giữ bản Go: giao diện vẫn chạy, chỉ là
  chọn TS trên thanh trên sẽ báo đỏ.
- **Trước buổi bảo vệ** mở trang và đổi qua cả hai backend vài phút trước để chúng
  thức dậy. Đừng đặt dịch vụ "ping" liên tục: nó ăn hết 750 giờ.
- **Đổi hợp đồng** (`chain.env`) thì sửa `CONTRACT_ADDRESS` và `VITE_CONTRACT_ADDRESS`
  trong `render.yaml`. `check.sh` báo lệch nếu quên.
- **Bí mật**: `deploy/.env` đã nằm trong `.gitignore`. Mật khẩu CSDL và `JWT_SECRET`
  chỉ nằm trong bảng điều khiển Render, không bao giờ trong repo.
- **Ghim IPFS thật**: đổi `IPFS_PROVIDER=pinata` và thêm `PINATA_JWT` trong env group
  trên Render (đừng ghi vào `render.yaml`).
- `VERIFY_ONCHAIN` luôn là `true` trên host. Cả hai backend từ chối khởi động nếu
  đặt `false` cùng `NODE_ENV=production`.
