# Rà soát smart contract `vnu-trust/contracts`

> Nguồn: sao chép từ `vnu-chain/contracts` (3 module Move: `authority`, `did_registry`, `vc_registry` — 1.729 dòng mã nguồn + 1.696 dòng test).
>
> **Trạng thái test:** `aptos move test` → **94/94 PASS**, trong đó 84 test gốc và 10 test mới do lần rà soát này bổ sung.

---

## 0. Kết luận nhanh

Logic nội tại của contract **không sai** — 84 test gốc đều xanh. Vấn đề nằm ở chỗ khác:

1. **Bộ test tự thỏa mãn các điều kiện tiền đề mà ứng dụng thật không thỏa mãn.** Đây là lý do contract "chạy đúng trong test nhưng hỏng khi tích hợp".
2. **Một số tính năng đã dựng khung nhưng chưa nối dây** (chuỗi ủy quyền, hạn dùng VC) — không phải bug, mà là phần còn thiếu.
3. **Nhiều trạng thái là một chiều, không có đường lùi** — thu hồi nhầm là mất vĩnh viễn.

Toàn bộ 10 phát hiện bên dưới đều có **test chứng minh** trong
[`tests/audit_findings_test.move`](../contracts/tests/audit_findings_test.move).
Mỗi test ở đó PASS nghĩa là lỗi tương ứng **có thật**. Sau khi sửa contract, các test này sẽ chuyển sang FAIL và cần viết lại thành test khẳng định hành vi đúng.

### Bảng tổng hợp

| Mã | Mức độ | Vấn đề | Module | Test chứng minh |
|---|---|---|---|---|
| **F-00** | 🔴 Chặn | Root bị đóng băng lúc compile, sai là khóa chết cả hệ thống | `authority` | (bằng chứng on-chain) |
| **F-01** | 🔴 Chặn | `approve_issuer` luôn đòi hash 32 byte kể cả khi không delegation | `authority` | `f01_…` |
| **F-02** | 🟠 Thiếu | Issuer có bit delegation vẫn không cấp được sub-issuer | `authority` | `f02_…` |
| **F-03** | 🔴 Nặng | Admin bị thu hồi → không cấp lại được, khóa vĩnh viễn | `authority` | `f03_…` |
| **F-04** | 🔴 Nặng | Issuer bị thu hồi → không approve lại, cũng không reactivate | `authority` | `f04a_`, `f04b_` |
| **F-05** | 🔴 Nặng | DID bị thu hồi → địa chỉ đó không đăng ký DID mới được | `did_registry` | `f05_…` |
| **F-06** | 🟠 Vừa | `register_did` nhận CID rỗng → DID không resolve được | `did_registry` | `f06_…` |
| **F-07** | 🟠 Vừa | Chủ DID tự ngừng thì không tự bật lại được | `did_registry` | `f07_…` |
| **F-08** | 🔴 Nặng | Issuer hết hạn ủy quyền → không thu hồi được VC mình đã cấp | `vc_registry` | `f08_…` |
| **F-09** | 🟠 Thiếu | `issue_vc` không có `expires_at` → mọi VC vĩnh viễn, mã xử lý hết hạn là mã chết | `vc_registry` | `f09_…` |
| **F-10** | 🟡 Nhẹ | View trả về vector không giới hạn → vỡ khi dữ liệu lớn | cả 3 | — |
| **F-11** | 🟡 Nhẹ | Mã lỗi dùng sai chỗ, nhánh mã chết, `id` sinh mong manh | cả 3 | — |

---

## F-00 🔴 Root bị đóng băng lúc compile

**Vị trí:** `sources/authority.move:108`

```move
root_admin: @root_admin,      // hiện tại — lấy từ named address lúc compile
// trước đây là: signer::address_of(admin)
```

`Move.toml` khai `root_admin = "_"`, nghĩa là giá trị **phải truyền lúc publish** (`--named-addresses root_admin=0x…`). Giá trị này ghi thẳng vào bytecode và `init_module` chỉ chạy đúng một lần.

**Bằng chứng trên Movement testnet** (package `0x4a6666…c6207`):

| Địa chỉ | `is_active_admin` |
|---|---|
| Package `@vnu` `0x4a6666…c6207` | `false` |
| `root_admin` on-chain `0xe14d54e8…aa50f4` | `true` |
| Profile `deployer` trong `.movement/config.yaml` | `false` |

Root on-chain **không phải** địa chỉ deploy, cũng **không phải** profile deployer. Mọi tài khoản "root" tạo mới trong ứng dụng đều abort `E_NOT_ROOT_ADMIN = 1001` khi gọi `grant_admin` / `approve_issuer`.

**Vì sao nguy hiểm:** đây là **bẫy một chiều**. `transfer_root` lại đòi chính chữ ký của root. Nếu không giữ khóa riêng của `0xe14d54e8…` thì toàn bộ cây quyền lực **khóa vĩnh viễn**, không cứu được, chỉ còn cách deploy lại package ở địa chỉ mới.

**Đề xuất sửa:**

```move
fun init_module(publisher: &signer) {
    let root = if (@root_admin == @0x0) { signer::address_of(publisher) } else { @root_admin };
    move_to(publisher, Authority { root_admin: root, /* … */ });
}
```

Kèm theo: bổ sung cơ chế **chuyển root hai bước** (`propose_root` → `accept_root`) để người nhận phải ký xác nhận, tránh chuyển nhầm sang địa chỉ không ai kiểm soát.

---

## F-01 🔴 `approve_issuer` luôn đòi hash 32 byte

**Vị trí:** `sources/authority.move:262-265`

```move
if (vc_type_mask & constants::VC_TYPE_DELEGATION() != 0) {
    assert!(admin_addr == authority.root_admin, errors::not_root_admin());
};
assert!(vector::length(&delegation_vc_hash) == 32, errors::hash_wrong_length());  // ← NGOÀI khối if
```

Kiểm tra độ dài nằm **ngoài** khối `if`, nên áp dụng cho **mọi** issuer. Cấp quyền cho một issuer thường (không có quyền ủy quyền lại), theo lẽ tự nhiên ta truyền `delegation_vc_hash = b""` → abort `E_HASH_WRONG_LENGTH = 4001`.

**Chính bộ test gốc đang né lỗi này** — `tests/authority_test.move:366-367`:

```move
let delegation_cid  = b"";                        // CID rỗng vì không có delegation
let delegation_hash = test_utils::mock_hash_v2(); // nhưng hash vẫn phải đủ 32 byte
```

Test truyền CID rỗng mà hash vẫn 32 byte nên test xanh; ứng dụng thật truyền cả hai đều rỗng nên đỏ.

**Sửa:** đưa `assert!` vào trong khối `if`, và khi có delegation thì bắt buộc cả `delegation_vc_cid` không rỗng.

---

## F-02 🟠 Chuỗi ủy quyền chưa được nối dây

**Vị trí:** `sources/authority.move:239-248`

`approve_issuer` mở đầu bằng `assert_is_active_admin(admin_addr)`. Issuer nằm trong bảng `authority.issuers`, **không bao giờ** nằm trong `authority.admins`, nên khi issuer gọi hàm này sẽ rơi vào nhánh `else` ở dòng 390-398 → abort `E_ADMIN_NOT_ACTIVE = 1010`.

Contract **đã có đủ khung** cho chuỗi ủy quyền: bit `VC_DELEGATION = 32`, hai trường `delegation_vc_cid` / `delegation_vc_hash`, và guard "chỉ root mới được cấp bit delegation". Nhưng **không hàm nào đọc bit đó để phân quyền** — nó hiện chỉ là dữ liệu trang trí.

**Sửa:** thêm nhánh trong `approve_issuer` cho phép người gọi là issuer đang hoạt động **và** có bit `VC_DELEGATION`, với hai ràng buộc bắt buộc:
- sub-issuer chỉ được cấp `vc_type_mask` là **tập con** của mask người cấp (không leo thang quyền);
- sub-issuer **không** được nhận bit `VC_DELEGATION` (chỉ root mới cấp được), hoặc giới hạn độ sâu chuỗi.

---

## F-03 / F-04 / F-05 🔴 Ba cái bẫy một chiều

Cùng một lỗi lặp lại ở ba nơi: **thu hồi chỉ đổi `status`, không xoá khỏi bảng chỉ mục**, trong khi hàm cấp mới lại chặn "đã tồn tại".

| | Thu hồi bằng | Cấp lại bị chặn bởi | Mã lỗi |
|---|---|---|---|
| Admin | `revoke_admin` | `assert!(!contains(admins, admin))` | `1003` |
| Issuer | `revoke_issuer` | `assert!(!contains(issuers, issuer))` | `1004` |
| DID | `admin_revoke_did` | `assert!(!contains(owner_to_id, owner))` | `2007` |

Với issuer còn nặng hơn: `reactivate_issuer` chặn `status == REVOKED` (chỉ hồi sinh được từ SUSPENDED), nên **issuer bị revoke là chết hẳn**.

F-05 đặc biệt nghiêm trọng về bảo mật: kịch bản **lộ khóa riêng**. Đúng ra người dùng phải được thu hồi DID cũ rồi đăng ký DID mới bằng khóa mới. Hiện tại làm vậy là mất địa chỉ vĩnh viễn.

**Sửa:** tách "định danh" khỏi "bản ghi hiện hành":
- khi thu hồi thì **xoá khỏi bảng chỉ mục** (`admins` / `issuers` / `owner_to_id`) nhưng **giữ nguyên bản ghi lịch sử** trong `roles` / `dids`;
- hoặc cho phép cấp lại với `version = version + 1` khi bản ghi cũ ở trạng thái REVOKED.

Cách thứ hai tốt hơn vì giữ được vết kiểm toán. Trường `version` đã có sẵn trong cả `RoleRecord` lẫn `DIDRecord` nhưng hiện luôn bằng 1 — đúng là chỗ để dùng.

---

## F-06 🟠 `register_did` nhận CID rỗng

**Vị trí:** `sources/did_registry.move:104`

```move
// assert CID minimum length sanity check     ← comment có, assert thì không
let did_registry = borrow_mut_did_registry();
```

Chỉ `document_hash` bị kiểm tra 32 byte; `document_cid` không kiểm tra gì. Đăng ký được một DID "active" nhưng không có tài liệu nào để resolve. Lỗi tương tự trong `vc_registry::issue_vc` — kiểm tra `content_cid` đang bị comment (dòng 115-118).

**Sửa:** bắt buộc CID không rỗng và có độ dài hợp lệ (CIDv1 base32 dài 59 ký tự, bắt đầu bằng `bafy`/`bafk`). Tối thiểu là `vector::length(&cid) > 0`.

---

## F-07 🟠 Chủ DID không tự bật lại được

**Vị trí:** `sources/did_registry.move:199-205`

Hàm tên là `deactivate_did` nhưng đặt trạng thái **SUSPENDED** chứ không phải REVOKED. Trong khi đó **không có entry nào cho chủ sở hữu tự kích hoạt lại** — `internal_set_did_status(ACTIVE)` chỉ được gọi từ `admin_reactivate_did`.

Hệ quả: người dùng tạm khóa DID của mình rồi phải đi xin admin mở lại. Sai tinh thần Self-Sovereign Identity.

**Sửa:** thêm `reactivate_own_did(owner: &signer)` cho phép chủ sở hữu tự bật lại **nếu** trạng thái hiện tại là SUSPENDED **và** người đặt suspend chính là chủ sở hữu (cần lưu thêm trường `suspended_by` để phân biệt tự khóa với bị admin khóa). Đồng thời đổi tên hàm cho khớp ngữ nghĩa: `suspend_own_did`.

---

## F-08 🔴 Issuer hết hạn không thu hồi được VC đã cấp

**Vị trí:** `sources/vc_registry.move:337` trong `internal_issuer_set_vc_status`

```move
authority::assert_is_active_issuer(caller, record.vc_type);
```

Hàm này kiểm tra cả `expires_at` của ủy quyền. Nên khi ủy quyền của issuer hết hạn, họ **không thể thu hồi những VC chính mình đã cấp trước đó**. Bằng cấp cấp sai sẽ "active" mãi cho tới khi admin ra tay.

Tương tự, issuer bị **suspend** cũng không thu hồi được VC cũ — điều này có thể là cố ý, nhưng trường hợp *hết hạn* thì rõ ràng là ngoài ý muốn.

**Sửa:** tách hai khái niệm. Việc thu hồi VC chỉ cần kiểm tra **quyền sở hữu** (`record.issuer_addr == caller`) và DID của issuer còn active, **không** cần ủy quyền còn hiệu lực:

```move
assert!(record.issuer_addr == caller, errors::not_vc_issuer());
did_registry::assert_owner_active(caller);
// BỎ assert_is_active_issuer — chỉ cần cho issue_vc, không cần cho revoke
```

Nguyên tắc: **cấp mới** cần quyền còn hiệu lực, **thu hồi** thì không — thu hồi luôn phải dễ hơn cấp.

---

## F-09 🟠 Mọi VC đều vĩnh viễn

**Vị trí:** `sources/vc_registry.move:94-102` và `:146`

```move
public entry fun issue_vc(
    issuer: &signer, holder_addr: address, vc_type: u64,
    vc_id_hash: vector<u8>, content_cid: vector<u8>, content_hash: vector<u8>,
)   // ← KHÔNG có tham số expires_at
…
expires_at: 0,   // luôn luôn là 0
```

ABI đã deploy xác nhận: `issue_vc` chỉ có 6 tham số, không có `expires_at`.

Hệ quả dây chuyền — toàn bộ phần xử lý hết hạn thành **mã chết**:
- `VC_STATUS_EXPIRED` không bao giờ được ghi vào storage;
- `assert!(record.status != VC_STATUS_EXPIRED, …)` trong cả hai hàm `internal_*_set_vc_status` là điều kiện không bao giờ đúng;
- `get_vc_by_id` **abort** khi VC hết hạn — sai về nguyên tắc: hàm view phải trả về bản ghi để bên xác minh tự đánh giá, chứ không nên abort.

Với bằng tốt nghiệp thì vĩnh viễn là hợp lý, nhưng **VC ủy quyền** (`VC_DELEGATION`) và thẻ sinh viên thì bắt buộc phải có hạn.

**Sửa:** thêm tham số `expires_at: u64` vào `issue_vc` (0 = vĩnh viễn), và sửa `get_vc_by_id` trả về bản ghi kèm trạng thái tính toán thay vì abort.

---

## F-10 🟡 View trả về vector không giới hạn

`authority::get_issuers()`, `get_admins()`, `did_registry::get_dids()`, `get_owners()`, `vc_registry::get_vcs()` đều gọi `smart_table::keys(…)` trả về **toàn bộ** khoá.

`smart_table` được thiết kế để tránh nạp hết vào bộ nhớ; `keys()` phá vỡ đúng mục đích đó. Trên mạng thật, khi số DID lên vài nghìn (hiện on-chain đã có **128 DID, 21 issuer, 20 admin**) các view này sẽ vượt giới hạn gas/kích thước phản hồi và hỏng.

**Sửa:** chuyển sang phân trang — `get_dids_paginated(start: u64, limit: u64)` — và để backend lập chỉ mục từ **sự kiện** (`DIDRegisteredEvent`, `IssuerApprovedEvent`, `VCIssuedEvent`) thay vì gọi view liệt kê. Các sự kiện đã được emit đầy đủ, rất phù hợp cho indexer.

---

## F-11 🟡 Nhóm lỗi nhỏ

**a) Mã lỗi dùng sai chỗ** — `did_registry.move:301, 317, 475` dùng `errors::invalid_cid()` (2008) cho phép kiểm tra "không tìm thấy id trong bảng `dids`". Phải là `errors::invalid_id()` (4003). Gây hiểu nhầm khi debug.

**b) Nhánh mã chết** — `authority.move:390-398`:

```move
if (admin == authority.root_admin) { return };   // root đã thoát ở đây
…
} else {
    assert!(admin == authority.root_admin, errors::admin_not_active());  // luôn false
};
```

Điều kiện trong `else` không bao giờ đúng vì root đã return từ đầu hàm. Thực chất là `abort admin_not_active()`. Nên viết thẳng cho rõ.

**c) `id` sinh mong manh** — `authority.move:178` và `:282`:

```move
let id = authority.admin_count + authority.issuer_count;
```

Hiện **chưa sai**, vì mỗi lần thêm đúng một counter tăng 1. Nhưng nó chỉ đúng nhờ trùng hợp: chỉ cần thêm thao tác xoá hoặc giảm counter (chính là thứ F-03/F-04 cần) là hai bản ghi sẽ đụng `id` và `smart_table::add` abort. **Phải sửa trước khi sửa F-03/F-04.** Dùng một biến `next_role_id` riêng, chỉ tăng.

Thêm nữa: `grant_admin` có `assert!(!contains(roles, id))` nhưng `approve_issuer` thì không — bất đối xứng.

**d) Một địa chỉ có thể vừa là admin vừa là issuer** — `approve_issuer` không kiểm tra `!contains(admins, …)` và ngược lại. Khi đó `get_info` chỉ trả về bản ghi issuer, che mất vai trò admin.

**e) Bộ đếm không giảm** — `issuer_vc_count` / `holder_vc_count` không giảm khi thu hồi VC. Chúng là "tổng đã từng cấp" chứ không phải "đang hiệu lực"; nếu giao diện hiển thị nhầm sẽ sai số liệu.

---

## 1. Thứ tự gọi bắt buộc (hiện tại)

Sai thứ tự là nguyên nhân của phần lớn lỗi khi tích hợp:

```
1. root  — phải đúng khóa đã nạp vào @root_admin lúc publish
2. admin  tự ký  → register_did            (bắt buộc trước bước 3)
3. root          → grant_admin(admin)
4. issuer tự ký  → register_did            (bắt buộc trước bước 5)
5. root/admin    → approve_issuer(issuer, mask, cid, hash_32_byte, expires)
                   ⚠ hash PHẢI đủ 32 byte dù không có delegation   (F-01)
                   ⚠ muốn cấp bit VC_DELEGATION thì phải là root
6. holder tự ký  → register_did            (bắt buộc trước bước 7)
7. issuer        → issue_vc(holder, …)
```

Điểm mấu chốt: **mỗi tài khoản phải tự gọi `register_did` bằng chữ ký của chính mình trước khi được cấp bất kỳ vai trò nào.** Root không đăng ký DID hộ người khác được. Bản thân root là ngoại lệ duy nhất không cần DID (`authority.move:387` return sớm).

## 2. Bảng tra mã abort

| Mã | Hằng số | Nghĩa thực tế khi tích hợp |
|---|---|---|
| `1001` | `E_NOT_ROOT_ADMIN` | Không ký bằng khóa root đã nạp lúc publish (F-00) |
| `1003` / `1004` | `*_ALREADY_EXISTS` | Đã từng tồn tại — kể cả khi đã thu hồi (F-03/F-04) |
| `1010` | `E_ADMIN_NOT_ACTIVE` | Người gọi không phải admin — issuer gọi `approve_issuer` (F-02) |
| `1012` | `E_ISSUER_CAP_EXPIRED` | Ủy quyền hết hạn — chặn cả việc thu hồi VC (F-08) |
| `2006` | `E_OWNER_NOT_EXISTS` | Địa chỉ đích chưa `register_did` |
| `2007` | `E_OWNER_HAS_DID` | Địa chỉ đã có DID, kể cả DID đã thu hồi (F-05) |
| `4001` | `E_HASH_WRONG_LENGTH` | Hash không đủ 32 byte — thường gặp ở `approve_issuer` (F-01) |

## 3. Thứ tự sửa đề xuất

| Đợt | Nội dung | Lý do xếp trước/sau |
|---|---|---|
| **1** | F-11c (`next_role_id`) | Phải xong trước, vì F-03/F-04 sẽ phá vỡ cách sinh `id` hiện tại |
| **2** | F-00, F-01, F-08 | Ba lỗi chặn đường, sửa nhỏ, hiệu quả ngay |
| **3** | F-03, F-04, F-05 | Bỏ các bẫy một chiều — cần đợt 1 xong trước |
| **4** | F-02, F-09 | Nối dây hai tính năng còn thiếu |
| **5** | F-06, F-07, F-10, F-11 | Dọn dẹp, phân trang, chuẩn hóa mã lỗi |

Mỗi đợt xong phải chạy lại `aptos move test` và cập nhật `tests/audit_findings_test.move` — test nào chuyển từ PASS sang FAIL nghĩa là lỗi đó đã được sửa, và cần viết lại thành test khẳng định hành vi đúng.

---

## 4. Cách chạy lại kiểm chứng

```bash
cd vnu-trust/contracts
aptos move test --skip-fetch-latest-git-deps                      # toàn bộ: 94 test
aptos move test --skip-fetch-latest-git-deps --filter audit       # chỉ 10 test chứng minh lỗi
```

---

## F-12 — Rà soát trước khi publish lại (11/11/2026): quyền vượt mức

Sáu chỗ hợp đồng cho phép nhiều hơn mức hợp lý. Tất cả đã sửa; mỗi chỗ có test
trong `tests/audit_findings_test.move` (`f12_*`), và đã kiểm bằng cách tạm gỡ
từng bản sửa: test tương ứng chuyển đỏ.

| # | Mức | Vấn đề | Cách sửa |
|---|---|---|---|
| a | Cao | `assert_is_active_issuer` chỉ đòi `mask & vc_type != 0`: issuer được cấp cử nhân cấp được `vc_type = 5` (cử nhân + tiến sĩ) | Đòi `vc_type != 0 && mask & vc_type == vc_type` |
| b | Cao | Issuer tự cấp văn bằng cho chính mình | `issue_vc` chặn `holder == issuer` (`E_SELF_ISSUE`) |
| c | TB | Issuer có bit uỷ quyền phê duyệt lại được issuer mà admin đã thu hồi | Đường uỷ quyền chỉ cấp cho địa chỉ chưa từng là issuer |
| d | TB | Admin khoá/thu hồi DID của admin khác hoặc root (lách "chỉ root thu hồi admin"); admin mở được DID chủ tự khoá | `assert_can_moderate_did` (`E_PROTECTED_TARGET`); DID chủ tự khoá chỉ chủ mở (`E_OWNER_LOCKED`) |
| e | TB | View `is_active_issuer`/`is_active_admin`/`can_delegate` không kiểm DID, nên issuer bị thu hồi DID vẫn hiện "tin cậy" | Ba view kiểm `has_active_did`, khớp các hàm assert |
| f | Thấp | Ai cũng đăng ký được chuỗi DID mang địa chỉ người khác (chặn người đó onboard) | `register_did` đòi chuỗi bắt đầu `did:` và kết thúc bằng địa chỉ chủ sở hữu (`E_DID_NOT_BOUND_TO_OWNER`) |

Hệ quả cần biết: chuỗi DID đã bị thu hồi không dùng lại được, nên đăng ký lại
(F-05) phải dùng tiền tố khác (ví dụ `did:vnu:v2:<địa chỉ>`).
