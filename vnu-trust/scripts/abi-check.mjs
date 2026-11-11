// Đối chiếu TÊN HÀM giữa contract, HAI backend và GIAO DIỆN.
//
// Vì sao cần: backend cũ từng gọi `vc_registry::issuer_vc` trong khi contract
// tên là `issue_vc`. Lỗi đó không có bài kiểm thử nào bắt được cho tới khi
// chạy thật với chuỗi thật — vì ở chế độ không nối chuỗi, việc xác minh giao
// dịch bị bỏ qua nên tên hàm sai chẳng gây hậu quả gì.
//
// Kịch bản này đọc thẳng mã nguồn Move, rút ra tập hàm `public entry fun` và
// `#[view] public fun`, rồi đối chiếu với tên mà mỗi backend đang dùng. Nó
// cũng bắt trường hợp ngược lại: hai backend dùng tập hàm KHÁC NHAU.
//
// Từ khi giao diện TỰ KÝ VÀ TỰ GỬI giao dịch, `frontend/src/lib/chain.ts` cũng
// là một nơi gọi tên hàm hợp đồng — và là nơi sai tên gây hậu quả sớm nhất, vì
// giao dịch bị fullnode từ chối ngay. Nên nó cũng được đối chiếu ở đây.
//
//   node scripts/abi-check.mjs
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const rows = [];
const check = (name, ok, detail = "") => {
  rows.push({ name, ok });
  console.log(`  ${ok ? "KHỚP" : "LỆCH"}  ${name}${detail ? `  → ${detail}` : ""}`);
};

// ---------- 1. Rút tên hàm từ mã nguồn Move ----------
const moveDir = join(root, "contracts", "sources");
const contract = { entry: new Map(), view: new Map() };

for (const file of readdirSync(moveDir).filter((f) => f.endsWith(".move"))) {
  const src = readFileSync(join(moveDir, file), "utf8");
  const module = /module\s+vnu::(\w+)/.exec(src)?.[1];
  if (!module) continue;

  // `public entry fun ten(` — có thể xuống dòng giữa tên và dấu ngoặc
  for (const m of src.matchAll(/public\s+entry\s+fun\s+(\w+)/g)) {
    contract.entry.set(`${module}::${m[1]}`, true);
  }
  // `#[view]` đứng ngay trước một `public fun ten(`
  for (const m of src.matchAll(/#\[view\][\s\S]{0,80}?public\s+fun\s+(\w+)/g)) {
    contract.view.set(`${module}::${m[1]}`, true);
  }
}

const allContract = new Set([...contract.entry.keys(), ...contract.view.keys()]);
console.log(`\n=== Contract khai báo ${contract.entry.size} hàm entry, ${contract.view.size} hàm view ===`);
check("Đọc được mã nguồn Move", allContract.size > 0, `${allContract.size} hàm`);

// ---------- 2. Tên hàm mà backend TypeScript dùng ----------
// abi.ts viết dạng `${MODULE.didRegistry}::register_did`, với MODULE.x là
// `${PKG}::did_registry`. Dựng lại bảng ánh xạ rồi thay thế.
const abiTs = readFileSync(join(root, "backend", "src", "chain", "abi.ts"), "utf8");
const tsModules = new Map();
for (const m of abiTs.matchAll(/(\w+):\s*`\$\{PKG\}::(\w+)`/g)) tsModules.set(m[1], m[2]);

const tsNames = new Set();
for (const m of abiTs.matchAll(/`\$\{MODULE\.(\w+)\}::(\w+)`/g)) {
  const mod = tsModules.get(m[1]);
  if (mod) tsNames.add(`${mod}::${m[2]}`);
}
check("Đọc được backend/src/chain/abi.ts", tsNames.size > 0, `${tsNames.size} hàm`);

// ---------- 3. Tên hàm mà backend Go dùng ----------
// registry.go viết dạng `c.Module("did_registry") + "::register_did"`
const goSrc = readdirSync(join(root, "backend-go", "internal", "chain"))
  .filter((f) => f.endsWith(".go"))
  .map((f) => readFileSync(join(root, "backend-go", "internal", "chain", f), "utf8"))
  .join("\n");

const goNames = new Set();
for (const m of goSrc.matchAll(/c\.Module\("(\w+)"\)\s*\+\s*"::(\w+)"/g)) {
  goNames.add(`${m[1]}::${m[2]}`);
}
check("Đọc được backend-go/internal/chain", goNames.size > 0, `${goNames.size} hàm`);

// ---------- 3b. Tên hàm mà GIAO DIỆN dùng ----------
// chain.ts viết dạng `${MODULE.didRegistry}::register_did`, với MODULE.x là
// `${CHAIN.contract}::did_registry` — cùng khuôn với abi.ts bên backend.
const chainTs = readFileSync(join(root, "frontend", "src", "lib", "chain.ts"), "utf8");
const feModules = new Map();
for (const m of chainTs.matchAll(/(\w+):\s*`\$\{CHAIN\.contract\}::(\w+)`/g)) {
  feModules.set(m[1], m[2]);
}
const feNames = new Set();
for (const m of chainTs.matchAll(/`\$\{MODULE\.(\w+)\}::(\w+)`/g)) {
  const mod = feModules.get(m[1]);
  if (mod) feNames.add(`${mod}::${m[2]}`);
}
check("Đọc được frontend/src/lib/chain.ts", feNames.size > 0, `${feNames.size} hàm`);

// ---------- 4. Mọi tên backend dùng đều phải tồn tại trong contract ----------
console.log("\n=== Tên backend dùng có tồn tại trong contract không ===");
for (const [label, names] of [["TypeScript", tsNames], ["Go", goNames], ["Giao diện", feNames]]) {
  const missing = [...names].filter((n) => !allContract.has(n));
  check(`${label}: mọi hàm được gọi đều có trong contract`, missing.length === 0,
    missing.length ? `KHÔNG TỒN TẠI: ${missing.join(", ")}` : `${names.size} hàm đều khớp`);
}

// ---------- 5. Hai backend phải dùng CÙNG tập hàm ----------
console.log("\n=== Hai backend có dùng cùng tập hàm không ===");
const onlyTs = [...tsNames].filter((n) => !goNames.has(n));
const onlyGo = [...goNames].filter((n) => !tsNames.has(n));
// Backend TypeScript khai báo sẵn một số hàm chưa tuyến nào gọi tới; điều đó
// chấp nhận được, nhưng phải liệt kê ra để không ai vô tình quên phần Go.
if (onlyTs.length) console.log(`       chỉ TS có: ${onlyTs.join(", ")}`);
if (onlyGo.length) console.log(`       chỉ Go có: ${onlyGo.join(", ")}`);
check("Không có hàm nào chỉ Go dùng mà TS thiếu", onlyGo.length === 0,
  onlyGo.length ? onlyGo.join(", ") : "không có");

// Giao diện gửi giao dịch, backend xác minh giao dịch đó bằng tên hàm nó biết.
// Giao diện gọi một hàm mà backend không có trong bảng của mình thì giao dịch
// lên chuỗi thành công nhưng backend từ chối ghi chỉ mục — hỏng nửa chừng, kiểu
// hỏng khó chẩn đoán nhất.
const feEntryOnly = [...feNames].filter((n) => contract.entry.has(n) && !tsNames.has(n));
if (feEntryOnly.length) console.log(`       chỉ giao diện có: ${feEntryOnly.join(", ")}`);
check("Mọi hàm entry giao diện gửi đều có trong bảng của backend", feEntryOnly.length === 0,
  feEntryOnly.length ? feEntryOnly.join(", ") : `${feNames.size} hàm đều có bên backend`);

// ---------- 6. Hàm entry đã sửa trong đợt rà soát phải còn/đã mất đúng ----------
console.log("\n=== Hệ quả của đợt sửa contract ===");
check("transfer_root một bước đã bị bỏ khỏi contract",
  !allContract.has("authority::transfer_root"),
  "chuyển root nay là hai bước propose_root + accept_root");
check("Không backend nào còn gọi transfer_root",
  !tsNames.has("authority::transfer_root") && !goNames.has("authority::transfer_root"));
for (const fn of ["authority::propose_root", "authority::accept_root",
                  "authority::cancel_root_transfer", "authority::can_delegate",
                  "authority::get_pending_root", "did_registry::reactivate_own_did",
                  "did_registry::suspend_own_did", "vc_registry::get_live_counts"]) {
  check(`contract có ${fn}`, allContract.has(fn));
}

const failed = rows.filter((r) => !r.ok);
console.log(`\n${rows.length - failed.length}/${rows.length} KHỚP` +
  (failed.length ? `  — ${failed.length} LỆCH:\n  ${failed.map((f) => f.name).join("\n  ")}` : "  — contract và hai backend gọi cùng một tập hàm"));
process.exit(failed.length ? 1 : 0);
