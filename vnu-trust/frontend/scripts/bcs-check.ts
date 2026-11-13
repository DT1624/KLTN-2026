// Kiểm bộ BCS của ví (src/lib/bcs.ts) — thứ cho phép ví tự kiểm thông điệp fullnode
// trả về trước khi ký (W-01, docs/SECURITY_REVIEW.md).
//
//   ../backend/node_modules/.bin/tsx scripts/bcs-check.ts           # chỉ phần tĩnh
//   ../backend/node_modules/.bin/tsx scripts/bcs-check.ts --live    # + đối chiếu fullnode thật
//
// Phần tĩnh: bảng kiểu tham số khớp mã Move (thêm/đổi hàm entry mà quên cập nhật
// bảng thì ví từ chối ký — đỏ ở đây trước khi người dùng gặp).
// Phần --live: chỉ gọi /transactions/encode_submission (fullnode MÃ HOÁ hộ, không
// gửi, không ghi gì lên chuỗi) rồi so từng byte với bản ví tự dựng.
import { readFileSync, readdirSync } from "node:fs";
import { ENTRY_PARAMS, signingMessage, hexToBytes, type EntryTx } from "../src/lib/bcs";

const ROOT = new URL("../../", import.meta.url);
const env = readFileSync(new URL("chain.env", ROOT), "utf8");
const CONTRACT = env.match(/^CONTRACT_ADDRESS=(\S+)/m)![1];
const FULLNODE = env.match(/^CHAIN_FULLNODE=(\S+)/m)![1].replace(/\/$/, "");
const CHAIN_ID = Number(env.match(/^CHAIN_ID=(\d+)/m)![1]);
const rows: { name: string; ok: boolean }[] = [];
const check = (name: string, ok: boolean, detail = "") => {
  rows.push({ name, ok });
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  → " + detail : ""}`);
};
const hex = (b: Uint8Array) => "0x" + Buffer.from(b).toString("hex");

console.log("\n=== Bảng kiểu tham số ↔ mã Move ===");
const srcDir = new URL("contracts/sources/", ROOT);
const fromMove: Record<string, string[]> = {};
for (const f of readdirSync(srcDir).filter((x) => x.endsWith(".move"))) {
  const src = readFileSync(new URL(f, srcDir), "utf8");
  const mod = src.match(/module\s+\w+::(\w+)/)![1];
  for (const m of src.matchAll(/public entry fun (\w+)\s*\(([\s\S]*?)\)/g)) {
    const params = m[2].split(",").map((p) => p.trim()).filter(Boolean).map((p) => p.split(":")[1].trim());
    fromMove[`${mod}::${m[1]}`] = params
      .filter((t) => t !== "&signer")
      .map((t) => (t === "address" ? "address" : t === "u64" ? "u64" : t === "vector<u8>" ? "bytes" : `?${t}`));
  }
}
for (const [fn, kinds] of Object.entries(ENTRY_PARAMS)) {
  const want = fromMove[fn];
  check(`${fn} khớp mã Move`, !!want && want.join(",") === kinds.join(","), want ? want.join(",") : "không có trong mã Move");
}

if (process.argv.includes("--live")) {
  console.log("\n=== Đối chiếu từng byte với encode_submission của fullnode thật (không gửi giao dịch) ===");
  const sender = CONTRACT; // địa chỉ công khai, chỉ dùng để dựng thông điệp
  const h32 = "0x" + "ab".repeat(32);
  const cid = "0x" + Buffer.from("bafkreiabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr").toString("hex");
  const cases: [string, unknown[]][] = [
    ["did_registry::register_did", ["0x" + Buffer.from(`did:vnu:holder:${sender}`).toString("hex"), cid, h32]],
    ["vc_registry::issue_vc", ["0x1", "4", h32, cid, h32, "1893456000"]],
    ["authority::approve_issuer", ["0x00000000000000000000000000000000000000000000000000000000000abc", "63", "0x", "0x", "0"]],
    ["vc_registry::revoke_vc", ["18446744073709551615", "0x" + Buffer.from("Lý do có dấu").toString("hex")]],
    ["authority::accept_root", []],
  ];
  for (const [fn, args] of cases) {
    const tx: EntryTx = {
      sender, sequence_number: "7", max_gas_amount: "200000", gas_unit_price: "100",
      expiration_timestamp_secs: "1893456000",
      payload: { function: `${CONTRACT}::${fn}`, type_arguments: [], arguments: args },
    };
    const r = await fetch(`${FULLNODE}/transactions/encode_submission`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...tx, payload: { type: "entry_function_payload", ...tx.payload } }),
    });
    const node = r.ok ? String(await r.json()) : `HTTP ${r.status}`;
    const mine = hex(signingMessage(tx, CHAIN_ID));
    check(`${fn}: ví tự dựng = fullnode`, node.toLowerCase() === mine, node === mine ? `${(mine.length - 2) / 2} byte` : `fullnode ${node.slice(0, 40)}…`);
  }
  // Fullnode ác ý: trả thông điệp của hàm khác — ví phải thấy lệch.
  const honest: EntryTx = {
    sender, sequence_number: "7", max_gas_amount: "200000", gas_unit_price: "100", expiration_timestamp_secs: "1893456000",
    payload: { function: `${CONTRACT}::authority::grant_admin`, type_arguments: [], arguments: [sender] },
  };
  const evil = { ...honest, payload: { ...honest.payload, function: `${CONTRACT}::authority::propose_root` } };
  check("thông điệp của hàm khác (propose_root thay grant_admin) bị phát hiện",
    hex(signingMessage(honest, CHAIN_ID)) !== hex(signingMessage(evil, CHAIN_ID)));
}

let threw = false;
try { hexToBytes("0xzz"); } catch { threw = true; }
check("hexToBytes từ chối ký tự không phải hex", threw);

const failed = rows.filter((r) => !r.ok);
console.log(`\n${rows.length - failed.length}/${rows.length} PASS  — ${failed.length ? failed.length + " FAIL" : "ví tự dựng đúng thông điệp ký"}`);
process.exit(failed.length ? 1 : 0);
