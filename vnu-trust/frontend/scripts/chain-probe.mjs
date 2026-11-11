// Kiểm chứng TẦNG CHUỖI của giao diện với fullnode THẬT — không ghi gì lên chuỗi.
//
// `frontend/src/lib/chain.ts` ký và gửi giao dịch mà không dùng Aptos SDK:
// nhờ fullnode BCS hoá qua `/transactions/encode_submission`, ký bằng @noble,
// rồi gửi. Bộ kiểm thử thường không chạm tới đường này vì nó cần mạng, nên
// kịch bản này đứng riêng: nó chạy đúng đường đó nhưng dừng ở
// `/transactions/simulate` thay vì `/transactions`.
//
// Mô phỏng chứng minh được đúng những thứ dễ sai nhất và không chứng minh được
// bằng đọc mã:
//   1. `vector<u8>` phải là CHUỖI HEX — truyền mảng số bị từ chối;
//   2. hàm entry tồn tại trên gói đã deploy, đúng số tham số;
//   3. thông điệp trả về từ encode_submission ký được và fullnode chấp nhận.
//
// Cố ý KHÔNG gửi giao dịch thật: gửi là tạo ra hiện vật công khai không lùi
// được. Và cố ý dùng chính hàm entry của hợp đồng làm phép thử, không dùng
// giao dịch chuyển token — hệ thống này không có chức năng chuyển token.
//
//   node frontend/scripts/chain-probe.mjs
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Đọc thông số từ chain.env — cùng nguồn duy nhất mà giao diện dùng. */
const chainEnv = Object.fromEntries(
  readFileSync(join(root, "chain.env"), "utf8")
    .split("\n")
    .filter((l) => l.includes("=") && !l.trimStart().startsWith("#"))
    .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]),
);

const FULLNODE = chainEnv.CHAIN_FULLNODE;
const CONTRACT = chainEnv.CONTRACT_ADDRESS;

const rows = [];
const check = (name, ok, detail = "") => {
  rows.push({ name, ok });
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  → ${detail}` : ""}`);
  return ok;
};

const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const bytesArg = (s) => hex(new TextEncoder().encode(s));

async function node(path, init) {
  const res = await fetch(FULLNODE + path, init);
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  return { status: res.status, body };
}
const post = (path, body) =>
  node(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

console.log(`\n=== Fullnode ${FULLNODE} ===`);
const health = await node("/");
check("Fullnode trả lời", health.status === 200, `chain_id=${health.body?.chain_id}`);
check("Đúng chain id trong chain.env",
  String(health.body?.chain_id) === String(chainEnv.CHAIN_ID),
  `fullnode=${health.body?.chain_id}, chain.env=${chainEnv.CHAIN_ID}`);

console.log(`\n=== Gói hợp đồng ${CONTRACT.slice(0, 12)}… ===`);
const didModule = await node(`/accounts/${CONTRACT}/module/did_registry`);
const ok = check("Đọc được module did_registry đã deploy", didModule.status === 200);

const registerDid = didModule.body?.abi?.exposed_functions?.find((f) => f.name === "register_did");
check("Gói đã deploy có hàm register_did", Boolean(registerDid),
  registerDid ? `${registerDid.params.length} tham số` : "không tìm thấy");

// Số tham số đã deploy so với mã nguồn hiện tại. Lệch là dấu hiệu gói trên
// chuỗi đã cũ — đúng tình trạng hiện nay của issue_vc (6 vs 7 tham số).
const vcModule = await node(`/accounts/${CONTRACT}/module/vc_registry`);
const issueVc = vcModule.body?.abi?.exposed_functions?.find((f) => f.name === "issue_vc");
const moveSrc = readFileSync(join(root, "contracts", "sources", "vc_registry.move"), "utf8");
const srcParams = /public entry fun issue_vc\(([\s\S]*?)\)\s*acquires/.exec(moveSrc)?.[1]
  .split(",").map((x) => x.trim()).filter(Boolean).length;
const deployedParams = issueVc ? issueVc.params.length : 0;
check("ABI trên chuỗi khớp mã nguồn issue_vc hiện tại", deployedParams === srcParams,
  `trên chuỗi ${deployedParams} tham số, mã nguồn ${srcParams} — lệch nghĩa là CHƯA publish lại`);

if (!ok) {
  console.log("\nKhông đọc được gói hợp đồng, dừng ở đây.");
  process.exit(1);
}

console.log("\n=== Ký và mô phỏng register_did (KHÔNG gửi lên chuỗi) ===");

// Người gửi trong phép mô phỏng: tài khoản `deployer` đã có sẵn trên chuỗi.
// Chỉ dùng KHOÁ CÔNG KHAI của nó (dữ liệu công khai, đọc từ
// vnu-chain/contracts/.movement/config.yaml) — không cần và không dùng khoá riêng.
const SENDER_PUB = "0x61ce325bb8fe57aa698412bfbe7b4ebc1f9c7673f44eae46d5595f7037679229";
const pubBytes = new Uint8Array(
  (SENDER_PUB.slice(2).match(/../g) ?? []).map((h) => parseInt(h, 16)),
);
// Đồng thời kiểm luôn phép dẫn xuất địa chỉ của ví: sha3_256(pubkey ‖ 0x00).
const SENDER = hex(sha3_256(new Uint8Array([...pubBytes, 0x00])));
check("Dẫn xuất địa chỉ từ khoá công khai đúng như ví làm",
  SENDER === "0x0ede7f6b38caab7ddfe757765fddbf07221f8b776c6395562faae571250708e3",
  SENDER);

const acct = await node(`/accounts/${SENDER}`);
check("Đọc được sequence_number của người gửi", acct.status === 200,
  `sequence=${acct.body?.sequence_number}`);


const did = `did:vnu:holder:${SENDER}`;
const cid = "bafkreiabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr";
const docHash = hex(sha3_256(new TextEncoder().encode("{}")));

const tx = {
  sender: SENDER,
  sequence_number: acct.body?.sequence_number ?? "0",
  max_gas_amount: "200000",
  gas_unit_price: "100",
  expiration_timestamp_secs: String(Math.floor(Date.now() / 1000) + 120),
  payload: {
    type: "entry_function_payload",
    function: `${CONTRACT}::did_registry::register_did`,
    type_arguments: [],
    // Ba tham số vector<u8>, tất cả dạng chuỗi hex.
    arguments: [bytesArg(did), bytesArg(cid), docHash],
  },
};

const encoded = await post("/transactions/encode_submission", tx);
check("encode_submission nhận tham số vector<u8> dạng hex", encoded.status === 200,
  encoded.status === 200
    ? `thông điệp ${(encoded.body.length - 2) / 2} byte`
    : JSON.stringify(encoded.body).slice(0, 160));

// Cùng một payload nhưng vector<u8> là MẢNG SỐ — phải bị từ chối. Nếu phép này
// "đạt" thì quyết định #6 đã sai và chain.ts đang mã hoá thừa.
const asArray = await post("/transactions/encode_submission", {
  ...tx,
  payload: { ...tx.payload, arguments: [[...new TextEncoder().encode(did)], bytesArg(cid), docHash] },
});
check("vector<u8> dạng mảng số BỊ TỪ CHỐI (đúng như quyết định #6)",
  asArray.status !== 200,
  `mã ${asArray.status}`);

if (encoded.status === 200) {
  const msg = encoded.body.replace(/^0x/, "");
  const bytes = new Uint8Array(msg.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(msg.slice(i * 2, i * 2 + 2), 16);
  const signature = ed25519.sign(bytes, ed25519.utils.randomPrivateKey());
  check("Ký được thông điệp bằng @noble (không cần Aptos SDK)", signature.length === 64);

  // Fullnode TỪ CHỐI mô phỏng giao dịch có chữ ký hợp lệ ("Simulated
  // transactions must not have a valid signature") — chính là rào để không ai
  // vô tình gửi thật khi định thử. Nên gửi chữ ký toàn số 0 kèm khoá công khai
  // thật của người gửi.
  const sim = await post("/transactions/simulate?estimate_gas_unit_price=true", {
    ...tx,
    signature: {
      type: "ed25519_signature",
      public_key: SENDER_PUB,
      signature: "0x" + "0".repeat(128),
    },
  });
  const result = Array.isArray(sim.body) ? sim.body[0] : sim.body;
  const status = result?.vm_status ?? JSON.stringify(sim.body).slice(0, 200);
  const reached = sim.status === 200;
  check("Fullnode chạy được mô phỏng lời gọi register_did", reached, status);
  // Tài khoản này đã đăng ký DID từ trước nên mô phỏng abort là ĐÚNG. Điều cần
  // chứng minh là abort của HỢP ĐỒNG (đã giải mã được tham số, đã vào tới thân
  // hàm), chứ không phải lỗi giải mã tham số hay sai số lượng tham số.
  check("Mô phỏng vào tới thân hàm (abort của hợp đồng, không phải lỗi tham số)",
    reached && /Move abort|Executed successfully/i.test(status), status);
}

const failed = rows.filter((r) => !r.ok);
console.log(`\n${rows.length - failed.length}/${rows.length} PASS` +
  (failed.length ? `  — ${failed.length} FAIL:\n  ${failed.map((f) => f.name).join("\n  ")}` : ""));
process.exit(failed.length ? 1 : 0);
