// Mô phỏng một giao dịch publish/nâng cấp gói — KHÔNG ghi gì lên chuỗi, KHÔNG cần khoá riêng.
//
//   cd contracts && movement move build-publish-payload --skip-fetch-latest-git-deps \
//     --named-addresses vnu=<CONTRACT_ADDRESS>,root_admin=0x0 --included-artifacts none \
//     --json-output-file /tmp/.../payload.json
//   node scripts/simulate-upgrade.mjs /tmp/.../payload.json [--max-gas 900000]
//
// Fullnode TỪ CHỐI mô phỏng có chữ ký hợp lệ (bài học #25): gửi chữ ký toàn số 0
// kèm KHOÁ CÔNG KHAI thật của người gửi (đọc từ một giao dịch cũ của chính người
// đó trên chuỗi — dữ liệu công khai). `authentication_key` KHÔNG phải khoá công khai.
// Trần gas phải nhỏ hơn số dư, nếu không mô phỏng báo INSUFFICIENT_BALANCE.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const env = readFileSync(new URL("../chain.env", import.meta.url), "utf8");
const CONTRACT = env.match(/^CONTRACT_ADDRESS=(\S+)/m)[1];
const NODE = env.match(/^CHAIN_FULLNODE=(\S+)/m)[1].replace(/\/$/, "");
const file = process.argv[2];
if (!file) { console.error("Cần đường dẫn tệp payload JSON"); process.exit(2); }
const maxGasArg = process.argv.indexOf("--max-gas");

const get = async (p) => { const r = await fetch(NODE + p); if (!r.ok) throw new Error(`${p}: HTTP ${r.status}`); return r.json(); };
const payloadJson = JSON.parse(readFileSync(file, "utf8"));
const [metaArg, codeArg] = payloadJson.args;
const modules = codeArg.value;
const payload = {
  type: "entry_function_payload",
  function: payloadJson.function_id,
  type_arguments: payloadJson.type_args ?? [],
  arguments: [metaArg.value, modules],
};

const account = await get(`/accounts/${CONTRACT}`);
const balance = BigInt((await get(`/accounts/${CONTRACT}/balance/0x1::aptos_coin::AptosCoin`)) ?? 0);
const { gas_estimate: price } = await get("/estimate_gas_price");
// Khoá công khai: lấy từ giao dịch gần nhất của chính tài khoản này (công khai trên chuỗi).
const txs = await get(`/accounts/${CONTRACT}/transactions?limit=1`);
const publicKey = txs[0]?.signature?.public_key;
if (!publicKey) throw new Error("Không đọc được khoá công khai của người gửi từ lịch sử giao dịch");
const maxGas = maxGasArg > 0 ? BigInt(process.argv[maxGasArg + 1]) : (balance / BigInt(price)) * 9n / 10n;

const tx = {
  sender: CONTRACT,
  sequence_number: account.sequence_number,
  max_gas_amount: String(maxGas),
  gas_unit_price: String(price),
  expiration_timestamp_secs: String(Math.floor(Date.now() / 1000) + 600),
  payload,
  signature: { type: "ed25519_signature", public_key: publicKey, signature: "0x" + "00".repeat(64) },
};
const r = await fetch(`${NODE}/transactions/simulate`, {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(tx),
});
const out = await r.json();
const sim = Array.isArray(out) ? out[0] : out;

const sha = (h) => createHash("sha256").update(Buffer.from(h.replace(/^0x/, ""), "hex")).digest("hex");
console.log(`Người gửi       : ${CONTRACT}`);
console.log(`Sequence        : ${account.sequence_number}`);
console.log(`Số dư           : ${balance} octas`);
console.log(`Giá gas / trần  : ${price} / ${maxGas}`);
console.log(`Số module       : ${modules.length}`);
modules.forEach((m, i) => console.log(`  module[${i}] sha256 ${sha(m)}  (${(m.length - 2) / 2} byte)`));
console.log(`HTTP            : ${r.status}`);
console.log(`vm_status       : ${sim?.vm_status ?? JSON.stringify(out).slice(0, 300)}`);
console.log(`success         : ${sim?.success}`);
console.log(`gas_used        : ${sim?.gas_used}  (~${sim?.gas_used ? (Number(sim.gas_used) * Number(price) / 1e8).toFixed(4) : "?"} MOVE)`);
process.exit(sim?.success ? 0 : 1);
