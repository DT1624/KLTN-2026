// Kiểm thử xác minh giao dịch ở chế độ NGHIÊM NGẶT bằng một fullnode GIẢ chạy cục bộ.
//
//   MOCK_PORT=4099 TS_BASE=http://localhost:4095/api GO_BASE=http://localhost:4096/api \
//     node scripts/tx-binding.mjs
//
// Hai backend phải chạy với VERIFY_ONCHAIN=true và CHAIN_FULLNODE=http://localhost:4099/v1.
// Vì sao dùng fullnode giả: muốn chứng minh backend từ chối giao dịch "thật nhưng
// sai tham số" thì phải có giao dịch thành công do CHÍNH người đang đăng nhập gửi —
// trên chuỗi thật điều đó đòi gửi giao dịch (ghi lên chuỗi). Fullnode giả trả đúng
// hình dạng JSON của fullnode Movement, kể cả thói quen in địa chỉ ở dạng RÚT GỌN
// (gói 0x0ede7f… hiện ra là 0xede7f…), là thứ đã làm hỏng phép so tên hàm (S-04).
//
// Phát hiện được kiểm: S-02 (tham số không đối chiếu, dùng lại giao dịch,
// onChainVcId do client khai, phát lại accept_root), S-04, P-10, và B8-T6/T7.
import { Account } from "@aptos-labs/ts-sdk";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { fakeEnvelope } from "./lib-envelope.mjs";

const PORT = Number(process.env.MOCK_PORT ?? 4099);
// Đặt TS_BASE=skip hoặc GO_BASE=skip để chỉ chạy một phía.
const SIDES = [["TS", process.env.TS_BASE ?? "http://localhost:4095/api"], ["Go", process.env.GO_BASE ?? "http://localhost:4096/api"]]
  .filter(([, base]) => base !== "skip");
const CONTRACT = readFileSync(new URL("../../chain.env", import.meta.url), "utf8").match(/^CONTRACT_ADDRESS=(\S+)/m)[1].toLowerCase();

const results = [];
const check = (name, passed, detail = "") => {
  results.push({ name, passed });
  console.log(`${passed ? "  PASS" : "  FAIL"}  ${name}${detail ? "  → " + detail : ""}`);
};

// ---------- fullnode giả ----------
// MOCK_ADDR_FORM=long: in địa chỉ đầy đủ — chỉ để chứng minh các phép S-02 đỏ
// đúng nguyên nhân trên mã chưa sửa S-04 (nếu không, S-04 chặn mọi giao dịch trước).
const LONG = process.env.MOCK_ADDR_FORM === "long";
const short = (a) => LONG ? "0x" + a.replace(/^0x/, "").padStart(64, "0") : "0x" + (a.replace(/^0x/, "").replace(/^0+/, "") || "0");
const norm = (a) => "0x" + String(a).replace(/^0x/, "").toLowerCase().padStart(64, "0");
const hexOf = (s) => "0x" + Buffer.from(s, "utf8").toString("hex");
const C = short(CONTRACT);
const state = { admins: new Set(), issuers: new Set(), root: CONTRACT, dids: new Map(), txs: new Map(), roles: new Map(), vcs: new Map(),
  // Nâng cấp 13/11: liên kết thay thế (C3) và DID theo chủ sở hữu (P4.1).
  replacements: new Map(), owners: new Map(), ownerStatus: new Map() };

// Giao dịch giả được coi là ĐÃ CHẠY trên chuỗi: áp hệ quả của nó vào trạng thái,
// để các view đọc lại (get_info, get_vc_status) trả đúng điều chuỗi thật sẽ trả.
// Backend kiểm trạng thái hiện tại sau khi xác minh giao dịch (chống phát lại),
// nên một fullnode giả có trạng thái cố định sẽ làm hỏng chính các ca hợp lệ.
const ROLE_FX = { approve_issuer: 1, grant_admin: 1, reactivate_issuer: 1, revoke_issuer: 2, revoke_admin: 2, suspend_issuer: 3 };
const VC_FX = { suspend_vc: 2, admin_suspend_vc: 2, admin_reinstate_vc: 1, revoke_vc: 4, admin_revoke_vc: 4 };
function apply(fn, args, events) {
  const [mod, name] = fn.split("::");
  if (mod === "authority" && ROLE_FX[name]) {
    const a = norm(args[0]);
    const prev = state.roles.get(a) ?? { mask: 0 };
    const mask = name === "approve_issuer" ? Number(args[1]) : name === "grant_admin" ? 0 : prev.mask;
    state.roles.set(a, { status: ROLE_FX[name], mask });
  }
  if (mod === "vc_registry" && VC_FX[name]) state.vcs.set(String(args[0]), VC_FX[name]);
  if (fn === "vc_registry::issue_vc") for (const e of events) state.vcs.set(String(e.data.id), 1);
  // C2: hợp đồng chỉ đổi những mục ghi trong VCBatchProcessedEvent.changed.
  const BATCH_FX = { admin_suspend_vcs: 2, admin_revoke_vcs: 4, delegator_suspend_vcs: 2, delegator_revoke_vcs: 4 };
  if (mod === "vc_registry" && BATCH_FX[name]) {
    for (const e of events) if (e.type.endsWith("VCBatchProcessedEvent")) for (const id of e.data.changed) state.vcs.set(String(id), BATCH_FX[name]);
  }
  // C3: cấp lại = cấp mới + thu hồi cũ + liên kết; nối = thu hồi cũ (nếu chưa) + liên kết.
  if (fn === "vc_registry::reissue_vc") {
    for (const e of events) {
      if (e.type.endsWith("VCIssuedEvent")) state.vcs.set(String(e.data.id), 1);
      if (e.type.endsWith("VCReplacedEvent")) { state.vcs.set(String(e.data.old_id), 4); state.replacements.set(String(e.data.old_id), String(e.data.new_id)); }
    }
  }
  if (fn === "vc_registry::admin_link_replacement") { state.vcs.set(String(args[0]), 4); state.replacements.set(String(args[0]), String(args[1])); }
}
function applyOwn(sender, fn) {
  if (fn === "did_registry::suspend_own_did") state.ownerStatus.set(norm(sender), 2);
  if (fn === "did_registry::reactivate_own_did") state.ownerStatus.set(norm(sender), 1);
}

function tx(sender, fn, args, events = []) {
  apply(fn, args, events);
  applyOwn(sender, fn);
  const hash = "0x" + randomBytes(32).toString("hex");
  state.txs.set(hash, {
    hash, success: true, vm_status: "Executed successfully", sender: short(sender), version: "1", timestamp: "0",
    payload: { type: "entry_function_payload", function: `${C}::${fn}`, type_arguments: [], arguments: args },
    events,
  });
  return hash;
}
function view(fn, args) {
  const name = fn.split("::").slice(1).join("::");
  if (norm(fn.split("::")[0]) !== norm(CONTRACT)) return null;
  switch (name) {
    case "authority::is_active_admin": return [state.admins.has(norm(args[0]))];
    case "authority::is_active_issuer": return [state.issuers.has(norm(args[0]))];
    case "authority::can_delegate": return [false];
    case "authority::get_root_admin": return [short(state.root)];
    case "authority::get_pending_root": return ["0x0"];
    case "did_registry::resolve_did": {
      const d = state.dids.get(String(args[0]).toLowerCase());
      return d ? [args[0], hexOf(d.cid), d.hash, 1, "1"] : null;
    }
    case "did_registry::has_active_did": return [(state.ownerStatus.get(norm(args[0])) ?? 1) === 1];
    case "did_registry::resolve_did_by_owner": {
      const o = state.owners.get(norm(args[0]));
      return o ? [hexOf(o.did), hexOf(o.cid), o.hash, state.ownerStatus.get(norm(args[0])) ?? 1, "1"] : null;
    }
    case "vc_registry::get_vc_status": return [state.vcs.get(String(args[0])) ?? 1];
    case "vc_registry::get_replacement": {
      const n = state.replacements.get(String(args[0]));
      return n === undefined ? [false, "0"] : [true, n];
    }
    case "authority::get_info": {
      const r = state.roles.get(norm(args[0]));
      return r ? [short(CONTRACT), String(r.mask), "0x", "0x", "0", r.status] : null;
    }
    default: return null;
  }
}
const server = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const send = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
    const url = req.url ?? "";
    if (url === "/v1/" || url === "/v1") return send(200, { chain_id: 250, ledger_version: "1" });
    const m = url.match(/^\/v1\/transactions\/by_hash\/(0x[0-9a-f]+)$/i);
    if (m) return state.txs.has(m[1].toLowerCase()) ? send(200, state.txs.get(m[1].toLowerCase())) : send(404, { message: "not found" });
    if (url === "/v1/view" && req.method === "POST") {
      try {
        const { function: fn, arguments: args } = JSON.parse(body);
        const out = view(fn, args ?? []);
        return out ? send(200, out) : send(400, { message: "Move abort" });
      } catch { return send(400, { message: "bad" }); }
    }
    send(404, { message: "no route" });
  });
});
await new Promise((ok, fail) => server.once("error", fail).listen(PORT, "127.0.0.1", ok));

// ---------- tiện ích gọi API ----------
async function call(base, method, path, body, token) {
  const r = await fetch(base + path, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = await r.text();
  let data; try { data = JSON.parse(t); } catch { data = t.slice(0, 200); }
  return { status: r.status, data };
}
function canonical(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
const sha3 = (v) => "0x" + createHash("sha3-256").update(typeof v === "string" ? v : canonical(v)).digest("hex");
const cidOf = () => "b" + Array.from(randomBytes(58), (b) => "abcdefghijklmnopqrstuvwxyz234567"[b % 32]).join("");
const err = (r) => (typeof r.data === "object" ? r.data?.error : r.data) ?? "";

async function actor(base, role, onChain) {
  const acct = Account.generate();
  const address = acct.accountAddress.toStringLong();
  if (onChain === "admin") state.admins.add(address);
  if (onChain === "issuer") state.issuers.add(address);
  const did = `did:vnu:${role}:${address}`;
  const reg = await call(base, "POST", "/entities/register", { address, publicKeyHex: acct.publicKey.toString(), did, role, label: "Kiểm thử giao dịch" });
  if (reg.status !== 201) throw new Error(`đăng ký ${role} lỗi ${reg.status}: ${err(reg)}`);
  const ch = await call(base, "POST", "/auth/challenge", { address });
  const signature = acct.sign(new TextEncoder().encode(ch.data.data.message)).toString();
  const vf = await call(base, "POST", "/auth/verify", { address, nonce: ch.data.data.nonce, signature });
  return { address, did, token: vf.data.data.token };
}

const statuses = {};
async function run(side, base) {
  const rec = (key, r) => { (statuses[key] ??= {})[side] = r.status; return r; };
  console.log(`\n=== ${side} (${base}) ===`);
  const health = await call(base, "GET", "/health");
  if (health.data?.data?.verifyOnChain !== true) { check(`${side}: backend chạy chế độ nghiêm ngặt`, false, "verifyOnChain != true"); return; }

  // --- DID ---
  const h = await actor(base, "holder");
  const other = await actor(base, "holder");
  const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: h.did };
  const cid1 = cidOf(), cid2 = cidOf();
  const didArgs = [hexOf(h.did), hexOf(cid1), sha3(doc)];
  const good = tx(h.address, "did_registry::register_did", didArgs);
  const save = (cid, txHash) => call(base, "POST", "/did/save", { did: h.did, documentCid: cid, documentHash: sha3(doc), docJson: doc, txHash }, h.token);

  // Mỗi phép "bị từ chối" phải bị từ chối ĐÚNG Ở BƯỚC ĐANG KIỂM (bài học 2):
  // lượt đầu viết bộ này, ca "người gửi khác" PASS vì bị bước P-10 chặn trước,
  // nên phá phép kiểm người gửi mà bộ vẫn xanh. `why` là mẩu thông điệp lỗi.
  const no = (r, why) => r.status === 400 && err(r).includes(why);
  let r = rec("did-cid", await save(cid2, good));
  check(`${side} S-02 /did/save: CID khác CID trong giao dịch → 400`, no(r, "Tham số thứ 2"), `${r.status} ${err(r)}`);
  r = rec("did-missing", await save(cid1, good));
  check(`${side} P-10 /did/save: DID chưa đọc được trên chuỗi → 400`, no(r, "Không đọc được DID"), `${r.status} ${err(r)}`);
  state.dids.set(hexOf(h.did).toLowerCase(), { cid: cid1, hash: sha3(doc) });
  // Cùng tham số, khác hàm — chỉ phép kiểm tên hàm chặn được.
  r = rec("did-fn", await save(cid1, tx(h.address, "did_registry::update_did_document", didArgs)));
  check(`${side} B8-T7 /did/save: giao dịch gọi hàm khác → 400`, no(r, "gọi hàm"), `${r.status} ${err(r)}`);
  // Cùng hàm, cùng tham số, khác người gửi — chỉ phép kiểm người gửi chặn được.
  r = rec("did-sender", await save(cid1, tx(other.address, "did_registry::register_did", didArgs)));
  check(`${side} B8-T6 /did/save: giao dịch của người khác → 400`, no(r, "Người gửi"), `${r.status} ${err(r)}`);
  r = rec("did-ok", await save(cid1, good));
  check(`${side} S-04 /did/save: giao dịch đúng (tên hàm in dạng rút gọn) → 201`, r.status === 201, `${r.status} ${err(r)}`);

  // --- Quyền hạn ---
  const admin = await actor(base, "admin", "admin");
  const x = await actor(base, "holder"), y = await actor(base, "holder");
  const approve = tx(admin.address, "authority::approve_issuer", [short(x.address), "1", "0x", "0x", "0"]);
  r = rec("auth-target", await call(base, "POST", "/admin/authority/issuers", { address: y.address, vcTypeMask: 1, expiresAt: 0, txHash: approve }, admin.token));
  check(`${side} S-02 approve_issuer dùng cho địa chỉ khác → 400`, no(r, "Tham số thứ 1"), `${r.status} ${err(r)}`);
  r = rec("auth-mask", await call(base, "POST", "/admin/authority/issuers", { address: x.address, vcTypeMask: 2, expiresAt: 0, txHash: approve }, admin.token));
  check(`${side} S-02 approve_issuer khai mặt nạ khác giao dịch → 400`, no(r, "Tham số thứ 2"), `${r.status} ${err(r)}`);
  r = rec("auth-ok", await call(base, "POST", "/admin/authority/issuers", { address: x.address, vcTypeMask: 1, expiresAt: 0, txHash: approve }, admin.token));
  check(`${side} approve_issuer đúng địa chỉ + mặt nạ → 201`, r.status === 201, `${r.status} ${err(r)}`);

  // accept_root cũ
  const ex = await actor(base, "holder");
  const accept = tx(ex.address, "authority::accept_root", []);
  r = rec("root-replay", await call(base, "POST", "/authority/root/accept", { txHash: accept }, ex.token));
  check(`${side} S-02 phát lại accept_root khi chuỗi nói root là người khác → 403`, r.status === 403 && err(r).includes("accept_root đã cũ"), `${r.status} ${err(r)}`);

  // --- Văn bằng ---
  const issuer = await actor(base, "issuer", "issuer");
  // P3: máy chủ kiểm cấu trúc phong bì TRƯỚC khi xác minh giao dịch (rẻ trước, đắt sau),
  // nên mỗi ca "sai tham số giao dịch" phải mang phong bì ĐÚNG cho dữ liệu nó khai —
  // nếu không nó bị chặn ở bước phong bì và PASS vì lý do sai (bài học #2).
  const pinEnv = async (vid, holderAddr) =>
    (await call(base, "POST", "/ipfs/pin", { json: fakeEnvelope(sha3(vid), holderAddr, issuer.address), name: "vc" }, issuer.token)).data.data.cid;
  const vcId = "urn:uuid:" + randomUUID();
  const vcJson = { id: vcId, issuer: issuer.did, credentialSubject: { id: h.did } };
  const cid = await pinEnv(vcId, h.address);
  const issueArgs = [short(h.address), "1", sha3(vcId), hexOf(cid), sha3(vcJson), "0"];
  const ev = [{ type: `${C}::vc_registry::VCIssuedEvent`, data: { id: "41", holder_addr: short(h.address), holder_did: hexOf(h.did) } }];
  const issueTx = tx(issuer.address, "vc_registry::issue_vc", issueArgs, ev);
  const body = (over = {}) => ({
    vcId, onChainVcId: 41, holderDid: h.did, holderAddress: h.address, vcType: 1, ipfsCid: cid,
    vcIdHash: sha3(vcId), contentHash: sha3(vcJson), proofValue: "z".repeat(32),
    issuedAt: new Date().toISOString(), expiresAt: null, txHash: issueTx, ...over,
  });
  r = rec("vc-id", await call(base, "POST", "/issuer/credentials", body({ onChainVcId: 42 }), issuer.token));
  check(`${side} S-02 onChainVcId khác sự kiện VCIssuedEvent → 400`, no(r, "onChainVcId"), `${r.status} ${err(r)}`);
  const vcJsonY = { id: vcId, issuer: issuer.did, credentialSubject: { id: y.did } };
  r = rec("vc-holder", await call(base, "POST", "/issuer/credentials", body({ holderDid: y.did, holderAddress: y.address, contentHash: sha3(vcJsonY), ipfsCid: await pinEnv(vcId, y.address) }), issuer.token));
  check(`${side} S-02 cấp cho holder khác holder trong giao dịch → 400`, no(r, "Tham số thứ 1"), `${r.status} ${err(r)}`);
  r = rec("vc-type", await call(base, "POST", "/issuer/credentials", body({ vcType: 4 }), issuer.token));
  check(`${side} S-02 khai loại văn bằng khác giao dịch → 400`, no(r, "Tham số thứ 2"), `${r.status} ${err(r)}`);
  r = rec("vc-ok", await call(base, "POST", "/issuer/credentials", body(), issuer.token));
  check(`${side} cấp văn bằng khớp giao dịch → 201, lưu số hiệu 41`, r.status === 201 && Number(r.data?.data?.on_chain_vc_id) === 41, `${r.status} ${err(r)}`);
  const vcId2 = "urn:uuid:" + randomUUID();
  const vcJson2 = { id: vcId2, issuer: issuer.did, credentialSubject: { id: h.did } };
  r = rec("vc-reuse", await call(base, "POST", "/issuer/credentials", body({ vcId: vcId2, vcIdHash: sha3(vcId2), contentHash: sha3(vcJson2), ipfsCid: await pinEnv(vcId2, h.address) }), issuer.token));
  check(`${side} S-02 dùng lại giao dịch issue_vc cho văn bằng thứ hai → 400`, no(r, "Tham số thứ 3"), `${r.status} ${err(r)}`);

  const enc = encodeURIComponent(vcId);

  // --- Chống phát lại (2026-11-13): giao dịch có thật nhưng CŨ ---
  // Issuer tạm ngưng, admin kích hoạt lại, rồi issuer gửi lại ĐÚNG giao dịch tạm
  // ngưng cũ: đúng hàm, đúng người gửi, đúng số hiệu VC — chỉ phép kiểm trạng
  // thái hiện tại trên chuỗi chặn được.
  const suspendTx = tx(issuer.address, "vc_registry::suspend_vc", ["41", hexOf("tạm ngưng")]);
  r = rec("st-suspend", await call(base, "POST", `/issuer/credentials/${enc}/suspend`, { reason: "kiểm thử", txHash: suspendTx }, issuer.token));
  check(`${side} issuer tạm ngưng VC bằng giao dịch đúng → 200`, r.status === 200, `${r.status} ${err(r)}`);
  const reinstateTx = tx(admin.address, "vc_registry::admin_reinstate_vc", ["41", hexOf("kích hoạt lại")]);
  r = rec("st-reinstate", await call(base, "POST", `/admin/credentials/${enc}/reinstate`, { reason: "kiểm thử", txHash: reinstateTx }, admin.token));
  check(`${side} admin kích hoạt lại VC → 200`, r.status === 200, `${r.status} ${err(r)}`);
  r = rec("st-replay", await call(base, "POST", `/issuer/credentials/${enc}/suspend`, { reason: "phát lại", txHash: suspendTx }, issuer.token));
  check(`${side} phát lại giao dịch tạm ngưng CŨ sau khi admin kích hoạt lại → 409`,
    r.status === 409 && err(r).includes("giao dịch đã cũ"), `${r.status} ${err(r)}`);
  // Admin tạm ngưng phải dùng admin_suspend_vc; gửi suspend_vc (hàm của issuer) bị từ chối.
  r = rec("st-admin-fn", await call(base, "POST", `/admin/credentials/${enc}/suspend`, { reason: "kiểm thử", txHash: tx(admin.address, "vc_registry::suspend_vc", ["41", hexOf("x")]) }, admin.token));
  check(`${side} admin tạm ngưng bằng suspend_vc (hàm của issuer) → 400`, no(r, "gọi hàm"), `${r.status} ${err(r)}`);

  // Phát lại revoke_issuer cũ sau khi issuer được cấp lại: chỉ mục không được hạ vai trò.
  const revokeIss = tx(admin.address, "authority::revoke_issuer", [short(x.address), hexOf("thu hồi")]);
  r = rec("role-revoke", await call(base, "POST", `/admin/authority/issuers/${x.address}/status`, { status: "revoked", reason: "kiểm thử", txHash: revokeIss }, admin.token));
  check(`${side} thu hồi issuer bằng giao dịch đúng → 200`, r.status === 200, `${r.status} ${err(r)}`);
  const reapprove = tx(admin.address, "authority::approve_issuer", [short(x.address), "1", "0x", "0x", "0"]);
  r = rec("role-reapprove", await call(base, "POST", "/admin/authority/issuers", { address: x.address, vcTypeMask: 1, expiresAt: 0, txHash: reapprove }, admin.token));
  check(`${side} cấp lại issuer → 201`, r.status === 201, `${r.status} ${err(r)}`);
  r = rec("role-replay", await call(base, "POST", `/admin/authority/issuers/${x.address}/status`, { status: "revoked", reason: "phát lại", txHash: revokeIss }, admin.token));
  check(`${side} phát lại revoke_issuer CŨ sau khi cấp lại → 409`,
    r.status === 409 && err(r).includes("giao dịch đã cũ"), `${r.status} ${err(r)}`);

  // ===== Nâng cấp 13/11/2026: C2 (theo lô), C3 (cấp lại / nối), P4.1 (tự khoá DID) =====
  const issueOne = async (id) => {
    const vid = "urn:uuid:" + randomUUID();
    const json = { id: vid, issuer: issuer.did, credentialSubject: { id: h.did } };
    const c = await pinEnv(vid, h.address);
    const t = tx(issuer.address, "vc_registry::issue_vc", [short(h.address), "1", sha3(vid), hexOf(c), sha3(json), "0"],
      [{ type: `${C}::vc_registry::VCIssuedEvent`, data: { id: String(id), holder_addr: short(h.address), holder_did: hexOf(h.did) } }]);
    const res = await call(base, "POST", "/issuer/credentials", {
      vcId: vid, onChainVcId: id, holderDid: h.did, holderAddress: h.address, vcType: 1, ipfsCid: c,
      vcIdHash: sha3(vid), contentHash: sha3(json), proofValue: "z".repeat(32),
      issuedAt: new Date().toISOString(), expiresAt: null, txHash: t,
    }, issuer.token);
    if (res.status !== 201) throw new Error(`cấp VC ${id} lỗi ${res.status}: ${err(res)}`);
    return vid;
  };
  const batchEv = (changed, skipped = []) => [{ type: `${C}::vc_registry::VCBatchProcessedEvent`, data: { new_status: 4, changed, skipped } }];
  const [v51, v52, v53] = [await issueOne(51), await issueOne(52), await issueOne(53)];
  const reasonB = "xem xét theo lô";
  const batchBody = (ids, txHash, action = "revoke") => ({ action, vcIds: ids, reason: reasonB, txHash });
  // Thứ tự id phải TĂNG DẦN như hợp đồng đòi: giao dịch ["52","51"] không khớp danh sách backend sắp lại.
  let bt = tx(admin.address, "vc_registry::admin_revoke_vcs", [["52", "51"], hexOf(reasonB)], []);
  r = rec("c2-order", await call(base, "POST", "/admin/credentials/batch", batchBody([v51, v52], bt), admin.token));
  check(`${side} C2 lô: id trong giao dịch không đúng thứ tự tăng dần → 400`, no(r, "Tham số thứ 1"), `${r.status} ${err(r)}`);
  bt = tx(admin.address, "vc_registry::admin_revoke_vcs", [["51", "52"], hexOf("lý do khác")], []);
  r = rec("c2-reason", await call(base, "POST", "/admin/credentials/batch", batchBody([v51, v52], bt), admin.token));
  check(`${side} C2 lô: lý do khác lý do trên chuỗi → 400`, no(r, "Tham số thứ 2"), `${r.status} ${err(r)}`);
  bt = tx(admin.address, "vc_registry::admin_suspend_vcs", [["51", "52"], hexOf(reasonB)], []);
  r = rec("c2-fn", await call(base, "POST", "/admin/credentials/batch", batchBody([v51, v52], bt), admin.token));
  check(`${side} C2 lô: action revoke nhưng giao dịch admin_suspend_vcs → 400`, no(r, "gọi hàm"), `${r.status} ${err(r)}`);
  bt = tx(admin.address, "vc_registry::admin_revoke_vcs", [["51", "52"], hexOf(reasonB)], []);
  r = rec("c2-noevent", await call(base, "POST", "/admin/credentials/batch", batchBody([v51, v52], bt), admin.token));
  check(`${side} C2 lô: giao dịch không phát VCBatchProcessedEvent → 400`, no(r, "VCBatchProcessedEvent"), `${r.status} ${err(r)}`);
  // Hợp đồng bỏ qua 52 (đổi 51) — backend ghi theo SỰ KIỆN, không theo danh sách client gửi.
  bt = tx(admin.address, "vc_registry::admin_revoke_vcs", [["51", "52"], hexOf(reasonB)], batchEv(["51"], ["52"]));
  r = rec("c2-ok", await call(base, "POST", "/admin/credentials/batch", batchBody([v51, v52], bt), admin.token));
  const d = r.data?.data ?? {};
  check(`${side} C2 lô hợp lệ: ghi đúng mục sự kiện báo đổi (51), bỏ qua 52 → 200`,
    r.status === 200 && d.changed?.length === 1 && d.changed[0] === v51 && d.skipped?.[0] === v52, `${r.status} ${JSON.stringify(d)}`);
  // Phát lại lô tạm ngưng CŨ sau khi admin kích hoạt lại → mọi mục đều cũ → 409.
  const sus53 = tx(admin.address, "vc_registry::admin_suspend_vcs", [["53"], hexOf(reasonB)], [{ type: `${C}::vc_registry::VCBatchProcessedEvent`, data: { new_status: 2, changed: ["53"], skipped: [] } }]);
  r = rec("c2-sus", await call(base, "POST", "/admin/credentials/batch", batchBody([v53], sus53, "suspend"), admin.token));
  check(`${side} C2 lô tạm ngưng → 200`, r.status === 200, `${r.status} ${err(r)}`);
  r = rec("c2-reinstate", await call(base, "POST", `/admin/credentials/${encodeURIComponent(v53)}/reinstate`, { reason: "kiểm thử", txHash: tx(admin.address, "vc_registry::admin_reinstate_vc", ["53", hexOf("x")]) }, admin.token));
  r = rec("c2-replay", await call(base, "POST", "/admin/credentials/batch", batchBody([v53], sus53, "suspend"), admin.token));
  check(`${side} C2 phát lại lô tạm ngưng CŨ sau khi kích hoạt lại → 409`, r.status === 409 && err(r).includes("giao dịch đã cũ"), `${r.status} ${err(r)}`);

  // --- C3: cấp lại ---
  const v61 = await issueOne(61);
  const nid = "urn:uuid:" + randomUUID();
  const njson = { id: nid, issuer: issuer.did, credentialSubject: { id: h.did }, "vnu:replaces": v61 };
  const ncid = await pinEnv(nid, h.address);
  const reArgs = (old) => [old, short(h.address), "1", sha3(nid), hexOf(ncid), sha3(njson), "0"];
  const issued62 = { type: `${C}::vc_registry::VCIssuedEvent`, data: { id: "62", holder_addr: short(h.address), holder_did: hexOf(h.did) } };
  const replaced = { type: `${C}::vc_registry::VCReplacedEvent`, data: { old_id: "61", new_id: "62" } };
  const reBody = (txHash) => ({
    vcId: nid, onChainVcId: 62, holderDid: h.did, holderAddress: h.address, vcType: 1, ipfsCid: ncid,
    vcIdHash: sha3(nid), contentHash: sha3(njson), proofValue: "z".repeat(32),
    issuedAt: new Date().toISOString(), expiresAt: null, txHash,
  });
  r = rec("c3-old", await call(base, "POST", `/issuer/credentials/${encodeURIComponent(v61)}/reissue`,
    reBody(tx(issuer.address, "vc_registry::reissue_vc", reArgs("60"), [issued62, replaced])), issuer.token));
  check(`${side} C3 cấp lại: giao dịch nhắm văn bằng cũ khác → 400`, no(r, "Tham số thứ 1"), `${r.status} ${err(r)}`);
  r = rec("c3-issue-fn", await call(base, "POST", `/issuer/credentials/${encodeURIComponent(v61)}/reissue`,
    reBody(tx(issuer.address, "vc_registry::issue_vc", reArgs("61").slice(1), [issued62])), issuer.token));
  check(`${side} C3 cấp lại bằng giao dịch issue_vc (không thu hồi cũ) → 400`, no(r, "gọi hàm"), `${r.status} ${err(r)}`);
  state.replacements.delete("61"); state.vcs.set("61", 1);
  r = rec("c3-noevent", await call(base, "POST", `/issuer/credentials/${encodeURIComponent(v61)}/reissue`,
    reBody(tx(issuer.address, "vc_registry::reissue_vc", reArgs("61"), [issued62])), issuer.token));
  check(`${side} C3 cấp lại: thiếu VCReplacedEvent → 400`, no(r, "VCReplacedEvent"), `${r.status} ${err(r)}`);
  r = rec("c3-ok", await call(base, "POST", `/issuer/credentials/${encodeURIComponent(v61)}/reissue`,
    reBody(tx(issuer.address, "vc_registry::reissue_vc", reArgs("61"), [issued62, replaced])), issuer.token));
  check(`${side} C3 cấp lại khớp giao dịch + sự kiện + chuỗi → 201`, r.status === 201 && r.data?.data?.replaces_vc_id === v61, `${r.status} ${err(r)}`);

  // --- C3: admin nối liên kết + chống phát lại ---
  const [v71, v72, v81, v82] = [await issueOne(71), await issueOne(72), await issueOne(81), await issueOne(82)];
  r = rec("c3-link-args", await call(base, "POST", `/admin/credentials/${encodeURIComponent(v71)}/replacement`,
    { newVcId: v72, txHash: tx(admin.address, "vc_registry::admin_link_replacement", ["71", "73"]) }, admin.token));
  check(`${side} C3 nối: giao dịch nhắm văn bằng mới khác → 400`, no(r, "Tham số thứ 2"), `${r.status} ${err(r)}`);
  state.replacements.delete("71"); state.vcs.set("71", 1);
  r = rec("c3-link-ok", await call(base, "POST", `/admin/credentials/${encodeURIComponent(v71)}/replacement`,
    { newVcId: v72, txHash: tx(admin.address, "vc_registry::admin_link_replacement", ["71", "72"]) }, admin.token));
  check(`${side} C3 nối liên kết khớp giao dịch → 200`, r.status === 200, `${r.status} ${err(r)}`);
  const link81 = tx(admin.address, "vc_registry::admin_link_replacement", ["81", "82"]);
  state.replacements.set("81", "999"); // chuỗi hiện ghi liên kết khác — giao dịch đã cũ
  r = rec("c3-link-stale", await call(base, "POST", `/admin/credentials/${encodeURIComponent(v81)}/replacement`,
    { newVcId: v82, txHash: link81 }, admin.token));
  check(`${side} C3 nối: chuỗi đang ghi liên kết khác → 409`, r.status === 409 && err(r).includes("đang được thay bằng"), `${r.status} ${err(r)}`);

  // --- P4.1: tự khoá DID ---
  state.owners.set(norm(h.address), { did: h.did, cid: cid1, hash: sha3(doc) });
  r = rec("p41-fn", await call(base, "POST", "/did/self-status", { status: "suspended", txHash: tx(h.address, "did_registry::reactivate_own_did", []) }, h.token));
  check(`${side} P4.1 tự khoá bằng giao dịch reactivate_own_did → 400`, no(r, "gọi hàm"), `${r.status} ${err(r)}`);
  r = rec("p41-sender", await call(base, "POST", "/did/self-status", { status: "suspended", txHash: tx(other.address, "did_registry::suspend_own_did", []) }, h.token));
  check(`${side} P4.1 tự khoá bằng giao dịch của người khác → 400`, no(r, "Người gửi"), `${r.status} ${err(r)}`);
  const selfLock = tx(h.address, "did_registry::suspend_own_did", []);
  r = rec("p41-ok", await call(base, "POST", "/did/self-status", { status: "suspended", txHash: selfLock }, h.token));
  check(`${side} P4.1 tự khoá DID bằng giao dịch đúng → 200`, r.status === 200, `${r.status} ${err(r)}`);
  r = rec("p41-open", await call(base, "POST", "/did/self-status", { status: "active", txHash: tx(h.address, "did_registry::reactivate_own_did", []) }, h.token));
  check(`${side} P4.1 tự mở DID → 200`, r.status === 200, `${r.status} ${err(r)}`);
  r = rec("p41-replay", await call(base, "POST", "/did/self-status", { status: "suspended", txHash: selfLock }, h.token));
  check(`${side} P4.1 phát lại giao dịch tự khoá CŨ sau khi đã mở → 409`, r.status === 409 && err(r).includes("giao dịch đã cũ"), `${r.status} ${err(r)}`);

  const wrong = tx(issuer.address, "vc_registry::revoke_vc", ["99", hexOf("lý do")]);
  r = rec("st-wrong", await call(base, "POST", `/issuer/credentials/${enc}/revoke`, { reason: "kiểm thử", txHash: wrong }, issuer.token));
  check(`${side} S-02 thu hồi bằng giao dịch của VC khác → 400`, no(r, "Tham số thứ 1"), `${r.status} ${err(r)}`);
  const right = tx(issuer.address, "vc_registry::revoke_vc", ["41", hexOf("lý do")]);
  r = rec("st-ok", await call(base, "POST", `/issuer/credentials/${enc}/revoke`, { reason: "kiểm thử", txHash: right }, issuer.token));
  check(`${side} thu hồi bằng giao dịch đúng VC → 200`, r.status === 200, `${r.status} ${err(r)}`);
}

try {
  for (const [side, base] of SIDES) await run(side, base);
  for (const [key, v] of Object.entries(statuses)) {
    if (v.TS !== undefined && v.Go !== undefined && v.TS !== v.Go) check(`đối chiếu ${key}: TS=${v.TS} Go=${v.Go}`, false);
  }
} catch (e) {
  check("kịch bản chạy hết", false, String(e?.message ?? e));
} finally {
  server.close();
}
const failed = results.filter((r) => !r.passed);
console.log(`\n${results.length - failed.length}/${results.length} PASS  — ${failed.length ? failed.length + " FAIL" : "xác minh giao dịch đối chiếu đủ tham số"}`);
process.exit(failed.length ? 1 : 0);
