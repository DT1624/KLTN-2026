import { createHash } from "node:crypto";
import { query, queryOne } from "../db/pool.js";
import { notFound, badRequest, conflict, forbidden } from "../utils/errors.js";
import { verifyTransaction, findEvent, type ArgSpec, type OnChainTx } from "../chain/client.js";
import type { PoolClient } from "pg";
import { ENTRY, MODULE, VC_TYPE_LABEL } from "../chain/abi.js";
import { getVcStatusOnChain, utf8ToHex, hexToUtf8, vcRecordsOnChain } from "../chain/registry.js";
import { sha3_256Hex } from "./ipfs.service.js";
import type { CredentialRow, EntityRow, VcStatus } from "../types/index.js";
import { OFFLINE } from "../chain/offline.js";
import { record } from "./audit.service.js";
import { assertEnvelope } from "./envelope.service.js";

export interface IssueVcInput {
  issuer: EntityRow;
  vcId: string;
  onChainVcId: number;
  holderDid: string;
  holderAddress: string;
  vcType: number;
  ipfsCid: string;
  vcIdHash: string;
  contentHash: string;
  proofValue: string;
  issuedAt: string;
  expiresAt: string | null;
  txHash: string;
}

/**
 * Ghi nhận VC sau khi issuer đã gửi giao dịch issue_vc lên chuỗi.
 * Quyền issuer đã được requireOnChainRole kiểm ở tuyến; thứ tự dưới đây là rẻ
 * trước, đắt sau và phải giống hệt backend Go.
 */
export async function saveIssuedVc(input: IssueVcInput): Promise<CredentialRow> {
  const { issuer } = input;
  await assertIssueInput(input);

  // Tham số giao dịch phải đúng là văn bằng đang ghi (S-02): cùng holder, loại,
  // vc_id_hash, CID, content_hash và hạn. Nếu không, một giao dịch thật dùng được
  // cho bao nhiêu văn bằng tuỳ ý, với loại văn bằng mà issuer không được cấp.
  const tx = await verifyTransaction(input.txHash, {
    expectedFunction: ENTRY.issueVc,
    expectedSender: issuer.address,
    args: issueArgs(input),
  });
  assertIssuedEvent(tx, input);

  const row = await insertCredential(input, null);
  await record(issuer.address, "vc.issue", input.vcId, {
    holderDid: input.holderDid,
    vcType: input.vcType,
    txHash: input.txHash,
  });
  return row;
}

/**
 * Các phép kiểm của việc cấp VC trước khi chạm chuỗi (dùng chung cho issue_vc và
 * reissue_vc), đúng thứ tự backend Go: tự cấp → hạn → hash vcId → trùng → phong bì.
 *
 * P3 (13/11/2026): máy chủ KHÔNG còn thấy nội dung văn bằng nên không tính lại được
 * `contentHash` — phép kiểm đó đã bỏ (xem envelope.service.ts về rào thay thế).
 */
export async function assertIssueInput(input: IssueVcInput): Promise<void> {
  if (input.holderAddress === input.issuer.address) {
    throw badRequest("Đơn vị cấp không được tự cấp văn bằng cho chính mình");
  }
  if (input.expiresAt && new Date(input.expiresAt) <= new Date(input.issuedAt)) {
    throw badRequest("Thời điểm hết hạn phải sau thời điểm cấp");
  }
  // Contract dùng hash của vc_id làm khoá chống trùng.
  const idHash = "0x" + createHash("sha3-256").update(input.vcId).digest("hex");
  if (idHash !== input.vcIdHash) {
    throw badRequest(`Hash của vcId không khớp (tính được ${idHash})`);
  }
  if (await queryOne("SELECT 1 FROM credentials WHERE vc_id = $1", [input.vcId])) {
    throw conflict("VC này đã được ghi nhận");
  }
  await assertEnvelope(input.ipfsCid, input.vcIdHash, input.holderAddress, input.issuer.address);
}

/** Sáu tham số của issue_vc sau signer — reissue_vc dùng đúng sáu tham số này sau old_vc_id. */
export function issueArgs(input: IssueVcInput): ArgSpec[] {
  return [
    { address: input.holderAddress },
    { u64: input.vcType },
    { bytes: input.vcIdHash },
    { bytes: utf8ToHex(input.ipfsCid) },
    { bytes: input.contentHash },
    { u64: input.expiresAt ? Math.floor(Date.parse(input.expiresAt) / 1000) : 0 },
  ];
}

/**
 * Số hiệu on-chain và DID holder lấy từ sự kiện của CHÍNH giao dịch, không tin
 * con số client khai — bước xác minh thứ 7 đối chiếu nội dung theo số hiệu này.
 */
export function assertIssuedEvent(tx: OnChainTx, input: IssueVcInput): void {
  if (OFFLINE) return;
  const ev = findEvent(tx, `${MODULE.vcRegistry}::VCIssuedEvent`);
  if (!ev) throw badRequest("Giao dịch không phát VCIssuedEvent");
  if (String(ev.id) !== String(input.onChainVcId)) {
    throw badRequest(`onChainVcId không khớp sự kiện trên chuỗi (chuỗi ghi ${String(ev.id)})`);
  }
  if (hexToUtf8(String(ev.holder_did ?? "")) !== input.holderDid) {
    throw badRequest("holderDid không khớp DID của người nhận ghi trên chuỗi");
  }
}

export async function insertCredential(
  input: IssueVcInput,
  replacesVcId: string | null,
  db: Pick<PoolClient, "query"> | null = null,
): Promise<CredentialRow> {
  const sql = `INSERT INTO credentials
       (vc_id, on_chain_vc_id, issuer_did, issuer_address, holder_did, holder_address,
        vc_type, ipfs_cid, vc_id_hash, content_hash, proof_value,
        issued_at, expires_at, tx_hash, replaces_vc_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`;
  const params = [
    input.vcId, input.onChainVcId, input.issuer.did, input.issuer.address,
    input.holderDid, input.holderAddress, input.vcType, input.ipfsCid,
    input.vcIdHash, input.contentHash, input.proofValue,
    input.issuedAt, input.expiresAt, input.txHash, replacesVcId,
  ];
  const row = db
    ? ((await db.query<CredentialRow>(sql, params)).rows[0] ?? null)
    : await queryOne<CredentialRow>(sql, params);
  if (!row) throw new Error("Chèn credentials thất bại");
  return row;
}

export async function getByVcId(vcId: string): Promise<CredentialRow | null> {
  return queryOne<CredentialRow>("SELECT * FROM credentials WHERE vc_id = $1", [vcId]);
}

export async function requireByVcId(vcId: string): Promise<CredentialRow> {
  const vc = await getByVcId(vcId);
  if (!vc) throw notFound("Không tìm thấy VC");
  return vc;
}

export async function listByHolder(holderDid: string): Promise<CredentialRow[]> {
  return query<CredentialRow>(
    "SELECT * FROM credentials WHERE holder_did = $1 ORDER BY issued_at DESC",
    [holderDid],
  );
}

export async function listByIssuer(issuerDid: string, status?: VcStatus): Promise<CredentialRow[]> {
  return status
    ? query<CredentialRow>(
        "SELECT * FROM credentials WHERE issuer_did = $1 AND status = $2 ORDER BY issued_at DESC",
        [issuerDid, status],
      )
    : query<CredentialRow>(
        "SELECT * FROM credentials WHERE issuer_did = $1 ORDER BY issued_at DESC",
        [issuerDid],
      );
}

/**
 * Đổi trạng thái VC sau khi giao dịch tương ứng đã lên chuỗi.
 *
 * Hai đường, khớp contract (vc_registry::set_status):
 *  - admin/root: luôn dùng hàm `admin_*` — kể cả khi chính họ từng cấp VC này
 *    (một địa chỉ không thể vừa là admin vừa là issuer còn sống);
 *  - issuer đã cấp VC: `suspend_vc` / `revoke_vc`, KHÔNG kích hoạt lại được.
 * Luật chuyển trạng thái kiểm lại ở đây cho khớp contract: revoked là cuối,
 * suspended chỉ đi từ active và ngược lại.
 */
export async function changeStatus(
  vcId: string,
  actor: EntityRow,
  next: Extract<VcStatus, "suspended" | "revoked" | "active">,
  reason: string,
  txHash: string,
): Promise<CredentialRow> {
  const vc = await requireByVcId(vcId);

  const isAdmin = actor.role === "admin" || actor.role === "root";
  const isIssuer = vc.issuer_address === actor.address;
  if (!isIssuer && !isAdmin) throw forbidden("Chỉ issuer đã cấp hoặc admin mới đổi được trạng thái");

  if (vc.status === "revoked") throw conflict("VC đã bị thu hồi, không đổi được nữa");
  if (next === "suspended" && vc.status !== "active") {
    throw conflict("Chỉ tạm ngưng được VC đang hoạt động");
  }
  if (next === "active" && vc.status !== "suspended") {
    throw conflict("Chỉ kích hoạt lại được VC đang tạm ngưng");
  }
  // Contract chỉ cho admin kích hoạt lại, để tránh issuer tự ngưng/bật né kiểm toán.
  if (next === "active" && !isAdmin) {
    throw forbidden("Chỉ admin mới kích hoạt lại được VC đã tạm ngưng");
  }
  // M-06 (issuer bị tạm ngưng/thu hồi hoặc DID không ACTIVE thì không tự đổi
  // trạng thái VC) do contract chặn khi nối chuỗi; issuer bị thu hồi thì
  // requireRole("issuer") đã chặn ở tuyến. Chế độ offline không mô hình hoá
  // DID/tạm ngưng của vai trò (xem offline.ts), nên không kiểm thêm ở đây.

  const expectedFn = isAdmin
    ? { revoked: ENTRY.adminRevokeVc, suspended: ENTRY.adminSuspendVc, active: ENTRY.adminReinstateVc }[next]
    : next === "revoked" ? ENTRY.revokeVc : ENTRY.suspendVc;

  // Giao dịch phải nhắm đúng VC này (S-02): một giao dịch revoke_vc thật trước
  // đây dùng được để đánh dấu thu hồi BẤT KỲ VC nào trong chỉ mục.
  if (!OFFLINE && vc.on_chain_vc_id === null) {
    throw badRequest("VC này chưa có số hiệu on-chain — không đối chiếu được giao dịch");
  }
  await verifyTransaction(txHash, {
    expectedFunction: expectedFn,
    expectedSender: actor.address,
    args: vc.on_chain_vc_id === null ? [] : [{ u64: vc.on_chain_vc_id }],
  });

  // Chống phát lại: giao dịch có thật nhưng CŨ (vd. suspend_vc trước lần admin
  // kích hoạt lại) vẫn qua mọi phép kiểm trên. Chuỗi hiện tại phải đúng là trạng
  // thái sắp ghi, nếu không chỉ mục sẽ nói dối về trạng thái văn bằng.
  if (!OFFLINE && vc.on_chain_vc_id !== null) {
    const onChain = await getVcStatusOnChain(vc.on_chain_vc_id);
    if (onChain !== next) {
      throw conflict(`Trên chuỗi VC đang "${onChain ?? "không đọc được"}", không phải "${next}" — giao dịch đã cũ`);
    }
  }

  const row = await queryOne<CredentialRow>(
    `UPDATE credentials
        SET status = $2, status_reason = $3, status_tx_hash = $4, updated_at = now()
      WHERE vc_id = $1 RETURNING *`,
    [vcId, next, reason, txHash],
  );
  if (!row) throw new Error("Cập nhật trạng thái VC thất bại");
  const action = next === "revoked" ? "vc.revoke" : next === "suspended" ? "vc.suspend" : "vc.reinstate";
  await record(actor.address, action, vcId, { reason, txHash, byAdmin: isAdmin });
  return row;
}

/**
 * Trạng thái hiệu lực của VC: kết hợp trạng thái trên chuỗi, trạng thái
 * trong CSDL và hạn dùng. Chuỗi được ưu tiên khi hai bên lệch nhau.
 */
export async function effectiveStatus(vc: CredentialRow): Promise<{
  status: VcStatus;
  source: "chain" | "db-index" | "db";
  drift: boolean;
}> {
  if (vc.expires_at && vc.expires_at.getTime() <= Date.now()) {
    return { status: "expired", source: "db", drift: false };
  }
  if (vc.on_chain_vc_id !== null) {
    const chain = await getVcStatusOnChain(vc.on_chain_vc_id);
    if (chain) {
      return { status: chain, source: OFFLINE ? "db-index" : "chain", drift: chain !== vc.status };
    }
  }
  return { status: vc.status, source: "db", drift: false };
}

type Effective = { status: VcStatus; source: "chain" | "db-index" | "db"; drift: boolean };

/**
 * Trạng thái hiệu lực của NHIỀU VC với MỘT lần gọi view (P5) — cùng luật với
 * effectiveStatus: hết hạn theo CSDL trước, rồi trạng thái chuỗi (ưu tiên khi lệch).
 */
export async function effectiveStatuses(
  rows: CredentialRow[],
  pre?: Map<number, { status: VcStatus }>,
): Promise<Map<string, Effective>> {
  const chain = pre ?? await vcRecordsOnChain(rows.flatMap((r) => (r.on_chain_vc_id === null ? [] : [r.on_chain_vc_id])));
  const out = new Map<string, Effective>();
  for (const vc of rows) {
    if (vc.expires_at && vc.expires_at.getTime() <= Date.now()) {
      out.set(vc.vc_id, { status: "expired", source: "db", drift: false });
      continue;
    }
    const c = vc.on_chain_vc_id === null ? undefined : chain.get(vc.on_chain_vc_id);
    out.set(vc.vc_id, c
      ? { status: c.status, source: OFFLINE ? "db-index" : "chain", drift: c.status !== vc.status }
      : { status: vc.status, source: "db", drift: false });
  }
  return out;
}

/** Số liệu cho biểu đồ: theo trạng thái, theo tháng (12 tháng gần nhất) và theo loại. */
async function credentialBreakdown(issuerDid: string | null) {
  const where = issuerDid ? "WHERE issuer_did = $1" : "";
  const args = issuerDid ? [issuerDid] : [];
  const [byStatus, byMonth, byType] = await Promise.all([
    query<{ status: VcStatus; n: string }>(
      `SELECT status, count(*)::text AS n FROM credentials ${where} GROUP BY status`, args),
    query<{ month: string; n: string }>(
      `SELECT to_char(date_trunc('month', issued_at), 'YYYY-MM') AS month, count(*)::text AS n
         FROM credentials ${where ? where + " AND" : "WHERE"} issued_at >= date_trunc('month', now()) - interval '11 months'
        GROUP BY 1 ORDER BY 1`, args),
    query<{ vc_type: number; n: string }>(
      `SELECT vc_type, count(*)::text AS n FROM credentials ${where} GROUP BY vc_type ORDER BY vc_type`, args),
  ]);
  const status: Record<VcStatus, number> = { active: 0, suspended: 0, expired: 0, revoked: 0 };
  for (const r of byStatus) status[r.status] = Number(r.n);
  return {
    ...status,
    total: Object.values(status).reduce((a, b) => a + b, 0),
    byMonth: byMonth.map((r) => ({ month: r.month, count: Number(r.n) })),
    byType: byType.map((r) => ({ vcType: r.vc_type, label: vcTypeLabel(r.vc_type), count: Number(r.n) })),
  };
}

export const statsByIssuer = (issuerDid: string) => credentialBreakdown(issuerDid);

/** Bảng phân tích toàn hệ thống cho admin. */
export async function systemAnalytics() {
  const [credentials, topIssuers, verif] = await Promise.all([
    credentialBreakdown(null),
    query<{ issuer_did: string; label: string | null; n: string }>(
      `SELECT c.issuer_did, e.label, count(*)::text AS n
         FROM credentials c LEFT JOIN entities e ON e.did = c.issuer_did
        GROUP BY c.issuer_did, e.label ORDER BY count(*) DESC, c.issuer_did LIMIT 5`),
    queryOne<{ total: string; valid: string }>(
      "SELECT count(*)::text AS total, count(*) FILTER (WHERE overall_valid)::text AS valid FROM verifications"),
  ]);
  return {
    credentials,
    topIssuers: topIssuers.map((r) => ({ did: r.issuer_did, label: r.label, count: Number(r.n) })),
    verifications: { total: Number(verif?.total ?? 0), valid: Number(verif?.valid ?? 0) },
  };
}

export function vcTypeLabel(t: number): string {
  const exact = VC_TYPE_LABEL[t];
  if (exact) return exact;
  const parts = Object.entries(VC_TYPE_LABEL)
    .filter(([bit]) => (t & Number(bit)) !== 0)
    .map(([, label]) => label);
  return parts.length > 0 ? parts.join(", ") : `Loại ${t}`;
}
