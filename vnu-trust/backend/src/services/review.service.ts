import { query, queryOne, withTx } from "../db/pool.js";
import { badRequest, conflict, forbidden, notFound } from "../utils/errors.js";
import { verifyTransaction, findEvent, normalizeAddress, type OnChainTx } from "../chain/client.js";
import { ENTRY, MODULE } from "../chain/abi.js";
import {
  getVcStatusOnChain, getReplacementOnChain, getDelegator, hasActiveDid, utf8ToHex, resolveDidByOwner,
} from "../chain/registry.js";
import { OFFLINE } from "../chain/offline.js";
import { record } from "./audit.service.js";
import {
  requireByVcId, assertIssueInput, issueArgs, assertIssuedEvent, insertCredential,
  type IssueVcInput,
} from "./vc.service.js";
import type { CredentialRow, EntityRow } from "../types/index.js";

/**
 * Nâng cấp hợp đồng 13/11/2026:
 *  - C2: xem xét và xử lý văn bằng THEO LÔ (admin mọi VC; issuer cha VC của
 *    sub-issuer của mình). Thu hồi issuer không làm VC mất hiệu lực — cấp trên
 *    xem xét rồi quyết định.
 *  - C3: cấp lại văn bằng có liên kết cũ → mới ghi trên chuỗi.
 *  - P4.2: ghi liên kết ví cũ → ví mới khi holder mất khoá (chỉ ở CSDL).
 * Mọi hàm ở đây phải giống hệt backend Go (internal/handlers/review.go): cùng thứ
 * tự kiểm, cùng mã lỗi.
 */

export const MAX_BATCH = 100;
/** Lý do hợp đồng ghi vào VC cũ khi nó bị thay (vc_registry::REASON_REPLACED). */
export const REASON_REPLACED = "replaced";

export type BatchAction = "suspend" | "revoke";
export type BatchMode = "admin" | "parent";

export interface BatchResult {
  /** Đã đổi trạng thái trên chuỗi và đã ghi chỉ mục. */
  changed: string[];
  /** Hợp đồng bỏ qua (đã ở trạng thái đích, đã thu hồi, hoặc hết hạn khi tạm ngưng). */
  skipped: string[];
  /** Đã đổi trên chuỗi nhưng trạng thái HIỆN TẠI đã khác (có thao tác khác chen vào) — không ghi. */
  stale: string[];
}

const TARGET: Record<BatchAction, "suspended" | "revoked"> = { suspend: "suspended", revoke: "revoked" };

function batchFunction(mode: BatchMode, action: BatchAction): string {
  if (mode === "admin") return action === "revoke" ? ENTRY.adminRevokeVcs : ENTRY.adminSuspendVcs;
  return action === "revoke" ? ENTRY.delegatorRevokeVcs : ENTRY.delegatorSuspendVcs;
}

/** Luật bỏ qua của hợp đồng (vc_registry::batch_can_apply), áp lên chỉ mục khi offline. */
function canApply(vc: CredentialRow, target: "suspended" | "revoked"): boolean {
  if (vc.status === "revoked") return false;
  if (target === "revoked") return true;
  const expired = vc.expires_at !== null && vc.expires_at.getTime() <= Date.now();
  return vc.status === "active" && !expired;
}

/** Danh sách VC do một issuer cấp — để cấp trên xem xét (C2). */
export async function listIssuedBy(issuerAddress: string): Promise<CredentialRow[]> {
  return query<CredentialRow>(
    "SELECT * FROM credentials WHERE issuer_address = $1 ORDER BY on_chain_vc_id NULLS LAST, issued_at",
    [normalizeAddress(issuerAddress)],
  );
}

/** Issuer cha xem VC của sub-issuer: chỉ khi `sub` đúng là sub-issuer của mình. */
export async function listSubIssuerVcs(parent: EntityRow, sub: string): Promise<CredentialRow[]> {
  const subAddr = normalizeAddress(sub);
  if ((await getDelegator(subAddr)) !== parent.address) {
    throw forbidden("Địa chỉ này không phải sub-issuer do bạn cấp");
  }
  return listIssuedBy(subAddr);
}

/**
 * Ghi chỉ mục sau một giao dịch xử lý theo lô. Thứ tự (rẻ trước, đắt sau):
 * hình dạng lô → VC tồn tại → số hiệu on-chain → quyền (issuer cha) → giao dịch
 * → sự kiện của chính giao dịch → trạng thái hiện tại trên chuỗi → ghi.
 */
export async function batchChangeStatus(
  actor: EntityRow,
  mode: BatchMode,
  action: BatchAction,
  vcIds: string[],
  reason: string,
  txHash: string,
): Promise<BatchResult> {
  if (vcIds.length < 1 || vcIds.length > MAX_BATCH) {
    throw badRequest(`vcIds: cần 1..${MAX_BATCH} văn bằng`);
  }
  if (new Set(vcIds).size !== vcIds.length) throw badRequest("vcIds: có mã văn bằng trùng lặp");

  const rows = await query<CredentialRow>("SELECT * FROM credentials WHERE vc_id = ANY($1)", [vcIds]);
  if (rows.length !== vcIds.length) {
    const found = new Set(rows.map((r) => r.vc_id));
    throw notFound(`Không tìm thấy VC ${vcIds.find((id) => !found.has(id))}`);
  }
  if (!OFFLINE && rows.some((r) => r.on_chain_vc_id === null)) {
    throw badRequest("Có VC chưa có số hiệu on-chain — không đối chiếu được giao dịch");
  }
  if (mode === "parent") {
    for (const r of rows) {
      if ((await getDelegator(r.issuer_address)) !== actor.address) {
        throw forbidden(`VC ${r.vc_id} không do sub-issuer của bạn cấp`);
      }
    }
  }

  // Hợp đồng đòi id TĂNG DẦN NGHIÊM NGẶT; giao diện sắp xếp giống hệt.
  rows.sort((a, b) => (a.on_chain_vc_id ?? 0) - (b.on_chain_vc_id ?? 0));
  const target = TARGET[action];
  const tx = await verifyTransaction(txHash, {
    expectedFunction: batchFunction(mode, action),
    expectedSender: actor.address,
    args: OFFLINE && rows.some((r) => r.on_chain_vc_id === null)
      ? []
      : [{ u64s: rows.map((r) => r.on_chain_vc_id as number) }, { bytes: utf8ToHex(reason) }],
  });

  const changedIds = OFFLINE ? null : batchChangedIds(tx);
  const result: BatchResult = { changed: [], skipped: [], stale: [] };
  for (const r of rows) {
    const changed = changedIds ? changedIds.has(Number(r.on_chain_vc_id)) : canApply(r, target);
    if (!changed) { result.skipped.push(r.vc_id); continue; }
    // Chống phát lại (quyết định #19), áp từng VC: giao dịch có thật nhưng có thể
    // đã cũ, hoặc có thao tác khác chen vào giữa lúc lên chuỗi và lúc ghi chỉ mục.
    if (!OFFLINE && (await getVcStatusOnChain(r.on_chain_vc_id as number)) !== target) {
      result.stale.push(r.vc_id);
      continue;
    }
    result.changed.push(r.vc_id);
  }
  if (result.changed.length === 0 && result.stale.length > 0) {
    throw conflict("Trạng thái trên chuỗi đã khác trạng thái giao dịch này đặt — giao dịch đã cũ");
  }

  if (result.changed.length > 0) {
    await query(
      `UPDATE credentials SET status = $2, status_reason = $3, status_tx_hash = $4, updated_at = now()
        WHERE vc_id = ANY($1)`,
      [result.changed, target, reason, txHash],
    );
  }
  for (const id of result.changed) {
    await record(actor.address, action === "revoke" ? "vc.revoke" : "vc.suspend", id, {
      reason, txHash, batch: true, byAdmin: mode === "admin", byParent: mode === "parent",
    });
  }
  return result;
}

/** Tập id đã đổi theo VCBatchProcessedEvent của CHÍNH giao dịch — không tin danh sách client gửi. */
function batchChangedIds(tx: OnChainTx): Set<number> {
  const ev = findEvent(tx, `${MODULE.vcRegistry}::VCBatchProcessedEvent`);
  if (!ev || !Array.isArray(ev.changed)) throw badRequest("Giao dịch không phát VCBatchProcessedEvent");
  return new Set((ev.changed as unknown[]).map((x) => Number(x)));
}

/**
 * Cấp lại văn bằng (reissue_vc). Thứ tự: các phép kiểm rẻ của cấp mới → VC cũ
 * tồn tại → quyền (issuer gốc hoặc issuer cha) → VC cũ đang hoạt động → cùng
 * loại → đổi holder thì holder cũ phải không còn DID ACTIVE → giao dịch → sự kiện
 * → trạng thái chuỗi → ghi cả hai bản ghi trong một giao dịch CSDL.
 */
export async function reissueVc(oldVcId: string, input: IssueVcInput): Promise<CredentialRow> {
  const { issuer } = input;
  await assertIssueInput(input);
  const old = await requireByVcId(oldVcId);

  const isOwner = old.issuer_address === issuer.address;
  if (!isOwner && (await getDelegator(old.issuer_address)) !== issuer.address) {
    throw forbidden("Chỉ issuer đã cấp văn bằng cũ (hoặc issuer cha của họ) mới cấp lại được");
  }
  // Văn bằng đang tạm ngưng / đã thu hồi thì không tự cấp lại được — nếu không,
  // issuer "làm mềm" được quyết định của admin. Trường hợp đó đi đường admin nối.
  if (old.status === "revoked") throw conflict("Văn bằng cũ đã bị thu hồi — chỉ admin nối liên kết được");
  if (old.status !== "active") throw conflict("Chỉ cấp lại được văn bằng đang hoạt động (kể cả đã hết hạn)");
  if (old.replaced_by_vc_id) throw conflict("Văn bằng cũ đã có bản thay thế");
  if (input.vcType !== old.vc_type) throw badRequest("Văn bằng thay thế phải cùng loại với văn bằng cũ");
  if (input.holderAddress !== old.holder_address && (await hasActiveDid(old.holder_address))) {
    throw conflict("Holder cũ vẫn có DID hoạt động — admin phải khoá/thu hồi DID cũ trước khi cấp sang ví mới");
  }
  if (!OFFLINE && old.on_chain_vc_id === null) {
    throw badRequest("Văn bằng cũ chưa có số hiệu on-chain — không đối chiếu được giao dịch");
  }

  const tx = await verifyTransaction(input.txHash, {
    expectedFunction: ENTRY.reissueVc,
    expectedSender: issuer.address,
    args: [old.on_chain_vc_id === null ? null : { u64: old.on_chain_vc_id }, ...issueArgs(input)],
  });
  assertIssuedEvent(tx, input);
  if (!OFFLINE) {
    const ev = findEvent(tx, `${MODULE.vcRegistry}::VCReplacedEvent`);
    if (!ev || String(ev.old_id) !== String(old.on_chain_vc_id) || String(ev.new_id) !== String(input.onChainVcId)) {
      throw badRequest("Giao dịch không phát VCReplacedEvent khớp văn bằng cũ và mới");
    }
    await assertLinkedOnChain(old.on_chain_vc_id as number, input.onChainVcId);
  }

  const row = await withTx(async (c) => {
    const inserted = await insertCredential(input, old.vc_id, c);
    await c.query(
      `UPDATE credentials SET status = 'revoked', status_reason = $2, status_tx_hash = $3,
              replaced_by_vc_id = $4, updated_at = now()
        WHERE vc_id = $1`,
      [old.vc_id, REASON_REPLACED, input.txHash, input.vcId],
    );
    return inserted;
  });
  await record(issuer.address, "vc.reissue", input.vcId, {
    replaces: old.vc_id, holderDid: input.holderDid, vcType: input.vcType, txHash: input.txHash,
    byParent: !isOwner,
  });
  return row;
}

/** Chống phát lại cho C3: chuỗi phải đang ghi đúng liên kết cũ → mới. */
async function assertLinkedOnChain(oldOnChain: number, newOnChain: number): Promise<void> {
  const linked = await getReplacementOnChain(oldOnChain);
  if (linked !== newOnChain) {
    throw conflict(`Trên chuỗi văn bằng cũ đang được thay bằng "${linked ?? "không có"}", không phải ${newOnChain}`);
  }
}

/**
 * Admin nối liên kết khi issuer gốc đã mất quyền: một issuer khác cấp văn bằng
 * mới bằng issue_vc, admin ký admin_link_replacement. Luật bám hợp đồng: cùng
 * loại, văn bằng mới đang hoạt động và mới hơn, chưa nối với văn bằng nào.
 */
export async function linkReplacement(
  admin: EntityRow,
  oldVcId: string,
  newVcId: string,
  txHash: string,
): Promise<{ old: CredentialRow; replacement: CredentialRow }> {
  if (oldVcId === newVcId) throw badRequest("Văn bằng không thể thay cho chính nó");
  const old = await requireByVcId(oldVcId);
  const neu = await requireByVcId(newVcId);
  if (old.replaced_by_vc_id) throw conflict("Văn bằng cũ đã có bản thay thế");
  if (neu.replaces_vc_id) throw conflict("Văn bằng mới đã thay cho một văn bằng khác");
  if (neu.vc_type !== old.vc_type) throw badRequest("Văn bằng thay thế phải cùng loại với văn bằng cũ");
  if (neu.status !== "active") throw conflict("Văn bằng thay thế phải đang hoạt động");
  if (!OFFLINE) {
    if (old.on_chain_vc_id === null || neu.on_chain_vc_id === null) {
      throw badRequest("Có văn bằng chưa có số hiệu on-chain — không đối chiếu được giao dịch");
    }
    if (neu.on_chain_vc_id <= old.on_chain_vc_id) throw badRequest("Văn bằng thay thế phải được cấp sau văn bằng cũ");
  }
  if (neu.holder_address !== old.holder_address && (await hasActiveDid(old.holder_address))) {
    throw conflict("Holder cũ vẫn có DID hoạt động — khoá/thu hồi DID cũ trước khi nối sang ví mới");
  }

  await verifyTransaction(txHash, {
    expectedFunction: ENTRY.adminLinkReplacement,
    expectedSender: admin.address,
    args: old.on_chain_vc_id === null || neu.on_chain_vc_id === null
      ? []
      : [{ u64: old.on_chain_vc_id }, { u64: neu.on_chain_vc_id }],
  });
  if (!OFFLINE) await assertLinkedOnChain(old.on_chain_vc_id as number, neu.on_chain_vc_id as number);

  const result = await withTx(async (c) => {
    // Lý do thu hồi cũ (vd. "gian lận") được giữ nguyên, giống hợp đồng.
    const o = await c.query<CredentialRow>(
      `UPDATE credentials
          SET status_reason = CASE WHEN status = 'revoked' THEN status_reason ELSE $2 END,
              status_tx_hash = CASE WHEN status = 'revoked' THEN status_tx_hash ELSE $3 END,
              status = 'revoked', replaced_by_vc_id = $4, updated_at = now()
        WHERE vc_id = $1 RETURNING *`,
      [old.vc_id, REASON_REPLACED, txHash, neu.vc_id],
    );
    const n = await c.query<CredentialRow>(
      "UPDATE credentials SET replaces_vc_id = $2, updated_at = now() WHERE vc_id = $1 RETURNING *",
      [neu.vc_id, old.vc_id],
    );
    return { old: o.rows[0]!, replacement: n.rows[0]! };
  });
  await record(admin.address, "vc.link", old.vc_id, { replacement: neu.vc_id, txHash });
  return result;
}

export interface MigrationRow {
  id: number;
  old_address: string;
  new_address: string;
  old_did: string;
  new_did: string;
  recorded_by: string;
  note: string;
  created_at: Date;
}

/**
 * P4.2 — admin ghi liên kết ví cũ → ví mới SAU KHI đã xác minh danh tính ngoài
 * hệ thống. Không có giao dịch nào: đây là hồ sơ hành chính, không phải quyền.
 * Rào: ví cũ không còn DID hoạt động (đã khoá/thu hồi), ví mới có DID hoạt động.
 */
export async function recordMigration(
  admin: EntityRow,
  oldAddress: string,
  newAddress: string,
  note: string,
): Promise<MigrationRow> {
  const oldAddr = normalizeAddress(oldAddress);
  const newAddr = normalizeAddress(newAddress);
  if (oldAddr === newAddr) throw badRequest("Ví mới phải khác ví cũ");
  const [oldEnt, newEnt] = await Promise.all([
    queryOne<EntityRow>("SELECT * FROM entities WHERE address = $1", [oldAddr]),
    queryOne<EntityRow>("SELECT * FROM entities WHERE address = $1", [newAddr]),
  ]);
  if (!oldEnt) throw notFound("Không tìm thấy ví cũ");
  if (!newEnt) throw notFound("Không tìm thấy ví mới");
  if (await queryOne("SELECT 1 FROM identity_migrations WHERE old_address = $1", [oldAddr])) {
    throw conflict("Ví cũ này đã được chuyển sang một ví khác");
  }
  if (await hasActiveDid(oldAddr)) {
    throw conflict("Ví cũ vẫn có DID hoạt động — khoá hoặc thu hồi DID cũ trước");
  }
  if (!(await hasActiveDid(newAddr))) throw conflict("Ví mới chưa có DID hoạt động");

  const row = await queryOne<MigrationRow>(
    `INSERT INTO identity_migrations (old_address, new_address, old_did, new_did, recorded_by, note)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [oldAddr, newAddr, oldEnt.did, newEnt.did, admin.address, note],
  );
  if (!row) throw new Error("Ghi liên kết danh tính thất bại");
  await record(admin.address, "did.migrate", oldEnt.did, { newDid: newEnt.did, note });
  return row;
}

/** Ví mới của một ví cũ (nếu đã được admin ghi nhận). */
export async function migrationOf(address: string): Promise<MigrationRow | null> {
  return queryOne<MigrationRow>(
    "SELECT * FROM identity_migrations WHERE old_address = $1",
    [normalizeAddress(address)],
  );
}

/**
 * P4.1 — chủ DID tự khoá (nghi lộ khoá) hoặc tự mở. Hợp đồng quyết định ai mở
 * được: tự khoá thì tự mở, bị admin khoá (kể cả khoá đè - M-08) thì chỉ admin mở.
 * Backend kiểm trạng thái chỉ mục (rẻ) → giao dịch → trạng thái chuỗi → ghi.
 */
export async function selfDidStatus(
  actor: EntityRow,
  next: "suspended" | "active",
  txHash: string,
): Promise<{ address: string; status: "suspended" | "active"; txHash: string }> {
  const doc = await queryOne<{ status: string }>(
    `SELECT d.status FROM did_documents d JOIN entities e ON e.id = d.entity_id
      WHERE e.address = $1 ORDER BY d.created_at DESC LIMIT 1`,
    [actor.address],
  );
  if (!doc) throw notFound("Bạn chưa có DID");
  if (doc.status === "revoked") throw conflict("DID đã bị thu hồi vĩnh viễn");
  if (next === "suspended" && doc.status !== "active") throw conflict("Chỉ khoá được DID đang hoạt động");
  if (next === "active" && doc.status !== "suspended") throw conflict("Chỉ mở được DID đang bị khoá");

  await verifyTransaction(txHash, {
    expectedFunction: next === "suspended" ? ENTRY.suspendOwnDid : ENTRY.reactivateOwnDid,
    expectedSender: actor.address,
    args: [],
  });
  if (!OFFLINE) {
    const onChain = await resolveDidByOwner(actor.address);
    if (!onChain || onChain.status !== next) {
      throw conflict(`Trên chuỗi DID đang "${onChain?.status ?? "không có"}", không khớp thao tác — giao dịch đã cũ`);
    }
  }
  await query(
    `UPDATE did_documents d SET status = $2, updated_at = now()
       FROM entities e WHERE e.id = d.entity_id AND e.address = $1 AND d.status <> 'revoked'`,
    [actor.address, next],
  );
  await record(actor.address, next === "suspended" ? "did.suspend" : "did.reactivate", actor.address, {
    txHash, self: true,
  });
  return { address: actor.address, status: next, txHash };
}

/** Issuer đã từng cấp văn bằng cho ví này chưa (điều kiện xem liên kết chuyển ví). */
export async function issuedToHolder(issuer: string, holder: string): Promise<boolean> {
  return (await queryOne(
    "SELECT 1 FROM credentials WHERE issuer_address = $1 AND holder_address = $2 LIMIT 1",
    [normalizeAddress(issuer), normalizeAddress(holder)],
  )) !== null;
}
