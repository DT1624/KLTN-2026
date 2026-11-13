import { randomBytes } from "node:crypto";
import { query, queryOne, withTx } from "../db/pool.js";
import { notFound, badRequest, gone, forbidden } from "../utils/errors.js";
import { sha3_256Hex, canonicalize } from "./ipfs.service.js";
import { assertShareBlob } from "./envelope.service.js";
import { effectiveStatus, effectiveStatuses, getByVcId, vcTypeLabel } from "./vc.service.js";
import { isActiveIssuer, verifyVcIntegrity, getReplacementOnChain, vcRecordsOnChain } from "../chain/registry.js";
import { verifyEd25519 } from "../utils/ed25519.js";
import { record } from "./audit.service.js";
import { OFFLINE } from "../chain/offline.js";
import { resolve as resolveDid } from "./did.service.js";
import { getByDid } from "./entity.service.js";
import type { PresentationRow, ShareTokenRow, EntityRow, CredentialRow } from "../types/index.js";

const MIN_TTL = 60;
const MAX_TTL = 7 * 24 * 3600;

export interface CreateVpInput {
  holder: EntityRow;
  vpId: string;
  verifierDid: string | null;
  vcIds: string[];
  ipfsCid: string;
  vpHash: string;
  proofValue: string;
  challenge: string | null;
  ttlSeconds: number;
}

/**
 * Lưu VP và sinh liên kết chia sẻ dùng một lần trong cùng một giao dịch CSDL
 * — trước đây hai bước này tách rời nên có thể tạo VP mồ côi khi bước sau lỗi.
 */
export async function createPresentation(
  input: CreateVpInput,
): Promise<{ vp: PresentationRow; share: ShareTokenRow }> {
  if (input.ttlSeconds < MIN_TTL || input.ttlSeconds > MAX_TTL) {
    throw badRequest(`Thời hạn chia sẻ phải trong khoảng ${MIN_TTL}..${MAX_TTL} giây`);
  }
  if (input.vcIds.length === 0) throw badRequest("VP phải chứa ít nhất một VC");

  // Mọi VC đưa vào VP phải thuộc về chính holder và còn hiệu lực.
  for (const vcId of input.vcIds) {
    const vc = await getByVcId(vcId);
    if (!vc) throw notFound(`Không tìm thấy VC ${vcId}`);
    if (vc.holder_did !== input.holder.did) {
      throw forbidden(`VC ${vcId} không thuộc về bạn`);
    }
    const eff = await effectiveStatus(vc);
    if (eff.status !== "active") {
      throw badRequest(`VC ${vcId} đang ở trạng thái "${eff.status}", không thể đưa vào VP`);
    }
  }

  // P3: IPFS chỉ giữ bản trình bày ĐÃ MÃ HOÁ (khoá nằm trong fragment liên kết).
  await assertShareBlob(input.ipfsCid);

  const token = randomBytes(24).toString("base64url");
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000);

  return withTx(async (c) => {
    const vpRes = await c.query<PresentationRow>(
      `INSERT INTO presentations
         (vp_id, holder_did, verifier_did, vc_ids, ipfs_cid, vp_hash, proof_value, challenge)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [
        input.vpId, input.holder.did, input.verifierDid, input.vcIds,
        input.ipfsCid, input.vpHash, input.proofValue, input.challenge,
      ],
    );
    const shareRes = await c.query<ShareTokenRow>(
      `INSERT INTO share_tokens (token, vp_id, holder_did, ipfs_cid, expires_at)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [token, input.vpId, input.holder.did, input.ipfsCid, expiresAt],
    );
    return { vp: vpRes.rows[0]!, share: shareRes.rows[0]! };
  }).then(async (out) => {
    await record(input.holder.address, "share.create", input.vpId, { vcIds: input.vcIds, ttlSeconds: input.ttlSeconds });
    return out;
  });
}

export async function listByHolder(holderDid: string): Promise<PresentationRow[]> {
  return query<PresentationRow>(
    "SELECT * FROM presentations WHERE holder_did = $1 ORDER BY created_at DESC",
    [holderDid],
  );
}

export async function getByVpId(vpId: string): Promise<PresentationRow | null> {
  return queryOne<PresentationRow>("SELECT * FROM presentations WHERE vp_id = $1", [vpId]);
}

/** Mở liên kết chia sẻ (bên xác minh quét QR). Tăng bộ đếm lượt xem. */
export async function openShareToken(token: string) {
  const row = await queryOne<ShareTokenRow>("SELECT * FROM share_tokens WHERE token = $1", [token]);
  if (!row) throw notFound("Liên kết chia sẻ không tồn tại");
  if (row.revoked_at) throw gone("Liên kết đã bị chủ sở hữu thu hồi");
  if (row.expires_at.getTime() <= Date.now()) throw gone("Liên kết đã hết hạn");

  await query("UPDATE share_tokens SET view_count = view_count + 1 WHERE token = $1", [token]);

  const vp = await getByVpId(row.vp_id);
  return {
    vpId: row.vp_id,
    holderDid: row.holder_did,
    ipfsCid: row.ipfs_cid,
    expiresAt: row.expires_at.toISOString(),
    viewCount: row.view_count + 1,
    vcIds: vp?.vc_ids ?? [],
  };
}

export async function revokeShareToken(token: string, holderDid: string, actor: string): Promise<void> {
  const row = await queryOne<ShareTokenRow>("SELECT * FROM share_tokens WHERE token = $1", [token]);
  if (!row) throw notFound("Liên kết chia sẻ không tồn tại");
  if (row.holder_did !== holderDid) throw forbidden("Liên kết này không thuộc về bạn");
  await query("UPDATE share_tokens SET revoked_at = now() WHERE token = $1 AND revoked_at IS NULL", [
    token,
  ]);
  await record(actor, "share.revoke", row.vp_id);
}

export async function listShareTokens(holderDid: string): Promise<ShareTokenRow[]> {
  return query<ShareTokenRow>(
    "SELECT * FROM share_tokens WHERE holder_did = $1 ORDER BY created_at DESC",
    [holderDid],
  );
}

// ============ Xác minh ============

export interface CheckResult {
  name: string;
  passed: boolean;
  detail: string;
  /**
   * Bước CẢNH BÁO: hiện cho người xác minh nhưng không quyết định overallValid.
   * Hiện chỉ có bước 6 (đơn vị cấp còn được tin cậy) — quyết định 13/11/2026, C2.
   */
  advisory?: boolean;
}

export interface VerificationReport {
  vpId: string;
  holderDid: string;
  overallValid: boolean;
  checks: CheckResult[];
  /** replacedBy (C3): vc_id của văn bằng thay thế — chỉ khi chuỗi xác nhận liên kết. */
  credentials: Array<{ vcId: string; status: string; issuerDid: string; typeLabel: string; replacedBy: string | null }>;
  verifiedAt: string;
}

/**
 * Xác minh đầy đủ một VP. Bảy bước kiểm tra độc lập, mỗi bước trả về
 * kết quả riêng để giao diện hiển thị rõ ràng chỗ nào hỏng, thay vì
 * chỉ một chữ "không hợp lệ".
 *
 * P3 (13/11/2026): IPFS chỉ giữ bản trình bày ĐÃ MÃ HOÁ; khoá nằm trong fragment
 * liên kết mà máy chủ không bao giờ nhận. Trình duyệt người xác minh giải mã rồi gửi
 * bản rõ `vpDoc` lên đây; máy chủ chạy 7 bước trên chính bản đó và KHÔNG lưu nó
 * (chỉ lưu báo cáo). Bản rõ bịa thì bước 2 (hash) và bước 3 (chữ ký) đỏ.
 */
export async function verifyPresentation(token: string, vpDoc: Record<string, unknown>): Promise<VerificationReport> {
  const share = await openShareToken(token);
  const checks: CheckResult[] = [];

  // 1. Bản trình bày đã mã hoá còn nằm trên IPFS, đúng định dạng.
  try {
    await assertShareBlob(share.ipfsCid);
    checks.push({ name: "Tải VP từ IPFS", passed: true, detail: `Bản mã tại CID ${share.ipfsCid}` });
  } catch (e) {
    checks.push({ name: "Tải VP từ IPFS", passed: false, detail: (e as Error).message });
  }

  const vpRow = await getByVpId(share.vpId);

  // 2. Toàn vẹn nội dung VP
  if (vpDoc && vpRow) {
    const h = sha3_256Hex(vpDoc);
    checks.push({
      name: "Toàn vẹn nội dung VP",
      passed: h === vpRow.vp_hash,
      detail: h === vpRow.vp_hash ? "Hash khớp" : `Hash lệch: ${h} ≠ ${vpRow.vp_hash}`,
    });
  }

  // 3. Chữ ký của holder trên VP
  if (vpDoc && vpRow) {
    const holder = await getByDid(vpRow.holder_did);
    let sigOk = false;
    let detail = "Không tìm thấy khoá công khai của holder";
    if (holder) {
      const { proof: _proof, ...unsigned } = vpDoc;
      sigOk = verifyEd25519(holder.public_key_hex, canonicalize(unsigned), vpRow.proof_value);
      detail = sigOk ? "Chữ ký hợp lệ" : "Chữ ký không khớp khoá công khai của holder";
    }
    checks.push({ name: "Chữ ký của người trình bày", passed: sigOk, detail });
  }

  // 4. DID của holder còn hoạt động
  if (vpRow) {
    try {
      const d = await resolveDid(vpRow.holder_did);
      checks.push({
        name: "DID người trình bày còn hiệu lực",
        passed: d.status === "active",
        detail: `Trạng thái "${d.status}" (nguồn: ${d.source})`,
      });
    } catch (e) {
      checks.push({ name: "DID người trình bày còn hiệu lực", passed: false, detail: (e as Error).message });
    }
  }

  // 5. Từng VC còn hiệu lực (đối chiếu chuỗi)
  const credentials: VerificationReport["credentials"] = [];
  let allVcValid = vpRow !== null && vpRow.vc_ids.length > 0;
  // Giữ lại hàng đã đọc để bước 5b dùng lại: đọc hai lần cùng một VC là nhân
  // đôi số truy vấn CSDL cho mỗi văn bằng trong bản trình bày.
  // P5: MỘT câu truy vấn cho mọi VC và MỘT lần đọc lô trên chuỗi (trạng thái + hash),
  // dùng chung cho bước 5 và 7 — trước đây là 2 view mỗi văn bằng.
  const ids = vpRow?.vc_ids ?? [];
  const byId = new Map((ids.length
    ? await query<CredentialRow>("SELECT * FROM credentials WHERE vc_id = ANY($1)", [ids])
    : []).map((r) => [r.vc_id, r]));
  const fetched = ids.map((vcId) => ({ vcId, row: byId.get(vcId) ?? null }));
  const present = fetched.flatMap((f) => (f.row ? [f.row] : []));
  const chainRecs = await vcRecordsOnChain(present.flatMap((r) => (r.on_chain_vc_id === null ? [] : [r.on_chain_vc_id])));
  const effs = await effectiveStatuses(present, chainRecs);
  for (const { vcId, row: vc } of fetched) {
    if (!vc) {
      allVcValid = false;
      credentials.push({ vcId, status: "không tìm thấy", issuerDid: "-", typeLabel: "-", replacedBy: null });
      continue;
    }
    const eff = effs.get(vc.vc_id)!;
    if (eff.status !== "active") allVcValid = false;
    credentials.push({
      vcId,
      status: eff.status,
      issuerDid: vc.issuer_did,
      typeLabel: vcTypeLabel(vc.vc_type),
      replacedBy: await confirmedReplacement(vc),
    });
  }
  checks.push({
    name: "Tất cả chứng chỉ còn hiệu lực",
    passed: allVcValid,
    detail: `${credentials.filter((c) => c.status === "active").length}/${credentials.length} còn hiệu lực`,
  });

  // 5b. Nội dung văn bằng vẫn khớp bản đã neo trên chuỗi.
  //
  // Bước 5 mới chỉ hỏi "văn bằng này còn hiệu lực không". Nó KHÔNG phát hiện
  // được việc nội dung bị sửa sau khi cấp: đổi điểm trong văn bằng rồi trình bày
  // thì trạng thái vẫn "active". Ở đây ta băm lại CHÍNH nội dung có trong bản
  // trình bày rồi hỏi chuỗi xem có đúng hash đã neo không (P3: máy chủ không còn
  // giữ bản rõ — dùng bản người xác minh nhận được, đúng thứ cần kiểm).
  const presented = new Map<string, Record<string, unknown>>();
  const embedded = Array.isArray(vpDoc.verifiableCredential) ? vpDoc.verifiableCredential : [];
  for (const v of embedded) {
    if (v && typeof v === "object" && typeof (v as { id?: unknown }).id === "string") {
      presented.set((v as { id: string }).id, v as Record<string, unknown>);
    }
  }
  let allIntact = credentials.length > 0;
  let intactCount = 0;
  // Các VC độc lập với nhau nên hỏi chuỗi song song: tuần tự thì một bản trình
  // bày 5 văn bằng phải chờ 5 vòng mạng nối tiếp.
  const intactResults = await Promise.all(
    fetched.map(async ({ vcId, row }) => {
      const doc = presented.get(vcId);
      if (!row || row.on_chain_vc_id === null || !doc) return false;
      const rec = chainRecs.get(row.on_chain_vc_id);
      // Bản ghi lô đã có content_hash: so tại chỗ, cùng ngữ nghĩa verify_integrity
      // (online: ACTIVE và hash khớp; offline giữ đúng hành vi cũ: chỉ so hash).
      if (rec?.contentHash) return (OFFLINE || rec.status === "active") && rec.contentHash === sha3_256Hex(doc).toLowerCase();
      return verifyVcIntegrity(row.on_chain_vc_id, sha3_256Hex(doc));
    }),
  );
  for (const ok of intactResults) {
    if (ok) intactCount++;
    else allIntact = false;
  }
  checks.push({
    name: "Nội dung văn bằng khớp bản neo trên chuỗi",
    passed: allIntact,
    detail: `${intactCount}/${credentials.length} khớp hash đã neo`,
  });

  // 6. Issuer của từng VC còn được tin cậy trên chuỗi
  // P5: hỏi mỗi issuer MỘT lần — một bản trình bày thường gồm nhiều văn bằng cùng đơn vị.
  const rows = present;
  const issuers = [...new Set(rows.map((r) => r.issuer_address))];
  const trust = new Map(await Promise.all(issuers.map(async (a) => [a, await isActiveIssuer(a)] as const)));
  const allIssuersTrusted = rows.length > 0 && rows.length === credentials.length && rows.every((r) => trust.get(r.issuer_address));
  // C2 (13/11/2026): thu hồi / tạm ngưng một đơn vị KHÔNG làm văn bằng họ đã cấp mất
  // hiệu lực — văn bằng thật của người học. Cấp trên xem xét rồi thu hồi theo lô; khi
  // đó bước 5 mới đỏ. Bước này vì vậy chỉ là CẢNH BÁO, không quyết định kết quả.
  checks.push({
    name: "Đơn vị cấp còn được tin cậy",
    passed: allIssuersTrusted,
    detail: allIssuersTrusted
      ? "Tất cả issuer đang hoạt động trên chuỗi"
      : "Có issuer đã bị thu hồi/tạm ngưng — văn bằng vẫn hiệu lực cho tới khi cấp trên xem xét",
    advisory: true,
  });

  const normalized = checks.map((c) => ({ ...c, advisory: c.advisory === true }));
  return {
    vpId: share.vpId,
    holderDid: share.holderDid,
    overallValid: normalized.every((c) => c.passed || c.advisory),
    checks: normalized,
    credentials,
    verifiedAt: new Date().toISOString(),
  };
}

/**
 * Văn bằng thay thế cho `vc` (C3) — chỉ trả khi chuỗi xác nhận đúng liên kết đó.
 * Chỉ mục CSDL nói "đã thay bằng X" mà chuỗi không ghi thì KHÔNG báo cho người
 * xác minh: đó chính là chỗ một chỉ mục bị sửa sẽ nói dối.
 */
async function confirmedReplacement(vc: CredentialRow): Promise<string | null> {
  if (!vc.replaced_by_vc_id) return null;
  if (OFFLINE) return vc.replaced_by_vc_id;
  const repl = await getByVcId(vc.replaced_by_vc_id);
  if (!repl || repl.on_chain_vc_id === null || vc.on_chain_vc_id === null) return null;
  return (await getReplacementOnChain(vc.on_chain_vc_id)) === repl.on_chain_vc_id ? repl.vc_id : null;
}

export async function saveVerification(
  vpId: string,
  verifierAddress: string,
  report: VerificationReport,
): Promise<void> {
  await query(
    "INSERT INTO verifications (vp_id, verifier_address, overall_valid, report) VALUES ($1,$2,$3,$4)",
    [vpId, verifierAddress, report.overallValid, report],
  );
}

export async function verificationHistory(verifierAddress: string, limit = 50) {
  return query(
    "SELECT * FROM verifications WHERE verifier_address = $1 ORDER BY created_at DESC LIMIT $2",
    [verifierAddress, limit],
  );
}
