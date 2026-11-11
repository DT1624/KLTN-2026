import { resolve as resolveDid, resolveByAddress } from "./did.service.js";
import { fetchJSON } from "./ipfs.service.js";
import { getByVcId, effectiveStatus, vcTypeLabel } from "./vc.service.js";
import { badRequest } from "../utils/errors.js";
import { getTransaction } from "../chain/client.js";

export type LookupKind = "did" | "address" | "cid" | "vcId" | "txHash";

/**
 * Đoán loại định danh người dùng dán vào ô tra cứu duy nhất ở trang chủ.
 *
 * Lưu ý: địa chỉ ví đầy đủ và mã giao dịch ĐỀU là "0x" + 64 ký tự hex, không
 * thể phân biệt bằng hình thức. Với trường hợp này trả về "address" rồi để
 * lookup() thử resolve DID trước, không có mới tra sang giao dịch.
 */
export function detectKind(raw: string): LookupKind {
  const q = raw.trim();
  if (/^did:/i.test(q)) return "did";
  if (/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/.test(q)) return "cid";
  if (/^urn:uuid:/i.test(q)) return "vcId";
  if (/^0x[0-9a-fA-F]{1,64}$/.test(q)) return "address";
  throw badRequest("Không nhận diện được định danh — hãy nhập DID, địa chỉ ví, CID hoặc mã VC");
}

/** Một chuỗi 0x + 64 hex vừa có thể là địa chỉ ví vừa có thể là mã giao dịch. */
const isAmbiguous = (q: string) => /^0x[0-9a-fA-F]{64}$/.test(q);

/** Tra cứu hợp nhất cho trang chủ công khai. */
export async function lookup(raw: string) {
  const q = raw.trim();
  const kind = detectKind(q);

  switch (kind) {
    case "did":
      return { kind, result: await resolveDid(q) };

    case "address": {
      try {
        return { kind, result: await resolveByAddress(q) };
      } catch (e) {
        // Chuỗi 0x+64hex có thể là mã giao dịch chứ không phải địa chỉ ví.
        if (!isAmbiguous(q)) throw e;
        const tx = await lookupTx(q);
        if (tx) return { kind: "txHash" as const, result: tx };
        throw badRequest(
          "Chuỗi này không phải địa chỉ ví có DID, cũng không phải mã giao dịch có thật",
        );
      }
    }

    case "cid": {
      const content = await fetchJSON(q);
      return { kind, result: { cid: q, content } };
    }

    case "vcId": {
      const vc = await getByVcId(q);
      if (!vc) throw badRequest(`Không tìm thấy VC ${q}`);
      const eff = await effectiveStatus(vc);
      // Chỉ công bố thông tin không nhạy cảm — không trả nội dung VC.
      return {
        kind,
        result: {
          vcId: vc.vc_id,
          status: eff.status,
          statusSource: eff.source,
          issuerDid: vc.issuer_did,
          holderDid: vc.holder_did,
          typeLabel: vcTypeLabel(vc.vc_type),
          issuedAt: vc.issued_at,
          expiresAt: vc.expires_at,
          ipfsCid: vc.ipfs_cid,
          txHash: vc.tx_hash,
        },
      };
    }

    case "txHash": {
      const tx = await lookupTx(q);
      if (!tx) throw badRequest("Không tìm thấy giao dịch trên chuỗi");
      return { kind, result: tx };
    }
  }
}

async function lookupTx(hash: string) {
  const tx = await getTransaction(hash);
  if (!tx) return null;
  return {
    hash: tx.hash,
    success: tx.success,
    vmStatus: tx.vm_status,
    sender: tx.sender,
    function: tx.payload?.function ?? null,
    version: tx.version,
  };
}
