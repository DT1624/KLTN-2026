import { query, queryOne } from "../db/pool.js";
import { notFound, badRequest, conflict } from "../utils/errors.js";
import { verifyTransaction } from "../chain/client.js";
import { ENTRY } from "../chain/abi.js";
import { resolveDidOnChain, resolveDidByOwner } from "../chain/registry.js";
import { fetchJSON, sha3_256Hex } from "./ipfs.service.js";
import type { DidDocumentRow, EntityRow } from "../types/index.js";
import { OFFLINE } from "../chain/offline.js";
import { record } from "./audit.service.js";

export interface SaveDidInput {
  entity: EntityRow;
  did: string;
  documentCid: string;
  documentHash: string;
  docJson: Record<string, unknown>;
  txHash: string;
}

/**
 * Ghi nhận DID sau khi trình duyệt đã gửi giao dịch register_did lên chuỗi.
 *
 * Ba lớp kiểm tra trước khi ghi — backend cũ không có lớp nào trong số này:
 *  1. Giao dịch có thật, thành công, đúng hàm register_did, đúng người gửi.
 *  2. Hash tài liệu do client khai đúng bằng hash tính lại từ chính doc_json.
 *  3. DID trên chuỗi khớp với CID/hash được khai.
 */
export async function saveDid(input: SaveDidInput): Promise<DidDocumentRow> {
  const { entity } = input;

  if (input.did !== entity.did) {
    throw badRequest("DID không khớp với tài khoản đang đăng nhập");
  }

  // Thứ tự kiểm tra: rẻ trước, đắt sau — và phải GIỐNG HỆT backend Go, nếu
  // không cùng một yêu cầu sai sẽ nhận hai mã lỗi khác nhau tuỳ backend nào
  // phục vụ. (Đúng loại lệch này từng lọt qua vì ở chế độ nghiêm ngặt cả hai
  // đều dừng sớm ở bước xác minh giao dịch.)

  // (1) Hash phải khớp nội dung — chặn việc ghim một đằng khai một nẻo.
  //     Không tốn I/O nên kiểm trước.
  const recomputed = sha3_256Hex(input.docJson);
  if (recomputed !== input.documentHash) {
    throw badRequest(
      `Hash tài liệu không khớp nội dung (tính được ${recomputed}, khai ${input.documentHash})`,
    );
  }

  // (2) Đã ghi rồi thì dừng — một lượt truy vấn CSDL, rẻ hơn gọi fullnode.
  const existing = await queryOne<DidDocumentRow>(
    "SELECT * FROM did_documents WHERE did = $1",
    [input.did],
  );
  if (existing) throw conflict("DID này đã được ghi nhận");

  // (3) Giao dịch phải có thật trên chuỗi và do chính chủ gửi — đắt nhất, để cuối.
  await verifyTransaction(input.txHash, {
    expectedFunction: ENTRY.registerDid,
    expectedSender: entity.address,
  });

  // (4) Đối chiếu với bản ghi trên chuỗi.
  const onChain = await resolveDidOnChain(input.did);
  if (onChain) {
    if (onChain.documentCid !== input.documentCid) {
      throw badRequest("CID khai báo không khớp CID đã ghi trên chuỗi");
    }
    if (onChain.status !== "active") {
      throw badRequest(`DID trên chuỗi đang ở trạng thái "${onChain.status}"`);
    }
  }

  const row = await queryOne<DidDocumentRow>(
    `INSERT INTO did_documents (entity_id, did, document_cid, document_hash, doc_json, tx_hash)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [entity.id, input.did, input.documentCid, input.documentHash, input.docJson, input.txHash],
  );
  if (!row) throw new Error("Chèn did_documents thất bại");
  await record(entity.address, "did.save", input.did, {
    documentCid: input.documentCid,
    txHash: input.txHash,
  });
  return row;
}

export async function getByDid(did: string): Promise<DidDocumentRow | null> {
  return queryOne<DidDocumentRow>("SELECT * FROM did_documents WHERE did = $1", [did]);
}

export interface ResolvedDid {
  did: string;
  /**
   * `chain` — đọc từ chuỗi. `db-index` — chế độ VERIFY_ONCHAIN=false, đọc từ
   * chỉ mục CSDL. `cache` — chuỗi không có, lùi về bản lưu trong CSDL.
   * KHÔNG được nói dối là "chain" khi thực ra đọc CSDL.
   */
  source: "chain" | "db-index" | "cache";
  status: string;
  documentCid: string;
  documentHash: string;
  version: number;
  document: unknown;
  /** Hash tính lại từ tài liệu lấy về có khớp hash trên chuỗi không. */
  integrityOk: boolean | null;
}

/**
 * Resolve DID lấy chuỗi làm nguồn sự thật, chỉ lùi về CSDL khi chuỗi
 * không có dữ liệu. Tài liệu luôn được kéo từ IPFS và băm lại để đối chiếu.
 */
export async function resolve(did: string): Promise<ResolvedDid> {
  const onChain = await resolveDidOnChain(did);

  if (onChain) {
    let document: unknown = null;
    let integrityOk: boolean | null = null;
    try {
      document = await fetchJSON(onChain.documentCid);
      integrityOk = sha3_256Hex(document) === onChain.documentHash;
    } catch {
      integrityOk = null; // không lấy được tài liệu thì không kết luận
    }
    return {
      did,
      source: OFFLINE ? "db-index" : "chain",
      status: onChain.status,
      documentCid: onChain.documentCid,
      documentHash: onChain.documentHash,
      version: onChain.version,
      document,
      integrityOk,
    };
  }

  const cached = await getByDid(did);
  if (!cached) throw notFound(`Không tìm thấy DID ${did}`);

  return {
    did,
    source: "cache",
    status: cached.status,
    documentCid: cached.document_cid,
    documentHash: cached.document_hash,
    version: cached.version,
    document: cached.doc_json,
    integrityOk: sha3_256Hex(cached.doc_json) === cached.document_hash,
  };
}

export async function resolveByAddress(address: string): Promise<ResolvedDid> {
  const onChain = await resolveDidByOwner(address);
  if (onChain) return resolve(onChain.did);

  const row = await queryOne<DidDocumentRow>(
    `SELECT d.* FROM did_documents d
       JOIN entities e ON e.id = d.entity_id
      WHERE e.address = $1`,
    [address],
  );
  if (!row) throw notFound(`Địa chỉ ${address} chưa có DID`);
  return resolve(row.did);
}
