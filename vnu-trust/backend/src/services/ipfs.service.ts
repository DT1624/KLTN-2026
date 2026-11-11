import { createHash } from "node:crypto";
import { cfg } from "../config/index.js";
import { query, queryOne } from "../db/pool.js";
import { upstream, badRequest } from "../utils/errors.js";
import { logger } from "../utils/logger.js";

export interface PinResult {
  cid: string;
  url: string;
  size: number;
}

const PINATA_PIN = "https://api.pinata.cloud/pinning/pinJSONToIPFS";

/** Đệm nội dung theo CID. Nội dung định địa chỉ theo hash nên không bao giờ cũ, chỉ cần chặn kích thước. */
const cache = new Map<string, unknown>();
const CACHE_MAX = 1000;
function remember(cid: string, body: unknown): void {
  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value!);
  cache.set(cid, body);
}

async function pinToPinata(json: unknown, name: string): Promise<PinResult> {
  const body = JSON.stringify({
    pinataContent: json,
    pinataMetadata: { name },
    pinataOptions: { cidVersion: 1 },
  });

  const res = await fetch(PINATA_PIN, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${cfg.PINATA_JWT}`,
    },
    body,
    signal: AbortSignal.timeout(20_000),
  });

  const text = await res.text();
  if (!res.ok) throw upstream(`Pinata trả ${res.status}`, text.slice(0, 300));

  const data = JSON.parse(text) as { IpfsHash: string; PinSize: number };
  return {
    cid: data.IpfsHash,
    url: `${cfg.IPFS_GATEWAY}/${data.IpfsHash}`,
    size: data.PinSize ?? Buffer.byteLength(body),
  };
}

/**
 * Chế độ mock (phát triển/CI): CID tất định từ nội dung, lưu ở bảng `ipfs_objects`
 * dùng chung để nội dung sống qua lần khởi động lại và hai backend cùng thấy.
 */
/** Ghi nội dung mock vào CSDL dùng chung. Trùng CID thì bỏ qua — cùng CID
 *  nghĩa là cùng nội dung, đó chính là ý nghĩa của định địa chỉ theo nội dung. */
async function persistMock(cid: string, json: unknown): Promise<void> {
  try {
    await query(
      "INSERT INTO ipfs_objects (cid, content) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING",
      [cid, JSON.stringify(json)],
    );
  } catch (err) {
    // Không làm hỏng thao tác chính: nội dung vẫn còn trong bộ đệm tiến trình.
    logger.error({ err, cid }, "Không lưu được nội dung mock vào CSDL");
  }
}

function pinToMock(json: unknown): PinResult {
  // Dùng bản tuần tự hoá TẤT ĐỊNH chứ không phải JSON.stringify: JSON.stringify
  // giữ thứ tự chèn còn json.Marshal của Go tự sắp xếp khoá, nên hai backend sẽ
  // sinh CID khác nhau cho cùng một nội dung.
  const raw = canonicalize(json);
  // Sinh CID tất định có ĐÚNG hình dạng CIDv1 base32 (b + 58 ký tự [a-z2-7]),
  // nếu không sẽ bị chính zCid của backend từ chối và test sẽ đạt vì lý do sai.
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  // sha3-256 để khớp backend Go — cả hệ thống dùng thống nhất SHA3.
  const seed = Buffer.concat([
    createHash("sha3-256").update(raw).digest(),
    createHash("sha3-256").update(raw + "#2").digest(),
  ]);
  let body = "";
  for (let i = 0; i < 52; i++) body += alphabet[seed[i]! % 32];
  const cid = "bafkrei" + body; // 7 + 52 = 59 ký tự, tức 58 ký tự sau "b" -> hợp lệ
  remember(cid, json);
  return { cid, url: `${cfg.IPFS_GATEWAY}/${cid}`, size: Buffer.byteLength(raw) };
}

export async function pinJSON(json: unknown, name: string): Promise<PinResult> {
  if (json === null || typeof json !== "object") {
    throw badRequest("Nội dung cần ghim phải là một đối tượng JSON");
  }
  if (cfg.IPFS_PROVIDER === "pinata") {
    const result = await pinToPinata(json, name);
    logger.info({ cid: result.cid, name, provider: "pinata" }, "Đã ghim lên IPFS");
    return result;
  }
  const result = pinToMock(json);
  await persistMock(result.cid, json);
  logger.info({ cid: result.cid, name, provider: "mock" }, "Đã ghim lên IPFS");
  return result;
}

/** Lấy nội dung JSON theo CID qua gateway công khai. */
export async function fetchJSON(cid: string): Promise<unknown> {
  if (cache.has(cid)) return cache.get(cid);

  if (cfg.IPFS_PROVIDER === "mock") {
    const row = await queryOne<{ content: unknown }>(
      "SELECT content FROM ipfs_objects WHERE cid = $1",
      [cid],
    );
    if (!row) throw badRequest(`Không tìm thấy CID ${cid} trong kho mock`);
    remember(cid, row.content);
    return row.content;
  }

  const res = await fetch(`${cfg.IPFS_GATEWAY}/${cid}`, { signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw upstream(`Gateway IPFS trả ${res.status} cho CID ${cid}`);
  const body = (await res.json()) as unknown;
  remember(cid, body);
  return body;
}

/**
 * Băm nội dung theo đúng cách contract mong đợi: SHA3-256 trên chuỗi JSON.
 * Hai bên (trình duyệt khi ký, backend khi xác minh) phải tuần tự hoá giống
 * hệt nhau, nên dùng JSON.stringify với khoá đã sắp xếp.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
}

export function sha3_256Hex(value: unknown): string {
  return "0x" + createHash("sha3-256").update(canonicalize(value)).digest("hex");
}
