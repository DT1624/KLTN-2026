import { sha3_256 } from "@noble/hashes/sha3";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

/**
 * vcIdHash = "0x" + SHA3-256 trên byte UTF-8 THÔ của chuỗi vcId. Khớp backend TS, Go và parity;
 * KHÔNG qua canonicalize (nếu không sẽ băm cả dấu nháy JSON và bị máy chủ từ chối).
 * Vector kiểm: "x" -> 0x741efa311f97686956946758e0d95f70f11ff2da4f2feb7c54314f44134ac49f
 */
export function vcIdHash(vcId: string): string {
  return "0x" + bytesToHex(sha3_256(utf8ToBytes(vcId)));
}
