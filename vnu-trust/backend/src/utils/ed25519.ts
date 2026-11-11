import { createPublicKey, verify } from "node:crypto";

// Tiền tố DER SPKI của khoá Ed25519 — ghép với 32 byte thô để node:crypto đọc được.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const hexBytes = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");

/** Kiểm chữ ký Ed25519 (khoá công khai và chữ ký dạng hex). Dữ liệu hỏng thì trả false. */
export function verifyEd25519(publicKeyHex: string, message: string, signatureHex: string): boolean {
  const pub = hexBytes(publicKeyHex);
  const sig = hexBytes(signatureHex);
  if (pub.length !== 32 || sig.length !== 64) return false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, pub]), format: "der", type: "spki" });
    return verify(null, Buffer.from(message, "utf8"), key, sig);
  } catch {
    return false;
  }
}
