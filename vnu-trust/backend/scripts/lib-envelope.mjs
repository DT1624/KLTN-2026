// Phong bì ĐÚNG CẤU TRÚC cho các kịch bản kiểm thử backend (P3, 13/11/2026).
//
// Backend không giải mã — nó chỉ kiểm cấu trúc phong bì (envelope.service.ts /
// envelope.go) — nên ở đây dùng byte ngẫu nhiên đúng kích thước. Mã hoá THẬT được
// kiểm ở frontend/scripts/vc-crypto-check.ts, chạy chính src/lib/vcCrypto.ts.
import { randomBytes } from "node:crypto";

const b = (n) => randomBytes(n).toString("base64");

export function fakeEnvelope(vcIdHash, holderAddress, issuerAddress, extra = {}) {
  return {
    v: 1, alg: "A256GCM", aad: `vnu-vc:${vcIdHash.toLowerCase()}`, iv: b(12), ct: b(96),
    recipients: [
      { kid: holderAddress, role: "holder", epk: b(32), iv: b(12), wk: b(48) },
      { kid: issuerAddress, role: "issuer", epk: b(32), iv: b(12), wk: b(48) },
    ],
    ...extra,
  };
}

export const fakeShareBlob = () => ({ v: 1, alg: "A256GCM", iv: b(12), ct: b(96) });
