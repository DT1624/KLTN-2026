/**
 * Thí nghiệm C — trạng thái theo từng bản ghi trên chuỗi so với Bitstring Status List.
 *
 * Hệ thống lưu trạng thái mỗi văn bằng thành một bản ghi riêng trên chuỗi. Chuẩn
 * W3C đề xuất một dãy bit nén (tối thiểu 131.072 vị trí) công bố trong một chứng
 * thực đã ký. Ở đây đo thật kích thước dãy bit sau nén GZIP theo tỉ lệ thu hồi,
 * với vị trí thu hồi ngẫu nhiên (10 hạt giống mỗi điểm), để định lượng đánh đổi
 * đã chọn ở Mục 3.8 thay vì chỉ mô tả nó.
 *
 *   node scripts/eval/statuslist.mjs
 */
import { gzipSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";

const OUT = process.env.OUT_DIR ?? "./.bench/eval";
const SIZES = [131_072, 1_048_576];
const RATES = [0, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.02, 0.05, 0.1];
const SEEDS = 10;

// Bộ sinh số giả ngẫu nhiên có hạt giống: chạy lại cho đúng cùng con số.
function rng(seed) {
  let s = seed >>> 0;
  return () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

const out = { meta: { at: new Date().toISOString(), seeds: SEEDS, gzipLevel: 9 }, data: [] };
for (const size of SIZES) {
  for (const rate of RATES) {
    const k = Math.round(size * rate);
    const bytes = [];
    for (let seed = 1; seed <= SEEDS; seed++) {
      const bits = new Uint8Array(size / 8);
      const r = rng(seed * 7919 + k);
      let set = 0;
      while (set < k) {
        const i = Math.floor(r() * size);
        if (!(bits[i >> 3] & (0x80 >> (i & 7)))) { bits[i >> 3] |= 0x80 >> (i & 7); set++; }
      }
      bytes.push(gzipSync(bits, { level: 9 }).length);
    }
    bytes.sort((a, b) => a - b);
    // Giới hạn dưới lý thuyết (entropy) của việc mã hoá k vị trí trong `size`: log2 C(size, k) bit.
    let lg = 0; for (let i = 0; i < k; i++) lg += Math.log2((size - i) / (i + 1));
    const row = { size, rate, revoked: k, gzipMedian: bytes[SEEDS >> 1], gzipMin: bytes[0], gzipMax: bytes[SEEDS - 1], entropyBytes: Math.ceil(lg / 8), rawBytes: size / 8 };
    out.data.push(row);
    console.log(`   ${size} vị trí, thu hồi ${(rate * 100).toFixed(2)}% (${k}): gzip ${row.gzipMedian} B, cận entropy ${row.entropyBytes} B`);
  }
}

mkdirSync(OUT, { recursive: true });
writeFileSync(`${OUT}/statuslist.json`, JSON.stringify(out, null, 2));
console.log(`  → ${OUT}/statuslist.json`);
