// Kiem thu thu vien hoa van doi chieu (src/lib/rosette.ts).
//   ../backend/node_modules/.bin/tsx scripts/rosette-check.ts
// ROSETTE_MODULE=<duong dan> de tro vao ban dot bien (chung minh test chuyen do).
import { sha3_256 } from "@noble/hashes/sha3";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils";

const modPath = process.env.ROSETTE_MODULE ?? "../src/lib/rosette.ts";
const { rosetteBytes, rosettePaths, rosetteSvg } = await import(modPath);

let pass = 0, fail = 0;
const check = (name: string, ok: boolean, d = "") => {
  ok ? pass++ : fail++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${d ? "  -> " + d : ""}`);
};
const hexSeed = (i: number) => "0x" + bytesToHex(sha3_256(utf8ToBytes("seed-" + i)));
const joined = (ps: { d: string }[]) => ps.map((p) => p.d).join("|");
const nums = (d: string) => (d.match(/-?\d+(?:\.\d+)?|NaN|Infinity/g) ?? []);
const pts = (d: string) => (d.match(/[ML]/g) ?? []).length;

// 1. rosetteBytes khop sha3_256 doc lap
for (const s of ["vnu-trust", "Đại học Quốc gia Hà Nội — văn bằng", ""]) {
  const got = rosetteBytes(s);
  const want = sha3_256(utf8ToBytes(s));
  check(`rosetteBytes dai 32 va khop sha3_256 ("${s.slice(0, 12)}")`, got.length === 32 && bytesToHex(got) === bytesToHex(want));
}

// 2. Tat dinh, ke ca sau khi bo dem bi day ra
const S0 = "0x0ede7f6b38caab7ddfe757765fddbf07221f8b776c6395562faae571250708e3";
const first = rosettePaths(S0, 1).map((p: any) => ({ d: p.d, w: p.w, o: p.o }));
rosettePaths("khac-xen-giua", 1);
const second = rosettePaths(S0, 1);
check("Cung seed goi 2 lan (co seed khac xen giua) -> giong het", JSON.stringify(first) === JSON.stringify(second));
for (let i = 0; i < 80; i++) rosettePaths(hexSeed(1000 + i), 1);
const third = rosettePaths(S0, 1);
check("Sau khi day > 64 seed khac ra khoi bo dem, seed dau van giong het", JSON.stringify(first) === JSON.stringify(third));

// 3. Khac seed -> khac
const seen = new Map<string, number>();
let dup = 0;
for (let i = 0; i < 200; i++) {
  const k = joined(rosettePaths(hexSeed(i), 1));
  if (seen.has(k)) dup++;
  seen.set(k, i);
}
check("200 seed khac nhau -> 200 hinh khac nhau", seen.size === 200 && dup === 0, `trung=${dup}`);
const S1 = S0.slice(0, -1) + "4";
check("Doi 1 ky tu cuoi cua dia chi hop dong -> hinh khac", joined(rosettePaths(S0, 1)) !== joined(rosettePaths(S1, 1)));

// 4. So path = M + M2 + 3 tinh doc lap tu sha3
let badCount = 0;
for (let i = 0; i < 60; i++) {
  const s = hexSeed(5000 + i);
  const b = sha3_256(utf8ToBytes(s));
  const want = 12 + (b[0] % 7) + 6 + (b[5] % 5) + 3;
  if (rosettePaths(s, 1).length !== want) badCount++;
}
check("So path = M + M2 + 3 (M=12+b0%7, M2=6+b5%5) cho 60 seed", badCount === 0, `sai=${badCount}`);

// 5. Hinh hoc
let geoBad = 0, bad = "";
for (let i = 0; i < 30; i++) {
  for (const p of rosettePaths(hexSeed(7000 + i), 1)) {
    if (!p.d.startsWith("M") || /NaN|Infinity/.test(p.d)) { geoBad++; bad = p.d.slice(0, 30); continue; }
    for (const n of nums(p.d)) {
      const v = Number(n);
      if (!Number.isFinite(v) || v < 0 || v > 240) { geoBad++; bad = n; }
    }
  }
}
check("Moi toa do huu han, trong [0,240], path bat dau bang M, khong NaN/Infinity", geoBad === 0, bad);

// 6. detail
const lo = rosettePaths("detail-test", 0.35), hi = rosettePaths("detail-test", 1), tiny = rosettePaths("detail-test", 0.01);
const total = (ps: { d: string }[]) => ps.reduce((a, p) => a + pts(p.d), 0);
check("detail 0.35 it diem hon detail 1, cung so path", lo.length === hi.length && total(lo) < total(hi), `${total(lo)} < ${total(hi)}`);
check("detail 0.01 van >= 48 diem/path va cung so path", tiny.length === hi.length && tiny.every((p: any) => pts(p.d) >= 48), `min=${Math.min(...tiny.map((p: any) => pts(p.d)))}`);

// 7. rosetteSvg
const svg: string = rosetteSvg("svg-test");
check("rosetteSvg bat dau <svg, co viewBox 0 0 240 240, du so <path",
  svg.startsWith("<svg") && svg.includes('viewBox="0 0 240 240"') && (svg.match(/<path/g) ?? []).length === rosettePaths("svg-test", 1).length);

// 8. Hieu nang (nguong 200 ms/lan chi de bat hoi quy lon, khong de do dac chinh xac)
const ts: number[] = [];
for (let i = 0; i < 50; i++) {
  const s = hexSeed(9000 + i);
  const t0 = performance.now();
  rosettePaths(s, 1);
  ts.push(performance.now() - t0);
}
ts.sort((a, b) => a - b);
const p50 = ts[24], p95 = ts[47];
console.log(`  perf: p50=${p50.toFixed(2)} ms p95=${p95.toFixed(2)} ms max=${ts[49].toFixed(2)} ms`);
check("rosettePaths(seed,1) moi lan < 200 ms", ts[49] < 200, `max=${ts[49].toFixed(2)} ms`);

console.log(`\nHoa van doi chieu: ${pass}/${pass + fail} dat`);
process.exit(fail ? 1 : 0);
