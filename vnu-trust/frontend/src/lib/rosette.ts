// Hoa văn đối chiếu tất định: cùng chuỗi hạt giống thì luôn ra cùng một hình.
// Mọi tham số lấy thẳng từ SHA3-256(seed), không dùng bộ sinh số ngẫu nhiên.
// Hàm thuần, không React, không DOM.
import { sha3_256 } from "@noble/hashes/sha3";
import { utf8ToBytes } from "@noble/hashes/utils";

export interface RosettePath {
  d: string;
  w: number;
  o: number;
}

const TAU = Math.PI * 2;
const C = 120; // tâm của viewBox 0 0 240 240

export function rosetteBytes(seed: string): Uint8Array {
  return sha3_256(utf8ToBytes(seed));
}

function gcd(a: number, b: number): number {
  while (b) {
    const t = b;
    b = a % b;
    a = t;
  }
  return a;
}

function trace(fn: (t: number) => [number, number], n: number, span: number): string {
  let d = "";
  for (let j = 0; j <= n; j++) {
    const [x, y] = fn((j / n) * span);
    d += (j ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
  }
  return d;
}

const CACHE_MAX = 64;
const cache = new Map<string, RosettePath[]>();

export function rosettePaths(seed: string, detail = 1): RosettePath[] {
  const key = seed + "|" + detail;
  const hit = cache.get(key);
  if (hit) return hit;

  const raw = rosetteBytes(seed);
  const b = (i: number): number => raw[i] ?? 0;
  const out: RosettePath[] = [];

  // Dải dệt ngoài: nhiều sợi sin lệch pha, xoay cả dải theo rot.
  const M = 12 + (b(0) % 7);
  const k1 = 11 + (b(1) % 11);
  const k2 = 3 + (b(2) % 5);
  const a1 = 0.085 + (b(3) / 255) * 0.04;
  const rot = (b(11) / 255) * TAU;
  const nBand = Math.max(48, Math.round(720 * detail));
  for (let i = 0; i < M; i++) {
    const ph = (i * TAU) / M + rot;
    out.push({
      d: trace(
        (t) => {
          const R = C * (0.79 + a1 * Math.sin(k1 * t + ph) + 0.028 * Math.sin(k2 * t - ph / 2));
          return [C + R * Math.cos(t), C + R * Math.sin(t)];
        },
        nBand,
        TAU,
      ),
      w: 0.5,
      o: 0.8,
    });
  }

  // Cánh hoa giữa.
  const p = 5 + (b(4) % 7);
  const M2 = 6 + (b(5) % 5);
  const a2 = 0.13 + (b(6) / 255) * 0.06;
  const base = 0.36 + (b(7) / 255) * 0.06;
  const nPetal = Math.max(48, Math.round(540 * detail));
  for (let k = 0; k < M2; k++) {
    const ph = (k * TAU) / (p * M2);
    out.push({
      d: trace(
        (t) => {
          const R = C * (base + a2 * Math.cos(p * t + ph));
          return [C + R * Math.cos(t), C + R * Math.sin(t)];
        },
        nPetal,
        TAU,
      ),
      w: 0.6,
      o: 0.9,
    });
  }

  // Tâm: một đường hypotrochoid; rr phải nguyên tố cùng nhau với Rr để đường khép kín sau rr vòng.
  const Rr = 5 + (b(8) % 5);
  let rr = 2 + (b(9) % (Rr - 2));
  while (gcd(Rr, rr) !== 1) rr = rr > 2 ? rr - 1 : Rr - 1;
  const dd = rr * (0.55 + (b(10) / 255) * 0.6);
  const s = (C * 0.2) / (Rr - rr + dd);
  const q = (Rr - rr) / rr;
  out.push({
    d: trace(
      (t) => [
        C + s * ((Rr - rr) * Math.cos(t) + dd * Math.cos(q * t)),
        C + s * ((Rr - rr) * Math.sin(t) - dd * Math.sin(q * t)),
      ],
      Math.max(64, Math.round(400 * rr * detail)),
      TAU * rr,
    ),
    w: 0.7,
    o: 1,
  });

  // Hai vòng dẫn.
  const ring = (f: number, n: number, w: number, o: number): RosettePath => ({
    d: trace((t) => [C + C * f * Math.cos(t), C + C * f * Math.sin(t)], n, TAU),
    w,
    o,
  });
  out.push(ring(0.97, Math.max(48, Math.round(180 * detail)), 0.9, 1));
  out.push(ring(0.62, Math.max(48, Math.round(160 * detail)), 0.4, 0.7));

  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next();
    if (!oldest.done) cache.delete(oldest.value);
  }
  cache.set(key, out);
  return out;
}

export function rosetteSvg(
  seed: string,
  opts?: { size?: number; color?: string; detail?: number },
): string {
  const size = opts?.size ?? 64;
  const color = opts?.color ?? "#2A1E5C";
  const paths = rosettePaths(seed, opts?.detail ?? 1);
  const body = paths
    .map((p) => `<path d="${p.d}" stroke-width="${p.w}" stroke-opacity="${p.o}"/>`)
    .join("");
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 240" width="${size}" height="${size}">` +
    `<g fill="none" stroke="${color}">${body}</g></svg>`
  );
}
