/**
 * Thí nghiệm B — giá trị băm nội dung KHÔNG MUỐI trên chuỗi như một "máy xác nhận".
 *
 * Hợp đồng neo content_hash = SHA3-256(chuẩn hoá(vc)) và vc_id_hash = SHA3-256(vcId).
 * Câu hỏi: kẻ đọc được chuỗi khôi phục được bao nhiêu thông tin của văn bằng,
 * tuỳ theo những gì họ đã biết trước? Thay vì lập luận, ta chạy tấn công thật:
 * dựng ứng viên theo đúng khuôn văn bằng của giao diện (pages/Issuer.tsx), băm,
 * so với hash mục tiêu, và đo thời gian.
 *
 *   node scripts/eval/oracle.mjs
 */
import { createHash, randomUUID } from "node:crypto";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import { writeFileSync, mkdirSync } from "node:fs";
import os from "node:os";

const canon = (v) => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
const h = (s) => createHash("sha3-256").update(s).digest("hex");

// Không gian giá trị — mỗi con số đều có lý do, ghi ở meta để báo cáo dẫn lại.
const PROGRAMS = Array.from({ length: 483 }, (_, i) => `Chương trình đào tạo số ${String(i + 1).padStart(3, "0")}`); // 483 CTĐT của ĐHQGHN
const GPAS = Array.from({ length: 401 }, (_, i) => (i / 100).toFixed(2)); // 0.00 … 4.00, bước 0,01
const YEARS = Array.from({ length: 27 }, (_, i) => String(2000 + i)); // 2000 … 2026

function makeVc(o) {
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1", { vnu: "https://vnu.edu.vn/credentials/v1#" }],
    id: o.vcId, type: ["VerifiableCredential", "VNUDegreeCredential"],
    issuer: o.issuer, issuanceDate: o.issuedAt,
    credentialSubject: { id: o.holder, "vnu:studentId": o.studentId, "vnu:degreeName": o.program,
      "vnu:faculty": o.faculty, "vnu:gpa": o.gpa, "vnu:graduationYear": o.year },
  };
}

/** Tách bản chuẩn hoá thành các đoạn cố định quanh các trường chưa biết — đúng cách kẻ tấn công tối ưu. */
function template(base, fields) {
  const marks = Object.fromEntries(fields.map((f, i) => [f, `@@${i}@@`]));
  const s = canon(makeVc({ ...base, ...marks }));
  const parts = s.split(/@@\d@@/);
  const order = [...s.matchAll(/@@(\d)@@/g)].map((m) => fields[Number(m[1])]);
  return { parts, order };
}

// ---------------------------------------------------------------- worker: băm một khoảng ứng viên
if (!isMainThread) {
  const { parts, n } = workerData;
  const t0 = performance.now();
  let x = 0;
  for (let i = 0; i < n; i++) {
    const s = parts[0] + (i % 401) + parts[1] + (i % 27) + parts[2];
    if (h(s).charCodeAt(0) === 0) x++;
  }
  parentPort.postMessage({ ms: performance.now() - t0, x });
}

if (isMainThread) {
  const OUT = process.env.OUT_DIR ?? "./.bench/eval";
  const out = { meta: { at: new Date().toISOString(), node: process.version, cpu: os.cpus()[0].model, cores: os.cpus().length,
    space: { programs: PROGRAMS.length, gpa: GPAS.length, years: YEARS.length, issuanceWindowMs: 60_000, studentIdStructured: 100_000 } }, data: {} };
  const log = (...x) => console.log("  ", ...x);

  const target = {
    vcId: `urn:uuid:${randomUUID()}`, issuer: `did:vnu:issuer:0x${"1a".repeat(32)}`,
    holder: `did:vnu:holder:0x${"7f".repeat(32)}`, issuedAt: "2026-06-30T08:15:42.317Z",
    studentId: "22028334", program: PROGRAMS[217], faculty: "Trường Đại học Công nghệ", gpa: "3.42", year: "2026",
  };

  // ---- 1. Tốc độ băm của một luồng, trên đúng khuôn văn bằng
  {
    const { parts } = template(target, ["gpa", "year"]);
    const N = 400_000;
    const runs = [];
    for (let r = 0; r < 5; r++) {
      const t0 = performance.now();
      for (let i = 0; i < N; i++) h(parts[0] + GPAS[i % 401] + parts[1] + YEARS[i % 27] + parts[2]);
      runs.push(N / ((performance.now() - t0) / 1000));
    }
    runs.sort((a, b) => a - b);
    out.data.rate1 = { median: runs[2], min: runs[0], max: runs[4] };
    log(`tốc độ 1 luồng: ${(runs[2] / 1e6).toFixed(3)} triệu ứng viên/giây`);
  }

  // ---- 2. Mở rộng theo số luồng (worker_threads)
  {
    const { parts } = template(target, ["gpa", "year"]);
    out.data.scaling = [];
    for (const w of [1, 2, 4].filter((x) => x <= os.cpus().length)) {
      const n = 300_000;
      const t0 = performance.now();
      await Promise.all(Array.from({ length: w }, () => new Promise((res, rej) => {
        const wk = new Worker(new URL(import.meta.url), { workerData: { parts, n } });
        wk.on("message", res); wk.on("error", rej);
      })));
      const rate = (n * w) / ((performance.now() - t0) / 1000);
      out.data.scaling.push({ workers: w, rate });
      log(`${w} luồng: ${(rate / 1e6).toFixed(3)} triệu/giây`);
    }
  }

  // ---- 3. Kịch bản A: biết mọi trường trừ điểm và năm tốt nghiệp — chạy THẬT tới khi khớp
  {
    const runs = [];
    for (let t = 0; t < 20; t++) {
      const secret = { ...target, vcId: `urn:uuid:${randomUUID()}`, gpa: GPAS[Math.floor(Math.random() * 401)], year: YEARS[Math.floor(Math.random() * 27)] };
      const goal = h(canon(makeVc(secret)));
      const { parts, order } = template(secret, ["gpa", "year"]);
      const t0 = performance.now();
      let found = null, tried = 0;
      outer: for (const g of GPAS) for (const y of YEARS) {
        const v = { gpa: g, year: y };
        tried++;
        if (h(parts[0] + v[order[0]] + parts[1] + v[order[1]] + parts[2]) === goal) { found = v; break outer; }
      }
      runs.push({ ms: performance.now() - t0, tried, ok: found?.gpa === secret.gpa && found?.year === secret.year });
    }
    out.data.scenarioA = { space: GPAS.length * YEARS.length, runs };
    log(`kịch bản A: ${runs.filter((r) => r.ok).length}/20 khôi phục đúng, trung vị ${runs.map((r) => r.ms).sort((a, b) => a - b)[10].toFixed(1)} ms`);
  }

  // ---- 4. Kịch bản B: biết vcId, người học, đơn vị; chưa biết thời điểm (ms trong cửa sổ 60 s),
  //         chương trình, điểm, năm. Không gian 3,1·10^11 — chạy thật một đoạn để đo tốc độ trên
  //         khuôn bốn ẩn, rồi ngoại suy.
  {
    const { parts, order } = template(target, ["issuedAt", "program", "gpa", "year"]);
    const base = Date.parse("2026-06-30T08:15:00.000Z");
    const N = 300_000;
    const t0 = performance.now();
    for (let i = 0; i < N; i++) {
      const v = { issuedAt: new Date(base + (i % 60_000)).toISOString(), program: PROGRAMS[i % 483], gpa: GPAS[i % 401], year: YEARS[i % 27] };
      h(parts[0] + v[order[0]] + parts[1] + v[order[1]] + parts[2] + v[order[2]] + parts[3] + v[order[3]] + parts[4]);
    }
    const rate = N / ((performance.now() - t0) / 1000);
    out.data.scenarioB = { rate, measured: N };
    log(`kịch bản B: ${(rate / 1e6).toFixed(3)} triệu/giây trên khuôn bốn ẩn`);
  }

  // ---- 5. Bảng không gian tìm kiếm cho các mô hình kẻ tấn công
  const S = out.meta.space;
  const best = Math.max(...out.data.scaling.map((s) => s.rate));
  const rateB = out.data.scenarioB.rate * (best / out.data.scaling[0].rate);
  const sc = [
    { id: "A1", label: "Biết mọi trường trừ điểm", log10: Math.log10(S.gpa) },
    { id: "A2", label: "Biết mọi trường trừ điểm và năm", log10: Math.log10(S.gpa * S.years) },
    { id: "B", label: "Biết vcId, người học, đơn vị", log10: Math.log10(S.issuanceWindowMs * S.programs * S.gpa * S.years) },
    { id: "C", label: "Như B, chưa biết mã sinh viên", log10: Math.log10(S.issuanceWindowMs * S.programs * S.gpa * S.years * S.studentIdStructured) },
    { id: "D", label: "Chỉ có dữ liệu trên chuỗi (không biết vcId)", log10: 122 * Math.log10(2) + Math.log10(S.issuanceWindowMs * S.programs * S.gpa * S.years * S.studentIdStructured) },
    { id: "E", label: "Như A1 nhưng có muối 128 bit", log10: 128 * Math.log10(2) + Math.log10(S.gpa) },
  ].map((s) => ({ ...s, secondsAllCores: 10 ** s.log10 / rateB }));
  out.data.scenarios = sc;
  for (const s of sc) log(`${s.id}: 10^${s.log10.toFixed(1)} ứng viên → ${s.secondsAllCores.toExponential(2)} giây (${os.cpus().length} lõi)`);

  mkdirSync(OUT, { recursive: true });
  writeFileSync(`${OUT}/oracle.json`, JSON.stringify(out, null, 2));
  console.log(`  → ${OUT}/oracle.json`);
}
