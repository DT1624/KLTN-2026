/**
 * Sinh biểu đồ pgfplots và bảng LaTeX từ .bench/eval/*.json.
 *
 * Tách ĐO khỏi VẼ như bench/plot.mjs: vẽ lại không cần đo lại, và số liệu nhúng
 * thẳng trong tệp .tex nên người đọc báo cáo kiểm được từng con số.
 *
 *   node scripts/eval/plot.mjs            # đọc .bench/eval, ghi .bench/eval/tex
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";

const IN = process.env.IN_DIR ?? "./.bench/eval";
const OUT = process.env.TEX_DIR ?? `${IN}/tex`;
mkdirSync(OUT, { recursive: true });
const read = (f) => (existsSync(`${IN}/${f}`) ? JSON.parse(readFileSync(`${IN}/${f}`, "utf8")) : null);
const f = (x, d = 1) => Number(x).toFixed(d);
const vn = (x, d = 1) => f(x, d).replace(".", "{,}"); // dấu thập phân kiểu Việt trong bảng
const head = (src, extra = "") => `% SINH TỰ ĐỘNG bởi vnu-trust/scripts/eval/plot.mjs — đừng sửa tay.\n% Nguồn: .bench/eval/${src}${extra ? "\n% " + extra : ""}\n`;
const save = (name, s) => { writeFileSync(`${OUT}/${name}.tex`, s); console.log(`   ${name}.tex`); };
const AXIS = `grid=both, grid style={gray!18}, label style={font=\\small}, tick label style={font=\\footnotesize},
    legend style={font=\\scriptsize, fill=white, fill opacity=0.85, text opacity=1, draw=gray!40}`;

// Bootstrap có hạt giống: khoảng tin cậy 95% của hệ số biến thiên.
function rng(seed) { let s = seed >>> 0; return () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const cvOf = (a) => { const m = a.reduce((x, y) => x + y, 0) / a.length; return Math.sqrt(a.reduce((s, x) => s + (x - m) ** 2, 0) / (a.length - 1)) / m * 100; };
function bootCI(a, B = 4000) { const r = rng(12345); const v = []; for (let b = 0; b < B; b++) { const s = a.map(() => a[Math.floor(r() * a.length)]); v.push(cvOf(s)); } v.sort((x, y) => x - y); return [v[Math.floor(0.025 * B)], v[Math.floor(0.975 * B)]]; }

// ============================================================ A. mật mã
const crypto = read("crypto.json");
if (crypto) {
  const d = crypto.data;
  const pb = d.pbkdf2.map((r) => `(${r.iterations},${f(r.ms.median, 2)})`).join(" ");
  const pbErr = d.pbkdf2.map((r) => `(${r.iterations},${f(r.ms.median, 2)}) +- (0,${f((r.ms.max - r.ms.min) / 2, 2)})`).join(" ");
  const noble = d.sha3.map((r) => `(${r.size},${f(r.noble.median, 2)})`).join(" ");
  const native = d.sha3.map((r) => `(${r.size},${f(r.native.median, 2)})`).join(" ");
  const t600 = d.pbkdf2.find((r) => r.iterations === 600000).ms.median;
  save("fig-crypto", head("crypto.json", `${crypto.meta.cpu}, Node ${crypto.meta.node}, ${crypto.meta.repeats} lượt mỗi điểm`) + `\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{groupplot}[group style={group size=2 by 1, horizontal sep=1.7cm}, width=0.5\\textwidth, height=5.4cm, ${AXIS}]
\\nextgroupplot[xmode=log, ymode=log, xlabel={Số vòng lặp PBKDF2}, ylabel={Thời gian (ms)},
    title={(a) Dẫn xuất khoá mở ví}, title style={font=\\small},
    extra x ticks={600000}, extra x tick labels={}, extra x tick style={grid=major, grid style={red!60, densely dashed, thick}}]
    \\addplot[color=blue!70!black, mark=*, mark size=1.5pt, thick, error bars/.cd, y dir=both, y explicit] coordinates {${pbErr}};
    \\node[font=\\scriptsize, red!60!black, anchor=south east, align=right] at (axis cs:560000,${f(t600 * 1.25, 1)}) {600.000 vòng\\\\${vn(t600, 1)} ms};
\\nextgroupplot[xmode=log, ymode=log, xlabel={Kích thước đầu vào (byte)}, ylabel={Thông lượng (MB/s)},
    title={(b) SHA3-256: thư viện JS so với OpenSSL}, title style={font=\\small}, legend pos=south east]
    \\addplot[color=red!70!black, mark=square*, mark size=1.5pt, thick] coordinates {${noble}};
    \\addlegendentry{@noble/hashes (JS thuần)}
    \\addplot[dashed, color=green!50!black, mark=*, mark size=1.5pt, thick] coordinates {${native}};
    \\addlegendentry{node:crypto (OpenSSL)}
\\end{groupplot}
\\end{tikzpicture}
\\caption{Chi phí mật mã phía máy khách: (a) thời gian dẫn xuất khoá theo số vòng lặp, thanh lỗi là khoảng nhỏ nhất--lớn nhất; (b) thông lượng băm theo kích thước đầu vào}
\\label{fig:v2-crypto}
\\end{figure}
`);
  const e = d.ed25519;
  const row = (name, us, note) => `${name} & ${vn(us.median, 1)} & ${vn(us.cv, 1)} & ${note} \\\\ \\hline`;
  save("tab-crypto", head("crypto.json") + `\\begin{table}[H]
\\centering
\\caption{Thời gian một phép mật mã phía máy khách (trung vị ${crypto.meta.repeats} lượt)}
\\label{tab:v2-crypto}
\\renewcommand{\\arraystretch}{1.2}
\\small
\\begin{tabular}{|p{5.4cm}|r|r|p{4.6cm}|}
\\hline
\\textbf{Phép tính} & \\textbf{µs} & \\textbf{CV (\\%)} & \\textbf{Dùng ở đâu} \\\\ \\hline
${row("Ed25519 sinh khoá", e.keygen.us, "Tạo ví")}
${row("Ed25519 ký thông điệp đăng nhập", e.sign.us, "Đăng nhập, ký VP, ký giao dịch")}
${row("Ed25519 kiểm chữ ký (JS thuần)", e.verify.us, "Kiểm chữ ký phía máy khách")}
${row(`Chuẩn hoá một VC ${d.vcHash.bytes} byte`, d.vcHash.canonUs, "Trước mọi phép băm")}
${row("Chuẩn hoá và băm SHA3-256 một VC", d.vcHash.canonHashUs, "Cấp phát, bước 6 xác minh")}
${row("AES-256-GCM mã hoá khoá 32 byte", d.aesgcm.encryptUs, "Lưu ví")}
${row("SLIP-0010, 5 cấp dẫn xuất", d.bip39.slip10Us, "Khôi phục trên máy khác")}
\\hline
\\multicolumn{4}{|l|}{\\textbf{Tính bằng mili giây}} \\\\ \\hline
BIP-39 cụm từ $\\rightarrow$ hạt giống & ${vn(d.bip39.seedMs.median, 1)} & ${vn(d.bip39.seedMs.cv, 1)} & PBKDF2-SHA512, 2048 vòng \\\\ \\hline
PBKDF2-SHA256, 600.000 vòng & ${vn(t600, 1)} & ${vn(d.pbkdf2.find((r) => r.iterations === 600000).ms.cv, 1)} & Mỗi lần mở ví \\\\ \\hline
\\end{tabular}
\\end{table}
`);
}

// ============================================================ B. máy xác nhận
const oracle = read("oracle.json");
if (oracle) {
  const d = oracle.data;
  const sc = d.scenarios;
  const ys = sc.map((s) => s.id).join(",");
  const coords = sc.map((s) => `(${f(Math.log10(Math.max(s.secondsAllCores, 1e-6)), 2)},${s.id})`).join(" ");
  const ref = [[0, "1 giây"], [Math.log10(86400), "1 ngày"], [Math.log10(3.15e7), "1 năm"], [Math.log10(4.35e17), "tuổi vũ trụ"]];
  save("fig-oracle", head("oracle.json", `${oracle.meta.cpu}, ${oracle.meta.cores} luồng`) + `\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{axis}[xbar, width=0.92\\textwidth, height=6.2cm, bar width=9pt,
    symbolic y coords={${ys}}, ytick=data, y dir=reverse,
    xlabel={$\\log_{10}$ thời gian vét cạn toàn bộ không gian (giây), ${oracle.meta.cores} luồng}, xmin=-4, xmax=50, clip=false,
    nodes near coords, nodes near coords style={font=\\scriptsize}, point meta=explicit symbolic,
    ${AXIS}, ymajorgrids=false]
    \\addplot[fill=red!45!white, draw=red!60!black] coordinates {${sc.map((s) => `(${f(Math.log10(Math.max(s.secondsAllCores, 1e-6)), 2)},${s.id}) [${s.secondsAllCores < 1 ? vn(s.secondsAllCores * 1000, 0) + "\\,ms" : s.secondsAllCores < 86400 * 400 ? vn(s.secondsAllCores / 86400, 1) + " ngày" : "$10^{" + f(Math.log10(s.secondsAllCores / 3.15e7), 0) + "}$ năm"}]`).join(" ")}};
${ref.map(([x, t]) => `    \\draw[gray!70, densely dashed] ({axis cs:${f(x, 2)},A1} |- {rel axis cs:0,0}) -- ({axis cs:${f(x, 2)},A1} |- {rel axis cs:0,1}) node[above, font=\\scriptsize, text=gray!60!black] {${t}};`).join("\n")}
\\end{axis}
\\end{tikzpicture}
\\caption{Thời gian để vét cạn không gian ứng viên của từng mô hình kẻ tấn công, ngoại suy từ tốc độ băm đo thật; A1 và A2 được chạy thật tới khi khớp}
\\label{fig:v2-oracle}
\\end{figure}
`);
  const runsA = d.scenarioA.runs.map((r) => r.ms).sort((a, b) => a - b);
  const best = Math.max(...d.scaling.map((s) => s.rate));
  save("tab-oracle", head("oracle.json") + `\\begin{table}[H]
\\centering
\\caption{Không gian tìm kiếm theo hiểu biết sẵn có của kẻ tấn công}
\\label{tab:v2-oracle}
\\renewcommand{\\arraystretch}{1.2}
\\small
\\begin{tabular}{|c|p{6.4cm}|r|r|}
\\hline
\\textbf{Mã} & \\textbf{Kẻ tấn công đã biết} & \\textbf{Số ứng viên} & \\textbf{Thời gian (${oracle.meta.cores} luồng)} \\\\ \\hline
${sc.map((s) => `${s.id} & ${s.label} & $10^{${f(s.log10, 1).replace(".", "{,}")}}$ & ${s.secondsAllCores < 1 ? vn(s.secondsAllCores * 1000, 1) + " ms" : s.secondsAllCores < 86400 * 400 ? vn(s.secondsAllCores / 86400, 1) + " ngày" : "$10^{" + f(Math.log10(s.secondsAllCores / 3.15e7), 0) + "}$ năm"} \\\\ \\hline`).join("\n")}
\\end{tabular}
\\end{table}
`);
  writeFileSync(`${OUT}/oracle-numbers.txt`, `rate1=${d.rate1.median}\nbest=${best}\nA median ms=${runsA[runsA.length >> 1]} max=${runsA[runsA.length - 1]} ok=${d.scenarioA.runs.filter((r) => r.ok).length}\nB rate=${d.scenarioB.rate}\n`);
}

// ============================================================ C. danh sách bit
const sl = read("statuslist.json");
if (sl) {
  const d = sl.data;
  const series = (size, key) => d.filter((r) => r.size === size && r.rate > 0).map((r) => `(${r.rate * 100},${f(r[key] / 1024, 3)})`).join(" ");
  const perRecordKB = (size) => d.filter((r) => r.size === size && r.rate > 0).map((r) => `(${r.rate * 100},${f(r.revoked * 32 / 1024, 3)})`).join(" ");
  save("fig-statuslist", head("statuslist.json", `${sl.meta.seeds} hạt giống mỗi điểm, gzip mức ${sl.meta.gzipLevel}`) + `\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{axis}[width=0.9\\textwidth, height=6.2cm, xmode=log, ymode=log,
    xlabel={Tỉ lệ chứng thực bị thu hồi (\\%)}, ylabel={Kích thước (KB)},
    legend pos=north west, legend cell align=left, ${AXIS}]
    \\addplot[color=blue!70!black, mark=*, mark size=1.5pt, thick] coordinates {${series(131072, "gzipMedian")}};
    \\addlegendentry{Danh sách 131.072 vị trí, sau GZIP}
    \\addplot[color=blue!70!black, densely dotted, thick] coordinates {${series(131072, "entropyBytes")}};
    \\addlegendentry{\\quad cận dưới entropy}
    \\addplot[color=red!70!black, mark=square*, mark size=1.5pt, thick] coordinates {${series(1048576, "gzipMedian")}};
    \\addlegendentry{Danh sách 1.048.576 vị trí, sau GZIP}
    \\addplot[color=red!70!black, densely dotted, thick] coordinates {${series(1048576, "entropyBytes")}};
    \\addlegendentry{\\quad cận dưới entropy}
    \\addplot[color=gray!70!black, dashed, thick] coordinates {(0.01,16) (10,16)};
    \\addlegendentry{131.072 vị trí, chưa nén (16 KB)}
\\end{axis}
\\end{tikzpicture}
\\caption{Kích thước danh sách trạng thái dạng bit theo tỉ lệ thu hồi, với vị trí thu hồi ngẫu nhiên}
\\label{fig:v2-statuslist}
\\end{figure}
`);
}

// ============================================================ E. ghim CPU
const iso = read("isolation.json");
if (iso) {
  const d = iso.data;
  const keys = [...new Set(d.map((r) => `${r.backend} ${r.route}`))];
  const sym = keys.map((k, i) => `g${i}`);
  const lab = keys.map((k) => k.replace("GO", "Go").replace("verify k=1", "xác minh").replace(/_/g, "\\_"));
  const series = (label) => keys.map((k, i) => {
    const r = d.find((x) => x.label === label && `${x.backend} ${x.route}` === k);
    const [lo, hi] = bootCI(r.raw.map((x) => x.p95));
    return { x: sym[i], y: r.p95.cv, lo, hi };
  });
  const sh = series("shared"), pn = series("pinned");
  const pts = (s) => s.map((p) => `(${p.x},${f(p.y, 2)}) -= (0,${f(p.y - p.lo, 2)}) += (0,${f(p.hi - p.y, 2)})`).join(" ");
  const ymax = Math.ceil(Math.max(...sh.concat(pn).map((p) => p.hi)) * 1.08 / 10) * 10;
  const r0 = d[0];
  save("fig-isolation", head("isolation.json", `${r0.repeats} lượt × ${r0.n} yêu cầu, ${r0.conc} đồng thời; khoảng tin cậy bootstrap 95%`) + `\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{axis}[ybar, width=0.95\\textwidth, height=6.0cm, bar width=10pt, ymin=0, ymax=${ymax},
    symbolic x coords={${sym.join(",")}}, xtick=data, xticklabels={${lab.map((l) => `{${l}}`).join(",")}},
    x tick label style={font=\\scriptsize, align=center, text width=1.9cm},
    ylabel={CV của p95 giữa các lượt (\\%)}, legend pos=north east, ${AXIS}, xmajorgrids=false,
    error bars/error bar style={black!70}]
    \\addplot[fill=gray!40, draw=gray!60!black, error bars/.cd, y dir=both, y explicit] coordinates {${pts(sh)}};
    \\addlegendentry{Bộ sinh tải dùng chung CPU}
    \\addplot[fill=blue!45, draw=blue!60!black, error bars/.cd, y dir=both, y explicit] coordinates {${pts(pn)}};
    \\addlegendentry{Ghim CPU: dịch vụ \\{0,1\\}, bộ sinh tải \\{2,3\\}}
\\end{axis}
\\end{tikzpicture}
\\caption{Độ phân tán của p95 giữa ${r0.repeats} lượt đo lặp lại, khi bộ sinh tải dùng chung và khi tách lõi CPU; thanh lỗi là khoảng tin cậy bootstrap 95\\% của CV}
\\label{fig:v2-isolation}
\\end{figure}
`);
  const line = (k) => {
    const a = d.find((x) => x.label === "shared" && `${x.backend} ${x.route}` === k), b = d.find((x) => x.label === "pinned" && `${x.backend} ${x.route}` === k);
    const name = k.replace("GO", "Go").replace("verify k=1", "xác minh $k{=}1$");
    return `${name} & ${vn(a.p95.mean, 2)} & ${vn(a.p95.cv, 1)} & ${vn(a.rps.median, 0)} & ${vn(b.p95.mean, 2)} & ${vn(b.p95.cv, 1)} & ${vn(b.rps.median, 0)} \\\\ \\hline`;
  };
  save("tab-isolation", head("isolation.json") + `\\begin{table}[H]
\\centering
\\caption{Kết quả đo lặp lại ${r0.repeats} lượt, mỗi lượt ${r0.n} yêu cầu ở ${r0.conc} yêu cầu đồng thời}
\\label{tab:v2-isolation}
\\renewcommand{\\arraystretch}{1.2}
\\small
\\begin{tabular}{|l|r|r|r|r|r|r|}
\\hline
& \\multicolumn{3}{c|}{\\textbf{Dùng chung CPU}} & \\multicolumn{3}{c|}{\\textbf{Ghim CPU}} \\\\ \\cline{2-7}
\\textbf{Cấu hình} & \\textbf{p95 (ms)} & \\textbf{CV (\\%)} & \\textbf{yc/s} & \\textbf{p95 (ms)} & \\textbf{CV (\\%)} & \\textbf{yc/s} \\\\ \\hline
${keys.map(line).join("\n")}
\\end{tabular}
\\end{table}
`);
}

// ============================================================ D. quy mô dữ liệu
const sc = read("scale.json");
if (sc) {
  const d = sc.data;
  const base = d.filter((r) => r.tag === "");
  const levels = [...new Set(base.map((r) => r.level))];
  const X = (L) => Math.max(L, 100); // trục log: đặt N=0 tại 10^2 và ghi nhãn "≈0"
  const colors = { "/did/resolve": "blue!70!black", "/holder/credentials": "orange!80!black", "verify k=1": "red!70!black", "verify k=8": "green!50!black" };
  const names = { "/did/resolve": "phân giải DID", "/holder/credentials": "ví: danh sách VC", "verify k=1": "xác minh $k{=}1$", "verify k=8": "xác minh $k{=}8$" };
  const panel = (be, legend = true) => Object.keys(colors).map((rt) => {
    const c = base.filter((r) => r.backend === be && r.route === rt).sort((a, b) => a.level - b.level).map((r) => `(${X(r.level)},${f(r.p50, 2)})`).join(" ");
    return `    \\addplot[color=${colors[rt]}, mark=*, mark size=1.5pt, thick] coordinates {${c}};` + (legend ? `\n    \\addlegendentry{${names[rt]}}` : "");
  }).join("\n");
  save("fig-scale", head("scale.json", "c = 1, thời gian phục vụ; N là số bản ghi chứng thực độn thêm") + `\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{groupplot}[group style={group size=2 by 1, horizontal sep=1.5cm}, width=0.5\\textwidth, height=6.0cm,
    xmode=log, ymode=log, xtick={100,1000,10000,100000}, xticklabels={$\\approx$0,$10^3$,$10^4$,$10^5$},
    xlabel={Số bản ghi độn thêm $N$}, ${AXIS}, legend style={at={(0.03,0.97)}, anchor=north west}]
\\nextgroupplot[ylabel={Trung vị độ trễ (ms)}, title={(a) Cài đặt TypeScript}, title style={font=\\small}]
${panel("TS")}
\\nextgroupplot[title={(b) Cài đặt Go}, title style={font=\\small}]
${panel("GO", false)}
\\end{groupplot}
\\end{tikzpicture}
\\caption{Trung vị thời gian phục vụ theo kích thước dữ liệu, đo ở một yêu cầu đồng thời; hai trục đều theo thang logarit}
\\label{fig:v2-scale}
\\end{figure}
`);
  const top = Math.max(...levels);
  const kRows = (tag, be) => [1, 2, 4, 8].map((k) => d.find((r) => r.level === top && (r.tag === tag || (tag === "noindex" && r.tag === "" )) && r.backend === be && r.route === `verify k=${k}`)).filter(Boolean);
  const kLine = (tag, be, style, name) => {
    const rows = kRows(tag, be);
    return `    \\addplot[${style}] coordinates {${rows.map((r) => `(${r.route.split("=")[1]},${f(r.p50, 2)})`).join(" ")}};\n    \\addlegendentry{${name}}`;
  };
  save("fig-scale-k", head("scale.json", `N = ${top}`) + `\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{axis}[width=0.85\\textwidth, height=6.0cm, xtick={1,2,4,8}, xlabel={Số văn bằng trong bản trình bày $k$}, ylabel={Trung vị độ trễ xác minh (ms)},
    ymode=log, legend style={at={(0.98,0.42)}, anchor=east}, legend columns=2, legend cell align=left, ${AXIS}]
${kLine("noindex", "TS", "color=red!70!black, mark=*, thick", "TS, không chỉ mục")}
${kLine("noindex", "GO", "color=red!70!black, mark=square*, dashed, thick", "Go, không chỉ mục")}
${kLine("index", "TS", "color=blue!70!black, mark=*, thick", "TS, có chỉ mục")}
${kLine("index", "GO", "color=blue!70!black, mark=square*, dashed, thick", "Go, có chỉ mục")}
\\end{axis}
\\end{tikzpicture}
\\caption{Độ trễ xác minh theo số văn bằng trong bản trình bày ở $N = 10^5$, trước và sau khi thêm chỉ mục trên \\texttt{on\\_chain\\_vc\\_id}}
\\label{fig:v2-scale-k}
\\end{figure}
`);
  const ex = sc.explain;
  const sizeMB = (L) => (sc.size.find((s) => s.level === L)?.credentialsBytes ?? 0) / 1048576;
  save("tab-scale", head("scale.json") + `\\begin{table}[H]
\\centering
\\caption{Kế hoạch thực thi của truy vấn trạng thái theo \\texttt{on\\_chain\\_vc\\_id} (EXPLAIN ANALYZE)}
\\label{tab:v2-explain}
\\renewcommand{\\arraystretch}{1.2}
\\small
\\begin{tabular}{|r|r|l|r|r|}
\\hline
\\textbf{$N$} & \\textbf{Bảng (MB)} & \\textbf{Kiểu quét} & \\textbf{Dòng bị lọc bỏ} & \\textbf{Thời gian (ms)} \\\\ \\hline
${ex.map((e) => `${e.level.toLocaleString("vi-VN")}${e.index ? " (có chỉ mục)" : ""} & ${vn(sizeMB(e.level), 1)} & ${e.node} & ${Number(e.rowsRemoved).toLocaleString("vi-VN")} & ${vn(e.execMs, 3)} \\\\ \\hline`).join("\n")}
\\end{tabular}
\\end{table}
`);
}

// ============================================================ F. chuỗi thật
const ch = read("chain.json");
if (ch) {
  const d = ch.data;
  const rtt = d.rtt.view.p50;
  const pat = d.pattern ?? [];
  save("fig-chain", head("chain.json", `fullnode ${ch.meta.fullnode}`) + `\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{axis}[width=0.85\\textwidth, height=6.0cm, xtick={1,2,4,8}, xlabel={Số văn bằng trong bản trình bày $k$}, ylabel={Thời gian các vòng gọi view (ms)},
    ymin=0, legend pos=north west, legend cell align=left, ${AXIS}]
    \\addplot[color=red!70!black, mark=*, thick] coordinates {${pat.map((p) => `(${p.k},${f(p.sequential.p50, 0)})`).join(" ")}};
    \\addlegendentry{Mẫu gọi hiện tại, đo thật}
    \\addplot[color=red!70!black, densely dotted, thick, domain=1:8, samples=8] {(x+3)*${f(rtt, 1)}};
    \\addlegendentry{Mô hình $(k+3)\\times$RTT, RTT $=${f(rtt, 0)}$\\,ms}
    \\addplot[color=blue!70!black, mark=square*, thick] coordinates {${pat.map((p) => `(${p.k},${f(p.parallel.p50, 0)})`).join(" ")}};
    \\addlegendentry{Song song hoá, đo thật}
    \\addplot[color=blue!70!black, densely dotted, thick, domain=1:8, samples=2] {2*${f(rtt, 1)}};
    \\addlegendentry{Mô hình $2\\times$RTT}
${pat.filter((p) => p.throttled > 0).map((p) => `    \\node[font=\\scriptsize, blue!60!black, anchor=north] at (axis cs:${p.k},${f(p.parallel.p50, 0)}) {\\shortstack{${p.throttled}/${p.calls}\\\\bị chặn}};`).join("\n")}
\\end{axis}
\\end{tikzpicture}
\\caption{Chi phí vòng gọi tới fullnode công khai của bước xác minh ở chế độ on-chain: mẫu gọi hiện tại so với mẫu song song hoá; nhãn ghi số lời gọi bị fullnode từ chối vì vượt hạn mức}
\\label{fig:v2-chain}
\\end{figure}
`);
  const g = d.gas.ops;
  save("tab-chain", head("chain.json") + `\\begin{table}[H]
\\centering
\\caption{Chi phí phía chuỗi đo trên mạng thử nghiệm Movement (chỉ đọc và mô phỏng)}
\\label{tab:v2-chain}
\\renewcommand{\\arraystretch}{1.2}
\\small
\\begin{tabular}{|p{6.6cm}|r|r|}
\\hline
\\textbf{Phép đo} & \\textbf{p50} & \\textbf{p95} \\\\ \\hline
Một vòng \\texttt{GET /v1/} (ms, ${ch.meta.samples} mẫu) & ${vn(d.rtt.ledger.p50, 0)} & ${vn(d.rtt.ledger.p95, 0)} \\\\ \\hline
Một lời gọi view \\texttt{is\\_active\\_issuer} (ms) & ${vn(d.rtt.view.p50, 0)} & ${vn(d.rtt.view.p95, 0)} \\\\ \\hline
\\multicolumn{3}{|l|}{\\textbf{Gas qua mô phỏng} (đơn vị gas $\\times$ giá ${g[0].gasUnitPrice} octa)} \\\\ \\hline
${g.map((o) => `\\texttt{${o.fn.replace(/_/g, "\\_")}} & \\multicolumn{2}{r|}{${o.gasUsed} đơn vị $=$ ${vn(o.gasUsed * o.gasUnitPrice / 1e8, 6)} MOVE} \\\\ \\hline`).join("\n")}
\\end{tabular}
\\end{table}
`);
}
console.log(`  → ${OUT}`);
