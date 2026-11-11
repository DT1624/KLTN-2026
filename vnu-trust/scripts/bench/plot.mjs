/**
 * Sinh biểu đồ pgfplots từ dữ liệu thô của `bench/sweep.mjs`.
 *
 * Tách ĐO khỏi VẼ: vẽ lại không cần đo lại, và dữ liệu nhúng thẳng vào tệp
 * .tex nên người đọc báo cáo kiểm chứng được con số mà không cần chạy gì.
 *
 *   node scripts/bench/plot.mjs            # đọc ./.bench, ghi ./.bench/tex
 *   IN_DIR=… OUT_DIR=… node scripts/bench/plot.mjs
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";

const IN = process.env.IN_DIR ?? "./.bench";
const OUT = process.env.OUT_DIR ?? "./.bench/tex";
mkdirSync(OUT, { recursive: true });

const read = (f) => JSON.parse(readFileSync(`${IN}/${f}`, "utf8"));
const repeat = read("repeat.json").data;
const sweep = read("sweep.json").data;
const dist = read("dist.json").data;
const meta = read("meta.json");
let sweep2 = null;
try { sweep2 = read("sweep2.json"); } catch { /* chưa chạy bench-sweep2 */ }
let samplesize = null;
try { samplesize = read("samplesize.json"); } catch { /* chưa chạy bench-samplesize */ }

const f = (x, d = 1) => Number(x).toFixed(d);
/** Nhãn tuyến dùng trong biểu đồ — \texttt không chạy trong nhãn pgfplots. */
const label = (r) => r.replace(/_/g, "\\_");

// ============================================================
// Biểu đồ 1 — Quét mức đồng thời (dùng sweep2: trung vị + dải min–max)
// ============================================================
if (sweep2) {
  const d = sweep2.data;
  const m2 = sweep2.meta;
  const routes = [...new Set(d.map((x) => x.route))];
  const colors = { "/health": "blue!70!black", "/did/resolve": "red!70!black", "/auth/me": "green!55!black" };
  const marks = { TS: "*", GO: "square*" };
  const dash = { TS: "", GO: "dashed," };

  // Dải min–max vẽ trước để nằm dưới đường trung vị. Phải làm cho nhiễu
  // NHÌN THẤY ĐƯỢC thay vì chỉ nhắc tới nó trong phần chú thích.
  const band = (metric) =>
    routes.flatMap((route) =>
      ["TS", "GO"].map((be) => {
        const rows = d.filter((x) => x.backend === be && x.route === route).sort((a, b) => a.conc - b.conc);
        const up = rows.map((r) => `(${r.conc},${f(r[metric + "_max"], 2)})`).join(" ");
        const lo = [...rows].reverse().map((r) => `(${r.conc},${f(r[metric + "_min"], 2)})`).join(" ");
        return `    \\addplot[draw=none, fill=${colors[route] ?? "gray"}, fill opacity=0.10, forget plot] coordinates {${up} ${lo}} \\closedcycle;`;
      }),
    ).join("\n");

  const line = (metric) =>
    routes.flatMap((route) =>
      ["TS", "GO"].map((be) => {
        const rows = d.filter((x) => x.backend === be && x.route === route).sort((a, b) => a.conc - b.conc);
        const coords = rows.map((r) => `(${r.conc},${f(r[metric], metric === "rps" ? 0 : 2)})`).join(" ");
        return `    \\addplot[${dash[be]}color=${colors[route] ?? "black"},mark=${marks[be]},mark size=1.5pt,thick] coordinates {${coords}};
    \\addlegendentry{${label(route)} --- ${be}}`;
      }),
    ).join("\n");

  const tex = `% SINH TỰ ĐỘNG bởi scripts/bench/plot.mjs — đừng sửa tay.
% Nguồn dữ liệu: .bench/sweep2.json
% ${m2.repeats} lượt mỗi điểm, n = max(1000, 40c), ${m2.totalRequests.toLocaleString("vi-VN")} yêu cầu, đo ${m2.startedAt}
\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{axis}[
    name=plotA,
    width=0.95\\textwidth, height=5.0cm,
    xlabel={}, ylabel={Thông lượng (yc/giây)},
    xmode=log, log basis x=2, xtick={1,2,4,8,16,32,64}, xticklabels={1,2,4,8,16,32,64},
    ymin=0, enlarge y limits={upper,value=0.34},
    grid=both, grid style={gray!18},
    legend style={font=\\tiny, at={(0.02,0.98)}, anchor=north west, fill=white, fill opacity=0.85, text opacity=1, draw=gray!40, legend columns=3},
    label style={font=\\small}, tick label style={font=\\footnotesize},
    title={(a) Thông lượng --- đường là trung vị của ${m2.repeats} lượt, vùng tô là khoảng nhỏ nhất--lớn nhất},
    title style={font=\\small},
]
${band("rps")}
${line("rps")}
\\end{axis}
\\begin{axis}[
    at={(plotA.below south west)}, anchor=above north west, yshift=-0.9cm,
    width=0.95\\textwidth, height=5.0cm,
    xlabel={Số yêu cầu đồng thời (thang logarit)}, ylabel={Độ trễ p95 (ms)},
    xmode=log, log basis x=2, xtick={1,2,4,8,16,32,64}, xticklabels={1,2,4,8,16,32,64},
    ymode=log,
    grid=both, grid style={gray!18},
    legend style={font=\\tiny, at={(0.02,0.98)}, anchor=north west, fill=white, fill opacity=0.85, text opacity=1, draw=gray!40, legend columns=3},
    label style={font=\\small}, tick label style={font=\\footnotesize},
    title={(b) Độ trễ p95 --- đường gạch đỏ là ngưỡng 500 ms của yêu cầu N11},
    title style={font=\\small},
    extra y ticks={500}, extra y tick labels={}, extra y tick style={grid=major, grid style={red!55, densely dashed, thick}},
]
${band("p95")}
${line("p95")}
\\end{axis}
\\end{tikzpicture}
\\caption{Hành vi của hệ thống khi tăng số yêu cầu đồng thời từ 1 đến 64. Đường liền là cài đặt TypeScript, đường gạch là cài đặt Go. Vùng tô nhạt là khoảng giữa lượt nhỏ nhất và lượt lớn nhất trong ${m2.repeats} lượt đo của cùng một điểm; độ rộng của vùng này chính là mức nhiễu mà Mục 4.9.2 lượng hoá.}
\\label{fig:bench-sweep}
\\end{figure}
`;
  writeFileSync(`${OUT}/fig-sweep.tex`, tex);

  // Bảng: đỉnh thông lượng và p95 theo trung vị / lớn nhất
  const rows = routes
    .flatMap((route) =>
      ["TS", "GO"].map((be) => {
        const rs = d.filter((x) => x.backend === be && x.route === route);
        const peak = rs.reduce((a, b) => (b.rps > a.rps ? b : a));
        const c8 = rs.find((x) => x.conc === 8);
        const maxP95 = Math.max(...rs.map((x) => x.p95_max));
        const medMax = Math.max(...rs.map((x) => x.p95));
        return `${be} & \\texttt{${label(route)}} & ${f(peak.rps, 0)} & ${peak.conc} & ${f(c8.p95, 1)} & ${f(medMax, 1)} & ${f(maxP95, 1)} & ${rs.reduce((n, x) => n + x.bad, 0)} \\\\`;
      }),
    )
    .join("\n");

  const tab = `% SINH TỰ ĐỘNG bởi scripts/bench/plot.mjs — đừng sửa tay.
% Nguồn dữ liệu: .bench/sweep2.json
\\begin{table}[H]
\\centering
\\caption{Kết quả quét mức đồng thời: ${m2.repeats} lượt mỗi điểm, tổng ${m2.totalRequests.toLocaleString("vi-VN")} yêu cầu}
\\label{tab:bench-sweep}
\\renewcommand{\\arraystretch}{1.2}
\\footnotesize
\\begin{tabular}{|c|l|r|c|r|r|r|c|}
\\hline
\\textbf{Cài đặt} & \\textbf{Tuyến} & \\textbf{Đỉnh (yc/s)} & \\textbf{tại c} & \\textbf{p95 ở c=8} & \\textbf{p95 trung vị lớn nhất} & \\textbf{p95 lớn nhất} & \\textbf{Lỗi} \\\\
\\hline
${rows}
\\hline
\\end{tabular}

\\vspace{0.2cm}
\\begin{minipage}{0.95\\textwidth}
\\footnotesize
Cột {\`\`}p95 trung vị lớn nhất{''} là giá trị lớn nhất của trung vị p95 trên bảy mức đồng thời; cột {\`\`}p95 lớn nhất{''} là giá trị lớn nhất quan sát được ở bất kỳ lượt đo nào. Khoảng cách giữa hai cột là mức nhiễu của phép đo.
\\end{minipage}
\\end{table}
`;
  writeFileSync(`${OUT}/tab-sweep.tex`, tab);
}

// ============================================================
// Biểu đồ 2 — Độ lặp lại: p95 trung bình ± độ lệch chuẩn
// ============================================================
{
  const routes = [...new Set(repeat.map((r) => r.route))];
  const bar = (be) =>
    routes
      .map((route, i) => {
        const r = repeat.find((x) => x.backend === be && x.route === route);
        return `(${i},${f(r.p95_mean, 2)}) +- (0,${f(r.p95_sd, 2)})`;
      })
      .join(" ");

  const cv = (be) =>
    routes
      .map((route, i) => {
        const r = repeat.find((x) => x.backend === be && x.route === route);
        return `(${i},${f((r.p95_sd / r.p95_mean) * 100, 1)})`;
      })
      .join(" ");

  const ticks = routes.map((r, i) => i).join(",");
  const tickLabels = routes.map((r) => label(r)).join(", ");

  const tex = `% SINH TỰ ĐỘNG bởi scripts/bench/plot.mjs — đừng sửa tay.
% Nguồn dữ liệu: .bench/repeat.json  (${meta.repeats} lượt mỗi tuyến, đo ${meta.startedAt})
\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{axis}[
    name=plotR,
    width=0.95\\textwidth, height=5.4cm,
    ybar, bar width=7pt,
    xlabel={}, ylabel={Độ trễ p95 (ms)},
    xtick={${ticks}}, xticklabels={${tickLabels}},
    x tick label style={font=\\scriptsize, rotate=20, anchor=north east},
    tick label style={font=\\footnotesize}, label style={font=\\small},
    ymin=0,
    grid=both, grid style={gray!18},
    error bars/y dir=both, error bars/y explicit,
    legend style={font=\\scriptsize, at={(0.98,0.98)}, anchor=north east, draw=gray!40},
    title={(a) p95 trung bình qua ${meta.repeats} lượt đo, thanh sai số là một độ lệch chuẩn},
    title style={font=\\small},
]
    \\addplot[fill=blue!35, draw=blue!60!black, error bars/error bar style={black}] coordinates {${bar("TS")}};
    \\addlegendentry{TypeScript}
    \\addplot[fill=orange!45, draw=orange!70!black, error bars/error bar style={black}] coordinates {${bar("GO")}};
    \\addlegendentry{Go}
\\end{axis}
\\begin{axis}[
    at={(plotR.below south west)}, anchor=above north west, yshift=-0.9cm,
    width=0.95\\textwidth, height=4.2cm,
    ybar, bar width=7pt,
    ylabel={Hệ số biến thiên của p95 (\\%)},
    xtick={${ticks}}, xticklabels={${tickLabels}},
    x tick label style={font=\\scriptsize, rotate=20, anchor=north east},
    tick label style={font=\\footnotesize}, label style={font=\\small},
    ymin=0,
    grid=both, grid style={gray!18},
    legend style={font=\\scriptsize, at={(0.98,0.98)}, anchor=north east, draw=gray!40},
    title={(b) Hệ số biến thiên --- càng cao thì số đo một lượt càng ít ý nghĩa},
    title style={font=\\small},
]
    \\addplot[fill=blue!35, draw=blue!60!black] coordinates {${cv("TS")}};
    \\addlegendentry{TypeScript}
    \\addplot[fill=orange!45, draw=orange!70!black] coordinates {${cv("GO")}};
    \\addlegendentry{Go}
\\end{axis}
\\end{tikzpicture}
\\caption{Độ lặp lại của phép đo độ trễ: cùng một phép đo (120 yêu cầu, 12 yêu cầu đồng thời) chạy lại ${meta.repeats} lần trên cùng một máy và cùng một cấu hình.}
\\label{fig:bench-repeat}
\\end{figure}
`;
  writeFileSync(`${OUT}/fig-repeat.tex`, tex);
}

// ============================================================
// Biểu đồ 3 — Phân bố độ trễ (hàm phân bố tích luỹ)
// ============================================================
{
  // Lấy mẫu theo phân vị thay vì theo chỉ số, để phần đuôi được thể hiện đủ
  // chi tiết mà tệp .tex không phình ra hàng nghìn toạ độ.
  const QS = [
    ...Array.from({ length: 19 }, (_, i) => (i + 1) * 5),      // 5..95
    96, 97, 98, 99, 99.3, 99.5, 99.7, 99.9, 100,
  ];
  const colors = { "/health": "blue!70!black", "/stats": "violet!70!black", "/did/resolve": "red!70!black" };
  const dash = { TS: "", GO: "dashed," };

  const curves = dist
    .map((d) => {
      const n = d.lat.length;
      const pts = QS.map((q) => {
        const idx = Math.min(n - 1, Math.max(0, Math.ceil((q / 100) * n) - 1));
        return `(${d.lat[idx]},${f(q, 2)})`;
      }).join(" ");
      return `    \\addplot[${dash[d.backend]}color=${colors[d.route]},thick,no marks] coordinates {${pts}};
    \\addlegendentry{${label(d.route)} --- ${d.backend}}`;
    })
    .join("\n");

  const rows = dist
    .map(
      (d) =>
        `${d.backend} & \\texttt{${label(d.route)}} & ${f(d.mean)} & ${f(d.p50)} & ${f(d.p95)} & ${f(d.p99)} & ${f(d.max)} & ${f(d.p95 / d.p50)}$\\times$ \\\\`,
    )
    .join("\n");

  const tex = `% SINH TỰ ĐỘNG bởi scripts/bench/plot.mjs — đừng sửa tay.
% Nguồn dữ liệu: .bench/dist.json  (${dist[0]?.n ?? "?"} yêu cầu mỗi tuyến, đo ${meta.startedAt})
\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{axis}[
    width=0.92\\textwidth, height=6.2cm,
    xlabel={Độ trễ (ms, thang logarit)}, ylabel={Tỉ lệ yêu cầu hoàn tất (\\%)},
    xmode=log,
    ymin=0, ymax=101,
    ytick={0,25,50,75,90,95,99,100},
    grid=both, grid style={gray!18},
    legend style={font=\\scriptsize, at={(0.02,0.98)}, anchor=north west, fill=white, fill opacity=0.85, text opacity=1, draw=gray!40},
    label style={font=\\small}, tick label style={font=\\footnotesize},
    extra y ticks={95}, extra y tick labels={}, extra y tick style={grid=major, grid style={red!40, densely dashed}},
]
${curves}
\\end{axis}
\\end{tikzpicture}
\\caption{Hàm phân bố tích luỹ của độ trễ, ${dist[0]?.n ?? ""} yêu cầu mỗi tuyến. Đường gạch ngang màu đỏ là mức phân vị 95. Khoảng cách giữa phần thân và phần đuôi của mỗi đường là lý do báo cáo dùng phân vị thay cho giá trị trung bình.}
\\label{fig:bench-dist}
\\end{figure}

\\begin{table}[H]
\\centering
\\caption{Thống kê độ trễ của ba tuyến, ${dist[0]?.n ?? ""} yêu cầu mỗi tuyến (đơn vị ms)}
\\label{tab:bench-dist}
\\renewcommand{\\arraystretch}{1.2}
\\begin{tabular}{|c|l|r|r|r|r|r|r|}
\\hline
\\textbf{Cài đặt} & \\textbf{Tuyến} & \\textbf{Trung bình} & \\textbf{p50} & \\textbf{p95} & \\textbf{p99} & \\textbf{Lớn nhất} & \\textbf{p95/p50} \\\\
\\hline
${rows}
\\hline
\\end{tabular}
\\end{table}
`;
  writeFileSync(`${OUT}/fig-dist.tex`, tex);
}

// ============================================================
// Bảng số liệu: độ lặp lại (để nêu con số chính xác trong báo cáo)
// ============================================================
{
  const rows = [...new Set(repeat.map((r) => r.route))]
    .flatMap((route) =>
      ["TS", "GO"].map((be) => {
        const r = repeat.find((x) => x.backend === be && x.route === route);
        const cv = (r.p95_sd / r.p95_mean) * 100;
        return `${be} & \\texttt{${label(route)}} & ${f(r.rps_mean, 0)} $\\pm$ ${f(r.rps_sd, 0)} & ${f((r.rps_sd / r.rps_mean) * 100)} & ${f(r.p95_mean)} $\\pm$ ${f(r.p95_sd)} & ${f(cv)} & ${f(r.p95_min)}--${f(r.p95_max)} \\\\`;
      }),
    )
    .join("\n");

  const tex = `% SINH TỰ ĐỘNG bởi scripts/bench/plot.mjs — đừng sửa tay.
% Nguồn dữ liệu: .bench/repeat.json
% Bảy cột với hai cột "x ± y" thì ở cỡ chữ thường sẽ tràn lề 92pt — thu nhỏ cỡ
% chữ và khoảng đệm cột thay vì cắt bớt cột, vì cột cuối chính là bằng chứng.
\\begingroup
\\footnotesize
\\setlength{\\tabcolsep}{4pt}
\\begin{longtable}{|c|l|r|r|r|r|r|}
\\caption{Độ lặp lại của phép đo: ${meta.repeats} lượt độc lập cho mỗi tuyến và mỗi cài đặt}
\\label{tab:bench-repeat} \\\\

\\hline
\\textbf{Cài đặt} & \\textbf{Tuyến} & \\textbf{yc/giây} & \\textbf{CV (\\%)} & \\textbf{p95 (ms)} & \\textbf{CV (\\%)} & \\textbf{p95 min--max} \\\\
\\hline
\\endfirsthead

\\hline
\\textbf{Cài đặt} & \\textbf{Tuyến} & \\textbf{yc/giây} & \\textbf{CV (\\%)} & \\textbf{p95 (ms)} & \\textbf{CV (\\%)} & \\textbf{p95 min--max} \\\\
\\hline
\\endhead

\\hline
\\endfoot

\\hline
\\endlastfoot

${rows}

\\end{longtable}
\\endgroup
`;
  writeFileSync(`${OUT}/tab-repeat.tex`, tex);
}

// ============================================================
// Biểu đồ 4 — Số mẫu và độ lặp lại của phép đo
// ============================================================
if (samplesize) {
  const d = samplesize.data;
  const meta2 = samplesize.meta;
  const routes = [...new Set(d.map((x) => x.route))];
  const colors = { "/health": "blue!70!black", "/did/resolve": "red!70!black", "/auth/me": "green!55!black" };
  const dash = { TS: "", GO: "dashed," };
  const marks = { TS: "*", GO: "square*" };

  const series = (field) =>
    routes.flatMap((route) =>
      ["TS", "GO"].map((be) => {
        const rows = d.filter((x) => x.backend === be && x.route === route).sort((a, b) => a.n - b.n);
        const coords = rows.map((r) => `(${r.n},${f(r[field], 2)})`).join(" ");
        return `    \\addplot[${dash[be]}color=${colors[route] ?? "black"},mark=${marks[be]},mark size=1.5pt,thick] coordinates {${coords}};
    \\addlegendentry{${label(route)} --- ${be}}`;
      }),
    ).join("\n");

  const tex = `% SINH TỰ ĐỘNG bởi scripts/bench/plot.mjs — đừng sửa tay.
% Nguồn dữ liệu: .bench/samplesize.json
% ${meta2.repeats} lượt độc lập cho mỗi mức số mẫu, đồng thời ${meta2.conc}, đo ${meta2.startedAt}
\\begin{figure}[H]
\\centering
\\begin{tikzpicture}
\\begin{axis}[
    name=ssA,
    width=0.95\\textwidth, height=5.0cm,
    xlabel={}, ylabel={Hệ số biến thiên của p95 (\\%)},
    xmode=log, log basis x=10,
    xtick={60,120,250,500,1000,2000,4000},
    xticklabels={60,120,250,500,1000,2000,4000},
    ymin=0,
    grid=both, grid style={gray!18},
    legend style={font=\\tiny, at={(0.98,0.98)}, anchor=north east, fill=white, fill opacity=0.85, text opacity=1, draw=gray!40},
    label style={font=\\small}, tick label style={font=\\footnotesize},
    title={(a) Độ phân tán của p95 giảm khi tăng số mẫu}, title style={font=\\small},
    extra y ticks={10}, extra y tick labels={}, extra y tick style={grid=major, grid style={red!45, densely dashed}},
]
${series("p95_cv")}
\\end{axis}
\\begin{axis}[
    at={(ssA.below south west)}, anchor=above north west, yshift=-0.9cm,
    width=0.95\\textwidth, height=5.0cm,
    xlabel={Số yêu cầu mỗi lượt đo (thang logarit)}, ylabel={p95 trung bình (ms)},
    xmode=log, log basis x=10,
    xtick={60,120,250,500,1000,2000,4000},
    xticklabels={60,120,250,500,1000,2000,4000},
    ymin=0,
    grid=both, grid style={gray!18},
    legend style={font=\\tiny, at={(0.98,0.98)}, anchor=north east, fill=white, fill opacity=0.85, text opacity=1, draw=gray!40},
    label style={font=\\small}, tick label style={font=\\footnotesize},
    title={(b) Giá trị p95 đo được cũng giảm --- mẫu nhỏ cho kết quả lệch cao}, title style={font=\\small},
]
${series("p95_mean")}
\\end{axis}
\\end{tikzpicture}
\\caption{Ảnh hưởng của số mẫu tới phép đo độ trễ. Mỗi điểm là trung bình của ${meta2.repeats} lượt đo độc lập ở cùng mức ${meta2.conc} yêu cầu đồng thời. Đường gạch đỏ ở hình (a) là mức hệ số biến thiên 10\\%.}
\\label{fig:bench-samplesize}
\\end{figure}
`;
  writeFileSync(`${OUT}/fig-samplesize.tex`, tex);

  // Bảng số liệu gọn: chỉ cột CV, để nêu con số trong văn bản
  const sizes = [...new Set(d.map((x) => x.n))].sort((a, b) => a - b);
  const header = sizes.map((n) => `\\textbf{${n}}`).join(" & ");
  const rows = routes
    .flatMap((route) =>
      ["TS", "GO"].map((be) => {
        const cells = sizes
          .map((n) => {
            const r = d.find((x) => x.backend === be && x.route === route && x.n === n);
            return r ? f(r.p95_cv, 1) : "---";
          })
          .join(" & ");
        return `${be} & \\texttt{${label(route)}} & ${cells} \\\\`;
      }),
    )
    .join("\n");

  const tabTex = `% SINH TỰ ĐỘNG bởi scripts/bench/plot.mjs — đừng sửa tay.
% Nguồn dữ liệu: .bench/samplesize.json
\\begin{table}[H]
\\centering
\\caption{Hệ số biến thiên của p95 theo số mẫu, tính trên ${meta2.repeats} lượt đo độc lập (đơn vị \\%)}
\\label{tab:bench-samplesize}
\\renewcommand{\\arraystretch}{1.2}
\\footnotesize
\\begin{tabular}{|c|l|${sizes.map(() => "r").join("|")}|}
\\hline
\\multirow{2}{*}{\\textbf{Cài đặt}} & \\multirow{2}{*}{\\textbf{Tuyến}} & \\multicolumn{${sizes.length}}{c|}{\\textbf{Số yêu cầu mỗi lượt đo}} \\\\
\\cline{3-${sizes.length + 2}}
 & & ${header} \\\\
\\hline
${rows}
\\hline
\\end{tabular}
\\end{table}
`;
  writeFileSync(`${OUT}/tab-samplesize.tex`, tabTex);
  console.log(`Đã sinh thêm: ${OUT}/{fig-samplesize,tab-samplesize}.tex`);
}

console.log(`Đã sinh: ${OUT}/{fig-sweep,fig-repeat,fig-dist,tab-repeat}.tex`);
