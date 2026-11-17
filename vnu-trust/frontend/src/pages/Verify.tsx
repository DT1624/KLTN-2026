import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, type VerificationReport } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { useTitle } from "../hooks/useTitle";
import { openPresentation, parseShareInput } from "../lib/vcStore";
import { Alert, Spinner, Mono, Empty, Row, StatusBadge, Badge, Section } from "../components/ui";
import { IconCheck, IconCross } from "../components/icons";
import Rosette from "../components/Rosette";
import Seal from "../components/Seal";

// Tên bước do máy chủ trả về sang nhãn dễ hiểu; không khớp thì hiện nguyên tên.
const CHECK_LABEL: Record<string, string> = {
  "Tải VP từ IPFS": "Lấy được bản trình bày đã mã hoá",
  "Toàn vẹn nội dung VP": "Bản trình bày còn nguyên vẹn",
  "Chữ ký của người trình bày": "Chữ ký của người trình bày hợp lệ",
  "DID người trình bày còn hiệu lực": "Danh tính người trình bày còn hoạt động",
  "Tất cả chứng chỉ còn hiệu lực": "Văn bằng chưa bị thu hồi, tạm ngưng hay hết hạn",
};
const checkLabel = (name: string) => CHECK_LABEL[name] ?? name;

/** Trang xác minh công khai: bên xác minh mở liên kết người học gửi là vào thẳng đây. */
export default function Verify() {
  useTitle("Xác minh văn bằng");
  const { token: routeToken } = useParams();
  const { wallet } = useWallet();
  const inputId = useId();
  const verdictRef = useRef<HTMLHeadingElement>(null);
  // P3: khoá giải mã nằm trong FRAGMENT (#k=…) — trình duyệt không gửi phần này lên máy chủ.
  const routeKey = new URLSearchParams(location.hash.slice(1)).get("k");
  const [token, setToken] = useState(routeToken ? `${routeToken}${routeKey ? `#k=${routeKey}` : ""}` : "");
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [err, setErr] = useState("");

  const preview = useQuery({
    queryKey: ["share", routeToken],
    queryFn: () => api.get<{ vpId: string; holderDid: string; expiresAt: string; vcIds: string[] }>(
      // Mã hoá: liên kết kiểu /verify/..%2F..%2Fadmin%2Faudit từng khiến trình duyệt
      // gửi kèm token của người đang đăng nhập sang tuyến khác (W-08).
      `/verify/share/${encodeURIComponent(routeToken ?? "")}`),
    enabled: Boolean(routeToken),
    retry: false,
  });

  const run = useMutation({
    mutationFn: async (input: string) => {
      const { token: t, key } = parseShareInput(input);
      if (!key) throw new Error("Liên kết thiếu khoá giải mã (#k=…). Hãy dùng đúng liên kết hoặc mã QR người sở hữu gửi.");
      const share = await api.get<{ ipfsCid: string }>(`/verify/share/${encodeURIComponent(t)}`);
      // Giải mã NGAY TRÊN MÁY người xác minh; sửa bản mã thì AES-GCM báo lỗi ở đây.
      let vp: Record<string, unknown>;
      try {
        vp = await openPresentation(share.ipfsCid, key);
      } catch {
        throw new Error("Không giải mã được bản trình bày — khoá trong liên kết sai, hoặc bản mã đã bị sửa.");
      }
      // Đăng nhập với vai trò xác minh thì lưu vào lịch sử, không thì chỉ kiểm tra.
      // Máy chủ chạy 7 bước trên bản rõ này rồi bỏ đi — chỉ lưu báo cáo.
      const canRecord = wallet && ["verifier", "admin", "root"].includes(wallet.role);
      return api.post<VerificationReport>(`/verify/share/${encodeURIComponent(t)}${canRecord ? "/record" : ""}`, { vp });
    },
    onSuccess: (r) => { setReport(r); setErr(""); },
    onError: (e) => { setErr((e as Error).message); setReport(null); },
  });

  // Kết quả vừa về thì đưa focus tới kết luận.
  useEffect(() => {
    if (report) verdictRef.current?.focus();
  }, [report]);

  return (
    <div className="max-w-4xl space-y-10">
      <header>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Xác minh văn bằng</h1>
        <p className="mt-2 text-muted max-w-prose">
          Dán liên kết người học gửi cho bạn. Trình duyệt của bạn tự giải mã văn bằng rồi đối chiếu bảy bước
          với sổ đăng ký trên chuỗi.
        </p>
      </header>

      <section className="sheet p-5">
        <form className="flex flex-col sm:flex-row sm:items-end gap-3"
          onSubmit={(e) => { e.preventDefault(); run.mutate(token.trim()); }}>
          <div className="flex-1 min-w-0">
            <label className="label" htmlFor={inputId}>Liên kết chia sẻ</label>
            <input id={inputId} className="input hex" value={token} onChange={(e) => setToken(e.target.value)}
              placeholder="…/verify/<mã>#k=<khoá>" />
          </div>
          <button className="btn-primary" disabled={run.isPending || token.trim().length < 8}>
            {run.isPending ? "Đang xác minh…" : "Xác minh"}
          </button>
        </form>

        {preview.isError && (
          <div className="mt-4"><Alert tone="bad" title="Liên kết không dùng được">
            {(preview.error as Error).message}
          </Alert></div>
        )}
        {preview.data && !report && (
          <p className="mt-4 text-sm text-muted">
            Liên kết còn hạn đến{" "}
            <strong className="font-semibold">{new Date(preview.data.expiresAt).toLocaleString("vi-VN")}</strong>,
            chứa {preview.data.vcIds.length} văn bằng. Bấm Xác minh để kiểm đủ bảy bước.
          </p>
        )}
      </section>

      {err && <Alert tone="bad" title="Xác minh thất bại">{err}</Alert>}
      {run.isPending && <Spinner label="Đang đối chiếu với sổ đăng ký trên chuỗi…" />}

      <div aria-live="polite">
        {report && <Report report={report} verdictRef={verdictRef} />}
      </div>
    </div>
  );
}

function Report({ report, verdictRef }: { report: VerificationReport; verdictRef: React.RefObject<HTMLHeadingElement> }) {
  const ok = report.overallValid;
  const n = report.credentials.length;
  const failIdx = report.checks.findIndex((c) => !c.passed && !c.advisory);
  const failed = failIdx >= 0 ? report.checks[failIdx] : undefined;
  // Hoa văn: seed tính một lần từ báo cáo, không đổi giữa các lần render.
  const firstVcId = report.credentials[0]?.vcId;
  const seed = useMemo(
    () => (n === 1 && firstVcId ? firstVcId : report.vpId),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [report.vpId, firstVcId],
  );
  // Hiệu ứng vẽ chỉ chạy ở lần render đầu của mỗi báo cáo (theo vpId). Render lại
  // cùng vpId thì tắt animate, để hoa văn không bị vẽ lại từ đầu (bản 1 hiện trống).
  const drawnFor = useRef<string | null>(null);
  const animate = drawnFor.current !== report.vpId;
  useEffect(() => {
    drawnFor.current = report.vpId;
  }, [report.vpId]);

  return (
    <div className="space-y-6">
      <section className="sheet shadow-raised p-6 sm:p-8 relative">
        <div className="grid lg:grid-cols-[minmax(0,1fr)_220px] gap-8">
          <div>
            <div className="flex gap-4 items-start">
              <span
                className={`w-11 h-11 shrink-0 rounded-full grid place-items-center ${ok ? "bg-success-soft text-success" : "bg-son-tint text-son"}`}
              >
                {ok ? <IconCheck className="w-6 h-6" /> : <IconCross className="w-6 h-6" />}
              </span>
              <div className="min-w-0">
                <h2
                  ref={verdictRef}
                  tabIndex={-1}
                  className={`text-3xl font-bold tracking-tight ${ok ? "text-ink" : "text-son"}`}
                >
                  {ok ? (n > 1 ? `${n} văn bằng đều thật` : "Văn bằng thật") : "Không xác minh được"}
                </h2>
                {ok ? (
                  <p className="mt-2 text-lg text-ink-2 max-w-[52ch]">
                    Còn hiệu lực. Đã đối chiếu với sổ đăng ký trên chuỗi lúc {new Date(report.verifiedAt).toLocaleString("vi-VN")}.
                  </p>
                ) : (
                  <p className="mt-2 text-lg text-ink-2 max-w-[52ch]">
                    {failed
                      ? <>Bước {failIdx + 1} không đạt: {checkLabel(failed.name)}. {failed.detail}</>
                      : "Có bước kiểm không đạt."}
                  </p>
                )}
              </div>
            </div>

            <ol className="rounded-sheet border border-rule overflow-hidden mt-5">
              {report.checks.map((c, i) => {
                const flagged = !c.passed;
                return (
                  <li
                    key={c.name}
                    className="grid grid-cols-[1.75rem_minmax(0,1fr)_auto] gap-3 px-4 py-3 border-t border-rule first:border-t-0 items-center"
                  >
                    <span className="text-muted tabular-nums">{i + 1}</span>
                    <div className="min-w-0">
                      <p className="font-semibold">{checkLabel(c.name)}</p>
                      {(flagged || c.advisory) && c.detail && (
                        <p className="mt-0.5 text-sm text-muted break-words">{c.detail}</p>
                      )}
                      {c.advisory && !c.passed && (
                        <p className="text-sm text-muted">Không ảnh hưởng kết quả xác minh.</p>
                      )}
                    </div>
                    {c.passed ? (
                      c.advisory ? <Badge tone="muted">Tham khảo</Badge> : <Badge tone="ok">Đạt</Badge>
                    ) : c.advisory ? (
                      <Badge tone="warn">Cần lưu ý</Badge>
                    ) : (
                      <Badge tone="bad">Không đạt</Badge>
                    )}
                  </li>
                );
              })}
            </ol>
          </div>

          <div className="relative lg:self-start">
            <div className="max-w-full">
              <Rosette seed={seed} size={220} animate={animate} title="Hoa văn đối chiếu của văn bằng" />
            </div>
            <p className="mt-4 text-sm text-muted">
              Người học mở văn bằng này trong ví sẽ thấy đúng hoa văn này.
            </p>
            {ok && (
              <div className="absolute top-0 right-4 lg:-top-4 lg:-right-4">
                <Seal size={130} animate={animate} />
              </div>
            )}
          </div>
        </div>
      </section>

      <Section title="Văn bằng trong bản trình bày">
        {n ? (
          <ul className="border-t border-rule">
            {report.credentials.map((c) => (
              <li key={c.vcId} className="flex items-start gap-4 border-b border-rule py-4 last:border-b-0">
                <Rosette seed={c.vcId} size={56} />
                <div className="min-w-0 flex-1">
                  <h3 className="text-base font-semibold">{c.typeLabel}</h3>
                  <p className="mt-1 text-sm text-muted">Cấp bởi <Mono value={c.issuerDid} /></p>
                  {c.replacedBy && (
                    <p className="mt-2 rounded-ctrl bg-warning-soft text-ink p-2 text-sm">
                      Văn bằng này đã được cấp lại. Bản mới: <Mono value={c.replacedBy} />
                    </p>
                  )}
                </div>
                <StatusBadge status={c.status} />
              </li>
            ))}
          </ul>
        ) : <Empty title="Bản trình bày không chứa văn bằng nào" />}
        <dl className="space-y-3 mt-4">
          <Row label="Người trình bày"><Mono value={report.holderDid} /></Row>
          <Row label="Mã bản trình bày"><Mono value={report.vpId} /></Row>
        </dl>
      </Section>
    </div>
  );
}
