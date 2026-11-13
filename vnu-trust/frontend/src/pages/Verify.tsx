import { useState } from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, type VerificationReport } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { openPresentation, parseShareInput } from "../lib/vcStore";
import { Card, Alert, Spinner, Badge, Mono, Empty } from "../components/ui";

/** Trang xác minh công khai — bên xác minh quét QR là vào thẳng đây. */
export default function Verify() {
  const { token: routeToken } = useParams();
  const { wallet } = useWallet();
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

  return (
    <div className="mx-auto max-w-3xl px-4 py-10 space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-ink-900">Xác minh văn bằng</h1>
        <p className="text-sm text-ink-600 mt-1">
          Dán mã chia sẻ hoặc quét QR. Hệ thống kiểm 7 bước độc lập và đối chiếu trực tiếp với blockchain.
        </p>
      </header>

      <Card>
        <form className="flex flex-col sm:flex-row gap-3"
          onSubmit={(e) => { e.preventDefault(); run.mutate(token.trim()); }}>
          <input className="input flex-1 mono" value={token} onChange={(e) => setToken(e.target.value)}
            placeholder="Liên kết chia sẻ (…/verify/<mã>#k=<khoá>)" aria-label="Liên kết chia sẻ" />
          <button className="btn-primary" disabled={run.isPending || token.trim().length < 8}>
            {run.isPending ? "Đang kiểm…" : "Xác minh"}
          </button>
        </form>

        {preview.isError && (
          <div className="mt-4"><Alert tone="bad" title="Liên kết không dùng được">
            {(preview.error as Error).message}
          </Alert></div>
        )}
        {preview.data && !report && (
          <div className="mt-4 text-sm text-ink-600">
            Liên kết hợp lệ, chứa {preview.data.vcIds.length} văn bằng, hết hạn lúc{" "}
            <strong>{new Date(preview.data.expiresAt).toLocaleString("vi-VN")}</strong>.
            Bấm “Xác minh” để kiểm tra đầy đủ.
          </div>
        )}
      </Card>

      {err && <Alert tone="bad" title="Xác minh thất bại">{err}</Alert>}
      {run.isPending && <Spinner label="Đang đối chiếu với blockchain…" />}

      {report && (
        <>
          <div className={`rounded-2xl p-6 text-center border-2 ${
            report.overallValid ? "bg-emerald-50 border-emerald-300" : "bg-rose-50 border-rose-300"
          }`}>
            <div className="text-5xl" aria-hidden>{report.overallValid ? "✅" : "⛔"}</div>
            <p className={`mt-3 text-xl font-bold ${report.overallValid ? "text-emerald-800" : "text-rose-800"}`}>
              {report.overallValid ? "Văn bằng hợp lệ" : "Không vượt qua xác minh"}
            </p>
            <p className="mt-1 text-sm text-ink-600">
              Kiểm lúc {new Date(report.verifiedAt).toLocaleString("vi-VN")}
            </p>
          </div>

          <Card title="Chi tiết 7 bước kiểm tra">
            <ul className="space-y-2.5">
              {report.checks.map((c) => (
                <li key={c.name} className="flex items-start gap-3 text-sm">
                  {/* Bước cảnh báo (bước 6 — C2): không quyết định kết quả, hiện màu vàng. */}
                  <span aria-hidden className="mt-0.5">{c.passed ? "✅" : c.advisory ? "⚠️" : "❌"}</span>
                  <div className="min-w-0">
                    <p className={`font-semibold ${c.passed ? "text-ink-800" : c.advisory ? "text-amber-700" : "text-rose-700"}`}>
                      {c.name}{!c.passed && c.advisory && <span className="font-normal text-xs"> · cảnh báo, không ảnh hưởng kết quả</span>}
                    </p>
                    <p className="text-ink-500 text-xs mt-0.5 break-words">{c.detail}</p>
                  </div>
                </li>
              ))}
            </ul>
          </Card>

          <Card title="Văn bằng trong bản trình bày">
            {report.credentials.length ? (
              <ul className="divide-y divide-ink-100">
                {report.credentials.map((c) => (
                  <li key={c.vcId} className="py-3 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="font-medium text-ink-800">{c.typeLabel}</p>
                      <p className="text-xs text-ink-500 mt-0.5">Cấp bởi <Mono value={c.issuerDid} /></p>
                      {c.replacedBy && (
                        <p className="text-xs text-amber-700 mt-1">
                          Văn bằng này đã được cấp lại — thay bằng <Mono value={c.replacedBy} /> (liên kết ghi trên chuỗi).
                        </p>
                      )}
                    </div>
                    <Badge tone={c.status === "active" ? "ok" : "bad"}>{c.status}</Badge>
                  </li>
                ))}
              </ul>
            ) : <Empty title="Bản trình bày không chứa văn bằng nào" />}
          </Card>

          <p className="text-xs text-ink-400 text-center">
            Người trình bày: <Mono value={report.holderDid} /> · Mã VP: <Mono value={report.vpId} />
          </p>
        </>
      )}
    </div>
  );
}
