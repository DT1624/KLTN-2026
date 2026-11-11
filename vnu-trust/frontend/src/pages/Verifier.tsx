import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type VerificationReport } from "../lib/api";
import { Card, Spinner, Empty, Badge, Mono } from "../components/ui";
import { ValidityMeter } from "../components/charts";

interface HistoryRow {
  id: string; vp_id: string; overall_valid: boolean;
  report: VerificationReport; created_at: string;
}

export default function Verifier() {
  const history = useQuery({
    queryKey: ["verifier", "history"],
    queryFn: () => api.get<HistoryRow[]>("/verify/history"),
  });

  const rows = history.data ?? [];
  const valid = rows.filter((r) => r.overall_valid).length;

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-ink-900">Bên xác minh</h1>
          <p className="text-sm text-ink-600 mt-1">Lịch sử các lần kiểm tra văn bằng của bạn.</p>
        </div>
        <Link className="btn-primary" to="/verify">Xác minh mã mới</Link>
      </header>

      {rows.length > 0 && (
        <Card title="Tỉ lệ hợp lệ">
          <ValidityMeter total={rows.length} valid={valid} />
        </Card>
      )}

      <Card title="Lịch sử xác minh">
        {history.isLoading ? <Spinner /> : rows.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-ink-400">
                <tr><th className="py-2">Thời điểm</th><th>Người trình bày</th><th>Số văn bằng</th><th>Kết quả</th></tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td className="py-2.5 text-ink-600">{new Date(r.created_at).toLocaleString("vi-VN")}</td>
                    <td><Mono value={r.report?.holderDid ?? "—"} /></td>
                    <td className="tabular-nums text-ink-600">{r.report?.credentials?.length ?? 0}</td>
                    <td>{r.overall_valid ? <Badge tone="ok">Hợp lệ</Badge> : <Badge tone="bad">Không hợp lệ</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty title="Chưa có lượt xác minh nào"
              hint="Quét mã QR của người sở hữu văn bằng để bắt đầu."
              action={<Link className="btn-primary" to="/verify">Xác minh ngay</Link>} />}
      </Card>
    </div>
  );
}
