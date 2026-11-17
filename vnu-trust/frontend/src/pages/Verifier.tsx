import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type VerificationReport } from "../lib/api";
import { useTitle } from "../hooks/useTitle";
import { Section, Alert, Spinner, Empty, Badge, Mono } from "../components/ui";
import { ValidityMeter } from "../components/charts";

interface HistoryRow {
  id: string; vp_id: string; overall_valid: boolean;
  report: VerificationReport; created_at: string;
}

export default function Verifier() {
  useTitle("Lịch sử xác minh");
  const history = useQuery({
    queryKey: ["verifier", "history"],
    queryFn: () => api.get<HistoryRow[]>("/verify/history"),
  });

  const rows = history.data ?? [];
  const valid = rows.filter((r) => r.overall_valid).length;

  return (
    <div className="space-y-10">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Lịch sử xác minh</h1>
          <p className="mt-2 text-muted max-w-prose">Các lần bạn đã kiểm tra văn bằng.</p>
        </div>
        <Link className="btn-primary" to="/verify">Xác minh văn bằng</Link>
      </header>

      {history.isError && (
        <Alert tone="bad" title="Không tải được lịch sử xác minh">
          {(history.error as Error).message}
        </Alert>
      )}

      {rows.length > 0 && (
        <Section title="Tỉ lệ hợp lệ">
          <ValidityMeter total={rows.length} valid={valid} />
        </Section>
      )}

      <Section title="Các lần xác minh">
        {history.isLoading ? <Spinner /> : rows.length ? (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr><th>Thời điểm</th><th>Người trình bày</th><th>Số văn bằng</th><th>Kết quả</th></tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td>{new Date(r.created_at).toLocaleString("vi-VN")}</td>
                    <td>{r.report?.holderDid ? <Mono value={r.report.holderDid} /> : "Không rõ"}</td>
                    <td className="tabular-nums">{r.report?.credentials?.length ?? 0}</td>
                    <td>{r.overall_valid ? <Badge tone="ok">Hợp lệ</Badge> : <Badge tone="bad">Không hợp lệ</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : history.isError ? null : (
          <Empty title="Chưa có lần xác minh nào"
            hint="Khi bạn xác minh một liên kết người học gửi, kết quả sẽ được lưu ở đây."
            action={<Link className="btn-primary" to="/verify">Xác minh văn bằng</Link>} />
        )}
      </Section>
    </div>
  );
}
