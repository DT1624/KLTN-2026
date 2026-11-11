import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { AUDIT_GROUPS, auditMeta, type AuditGroup } from "../../lib/constants";
import { Card, Badge, Mono, Spinner, Empty, Alert } from "../../components/ui";
import { SplitPane } from "../../components/Tabs";

interface AuditRow {
  id: number;
  actor: string;
  action: string;
  target: string | null;
  detail: Record<string, unknown> | null;
  created_at: string;
}

const PAGE = 50;

/**
 * Nhật ký & truy vết.
 *
 * Bảng chính là dòng thời gian; hai panel bên cạnh là bộ lọc theo nhóm hành
 * động và chi tiết của dòng đang chọn. Chi tiết nằm ở panel riêng thay vì mở
 * rộng trong bảng để so sánh được nhiều dòng mà không mất chỗ đang đọc.
 *
 * Bảng `audit_log` từng nằm im trong lược đồ mà **không backend nào ghi vào** —
 * `GET /admin/audit` luôn trả rỗng và chẳng bộ kiểm thử nào phát hiện. Nay cả
 * hai backend cùng ghi với cùng bộ tên hành động.
 */
export default function AuditTab() {
  const [group, setGroup] = useState<AuditGroup | "all">("all");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<AuditRow | null>(null);

  const audit = useQuery({
    queryKey: ["admin", "audit", offset],
    queryFn: () => api.get<AuditRow[]>(`/admin/audit?limit=${PAGE}&offset=${offset}`),
  });

  const rows = audit.data ?? [];
  const filtered = group === "all" ? rows : rows.filter((r) => auditMeta(r.action).group === group);

  const counts = rows.reduce<Record<string, number>>((acc, r) => {
    const g = auditMeta(r.action).group;
    acc[g] = (acc[g] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <SplitPane
      side={
        <>
          <Card title="Bộ lọc">
            <div className="space-y-1.5">
              {AUDIT_GROUPS.map((g) => (
                <button key={g.id} type="button"
                  onClick={() => setGroup(g.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition ${
                    group === g.id
                      ? "bg-brand-50 text-brand-700 font-semibold"
                      : "text-ink-600 hover:bg-ink-50"
                  }`}>
                  {g.label}
                  <span className="tabular-nums text-xs text-ink-400">
                    {g.id === "all" ? rows.length : counts[g.id] ?? 0}
                  </span>
                </button>
              ))}
            </div>
            <p className="mt-3 text-xs text-ink-400">
              Lọc trên {rows.length} bản ghi của trang hiện tại.
            </p>
          </Card>

          <Card title="Chi tiết">
            {!selected ? (
              <p className="text-sm text-ink-500">Chọn một dòng trong nhật ký để xem chi tiết.</p>
            ) : (
              <div className="space-y-3 text-sm">
                <div>
                  <p className="text-ink-400 text-xs uppercase tracking-wide">Hành động</p>
                  <Badge tone={auditMeta(selected.action).tone}>
                    {auditMeta(selected.action).label}
                  </Badge>
                  <p className="mono text-xs text-ink-400 mt-1">{selected.action}</p>
                </div>
                <div>
                  <p className="text-ink-400 text-xs uppercase tracking-wide">Thời điểm</p>
                  <p className="text-ink-800">
                    {new Date(selected.created_at).toLocaleString("vi-VN")}
                  </p>
                </div>
                <div>
                  <p className="text-ink-400 text-xs uppercase tracking-wide">Người thực hiện</p>
                  <Mono value={selected.actor} />
                </div>
                {selected.target && (
                  <div>
                    <p className="text-ink-400 text-xs uppercase tracking-wide">Đối tượng</p>
                    <Mono value={selected.target} />
                  </div>
                )}
                {selected.detail && (
                  <div>
                    <p className="text-ink-400 text-xs uppercase tracking-wide mb-1">Dữ liệu kèm theo</p>
                    <pre className="mono text-xs bg-ink-50 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-all">
                      {JSON.stringify(selected.detail, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </Card>
        </>
      }
    >
      <Card title="Nhật ký kiểm toán"
        subtitle="Mọi thao tác làm thay đổi trạng thái tin cậy, ghi bởi cả hai backend."
        actions={
          <div className="flex gap-2">
            <button className="btn-ghost !px-3 !py-1.5 text-xs" type="button"
              disabled={offset === 0}
              onClick={() => { setOffset((o) => Math.max(0, o - PAGE)); setSelected(null); }}>
              ← Mới hơn
            </button>
            <button className="btn-ghost !px-3 !py-1.5 text-xs" type="button"
              disabled={rows.length < PAGE}
              onClick={() => { setOffset((o) => o + PAGE); setSelected(null); }}>
              Cũ hơn →
            </button>
          </div>
        }>
        {audit.isLoading && <Spinner />}
        {!audit.isLoading && !rows.length && (
          <Empty title="Chưa có thao tác nào được ghi nhận"
            hint="Nhật ký ghi lại việc đăng ký DID, cấp và đổi trạng thái văn bằng, cấp và thu hồi quyền." />
        )}
        {!audit.isLoading && !!rows.length && !filtered.length && (
          <Alert tone="info">Trang này không có bản ghi nào thuộc nhóm đã chọn.</Alert>
        )}

        {!!filtered.length && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-ink-400">
                <tr><th className="py-2">Thời điểm</th><th>Hành động</th><th>Người thực hiện</th><th>Đối tượng</th></tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {filtered.map((r) => (
                  <tr key={r.id}
                    onClick={() => setSelected(r)}
                    className={`cursor-pointer transition ${
                      selected?.id === r.id ? "bg-brand-50/70" : "hover:bg-ink-50"
                    }`}>
                    <td className="py-2.5 text-ink-600 whitespace-nowrap">
                      {new Date(r.created_at).toLocaleString("vi-VN")}
                    </td>
                    <td><Badge tone={auditMeta(r.action).tone}>{auditMeta(r.action).label}</Badge></td>
                    <td><Mono value={r.actor} /></td>
                    <td>{r.target
                      ? <Mono value={r.target} />
                      : <span className="text-ink-400">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </SplitPane>
  );
}
