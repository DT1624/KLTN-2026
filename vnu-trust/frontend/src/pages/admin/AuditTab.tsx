import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { AUDIT_GROUPS, auditMeta, type AuditGroup } from "../../lib/constants";
import { Section, Badge, Mono, Spinner, Empty, Alert, Row } from "../../components/ui";
import { IconChevronLeft, IconChevronRight } from "../../components/icons";
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
  const filterId = "f-" + useId();
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
          <div className="sheet p-5">
            <label className="label" htmlFor={filterId}>Nhóm thao tác</label>
            <select id={filterId} className="input" value={group}
              onChange={(e) => setGroup(e.target.value as AuditGroup | "all")}>
              {AUDIT_GROUPS.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.label} ({g.id === "all" ? rows.length : counts[g.id] ?? 0})
                </option>
              ))}
            </select>
            <p className="mt-1 text-sm text-muted">
              Lọc trên {rows.length} bản ghi của trang hiện tại.
            </p>
          </div>

          <Section title="Chi tiết">
            {!selected ? (
              <p className="text-muted">Chọn một dòng trong nhật ký để xem chi tiết.</p>
            ) : (
              <dl className="space-y-3">
                <Row label="Hành động">
                  <Badge tone={auditMeta(selected.action).tone}>
                    {auditMeta(selected.action).label}
                  </Badge>
                  <p className="hex mt-1">{selected.action}</p>
                </Row>
                <Row label="Thời điểm">
                  {new Date(selected.created_at).toLocaleString("vi-VN")}
                </Row>
                <Row label="Người thực hiện"><Mono value={selected.actor} /></Row>
                {selected.target && (
                  <Row label="Đối tượng"><Mono value={selected.target} /></Row>
                )}
                {selected.detail && (
                  <Row label="Dữ liệu kèm theo">
                    <pre className="hex bg-tint rounded-ctrl p-3 overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(selected.detail, null, 2)}
                    </pre>
                  </Row>
                )}
              </dl>
            )}
          </Section>
        </>
      }
    >
      <Section title="Nhật ký kiểm toán"
        description="Mọi thao tác làm thay đổi trạng thái tin cậy. Cả hai máy chủ đều ghi vào nhật ký này."
        actions={
          <div className="flex gap-2">
            <button className="btn-secondary inline-flex items-center gap-1" type="button"
              disabled={offset === 0}
              onClick={() => { setOffset((o) => Math.max(0, o - PAGE)); setSelected(null); }}>
              <IconChevronLeft />
              Mới hơn
            </button>
            <button className="btn-secondary inline-flex items-center gap-1" type="button"
              disabled={rows.length < PAGE}
              onClick={() => { setOffset((o) => o + PAGE); setSelected(null); }}>
              Cũ hơn
              <IconChevronRight />
            </button>
          </div>
        }>
        {audit.isLoading && <Spinner />}
        {!audit.isLoading && !rows.length && (
          <Empty title="Chưa có thao tác nào được ghi nhận"
            hint="Cấp, thu hồi hay tạm ngưng văn bằng sẽ hiện ở đây." />
        )}
        {!audit.isLoading && !!rows.length && !filtered.length && (
          <Alert tone="info">Trang này không có bản ghi nào thuộc nhóm đã chọn.</Alert>
        )}

        {!!filtered.length && (
          <div className="overflow-x-auto">
            <table className="table table-interactive">
              <thead>
                <tr><th>Thời điểm</th><th>Hành động</th><th>Người thực hiện</th><th>Đối tượng</th></tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <tr key={r.id}
                    data-selected={selected?.id === r.id ? "true" : undefined}
                    onClick={() => setSelected(r)}>
                    <td className="whitespace-nowrap">
                      <button type="button" className="btn-quiet text-left"
                        aria-pressed={selected?.id === r.id}
                        onClick={(e) => { e.stopPropagation(); setSelected(r); }}>
                        {new Date(r.created_at).toLocaleString("vi-VN")}
                      </button>
                    </td>
                    <td><Badge tone={auditMeta(r.action).tone}>{auditMeta(r.action).label}</Badge></td>
                    <td><Mono value={r.actor} /></td>
                    <td>{r.target
                      ? <Mono value={r.target} />
                      : <span className="text-muted">Không có</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </SplitPane>
  );
}
