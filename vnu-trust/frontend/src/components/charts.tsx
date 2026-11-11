import { useState } from "react";

/** Biểu đồ nhỏ, thuần CSS — đủ cho bảng điều khiển mà không kéo thêm thư viện. */

export interface MonthPoint { month: string; count: number }
export interface BarItem { key: string; label: string; count: number }

// Màu trạng thái trùng với StatusBadge để người xem không phải học lại.
const STATUS = [
  { key: "active", label: "Đang hiệu lực", cls: "bg-emerald-500" },
  { key: "suspended", label: "Tạm ngưng", cls: "bg-amber-400" },
  { key: "expired", label: "Hết hạn", cls: "bg-ink-300" },
  { key: "revoked", label: "Đã thu hồi", cls: "bg-rose-500" },
] as const;

type StatusCounts = Record<(typeof STATUS)[number]["key"], number>;

/** Thanh xếp chồng tỉ lệ văn bằng theo trạng thái, kèm chú giải có số. */
export function StatusBar({ counts }: { counts: StatusCounts }) {
  const total = STATUS.reduce((s, x) => s + counts[x.key], 0);
  if (!total) return <p className="text-sm text-ink-400">Chưa có văn bằng nào.</p>;
  return (
    <div>
      <div className="flex h-3 gap-0.5 rounded-full overflow-hidden bg-ink-100" role="img"
        aria-label={STATUS.map((s) => `${s.label} ${counts[s.key]}`).join(", ")}>
        {STATUS.filter((s) => counts[s.key] > 0).map((s) => (
          <div key={s.key} className={s.cls} style={{ width: `${(counts[s.key] / total) * 100}%` }}
            title={`${s.label}: ${counts[s.key]} (${pct(counts[s.key], total)})`} />
        ))}
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-sm">
        {STATUS.map((s) => (
          <li key={s.key} className="flex items-center gap-1.5 text-ink-600">
            <span className={`w-2.5 h-2.5 rounded-sm ${s.cls}`} aria-hidden />
            {s.label} <span className="font-semibold text-ink-800 tabular-nums">{counts[s.key]}</span>
            <span className="text-ink-400 tabular-nums">· {pct(counts[s.key], total)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Cột theo tháng cho 12 tháng gần nhất; tháng không có dữ liệu vẫn hiện cột 0. */
export function MonthlyBars({ data }: { data: MonthPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const months = last12Months();
  const byMonth = new Map(data.map((d) => [d.month, d.count]));
  const points = months.map((m) => ({ month: m, count: byMonth.get(m) ?? 0 }));
  const max = Math.max(1, ...points.map((p) => p.count));
  const shown = hover ?? points.length - 1;

  return (
    <div>
      <p className="text-sm text-ink-600 h-5">
        {monthLabel(points[shown]!.month)}:{" "}
        <span className="font-semibold text-ink-900 tabular-nums">{points[shown]!.count}</span> văn bằng
      </p>
      <div className="mt-2 flex items-end gap-1 h-32 border-b border-ink-200" onMouseLeave={() => setHover(null)}>
        {points.map((p, i) => (
          // Vùng bắt chuột cao hết khung để không phải trỏ trúng cột thấp.
          <div key={p.month} className="flex-1 h-full flex items-end cursor-default"
            onMouseEnter={() => setHover(i)} title={`${monthLabel(p.month)}: ${p.count}`}>
            <div className={`w-full rounded-t ${i === shown ? "bg-brand-600" : "bg-brand-300"}`}
              style={{ height: p.count ? `${Math.max(4, (p.count / max) * 100)}%` : "0" }} />
          </div>
        ))}
      </div>
      <div className="mt-1 flex justify-between text-xs text-ink-400">
        <span>{monthLabel(points[0]!.month)}</span>
        <span>{monthLabel(points[points.length - 1]!.month)}</span>
      </div>
    </div>
  );
}

/** Danh sách thanh ngang có nhãn và số — đọc được cả khi không nhìn màu. */
export function BarList({ items, empty = "Chưa có dữ liệu." }: { items: BarItem[]; empty?: string }) {
  if (!items.length) return <p className="text-sm text-ink-400">{empty}</p>;
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <ul className="space-y-2.5">
      {items.map((i) => (
        <li key={i.key}>
          <div className="flex justify-between gap-3 text-sm">
            <span className="text-ink-700 truncate" title={i.label}>{i.label}</span>
            <span className="font-semibold text-ink-900 tabular-nums">{i.count}</span>
          </div>
          <div className="mt-1 h-2 rounded-full bg-ink-100">
            <div className="h-2 rounded-full bg-brand-500" style={{ width: `${(i.count / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

/** Tỉ lệ hợp lệ của các lượt xác minh: một con số lớn + thanh hai trạng thái. */
export function ValidityMeter({ total, valid }: { total: number; valid: number }) {
  if (!total) return <p className="text-sm text-ink-400">Chưa có lượt xác minh nào.</p>;
  return (
    <div>
      <p className="text-3xl font-bold text-ink-900 tabular-nums">{pct(valid, total)}</p>
      <p className="text-sm text-ink-500">hợp lệ trên {total} lượt xác minh</p>
      <div className="mt-3 flex h-2.5 gap-0.5 rounded-full overflow-hidden">
        <div className="bg-emerald-500" style={{ width: `${(valid / total) * 100}%` }} title={`Hợp lệ: ${valid}`} />
        <div className="bg-rose-500 flex-1" title={`Không hợp lệ: ${total - valid}`} />
      </div>
      <p className="mt-2 text-xs text-ink-500">
        ✅ Hợp lệ {valid} · ⛔ Không hợp lệ {total - valid}
      </p>
    </div>
  );
}

const pct = (n: number, total: number) => `${Math.round((n / total) * 100)}%`;

function last12Months(): string[] {
  const now = new Date();
  return Array.from({ length: 12 }, (_, i) => {
    const d = new Date(now.getFullYear(), now.getMonth() - 11 + i, 1);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
  });
}

const monthLabel = (m: string) => `${m.slice(5)}/${m.slice(0, 4)}`;
