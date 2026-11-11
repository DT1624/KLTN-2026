import { useSearchParams } from "react-router-dom";
import type { ReactNode } from "react";

export interface TabDef {
  id: string;
  label: string;
  /** Con số nhỏ bên cạnh nhãn — số bản ghi, số việc đang chờ… */
  count?: number;
  /** Ẩn hẳn tab khi tài khoản không có quyền tương ứng. */
  hidden?: boolean;
}

/**
 * Thanh tab đồng bộ với URL (`?tab=…`).
 *
 * Đưa tab vào URL để còn gửi được đường dẫn thẳng tới đúng mục — quan trọng
 * nhất với tab nhật ký, nơi người ta hay cần chỉ chỗ cho nhau xem.
 */
export function useTabs(tabs: TabDef[], key = "tab") {
  const [params, setParams] = useSearchParams();
  const visible = tabs.filter((t) => !t.hidden);
  const requested = params.get(key);
  const active = visible.some((t) => t.id === requested) ? requested! : visible[0]?.id ?? "";

  const select = (id: string) => {
    const next = new URLSearchParams(params);
    next.set(key, id);
    // replace: đổi tab không nên nhét thêm một mục vào lịch sử trình duyệt,
    // nếu không bấm Back mười lần mới ra khỏi trang.
    setParams(next, { replace: true });
  };

  return { active, select, visible };
}

export function TabBar({ tabs, active, onSelect }: {
  tabs: TabDef[];
  active: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="flex gap-1 p-1 bg-ink-100 rounded-xl overflow-x-auto" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          type="button"
          aria-selected={active === t.id}
          onClick={() => onSelect(t.id)}
          className={`px-3.5 py-2 rounded-lg text-sm font-semibold whitespace-nowrap transition ${
            active === t.id ? "bg-white text-ink-900 shadow-sm" : "text-ink-600 hover:text-ink-900"
          }`}
        >
          {t.label}
          {t.count !== undefined && (
            <span className={`ml-1.5 tabular-nums text-xs ${active === t.id ? "text-ink-500" : "text-ink-400"}`}>
              {t.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

/** Khung hai cột cho tab có panel phụ bên cạnh (dùng ở tab Nhật ký & truy vết). */
export function SplitPane({ side, children }: { side: ReactNode; children: ReactNode }) {
  return (
    <div className="grid lg:grid-cols-[minmax(0,1fr)_22rem] gap-5 items-start">
      <div className="min-w-0 space-y-5">{children}</div>
      <div className="space-y-5 lg:sticky lg:top-20">{side}</div>
    </div>
  );
}
