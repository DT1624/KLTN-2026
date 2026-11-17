import { useSearchParams } from "react-router-dom";
import type { KeyboardEvent, ReactNode } from "react";

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
  // Phím mũi tên chuyển tab; chỉ tab đang chọn nằm trong thứ tự Tab (roving tabIndex).
  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    e.preventDefault();
    const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    if (!next) return;
    onSelect(next.id);
    document.getElementById("tab-" + next.id)?.focus();
  };

  return (
    <div className="flex gap-1 border-b border-rule overflow-x-auto" role="tablist">
      {tabs.map((t, i) => (
        <button
          key={t.id}
          id={"tab-" + t.id}
          role="tab"
          type="button"
          aria-selected={active === t.id}
          aria-controls={"panel-" + t.id}
          tabIndex={active === t.id ? 0 : -1}
          onClick={() => onSelect(t.id)}
          onKeyDown={(e) => onKeyDown(e, i)}
          className={`px-3.5 py-3 -mb-px text-sm whitespace-nowrap border-b-2 ${
            active === t.id
              ? "text-primary font-semibold border-primary"
              : "text-ink-2 hover:text-ink font-medium border-transparent"
          }`}
        >
          {t.label}
          {t.count !== undefined && (
            <span className={`ml-1.5 chip tabular-nums text-xs ${
              active === t.id ? "bg-primary-soft text-primary" : "bg-tint text-muted"
            }`}>{t.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

/** Nội dung của một tab; `id` trùng với `TabDef.id`. */
export function TabPanel({ id, children }: { id: string; children: ReactNode }) {
  return (
    <div role="tabpanel" id={"panel-" + id} aria-labelledby={"tab-" + id}>
      {children}
    </div>
  );
}

/** Khung hai cột cho tab có panel phụ bên cạnh (dùng ở tab Nhật ký & truy vết). */
export function SplitPane({ side, children }: { side: ReactNode; children: ReactNode }) {
  return (
    <div className="grid lg:grid-cols-[minmax(0,1fr)_22rem] gap-6 items-start">
      <div className="min-w-0 space-y-6">{children}</div>
      <div className="min-w-0 space-y-6 lg:sticky lg:top-6">{side}</div>
    </div>
  );
}
