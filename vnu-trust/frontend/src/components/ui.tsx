import type { ReactNode } from "react";

export function Badge({ tone, children }: { tone: "ok" | "warn" | "bad" | "info" | "muted"; children: ReactNode }) {
  const map = {
    ok: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200",
    warn: "bg-amber-50 text-amber-700 ring-1 ring-amber-200",
    bad: "bg-rose-50 text-rose-700 ring-1 ring-rose-200",
    info: "bg-brand-50 text-brand-700 ring-1 ring-brand-200",
    muted: "bg-ink-100 text-ink-600 ring-1 ring-ink-200",
  } as const;
  return <span className={`chip ${map[tone]}`}>{children}</span>;
}

const STATUS_TONE = {
  active: "ok", suspended: "warn", expired: "muted", revoked: "bad",
} as const;

export function StatusBadge({ status }: { status: string }) {
  const label: Record<string, string> = {
    active: "Đang hiệu lực", suspended: "Tạm ngưng",
    expired: "Hết hạn", revoked: "Đã thu hồi",
  };
  const tone = STATUS_TONE[status as keyof typeof STATUS_TONE] ?? "muted";
  return <Badge tone={tone}>{label[status] ?? status}</Badge>;
}

export function RoleBadge({ role }: { role: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    root: { label: "Quản trị gốc", cls: "bg-accent-100 text-accent-700 ring-1 ring-accent-200" },
    admin: { label: "Quản trị viên", cls: "bg-indigo-50 text-indigo-700 ring-1 ring-indigo-200" },
    issuer: { label: "Đơn vị cấp bằng", cls: "bg-brand-50 text-brand-700 ring-1 ring-brand-200" },
    holder: { label: "Người sở hữu", cls: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" },
    verifier: { label: "Bên xác minh", cls: "bg-amber-50 text-amber-700 ring-1 ring-amber-200" },
  };
  const v = map[role] ?? { label: role, cls: "bg-ink-100 text-ink-600" };
  return <span className={`chip ${v.cls}`}>{v.label}</span>;
}

export function Card({ title, subtitle, actions, children, className = "" }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`card p-5 sm:p-6 ${className}`}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 mb-4">
          <div>
            {title && <h2 className="text-base font-bold text-ink-900">{title}</h2>}
            {subtitle && <p className="text-sm text-ink-500 mt-0.5">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="card p-5">
      <p className="text-xs font-semibold uppercase tracking-wide text-ink-500">{label}</p>
      <p className="mt-2 text-3xl font-bold text-ink-900 tabular-nums">{value}</p>
      {hint && <p className="mt-1 text-xs text-ink-400">{hint}</p>}
    </div>
  );
}

export function Empty({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="text-center py-12 px-4">
      <div className="mx-auto w-12 h-12 rounded-2xl bg-ink-100 grid place-items-center text-2xl">📭</div>
      <p className="mt-3 font-semibold text-ink-700">{title}</p>
      {hint && <p className="mt-1 text-sm text-ink-500 max-w-sm mx-auto">{hint}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Alert({ tone = "info", title, children }: {
  tone?: "info" | "ok" | "warn" | "bad"; title?: string; children: ReactNode;
}) {
  const map = {
    info: "bg-brand-50 border-brand-200 text-brand-900",
    ok: "bg-emerald-50 border-emerald-200 text-emerald-900",
    warn: "bg-amber-50 border-amber-200 text-amber-900",
    bad: "bg-rose-50 border-rose-200 text-rose-900",
  } as const;
  const icon = { info: "ℹ️", ok: "✅", warn: "⚠️", bad: "⛔" } as const;
  return (
    <div className={`rounded-xl border px-4 py-3 text-sm ${map[tone]}`} role={tone === "bad" ? "alert" : undefined}>
      <div className="flex gap-2.5">
        <span aria-hidden>{icon[tone]}</span>
        <div className="min-w-0">
          {title && <p className="font-semibold mb-0.5">{title}</p>}
          <div className="leading-relaxed">{children}</div>
        </div>
      </div>
    </div>
  );
}

export function Spinner({ label = "Đang tải…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-10 text-ink-500 text-sm">
      <span className="w-4 h-4 rounded-full border-2 border-ink-200 border-t-brand-600 animate-spin" />
      {label}
    </div>
  );
}

/** Hiển thị chuỗi dài (địa chỉ, CID, hash) có nút sao chép. */
export function Mono({ value, truncate = true }: { value: string; truncate?: boolean }) {
  const shown = truncate && value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
  return (
    <button
      type="button"
      onClick={() => navigator.clipboard?.writeText(value)}
      title={`Bấm để sao chép: ${value}`}
      className="mono inline-flex items-center gap-1.5 rounded-md bg-ink-50 px-2 py-1 hover:bg-ink-100 transition text-ink-700"
    >
      {shown}
      <span className="text-ink-400" aria-hidden>⧉</span>
    </button>
  );
}

/**
 * Ô nhập có nhãn — dùng chung cho mọi biểu mẫu để nhãn, khoảng cách và
 * `htmlFor` luôn nhất quán, và để không ai phải chép lại bốn dòng JSX.
 */
export function Field({ label, value, onChange, placeholder, required, mono, type = "text", hint, disabled }: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  required?: boolean;
  mono?: boolean;
  type?: string;
  hint?: ReactNode;
  disabled?: boolean;
}) {
  const id = "f-" + label.toLowerCase().replace(/[^a-z0-9]+/gi, "-");
  return (
    <div>
      <label className="label" htmlFor={id}>{label}</label>
      <input
        id={id}
        type={type}
        className={`input ${mono ? "mono" : ""}`}
        value={value}
        required={required}
        disabled={disabled}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
      {hint && <p className="text-xs text-ink-400 mt-1">{hint}</p>}
    </div>
  );
}

/** Dòng nhãn — giá trị, dùng trong các bảng tóm tắt. */
export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-ink-400 text-xs uppercase tracking-wide">{label}</dt>
      <dd className="text-ink-800 mt-0.5">{children}</dd>
    </div>
  );
}
