import { useEffect, useId, useState } from "react";
import type { ReactNode } from "react";
import { IconCheck, IconCross, IconPause, IconAlert, IconInfo, IconCopy } from "./icons";

const CHIP = "inline-flex items-center gap-1";

export function Badge({ tone, children }: { tone: "ok" | "warn" | "bad" | "info" | "muted"; children: ReactNode }) {
  const map = {
    ok: "bg-success-soft text-success",
    warn: "bg-warning-soft text-warning",
    bad: "bg-son-tint text-son",
    info: "bg-primary-soft text-primary",
    muted: "bg-tint text-muted",
  } as const;
  return <span className={`chip ${CHIP} ${map[tone]}`}>{children}</span>;
}

/** Nhãn trạng thái: xanh (còn hiệu lực), vàng (tạm), xám (hết hạn), đỏ (thu hồi); có biểu tượng đi kèm. */
function ShapeChip({ kind, label }: { kind: "active" | "suspended" | "expired" | "revoked" | "other"; label: string }) {
  switch (kind) {
    case "active":
      return <span className={`chip ${CHIP} bg-success-soft text-success`}><IconCheck />{label}</span>;
    case "suspended":
      return <span className={`chip ${CHIP} bg-warning-soft text-warning`}><IconPause />{label}</span>;
    case "expired":
      return <span className={`chip ${CHIP} bg-tint text-muted`}>{label}</span>;
    case "revoked":
      return <span className={`chip ${CHIP} bg-son-tint text-son`}><IconCross />{label}</span>;
    default:
      return <Badge tone="muted">{label}</Badge>;
  }
}

const STATUS_LABEL: Record<string, string> = {
  active: "Còn hiệu lực",
  suspended: "Tạm ngưng",
  expired: "Hết hạn",
  revoked: "Đã thu hồi",
  pending: "Đang chờ",
};

export function statusLabel(s: string): string {
  return STATUS_LABEL[s] ?? s;
}

export function roleLabel(role: string): string {
  const map: Record<string, string> = {
    root: "Quản trị gốc",
    admin: "Quản trị viên",
    issuer: "Đơn vị cấp bằng",
    holder: "Người học",
    verifier: "Bên xác minh",
  };
  return map[role] ?? role;
}

export function StatusBadge({ status }: { status: string }) {
  if (status === "active" || status === "suspended" || status === "expired" || status === "revoked") {
    return <ShapeChip kind={status} label={statusLabel(status)} />;
  }
  return <ShapeChip kind="other" label={statusLabel(status)} />;
}

export function DidStatusBadge({ status }: { status: string }) {
  if (status === "active") return <ShapeChip kind="active" label="Đang hoạt động" />;
  if (status === "suspended") return <ShapeChip kind="suspended" label="Đang khoá" />;
  if (status === "revoked") return <ShapeChip kind="revoked" label="Đã thu hồi" />;
  return <ShapeChip kind="other" label={statusLabel(status)} />;
}

export function RoleStatusBadge({ status }: { status: string }) {
  if (status === "active") return <ShapeChip kind="active" label="Đang hoạt động" />;
  if (status === "suspended") return <ShapeChip kind="suspended" label="Tạm ngưng" />;
  if (status === "revoked") return <ShapeChip kind="revoked" label="Đã thu hồi" />;
  return <ShapeChip kind="other" label={statusLabel(status)} />;
}

export function RoleBadge({ role }: { role: string }) {
  const cls = role === "root" ? "bg-primary-soft text-primary ring-1 ring-primary" : "bg-primary-soft text-primary";
  return <span className={`chip ${CHIP} ${cls}`}>{roleLabel(role)}</span>;
}

export function Card({ title, subtitle, actions, children, className = "" }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`sheet p-5 sm:p-6 ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-3 mb-4">
          <div className="min-w-0">
            {title && <h2 className="text-lg font-semibold text-ink">{title}</h2>}
            {subtitle && <p className="text-sm text-muted max-w-prose mt-1">{subtitle}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2 sm:justify-end">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

/** Mục dạng thẻ, có thể gắn `id` để neo. */
export function Section({ title, description, actions, children, className = "", id }: {
  title?: ReactNode; description?: ReactNode; actions?: ReactNode; children?: ReactNode; className?: string; id?: string;
}) {
  return (
    <section id={id} className={`sheet p-5 sm:p-6 ${className}`}>
      {(title || description || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-3 mb-4">
          <div className="min-w-0">
            {title && <h2 className="text-lg font-semibold text-ink">{title}</h2>}
            {description && <p className="text-sm text-muted max-w-prose mt-1">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2 sm:justify-end">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="sheet p-4 min-w-0">
      <p className="text-sm text-muted">{label}</p>
      <p className="mt-1 text-2xl font-bold tabular-nums text-ink">{value}</p>
      {hint && <p className="mt-1 text-xs text-muted">{hint}</p>}
    </div>
  );
}

/** Lưới thẻ số liệu. */
export function Ledger({ items }: { items: { label: string; value: ReactNode; hint?: string }[] }) {
  return (
    <dl className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {items.map((it, i) => (
        <div key={`${i}-${it.label}`} className="sheet p-4 min-w-0">
          <dt className="text-sm text-muted">{it.label}</dt>
          <dd className="mt-1 text-2xl font-bold tabular-nums text-ink">{it.value}</dd>
          {it.hint && <dd className="mt-1 text-xs text-muted">{it.hint}</dd>}
        </div>
      ))}
    </dl>
  );
}

export function Empty({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="rounded-sheet border border-dashed border-pencil bg-sheet p-6 text-left">
      <p className="text-base font-semibold text-ink">{title}</p>
      {hint && <p className="mt-1 text-sm text-muted max-w-prose">{hint}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Alert({ tone = "info", title, children }: {
  tone?: "info" | "ok" | "warn" | "bad"; title?: string; children: ReactNode;
}) {
  const map = {
    info: "bg-primary-soft",
    ok: "bg-success-soft",
    warn: "bg-warning-soft",
    bad: "bg-son-tint",
  } as const;
  const text = { info: "text-primary", ok: "text-success", warn: "text-warning", bad: "text-son" } as const;
  const Icon = { info: IconInfo, ok: IconCheck, warn: IconAlert, bad: IconCross }[tone];
  return (
    <div className={`rounded-sheet p-4 text-ink ${map[tone]}`} role={tone === "bad" ? "alert" : undefined}>
      <div className="flex gap-3">
        <Icon className={`w-4 h-4 mt-1 shrink-0 ${text[tone]}`} />
        <div className="min-w-0">
          {title && <p className={`font-semibold mb-0.5 ${text[tone]}`}>{title}</p>}
          <div className="text-sm leading-relaxed text-ink-2 break-words [overflow-wrap:anywhere]">{children}</div>
        </div>
      </div>
    </div>
  );
}

export function Spinner({ label = "Đang tải…" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="flex items-center gap-3 py-10 text-muted text-sm">
      <span
        aria-hidden
        className="w-4 h-4 rounded-full border-2 border-rule border-t-primary animate-spin motion-reduce:hidden"
      />
      {label}
    </div>
  );
}

/** Hiển thị chuỗi dài (địa chỉ, CID, hash) có nút sao chép. */
export function Mono({ value, truncate = true }: { value: string; truncate?: boolean }) {
  const [copied, setCopied] = useState<"" | "ok" | "fail">("");
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(""), copied === "fail" ? 2000 : 1500);
    return () => clearTimeout(t);
  }, [copied]);
  const shown = truncate && value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1 max-w-full">
      <span className="hex" title={value}>{shown}</span>
      <button
        type="button"
        aria-label={"Sao chép " + value}
        onClick={() => {
          if (!navigator.clipboard?.writeText) { setCopied("fail"); return; }
          navigator.clipboard.writeText(value).then(() => setCopied("ok"), () => setCopied("fail"));
        }}
        className="btn-quiet inline-flex items-center gap-1 text-sm"
      >
        <IconCopy />
      </button>
      <span aria-live="polite" className="text-sm text-muted">{copied === "ok" ? "Đã chép" : copied === "fail" ? "Không chép được, hãy bôi đen để chép" : ""}</span>
    </span>
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
  const uid = useId();
  const id = "f-" + uid;
  const hintId = hint ? id + "-hint" : undefined;
  return (
    <div>
      <label className="label" htmlFor={id}>{label}</label>
      <input
        id={id}
        type={type}
        className={`input ${mono ? "hex" : ""}`}
        value={value}
        required={required}
        disabled={disabled}
        placeholder={placeholder}
        aria-describedby={hintId}
        onChange={(e) => onChange(e.target.value)}
      />
      {hint && <p id={hintId} className="text-sm text-muted mt-1">{hint}</p>}
    </div>
  );
}

/** Dòng nhãn — giá trị, dùng trong các bảng tóm tắt. */
export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-[12rem_1fr] gap-x-4 gap-y-1">
      <dt className="text-sm text-muted">{label}</dt>
      <dd className="text-base min-w-0">{children}</dd>
    </div>
  );
}
