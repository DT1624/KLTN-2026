import { useId } from "react";
import { useQuery } from "@tanstack/react-query";
import { BACKENDS, getBackend, setBackend, isBackendLocked, type BackendId } from "../lib/backend";
import { api } from "../lib/api";

/**
 * Bộ chuyển backend. Hai cài đặt TypeScript và Go dùng chung hợp đồng API và
 * chung CSDL, nên đổi qua lại không mất dữ liệu — rất tiện để đối chiếu.
 */
export default function BackendSwitch() {
  const selectId = useId();
  const current = getBackend();
  const locked = isBackendLocked();

  const health = useQuery({
    queryKey: ["backend-health", current.id],
    queryFn: () => api.get<{ status: string; backend?: string }>("/health"),
    retry: false,
    refetchInterval: 30_000,
  });

  if (locked) {
    return (
      <span className="chip bg-tint text-muted" title={current.base}>
        Máy chủ cố định
      </span>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <label className="text-xs font-medium text-muted" htmlFor={selectId}>Máy chủ</label>
      <select
        id={selectId}
        className="input py-1.5 text-sm w-auto"
        value={current.id}
        onChange={(e) => setBackend(e.target.value as BackendId)}
        title="Hai bản máy chủ dùng chung giao diện lập trình và chung cơ sở dữ liệu"
      >
        {Object.values(BACKENDS).map((b) => (
          <option key={b.id} value={b.id}>
            Bản {b.label}
          </option>
        ))}
      </select>
      <span
        className={`text-xs ${health.isSuccess ? "text-success" : health.isError ? "text-son" : "text-muted"}`}
        role="status"
        aria-live="polite"
      >
        {health.isSuccess ? "đang chạy" : health.isError ? "không phản hồi" : "đang kiểm tra"}
      </span>
    </div>
  );
}
