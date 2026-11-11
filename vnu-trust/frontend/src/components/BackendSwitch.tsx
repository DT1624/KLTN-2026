import { useQuery } from "@tanstack/react-query";
import { BACKENDS, getBackend, setBackend, isBackendLocked, type BackendId } from "../lib/backend";
import { api } from "../lib/api";

/**
 * Bộ chuyển backend. Hai cài đặt TypeScript và Go dùng chung hợp đồng API và
 * chung CSDL, nên đổi qua lại không mất dữ liệu — rất tiện để đối chiếu.
 */
export default function BackendSwitch() {
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
      <span className="chip bg-ink-100 text-ink-600 ring-1 ring-ink-200" title={current.base}>
        API cố định
      </span>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <span
        className={`w-2 h-2 rounded-full shrink-0 ${
          health.isSuccess ? "bg-emerald-500" : health.isError ? "bg-rose-500" : "bg-ink-300"
        }`}
        title={health.isSuccess ? "Backend đang chạy" : health.isError ? "Không kết nối được" : "Đang kiểm tra"}
        aria-hidden
      />
      <label className="sr-only" htmlFor="backend-select">Chọn backend</label>
      <select
        id="backend-select"
        className="rounded-lg border border-ink-200 bg-white px-2.5 py-1.5 text-xs font-semibold text-ink-700
                   hover:bg-ink-50 focus:border-brand-500 outline-none transition"
        value={current.id}
        onChange={(e) => setBackend(e.target.value as BackendId)}
        title="Hai backend dùng chung hợp đồng API và chung cơ sở dữ liệu"
      >
        {Object.values(BACKENDS).map((b) => (
          <option key={b.id} value={b.id}>
            API {b.label} :{b.port}
          </option>
        ))}
      </select>
    </div>
  );
}
