/**
 * Bộ chọn backend.
 *
 * Hai backend (TypeScript và Go) cài đặt CÙNG một hợp đồng API trên CÙNG một
 * CSDL, nên giao diện chỉ cần đổi tiền tố đường dẫn là chuyển được, không phải
 * build lại. Đây là cách để đối chiếu hai cài đặt trong lúc chạy.
 *
 * Lựa chọn lưu trong localStorage (khác với token phiên vốn nằm ở
 * sessionStorage), để người dùng đóng tab mở lại vẫn giữ nguyên backend đang thử.
 */
export type BackendId = "ts" | "go";

export interface BackendInfo {
  id: BackendId;
  label: string;
  base: string;
  port: number;
  tech: string;
}

// Chạy máy nhà: proxy của Vite chuyển /api-ts và /api-go sang cổng 4000/4001.
// Triển khai lên host: đặt URL đầy đủ của từng backend lúc build, ví dụ
// VITE_API_TS_URL=https://vnu-trust-ts.onrender.com/api — giao diện gọi thẳng
// sang đó (CORS do FRONTEND_ORIGIN của backend cho phép), bộ chọn vẫn dùng được.
const tsBase = (import.meta.env.VITE_API_TS_URL || "/api-ts").replace(/\/$/, "");
const goBase = (import.meta.env.VITE_API_GO_URL || "/api-go").replace(/\/$/, "");

export const BACKENDS: Record<BackendId, BackendInfo> = {
  ts: { id: "ts", label: "TypeScript", base: tsBase, port: 4000, tech: "Express + pg" },
  go: { id: "go", label: "Go", base: goBase, port: 4001, tech: "net/http + pgx" },
};

const KEY = "vnu_trust_backend";

export function getBackend(): BackendInfo {
  // Biến môi trường lúc build vẫn được tôn trọng để triển khai thật có thể
  // ghim cứng một backend, khi đó giao diện không cho đổi.
  const forced = import.meta.env.VITE_API_BASE;
  if (forced) {
    return { id: "ts", label: "cố định", base: forced, port: 0, tech: forced };
  }
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === "go" || saved === "ts") return BACKENDS[saved];
  } catch {
    /* chế độ riêng tư có thể chặn localStorage */
  }
  return BACKENDS.ts;
}

export const isBackendLocked = () => Boolean(import.meta.env.VITE_API_BASE);

/**
 * Đổi backend. Phải tải lại trang vì token phiên do backend nào cấp thì chỉ
 * backend đó hiểu — tuy hai bên dùng chung JWT_SECRET nên thực tế vẫn dùng
 * chéo được, việc tải lại chủ yếu để mọi truy vấn đang cache được làm mới.
 */
export function setBackend(id: BackendId): void {
  try {
    localStorage.setItem(KEY, id);
  } catch {
    /* bỏ qua */
  }
  location.reload();
}
