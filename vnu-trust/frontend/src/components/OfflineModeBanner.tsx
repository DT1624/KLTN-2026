import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { getBackend } from "../lib/backend";

interface Health {
  status: string;
  backend: string;
  verifyOnChain?: boolean;
}

/**
 * Cảnh báo khi máy chủ đang chạy với VERIFY_ONCHAIN=false.
 *
 * Ở chế độ đó backend KHÔNG kiểm tra giao dịch có thật trên chuỗi và đọc quyền
 * từ CSDL thay vì hỏi contract — tiện để phát triển và kiểm thử, nhưng mọi thứ
 * hiển thị ra đều không còn được chuỗi bảo chứng. Người dùng phải nhìn thấy
 * điều này, nếu không rất dễ tưởng nhầm dữ liệu đã được neo lên chuỗi.
 */
export default function OfflineModeBanner() {
  const health = useQuery({
    queryKey: ["health", getBackend().id],
    queryFn: () => api.get<Health>("/health"),
    staleTime: 30_000,
    retry: false,
  });

  if (health.data?.verifyOnChain !== false) return null;

  return (
    <div className="bg-amber-50 border-b border-amber-200" role="status">
      <div className="mx-auto max-w-6xl px-4 py-2.5 text-sm text-amber-900 flex flex-wrap items-center gap-x-2 gap-y-1">
        <span aria-hidden="true">⚠️</span>
        <strong className="font-semibold">Chế độ phát triển — không kiểm chứng trên chuỗi.</strong>
        <span className="text-amber-800">
          Máy chủ đang bỏ qua bước xác minh giao dịch và đọc quyền từ cơ sở dữ liệu.
          Dữ liệu hiển thị ở đây chưa được blockchain bảo chứng.
        </span>
      </div>
    </div>
  );
}
