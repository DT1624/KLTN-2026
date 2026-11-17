import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { getBackend } from "../lib/backend";
import { IconAlert } from "./icons";

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
    <div className="bg-mark-soft border-b-2 border-mark text-ink" role="status">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 py-2.5 text-sm flex flex-wrap items-center gap-x-2 gap-y-1">
        <IconAlert className="w-4 h-4 shrink-0 text-warning" />
        <strong className="font-bold">Chế độ thử, chưa nối chuỗi.</strong>
        <span>
          Máy chủ đang bỏ qua bước xác minh giao dịch và đọc quyền từ cơ sở dữ liệu.
          Những gì hiện ở đây chưa được sổ đăng ký trên chuỗi xác nhận.
        </span>
      </div>
    </div>
  );
}
