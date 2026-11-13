import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useWallet } from "../hooks/useWallet";
import { backupNeed, type BackupNeed } from "../lib/backup";

/** Băng nhắc sao lưu dưới thanh trên (P4.3) — chỉ hiện khi ví đang mở và còn việc phải làm. */
export default function BackupBanner() {
  const { wallet } = useWallet();
  const [need, setNeed] = useState<BackupNeed>("none");
  useEffect(() => {
    if (!wallet) return;
    const update = () => setNeed(backupNeed(wallet.address));
    update();
    window.addEventListener("vnu-backup", update);
    return () => window.removeEventListener("vnu-backup", update);
  }, [wallet]);
  if (!wallet || need === "none") return null;
  return (
    <div className={need === "backup" ? "bg-rose-50 border-b border-rose-200" : "bg-amber-50 border-b border-amber-200"}>
      <div className="mx-auto max-w-6xl px-4 py-2 text-sm flex flex-wrap items-center gap-2">
        <span aria-hidden>{need === "backup" ? "⚠️" : "🔁"}</span>
        <span className={need === "backup" ? "text-rose-800" : "text-amber-800"}>
          {need === "backup"
            ? "Ví này chưa được sao lưu trên máy này. Mất khoá là mất tài khoản và không đọc được văn bằng của mình."
            : "Đã lâu bạn chưa kiểm tra lại 12 từ khôi phục."}
        </span>
        <Link className="underline font-medium" to="/account#sao-luu">
          {need === "backup" ? "Sao lưu ngay" : "Kiểm tra ngay"}
        </Link>
      </div>
    </div>
  );
}
