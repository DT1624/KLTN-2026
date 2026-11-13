/**
 * Nhắc sao lưu (P4.3, 13/11/2026).
 *
 * Ví phi lưu ký: mất khoá là mất tài khoản — và từ P3 còn mất luôn khả năng TỰ ĐỌC
 * văn bằng của mình (nội dung chỉ giải mã được bằng khoá ví). Hệ thống không lưu 12 từ
 * ở đâu cả, nên chỉ có thể NHẮC và KIỂM:
 *  - đã xác nhận chép 12 từ (lúc tạo ví) hoặc đã khôi phục bằng 12 từ;
 *  - đã tải tệp sao lưu (keystore đã mã hoá);
 *  - kiểm tra định kỳ: gõ lại đủ 12 từ, ví dẫn ra địa chỉ rồi so với địa chỉ đang mở —
 *    không cần lưu bí mật nào để kiểm.
 * Trạng thái là tiện ích THEO TỪNG MÁY nên để ở localStorage; mọi lần đọc/ghi đều bọc
 * try/catch (chế độ riêng tư, bộ nhớ bị chặn) và thiếu dữ liệu thì coi như chưa sao lưu.
 */
export interface BackupState { mnemonicAt?: string; keystoreAt?: string; checkedAt?: string }

const KEY = (address: string) => `vnu-backup:${address.toLowerCase()}`;
/** Sau bao lâu thì nhắc kiểm tra lại 12 từ. */
export const CHECK_EVERY_DAYS = 90;

export function getBackup(address: string): BackupState {
  try {
    return JSON.parse(localStorage.getItem(KEY(address)) ?? "{}") as BackupState;
  } catch {
    return {};
  }
}

export function markBackup(address: string, field: keyof BackupState): void {
  try {
    const s = getBackup(address);
    s[field] = new Date().toISOString();
    localStorage.setItem(KEY(address), JSON.stringify(s));
    window.dispatchEvent(new Event("vnu-backup"));
  } catch {
    /* bộ nhớ trình duyệt bị chặn — chỉ mất lời nhắc, không mất gì khác */
  }
}

export type BackupNeed = "none" | "check" | "backup";

/** "backup": chưa có cách khôi phục nào; "check": lâu rồi chưa kiểm lại 12 từ. */
export function backupNeed(address: string, now = Date.now()): BackupNeed {
  const s = getBackup(address);
  if (!s.mnemonicAt && !s.keystoreAt) return "backup";
  const last = s.checkedAt ?? s.mnemonicAt;
  if (s.mnemonicAt && last && now - Date.parse(last) > CHECK_EVERY_DAYS * 86_400_000) return "check";
  return "none";
}
