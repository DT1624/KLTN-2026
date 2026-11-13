// Kiểm logic nhắc sao lưu (src/lib/backup.ts) — P4.3.
//   ../backend/node_modules/.bin/tsx scripts/backup-check.ts
const store = new Map<string, string>();
let broken = false;
(globalThis as any).localStorage = {
  getItem: (k: string) => { if (broken) throw new Error("blocked"); return store.get(k) ?? null; },
  setItem: (k: string, v: string) => { if (broken) throw new Error("blocked"); store.set(k, v); },
};
(globalThis as any).window = { dispatchEvent: () => true };
(globalThis as any).Event = class { constructor(public type: string) {} };

const { backupNeed, markBackup, getBackup, CHECK_EVERY_DAYS } = await import("../src/lib/backup");
const { previewFromMnemonic } = await import("../src/lib/wallet");
const { newMnemonic } = await import("../src/lib/mnemonic");

const rows: boolean[] = [];
const check = (name: string, ok: boolean, d = "") => { rows.push(ok); console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${d ? "  → " + d : ""}`); };
const A = "0x" + "a".repeat(64), B = "0x" + "b".repeat(64), C = "0x" + "c".repeat(64);

check("Ví mới chưa sao lưu → nhắc 'backup'", backupNeed(A) === "backup");
markBackup(A, "keystoreAt");
check("Đã tải tệp sao lưu → không nhắc", backupNeed(A) === "none");
store.set(`vnu-backup:${B}`, JSON.stringify({ mnemonicAt: new Date(Date.now() - (CHECK_EVERY_DAYS + 1) * 86_400_000).toISOString() }));
check(`Đã chép 12 từ nhưng quá ${CHECK_EVERY_DAYS} ngày chưa kiểm → nhắc 'check'`, backupNeed(B) === "check");
markBackup(B, "checkedAt");
check("Vừa kiểm lại 12 từ → không nhắc", backupNeed(B) === "none");
check("Địa chỉ khác chữ hoa/thường dùng chung trạng thái", getBackup(A.toUpperCase().replace("0X", "0x")).keystoreAt !== undefined);
broken = true;
let threw = false;
try { markBackup(C, "mnemonicAt"); } catch { threw = true; }
check("Bộ nhớ trình duyệt bị chặn → không ném lỗi, coi như chưa sao lưu", !threw && backupNeed(C) === "backup");
broken = false;
// Phép kiểm 12 từ ở trang "Danh tính & gas" so địa chỉ dẫn ra với ví đang mở.
const m1 = newMnemonic(), m2 = newMnemonic();
check("12 từ đúng → cùng địa chỉ; 12 từ khác → địa chỉ khác",
  previewFromMnemonic(m1).address === previewFromMnemonic(m1).address && previewFromMnemonic(m1).address !== previewFromMnemonic(m2).address);

const failed = rows.filter((x) => !x).length;
console.log(`\n${rows.length - failed}/${rows.length} PASS  — ${failed ? failed + " FAIL" : "nhắc sao lưu đúng"}`);
process.exit(failed ? 1 : 0);
