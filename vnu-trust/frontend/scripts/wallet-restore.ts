// Kiểm thử CHÍNH src/lib/wallet.ts (không mô phỏng lại) cho luồng khôi phục ví:
//   ../backend/node_modules/.bin/tsx scripts/wallet-restore.ts
//
// Hai lỗi thật đã sửa ngày 13/11/2026:
//  1. Quên mật khẩu trên chính máy cũ: khôi phục bằng 12 từ bị chặn "ví đã có sẵn,
//     hãy dùng Mở ví" — mà Mở ví cần đúng mật khẩu đã quên.
//  2. DID dựng lại theo vai trò HIỆN TẠI thay vì DID máy chủ đã ghi danh: holder
//     được phong issuer khôi phục ví thì mang DID sai.
//
// IndexedDB giả trong bộ nhớ: wallet.ts chỉ dùng open / một object store /
// get / put / getAll / delete, nên không cần thêm phụ thuộc nào.

type Req = { result?: unknown; error?: unknown; onsuccess?: () => void; onerror?: () => void; onupgradeneeded?: () => void };
const stores = new Map<string, Map<string, unknown>>();
const later = (f: () => void) => setTimeout(f, 0);
const request = (run: () => unknown): Req => {
  const r: Req = {};
  later(() => { r.result = run(); r.onsuccess?.(); });
  return r;
};
(globalThis as { indexedDB?: unknown }).indexedDB = {
  open() {
    const db = {
      objectStoreNames: { contains: (n: string) => stores.has(n) },
      createObjectStore: (n: string) => { stores.set(n, new Map()); },
      transaction: (n: string) => {
        const s = stores.get(n)!;
        const t: { oncomplete?: () => void; objectStore: () => unknown } = {
          objectStore: () => ({
            get: (k: string) => request(() => structuredClone(s.get(k))),
            getAll: () => request(() => [...s.values()].map((v) => structuredClone(v))),
            put: (v: { address: string }) => request(() => { s.set(v.address, structuredClone(v)); return v.address; }),
            delete: (k: string) => request(() => { s.delete(k); }),
          }),
        };
        later(() => later(() => t.oncomplete?.()));
        return t;
      },
      close() {},
    };
    const r: Req = {};
    later(() => { r.result = db; if (!stores.size) r.onupgradeneeded?.(); r.onsuccess?.(); });
    return r;
  },
};

const { createWallet, restoreFromMnemonic, unlockWallet, listKeystores } = await import("../src/lib/wallet");
const { newMnemonic } = await import("../src/lib/mnemonic");

let failed = 0;
const check = (name: string, ok: boolean, detail = "") => {
  if (!ok) failed++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  → " + detail : ""}`);
};
const rejects = async (p: Promise<unknown>) => { try { await p; return false; } catch { return true; } };

const OLD = "Mat-khau-cu-2026!", NEW = "Mat-khau-moi-2026!";
const phrase = newMnemonic();
const created = await createWallet({ role: "holder", label: "Sinh vien A", passphrase: OLD, mnemonic: phrase });

// 1. Quên mật khẩu trên chính máy này: cụm từ phải đủ để đặt mật khẩu mới.
const restored = await restoreFromMnemonic(phrase, NEW, "holder", "Ví khôi phục").catch((e: Error) => e);
check("khôi phục bằng 12 từ khi ví đã có trên máy (quên mật khẩu) không bị chặn",
  !(restored instanceof Error), restored instanceof Error ? restored.message : "");
check("ra đúng địa chỉ cũ", !(restored instanceof Error) && restored.address === created.address);
check("mở được bằng mật khẩu MỚI", !(await rejects(unlockWallet(created.address, NEW))));
check("mật khẩu CŨ không còn mở được", await rejects(unlockWallet(created.address, OLD)));
check("giữ tên hiển thị cục bộ (máy chủ không trả tên — P-05)",
  !(restored instanceof Error) && restored.label === "Sinh vien A", !(restored instanceof Error) ? restored.label : "");
check("không tạo bản trùng trong kho", (await listKeystores()).length === 1);

// 2. DID phải là DID máy chủ đã ghi danh, không dựng lại theo vai trò hiện tại.
const serverDid = `did:vnu:holder:${created.address}`;
const promoted = await restoreFromMnemonic(phrase, NEW, "issuer", "x", undefined, serverDid);
check("holder được phong issuer khôi phục ví vẫn mang DID đã ghi danh", promoted.did === serverDid, promoted.did);
check("vai trò cập nhật theo máy chủ", promoted.role === "issuer");

// Đối chứng: DID máy chủ của địa chỉ KHÁC thì bỏ qua — không để máy chủ (hay kẻ
// giả máy chủ) gán cho ví một DID không gắn với khoá của nó.
const bogus = await restoreFromMnemonic(phrase, NEW, "holder", "x", undefined, "did:vnu:holder:0x" + "9".repeat(64));
check("DID máy chủ không kết thúc bằng địa chỉ ví thì bị bỏ qua", bogus.did === serverDid, bogus.did);

// Đối chứng: cụm từ sai vẫn bị từ chối (phép thử phải đỏ được).
// Lý do sửa (17/11/2026): bản cũ đảo thứ tự từ, nhưng 12 từ có 4 bit kiểm tra nên ~1/16 hoán vị
// vẫn hợp lệ -> test chập chờn (đỏ 2/8 lần chạy). Nay chọn cụm từ SAI mã kiểm tra một cách tất định:
// đổi từ cuối lần lượt qua danh sách từ cho tới khi isValidMnemonic = false.
const { isValidMnemonic } = await import("../src/lib/mnemonic");
const { wordlist: WL } = await import("@scure/bip39/wordlists/english");
const head = phrase.split(" ").slice(0, 11).join(" ");
const badTail = WL.find((w) => !isValidMnemonic(`${head} ${w}`))!;
const badPhrase = `${head} ${badTail}`;
check("tiền đề: cụm từ thử là cụm từ sai mã kiểm tra", !isValidMnemonic(badPhrase));
check("cụm từ sai mã kiểm tra bị từ chối", await rejects(restoreFromMnemonic(badPhrase, NEW, "holder", "x")));

console.log(`\n${failed ? `${failed} FAIL` : "11/11 PASS  — khôi phục ví từ cụm từ"}`);
process.exit(failed ? 1 : 0);
