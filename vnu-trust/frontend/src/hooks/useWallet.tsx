import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { listKeystores, unlockWallet, updateKeystoreRole, type StoredKeystore, type UnlockedWallet } from "../lib/wallet";
import { login, logout as doLogout } from "../lib/auth";
import { useQueryClient } from "@tanstack/react-query";
import { session } from "../lib/api";

/** Tự khoá ví sau khoảng thời gian không thao tác, để máy bỏ quên không bị lợi dụng. */
const IDLE_LOCK_MS = 15 * 60_000;

interface WalletCtx {
  wallet: UnlockedWallet | null;
  keystores: StoredKeystore[];
  loading: boolean;
  unlock: (address: string, passphrase: string) => Promise<UnlockedWallet>;
  adopt: (w: UnlockedWallet) => Promise<void>;
  lock: () => void;
  refreshKeystores: () => Promise<void>;
  secondsUntilLock: number | null;
}

const Ctx = createContext<WalletCtx | null>(null);

export function WalletProvider({ children }: { children: ReactNode }) {
  const [wallet, setWallet] = useState<UnlockedWallet | null>(null);
  const [keystores, setKeystores] = useState<StoredKeystore[]>([]);
  const [loading, setLoading] = useState(true);
  const [secondsUntilLock, setSeconds] = useState<number | null>(null);
  const lastActivity = useRef(Date.now());
  // Bộ đệm truy vấn giữ dữ liệu của tài khoản trước; đổi danh tính là xoá sạch
  // để tài khoản sau tải lại từ máy chủ, không thấy văn bằng của người khác.
  const qc = useQueryClient();

  const refreshKeystores = useCallback(async () => {
    setKeystores(await listKeystores());
  }, []);

  useEffect(() => {
    refreshKeystores().finally(() => setLoading(false));
  }, [refreshKeystores]);

  const lock = useCallback(() => {
    setWallet(null);
    doLogout();
    qc.clear();
    setSeconds(null);
  }, [qc]);

  /**
   * Sau khi mở ví thì đăng nhập luôn để lấy token phiên, đồng thời **đồng bộ
   * vai trò theo máy chủ**: ví khai "holder" nhưng đã được phong admin thì phải
   * thấy menu admin, chứ không phải giữ mãi vai trò tự khai lúc tạo ví.
   */
  const finishUnlock = useCallback(async (w: UnlockedWallet): Promise<UnlockedWallet> => {
    const { role } = await login(w);
    const synced = role === w.role ? w : { ...w, role };
    if (role !== w.role) await updateKeystoreRole(w.address, role);
    qc.clear();
    setWallet(synced);
    lastActivity.current = Date.now();
    return synced;
  }, [qc]);

  const unlock = useCallback(
    async (address: string, passphrase: string) => {
      const w = await unlockWallet(address, passphrase);
      return finishUnlock(w);
    },
    [finishUnlock],
  );

  const adopt = useCallback(
    async (w: UnlockedWallet) => {
      await finishUnlock(w);
      await refreshKeystores();
    },
    [finishUnlock, refreshKeystores],
  );

  // Đồng hồ tự khoá.
  useEffect(() => {
    if (!wallet) return;
    const bump = () => { lastActivity.current = Date.now(); };
    const events: (keyof WindowEventMap)[] = ["click", "keydown", "mousemove", "scroll", "touchstart"];
    events.forEach((e) => window.addEventListener(e, bump, { passive: true }));

    const timer = setInterval(() => {
      const left = IDLE_LOCK_MS - (Date.now() - lastActivity.current);
      setSeconds(Math.max(0, Math.ceil(left / 1000)));
      if (left <= 0) lock();
    }, 1000);

    return () => {
      events.forEach((e) => window.removeEventListener(e, bump));
      clearInterval(timer);
    };
  }, [wallet, lock]);

  // Token phiên mất (hết hạn hoặc bị 401) thì khoá ví theo.
  useEffect(() => {
    if (wallet && !session.get()) lock();
  });

  const value = useMemo(
    () => ({ wallet, keystores, loading, unlock, adopt, lock, refreshKeystores, secondsUntilLock }),
    [wallet, keystores, loading, unlock, adopt, lock, refreshKeystores, secondsUntilLock],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useWallet(): WalletCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useWallet phải nằm trong <WalletProvider>");
  return ctx;
}
