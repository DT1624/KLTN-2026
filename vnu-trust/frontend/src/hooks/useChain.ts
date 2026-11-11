/**
 * Cầu nối giữa giao diện, ví và chuỗi.
 *
 * Mọi thao tác ghi đều đi qua đúng một đường: **ví ký → gửi lên chuỗi → chờ
 * xác nhận → đưa mã giao dịch thật cho backend ghi chỉ mục**. Người dùng không
 * bao giờ nhìn thấy, chép, hay dán mã giao dịch.
 */
import { useCallback, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type Entity } from "../lib/api";
import { getBackend } from "../lib/backend";
import { useWallet } from "./useWallet";
import { ensureGas, submitEntry, type TxOutcome } from "../lib/chain";

// ---------- Trạng thái hệ thống ----------

interface Health {
  status: string;
  backend: string;
  verifyOnChain?: boolean;
}

/**
 * Backend đang chạy `VERIFY_ONCHAIN=true` hay không.
 *
 * Cùng một cờ quyết định cả hai phía: backend bật thì nó xác minh giao dịch
 * thật, nên giao diện cũng phải gửi giao dịch thật. Backend tắt thì trên chuỗi
 * hoặc chưa có gói, hoặc là gói cũ — gửi lên chỉ tổ báo lỗi, nên ví chỉ ký cục
 * bộ và giao diện nói thẳng là chưa lên chuỗi.
 */
export function useChainMode() {
  const health = useQuery({
    queryKey: ["health", getBackend().id],
    queryFn: () => api.get<Health>("/health"),
    staleTime: 30_000,
    retry: false,
  });
  return {
    /** Chưa biết thì mặc định coi là có nối chuỗi — an toàn hơn là ngược lại. */
    live: health.data?.verifyOnChain !== false,
    loading: health.isLoading,
  };
}

export interface LiveStatus {
  entity: Entity;
  onChain: {
    hasActiveDid: boolean;
    isActiveAdmin: boolean;
    isActiveIssuer: boolean;
    canDelegate: boolean;
  };
  consistent: boolean;
}

/** Quyền THẬT của tài khoản đang đăng nhập, đọc từ chuỗi chứ không từ vai trò khai trong ví. */
export function useMe() {
  const { wallet } = useWallet();
  return useQuery({
    queryKey: ["me", wallet?.address, getBackend().id],
    queryFn: () => api.get<LiveStatus>("/auth/me"),
    enabled: Boolean(wallet),
    staleTime: 10_000,
  });
}

export interface RootSnapshot {
  rootAdmin: string | null;
  pendingRoot: string | null;
  callerIsRoot: boolean;
  callerIsPendingRoot: boolean;
  source: string;
}

/** Ai đang là root, ai đang chờ ký nhận. Mọi tài khoản đã đăng nhập đều xem được. */
export function useAuthorityRoot() {
  const { wallet } = useWallet();
  return useQuery({
    queryKey: ["authority", "root", wallet?.address, getBackend().id],
    queryFn: () => api.get<RootSnapshot>("/authority/root"),
    enabled: Boolean(wallet),
    staleTime: 10_000,
  });
}

// ---------- Gửi giao dịch ----------

export type TxStep = "idle" | "preparing" | "gas" | "signing" | "waiting" | "indexing" | "done" | "error";

const STEP_LABEL: Record<TxStep, string> = {
  idle: "",
  preparing: "Đang chuẩn bị dữ liệu…",
  gas: "Kiểm tra gas…",
  signing: "Đang ký bằng khoá trong ví…",
  waiting: "Đang chờ chuỗi xác nhận…",
  indexing: "Đang ghi vào chỉ mục…",
  done: "Xong",
  error: "Thất bại",
};

export interface RunOptions<T> {
  /** Hàm entry của contract, lấy từ `ENTRY` trong lib/chain.ts */
  fn: string;
  /**
   * Tham số của hàm entry. Truyền một hàm bất đồng bộ khi còn phải chuẩn bị dữ
   * liệu trước (ghim IPFS, tính hash) — làm vậy thì lỗi ở bước chuẩn bị cũng
   * hiện đúng chỗ như lỗi ký, thay vì văng ra ngoài thành ngoại lệ không ai bắt.
   */
  args: unknown[] | (() => Promise<unknown[]>);
  /** Chạy sau khi giao dịch đã xác nhận — nơi gọi backend với txHash thật. */
  index?: (out: TxOutcome) => Promise<T>;
  /** Gas tối thiểu cần có trước khi ký (octas). */
  minGas?: bigint;
}

export interface ChainTx {
  step: TxStep;
  label: string;
  busy: boolean;
  hash: string | null;
  submitted: boolean;
  error: string | null;
  run: <T>(opts: RunOptions<T>) => Promise<T | undefined>;
  reset: () => void;
}

/**
 * Một lượt "ký & gửi" hoàn chỉnh, kèm trạng thái để giao diện hiển thị.
 *
 * Nuốt lỗi có chủ ý: mọi lỗi đều được đưa vào `error` để hiển thị tại chỗ,
 * `run` trả về `undefined` thay vì ném — nơi gọi chỉ cần kiểm tra kết quả.
 */
export function useChainTx(): ChainTx {
  const { wallet } = useWallet();
  const { live } = useChainMode();
  const [step, setStep] = useState<TxStep>("idle");
  const [hash, setHash] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = useCallback(() => {
    setStep("idle"); setHash(null); setError(null); setSubmitted(false);
  }, []);

  const run = useCallback(
    async <T,>({ fn, args, index, minGas }: RunOptions<T>): Promise<T | undefined> => {
      if (!wallet) { setError("Ví chưa mở"); setStep("error"); return undefined; }
      setError(null); setHash(null); setSubmitted(false);
      try {
        let callArgs: unknown[];
        if (typeof args === "function") {
          setStep("preparing");
          callArgs = await args();
        } else {
          callArgs = args;
        }
        if (live) {
          setStep("gas");
          await ensureGas(wallet.address, minGas ?? 20_000_000n);
        }
        setStep("signing");
        const out = await submitEntry(wallet, fn, callArgs, {
          live,
          onPhase: (p) => setStep(p === "waiting" ? "waiting" : "signing"),
        });
        setHash(out.hash);
        setSubmitted(out.submitted);

        if (index) {
          setStep("indexing");
          const result = await index(out);
          setStep("done");
          return result;
        }
        setStep("done");
        return undefined;
      } catch (e) {
        setError((e as Error).message);
        setStep("error");
        return undefined;
      }
    },
    [wallet, live],
  );

  return { step, label: STEP_LABEL[step], busy: step !== "idle" && step !== "done" && step !== "error", hash, submitted, error, run, reset };
}
