import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getBackup, markBackup, backupNeed, CHECK_EVERY_DAYS } from "../lib/backup";
import { previewFromMnemonic } from "../lib/wallet";
import { isValidMnemonic, normalizeMnemonic } from "../lib/mnemonic";
import { Link } from "react-router-dom";
import { useWallet } from "../hooks/useWallet";
import { useMe, useAuthorityRoot, useChainTx, useChainMode } from "../hooks/useChain";
import { ENTRY, VIEW, view } from "../lib/chain";
import { api } from "../lib/api";
import { Alert, Mono, Badge, RoleBadge, Spinner, Section, roleLabel } from "../components/ui";
import { useTitle } from "../hooks/useTitle";
import Rosette from "../components/Rosette";
import DidCard from "../components/DidCard";
import GasPanel from "../components/GasPanel";
import TxProgress, { SignSheet } from "../components/ChainTx";

/**
 * Trang "Tài khoản" — nơi mọi tài khoản chuẩn bị để hoạt động được.
 *
 * Hai thứ một tài khoản mới cần trước khi làm bất cứ việc gì: **gas** để trả
 * phí giao dịch, và **DID** vì hợp đồng đòi DID đang hoạt động ở hầu hết các
 * hàm. Gom cả hai về một chỗ để không ai phải đoán vì sao nút của mình báo lỗi.
 */
export default function Account() {
  useTitle("Tài khoản");
  const { wallet } = useWallet();
  const me = useMe();
  const root = useAuthorityRoot();

  if (!wallet) return <Alert tone="warn" title="Chưa mở ví">Hãy mở ví để xem trang này.</Alert>;
  if (me.isLoading) return <Spinner label="Đang đọc hồ sơ…" />;

  const on = me.data?.onChain;
  const serverRole = me.data?.entity.role ?? wallet.role;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Tài khoản</h1>
        <p className="text-muted max-w-prose mt-2">
          Chuẩn bị tài khoản: nhận phí giao dịch, đăng ký DID, xem quyền thật của mình trên chuỗi.
        </p>
      </header>

      <section className="sheet p-5 sm:p-6 space-y-5">
        <div className="flex flex-wrap gap-5 items-center">
          <Rosette seed={wallet.did || wallet.address} size={96} title="Hoa văn danh tính của bạn" />
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-lg font-semibold">{me.data?.entity.label ?? wallet.label}</h2>
              <RoleBadge role={serverRole} />
            </div>
            <Mono value={wallet.address} />
          </div>
        </div>

        <div>
          <p className="label mb-1.5">Quyền trên chuỗi</p>
          <div className="flex flex-wrap gap-2">
            <Badge tone={on?.hasActiveDid ? "ok" : "warn"}>
              {on?.hasActiveDid ? "DID đang hoạt động" : "Chưa có DID hoạt động"}
            </Badge>
            <Badge tone={on?.isActiveIssuer ? "ok" : "muted"}>
              {on?.isActiveIssuer ? "Đơn vị cấp bằng đang hoạt động" : "Không phải đơn vị cấp bằng"}
            </Badge>
            <Badge tone={on?.isActiveAdmin ? "ok" : "muted"}>
              {on?.isActiveAdmin ? "Quản trị viên đang hoạt động" : "Không phải quản trị viên"}
            </Badge>
            {on?.canDelegate && <Badge tone="info">Được uỷ quyền lại</Badge>}
            {root.data?.callerIsRoot && <Badge tone="info">Quản trị gốc</Badge>}
          </div>

          {me.data && !me.data.consistent && (
            <div className="mt-3">
              <Alert tone="warn" title="Vai trò chưa khớp quyền trên chuỗi">
                Vai trò trong ứng dụng ({roleLabel(serverRole)}) chưa khớp quyền trên chuỗi
                ({on?.isActiveAdmin ? "Quản trị viên" : on?.isActiveIssuer ? "Đơn vị cấp bằng" : "Người học"}).
                Nút bấm trong khu vực đó sẽ bị chuỗi từ chối cho tới khi quyền được cấp thật.
              </Alert>
            </div>
          )}
        </div>
      </section>

      <div className="grid lg:grid-cols-2 gap-6 items-start">
        <DidCard />
        <GasPanel />
      </div>
      <BackupCard />
      <SelfLockCard />

      {root.data?.callerIsPendingRoot && <AcceptRootCard />}

      <Section title="Đi tới">
        <ul className="space-y-2">
          <li><Link className="link" to="/holder">Văn bằng của tôi</Link></li>
          {(on?.isActiveIssuer || serverRole === "issuer") && (
            <li><Link className="link" to="/issuer">Cấp văn bằng</Link></li>
          )}
          {(on?.isActiveAdmin || serverRole === "admin" || serverRole === "root") && (
            <li><Link className="link" to="/admin">Quản trị</Link></li>
          )}
          {root.data?.callerIsRoot && <li><Link className="link" to="/root">Quản trị gốc</Link></li>}
        </ul>
      </Section>
    </div>
  );
}

/**
 * Bước 2 của chuyển quyền root: người được đề cử TỰ KÝ để nhận.
 *
 * Thẻ này cố tình nằm ở trang cá nhân chứ không nằm trong khu quản trị: lúc ký
 * nhận, người đó vẫn **chưa** phải root, nên không vào được màn hình root.
 * Chính chữ ký này mới là bằng chứng họ giữ khoá riêng — thứ mà kiểu chuyển
 * quyền một bước ngày trước không bao giờ chứng minh được (F-00).
 */
function AcceptRootCard() {
  const qc = useQueryClient();
  const tx = useChainTx();

  return (
    <SignSheet tx={tx}>
      <h2 className="text-lg font-semibold">Bạn đang được đề cử làm quản trị gốc</h2>
      <p className="text-muted max-w-prose mt-1 mb-4">
        Quyền quản trị gốc chỉ thật sự chuyển sang khi chính bạn ký nhận.
      </p>
      <Alert tone="warn" title="Đọc kỹ trước khi nhận">
        Nhận quyền quản trị gốc nghĩa là bạn chịu trách nhiệm cấp và thu hồi toàn bộ quyền quản trị
        viên và đơn vị cấp bằng của hệ thống. Quản trị gốc cũ sẽ mất quyền ngay khi giao dịch này
        thành công.
      </Alert>

      <button className="btn-primary mt-4" type="button" disabled={tx.busy}
        onClick={() => void tx.run({
          fn: ENTRY.acceptRoot,
          args: [],
          index: async (out) => {
            const r = await api.post("/authority/root/accept", { txHash: out.hash });
            qc.invalidateQueries();
            return r;
          },
        })}>
        {tx.busy ? tx.label : "Ký nhận quyền quản trị gốc"}
      </button>

      <div className="mt-4"><TxProgress tx={tx} okTitle="Đã nhận quyền quản trị gốc" /></div>
    </SignSheet>
  );
}

/**
 * P4.1 — tự khoá DID khi nghi lộ khoá (mất máy đang mở ví, lộ 12 từ).
 *
 * Khoá DID làm MỌI vai trò của địa chỉ ngừng dùng được và không ai cấp được văn
 * bằng mới cho nó — khoanh vùng thiệt hại trong lúc chờ xử lý. Luật do hợp đồng
 * quyết định (`suspended_by`): tự khoá thì tự mở; nếu kẻ trộm khoá nhanh tay tự mở
 * lại, admin KHOÁ ĐÈ (M-08) và từ đó chỉ admin mở được.
 */
function SelfLockCard() {
  const { wallet } = useWallet();
  const { live } = useChainMode();
  const qc = useQueryClient();
  const tx = useChainTx();
  const [last, setLast] = useState<"suspended" | "active" | null>(null);
  const did = useQuery({
    queryKey: ["did", "self", wallet?.address],
    queryFn: () => api.get<{ status: string; did: string }>(`/did/by-address/${wallet!.address}`),
    enabled: !!wallet, retry: false,
  });
  // Ai đã khoá: chỉ đọc được từ chuỗi. Offline thì không biết — nói thật là không biết.
  const record = useQuery({
    queryKey: ["did", "record", wallet?.address],
    queryFn: () => view<[{ suspended_by: string }]>(VIEW.getDidByOwner, [wallet!.address]),
    enabled: !!wallet && live && did.data?.status === "suspended", retry: false,
  });
  if (!wallet || !did.data) return null;
  const status = did.data.status;
  if (status === "revoked") {
    return (
      <Section title="DID đã bị thu hồi">
        <Alert tone="bad" title="Địa chỉ này không dùng lại được">
          Thu hồi DID là vĩnh viễn. Hãy lập ví mới, đăng ký DID mới, rồi nhờ quản trị viên ghi nhận
          chuyển ví để đơn vị cấp bằng cấp lại văn bằng sang ví mới.
        </Alert>
      </Section>
    );
  }
  const norm = (a: string) => "0x" + a.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  const by = record.data?.[0]?.suspended_by;
  const lockedBySelf = by ? norm(by) === norm(wallet.address) : null;

  const run = (next: "suspended" | "active") => {
    setLast(next);
    void tx.run({
      fn: next === "suspended" ? ENTRY.suspendOwnDid : ENTRY.reactivateOwnDid,
      args: [],
      index: async (out) => {
        const r = await api.post("/did/self-status", { status: next, txHash: out.hash });
        qc.invalidateQueries();
        return r;
      },
    });
  };

  return (
    <SignSheet tx={tx}>
      <h2 className="text-lg font-semibold">Khoá khẩn cấp</h2>
      <p className="text-muted max-w-prose mt-1 mb-4">
        Nghi lộ khoá riêng hoặc 12 từ? Khoá DID ngay để không ai dùng được danh tính này.
      </p>
      {status === "active" ? (
        <>
          <Alert tone="warn" title="Hệ quả của việc khoá">
            Mọi vai trò (đơn vị cấp bằng, quản trị) của địa chỉ này ngừng ngay; không ai cấp được
            văn bằng mới cho bạn. Văn bằng đã có vẫn còn nguyên. Bạn tự mở lại được, trừ khi quản
            trị viên khoá đè, khi đó chỉ quản trị viên mở được.
          </Alert>
          <button className="btn-danger mt-4" type="button" disabled={tx.busy} onClick={() => run("suspended")}>
            {tx.busy ? tx.label : "Ký và khoá DID của tôi"}
          </button>
        </>
      ) : (
        <>
          <Alert tone={lockedBySelf === false ? "bad" : "info"} title="DID đang bị khoá">
            {lockedBySelf === false
              ? "Quản trị viên đã khoá DID này, chỉ quản trị viên mở được. Liên hệ phòng đào tạo."
              : lockedBySelf === true
                ? "Bạn đã tự khoá DID này. Chỉ mở lại khi chắc chắn khoá riêng chưa bị lộ."
                : "Không đọc được ai đã khoá (chế độ không nối chuỗi). Nếu quản trị viên khoá, chuỗi sẽ từ chối giao dịch mở khoá."}
          </Alert>
          <button className="btn-primary mt-4" type="button" disabled={tx.busy || lockedBySelf === false}
            onClick={() => run("active")}>
            {tx.busy ? tx.label : "Ký và mở khoá DID"}
          </button>
        </>
      )}
      <div className="mt-4">
        <TxProgress tx={tx} okTitle={last === "active" ? "Đã mở khoá DID" : "Đã khoá DID"} />
      </div>
    </SignSheet>
  );
}

/**
 * P4.3 — sao lưu và kiểm tra 12 từ định kỳ. Hệ thống không lưu 12 từ nên phép kiểm
 * dẫn địa chỉ từ cụm từ vừa gõ (ngay trên máy, không gửi đi đâu) rồi so với ví đang mở.
 */
function BackupCard() {
  const { wallet } = useWallet();
  const [phrase, setPhrase] = useState("");
  const [result, setResult] = useState<"ok" | "bad" | "invalid" | null>(null);
  const [, bump] = useState(0);
  useEffect(() => {
    const f = () => bump((n) => n + 1);
    window.addEventListener("vnu-backup", f);
    return () => window.removeEventListener("vnu-backup", f);
  }, []);
  if (!wallet) return null;
  const st = getBackup(wallet.address);
  const need = backupNeed(wallet.address);
  const fmt = (d?: string) => (d ? new Date(d).toLocaleDateString("vi-VN") : "chưa");

  const check = () => {
    const p = normalizeMnemonic(phrase);
    if (!isValidMnemonic(p)) { setResult("invalid"); return; }
    const ok = previewFromMnemonic(p).address.toLowerCase() === wallet.address.toLowerCase();
    setResult(ok ? "ok" : "bad");
    if (ok) { markBackup(wallet.address, "mnemonicAt"); markBackup(wallet.address, "checkedAt"); }
    setPhrase("");
  };

  return (
    <div id="sao-luu">
      <Section title="Sao lưu ví" description="Mất khoá là mất tài khoản, và không đọc được văn bằng của chính mình (nội dung đã mã hoá).">
        <dl className="grid sm:grid-cols-3 gap-3 text-sm">
          <div><dt className="label">Đã xác nhận chép 12 từ</dt><dd className="font-semibold">{fmt(st.mnemonicAt)}</dd></div>
          <div><dt className="label">Đã tải tệp sao lưu</dt><dd className="font-semibold">{fmt(st.keystoreAt)}</dd></div>
          <div><dt className="label">Lần kiểm tra 12 từ gần nhất</dt><dd className="font-semibold">{fmt(st.checkedAt)}</dd></div>
        </dl>
        {need === "backup" && (
          <div className="mt-3"><Alert tone="bad" title="Chưa có cách khôi phục nào trên máy này">
            Tải tệp sao lưu ở trang <Link className="link" to="/wallet">Ví</Link>, hoặc kiểm tra 12 từ bên dưới nếu bạn đã chép.
          </Alert></div>
        )}
        {need === "check" && (
          <div className="mt-3"><Alert tone="warn" title={`Đã hơn ${CHECK_EVERY_DAYS} ngày chưa kiểm tra`}>
            Gõ lại 12 từ để chắc tờ giấy của bạn vẫn đúng và đọc được.
          </Alert></div>
        )}
        <form className="mt-4 flex flex-col sm:flex-row gap-3" onSubmit={(e) => { e.preventDefault(); check(); }}>
          <input className="input flex-1" type="password" autoComplete="off" value={phrase}
            onChange={(e) => { setPhrase(e.target.value); setResult(null); }}
            placeholder="Gõ đủ 12 từ, cách nhau bằng dấu cách" aria-label="12 từ khôi phục" />
          <button className="btn-secondary" type="submit" disabled={phrase.trim().split(/\s+/).length < 12}>Kiểm tra</button>
        </form>
        <div role="status" aria-live="polite">
          {result === "ok" && <div className="mt-3"><Alert tone="ok" title="Đúng">12 từ này khôi phục đúng ví đang mở.</Alert></div>}
          {result === "bad" && <div className="mt-3"><Alert tone="bad" title="Không khớp">12 từ hợp lệ nhưng sinh ra một ví khác. Tờ giấy có thể chép sai thứ tự hoặc sai từ.</Alert></div>}
          {result === "invalid" && <div className="mt-3"><Alert tone="bad" title="Cụm từ không hợp lệ">Kiểm tra lại chính tả và đủ 12 từ.</Alert></div>}
        </div>
      </Section>
    </div>
  );
}
