import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { useWallet } from "../hooks/useWallet";
import { useAuthorityRoot } from "../hooks/useChain";
import { RoleBadge, Mono } from "./ui";
import BackendSwitch from "./BackendSwitch";
import OfflineModeBanner from "./OfflineModeBanner";

const NAV: Record<string, { to: string; label: string }[]> = {
  holder: [{ to: "/holder", label: "Văn bằng của tôi" }],
  issuer: [{ to: "/issuer", label: "Cấp văn bằng" }],
  verifier: [{ to: "/verifier", label: "Lịch sử xác minh" }],
  admin: [{ to: "/admin", label: "Quản trị" }],
  root: [{ to: "/admin", label: "Quản trị" }],
};

export default function Layout() {
  const { wallet, lock, secondsUntilLock } = useWallet();
  const root = useAuthorityRoot();
  const nav = useNavigate();

  // Vai trò trong ví chỉ quyết định menu; quyền thật vẫn do hợp đồng nói. Riêng
  // mục quản trị gốc bám theo `callerIsRoot` đọc từ chuỗi, vì root có thể vừa
  // được chuyển sang một ví mà ví đó vẫn đang khai vai trò cũ.
  const links = wallet
    ? [
        { to: "/account", label: "Danh tính" },
        ...(NAV[wallet.role] ?? []),
        ...(root.data?.callerIsRoot ? [{ to: "/root", label: "Quản trị gốc" }] : []),
      ]
    : [];

  return (
    <div className="min-h-screen flex flex-col">
      <header className="sticky top-0 z-20 bg-white/85 backdrop-blur border-b border-ink-100">
        <div className="mx-auto max-w-6xl px-4 h-16 flex items-center gap-4">
          <Link to="/" className="flex items-center gap-2.5 font-bold text-ink-900 shrink-0">
            <span className="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-400 to-accent-500 grid place-items-center text-white text-sm">
              VT
            </span>
            VNU-Trust
          </Link>

          <nav className="hidden sm:flex items-center gap-1 ml-2">
            <NavLink to="/" end className={navCls}>Tra cứu</NavLink>
            <NavLink to="/verify" className={navCls}>Xác minh</NavLink>
            {links.map((l) => <NavLink key={l.to} to={l.to} className={navCls}>{l.label}</NavLink>)}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            <div className="hidden lg:block"><BackendSwitch /></div>
            {wallet ? (
              <>
                <div className="hidden md:flex flex-col items-end leading-tight">
                  <span className="text-sm font-semibold text-ink-800">{wallet.label}</span>
                  <Mono value={wallet.address} />
                </div>
                <RoleBadge role={wallet.role} />
                {secondsUntilLock !== null && secondsUntilLock < 120 && (
                  <span className="chip bg-amber-50 text-amber-700 ring-1 ring-amber-200" title="Ví sẽ tự khoá khi không thao tác">
                    Khoá sau {secondsUntilLock}s
                  </span>
                )}
                <button className="btn-ghost !px-3 !py-1.5 text-xs"
                  onClick={() => { lock(); nav("/"); }}>Khoá ví</button>
              </>
            ) : (
              <Link className="btn-primary !py-2" to="/wallet">Mở ví</Link>
            )}
          </div>
        </div>
      </header>

      <OfflineModeBanner />

      <main className="flex-1 mx-auto w-full max-w-6xl px-4 py-8">
        {/* key theo địa chỉ: đổi ví là dựng lại trang, không sót trạng thái biểu mẫu của ví trước. */}
        <Outlet key={wallet?.address ?? "khach"} />
      </main>

      <footer className="border-t border-ink-100 bg-white">
        <div className="mx-auto max-w-6xl px-4 py-6 text-xs text-ink-400 flex flex-wrap gap-x-6 gap-y-2 justify-between">
          <span>VNU-Trust — Danh tính tự chủ &amp; văn bằng khả kiểm trên Movement Network</span>
          <span className="flex items-center gap-2">
            Khoá riêng được tạo và mã hoá ngay trong trình duyệt, không bao giờ gửi lên máy chủ.
            <span className="lg:hidden"><BackendSwitch /></span>
          </span>
        </div>
      </footer>
    </div>
  );
}

const navCls = ({ isActive }: { isActive: boolean }) =>
  `px-3 py-1.5 rounded-lg text-sm font-medium transition ${
    isActive ? "bg-brand-50 text-brand-700" : "text-ink-600 hover:text-ink-900 hover:bg-ink-50"
  }`;
