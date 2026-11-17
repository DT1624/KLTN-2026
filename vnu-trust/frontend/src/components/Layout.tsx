import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useWallet } from "../hooks/useWallet";
import { useAuthorityRoot } from "../hooks/useChain";
import { CHAIN } from "../lib/chain";
import { roleLabel } from "./ui";
import { IconClose, IconLock, IconMenu } from "./icons";
import Rosette from "./Rosette";
import BackendSwitch from "./BackendSwitch";
import OfflineModeBanner from "./OfflineModeBanner";
import BackupBanner from "./BackupBanner";

const NAV: Record<string, { to: string; label: string }[]> = {
  holder: [{ to: "/holder", label: "Văn bằng của tôi" }],
  issuer: [{ to: "/issuer", label: "Cấp văn bằng" }],
  verifier: [{ to: "/verifier", label: "Lịch sử xác minh" }],
  admin: [{ to: "/admin", label: "Quản trị" }],
  root: [{ to: "/admin", label: "Quản trị" }],
};

/** Đếm ngược dạng m:ss. */
const mmss = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;

type Item = { to: string; label: string; end: boolean };

export default function Layout() {
  const { wallet, lock, secondsUntilLock } = useWallet();
  const root = useAuthorityRoot();
  const nav = useNavigate();
  const loc = useLocation();
  const [open, setOpen] = useState(false);
  const mobileRef = useRef<HTMLDivElement>(null);
  const menuBtnRef = useRef<HTMLButtonElement>(null);
  const wasOpen = useRef(false);

  // Vai trò trong ví chỉ quyết định menu; quyền thật vẫn do hợp đồng nói. Riêng
  // mục quản trị gốc bám theo `callerIsRoot` đọc từ chuỗi, vì root có thể vừa
  // được chuyển sang một ví mà ví đó vẫn đang khai vai trò cũ.
  const links: Item[] = [
    { to: "/", label: "Tra cứu", end: true },
    { to: "/verify", label: "Xác minh văn bằng", end: false },
    ...(wallet
      ? [
          ...(NAV[wallet.role] ?? []).map((l) => ({ ...l, end: false })),
          ...(root.data?.callerIsRoot ? [{ to: "/root", label: "Quản trị gốc", end: false }] : []),
          { to: "/account", label: "Tài khoản", end: false },
        ]
      : []),
  ];

  // Chia nhóm cho thanh bên; điều kiện hiện từng mục vẫn là điều kiện của `links`.
  const byTo = (tos: string[]) => links.filter((l) => tos.includes(l.to));
  const groups: { name: string; items: Item[] }[] = [
    { name: "Chung", items: byTo(["/", "/verify"]) },
    { name: "Của tôi", items: byTo(["/holder", "/account"]) },
    { name: "Nhà trường", items: byTo(["/issuer", "/verifier", "/admin", "/root"]) },
  ].filter((g) => g.items.length > 0);

  // Đóng menu khi đổi trang.
  useEffect(() => { setOpen(false); }, [loc.pathname, loc.search]);

  // Esc đóng menu; mở menu thì đưa focus vào mục đầu.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { setOpen(false); return; }
      if (e.key !== "Tab") return;
      // Bẫy focus trong ngăn kéo: vòng từ phần tử cuối về đầu và ngược lại.
      const items = mobileRef.current?.querySelectorAll<HTMLElement>("a[href], button:not([disabled]), select, input, [tabindex]:not([tabindex='-1'])");
      if (!items || items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      const cur = document.activeElement;
      if (e.shiftKey && (cur === first || !mobileRef.current?.contains(cur))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (cur === last || !mobileRef.current?.contains(cur))) { e.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", onKey);
    mobileRef.current?.querySelector<HTMLElement>("a")?.focus();
    // Khoá cuộn nền khi ngăn kéo mở; trả lại giá trị cũ khi đóng.
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    // Nới lên cỡ lg thì ngăn kéo không còn nghĩa: đóng.
    const mq = window.matchMedia("(min-width: 1024px)");
    const onMq = (e: MediaQueryListEvent) => { if (e.matches) setOpen(false); };
    mq.addEventListener("change", onMq);
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
      mq.removeEventListener("change", onMq);
    };
  }, [open]);

  // Đóng ngăn kéo thì trả focus về nút Menu.
  useEffect(() => {
    if (wasOpen.current && !open) menuBtnRef.current?.focus();
    wasOpen.current = open;
  }, [open]);

  const seed = CHAIN.contract || "VNU-Trust";
  const countdown = secondsUntilLock !== null && secondsUntilLock < 120 ? secondsUntilLock : null;
  const announce = countdown !== null && [60, 30, 10].includes(countdown) ? `Ví sẽ tự khoá sau ${countdown} giây` : "";

  const brand = (
    <Link to="/" className="flex items-center gap-2.5 shrink-0">
      <Rosette seed={seed} size={36} />
      <span className="flex flex-col">
        <span className="text-[17px] font-bold text-primary leading-tight">VNU-Trust</span>
        <span className="text-xs text-muted">Văn bằng số ĐHQGHN</span>
      </span>
    </Link>
  );

  const menuBtn = (cls: string) => (
    <button type="button" ref={menuBtnRef} className={cls}
      aria-expanded={open} aria-controls="mobile-nav"
      onClick={() => setOpen((v) => !v)}>
      {open ? <IconClose /> : <IconMenu />}Menu
    </button>
  );

  const itemCls = ({ isActive }: { isActive: boolean }) =>
    `block rounded-ctrl px-2.5 py-2 text-[15px] font-medium ${
      isActive ? "bg-primary-soft text-primary font-semibold" : "text-ink-2 hover:bg-paper hover:text-ink"
    }`;

  /** Nội dung thanh bên, dùng chung cho thanh bên cố định và ngăn kéo. */
  const sideBody = (
    <>
      {brand}
      <nav className="flex flex-col gap-4" aria-label="Điều hướng chính">
        {groups.map((g) => (
          <div key={g.name} className="flex flex-col gap-0.5">
            <span className="text-xs font-semibold text-muted px-2.5 pb-1">{g.name}</span>
            {g.items.map((l) => (
              <NavLink key={l.to} to={l.to} end={l.end} className={itemCls}>{l.label}</NavLink>
            ))}
          </div>
        ))}
      </nav>
      {wallet && (
        <div className="mt-auto flex flex-col gap-3">
          <div className="rounded-sheet border border-rule p-3 flex flex-col gap-3">
            <div className="flex items-center gap-2.5">
              <Rosette seed={wallet.did ?? wallet.address} size={36} />
              <div className="min-w-0">
                <div className="text-sm font-semibold truncate">{wallet.label}</div>
                <div className="text-xs text-muted">{roleLabel(wallet.role)}</div>
              </div>
            </div>
            {countdown !== null && (
              <span className="chip bg-warning-soft text-warning self-start">Khoá sau {mmss(countdown)}</span>
            )}
            <button type="button" className="btn-secondary w-full inline-flex items-center justify-center gap-1.5"
              onClick={() => { setOpen(false); lock(); nav("/"); }}>
              <IconLock />Khoá ví
            </button>
          </div>
          <BackendSwitch />
        </div>
      )}
    </>
  );

  const footerText = "VNU-Trust, danh tính và văn bằng số của ĐHQGHN trên Movement testnet.";

  if (wallet) {
    return (
      <div className="min-h-screen lg:grid lg:grid-cols-[248px_minmax(0,1fr)]">
        <a className="skip-link" href="#main">Bỏ qua điều hướng</a>
        <span className="sr-only" role="status" aria-live="polite">{announce}</span>

        <aside className="hidden lg:flex bg-sheet border-r border-rule sticky top-0 h-screen overflow-y-auto flex-col p-3 gap-4">
          {sideBody}
        </aside>

        <div className="min-w-0 flex flex-col min-h-screen">
          <header className="lg:hidden bg-sheet border-b border-rule px-4 sm:px-6 py-2.5 flex items-center justify-between gap-4">
            {brand}
            <div className="flex items-center gap-2">
              {countdown !== null && (
                <span className="chip bg-warning-soft text-warning">Khoá sau {mmss(countdown)}</span>
              )}
              {menuBtn("btn-secondary inline-flex items-center gap-1.5")}
            </div>
          </header>

          {open && (
            <div className="lg:hidden fixed inset-0 z-50">
              <div className="absolute inset-0 bg-ink/30" onClick={() => setOpen(false)} aria-hidden="true" />
              <div id="mobile-nav" ref={mobileRef} role="dialog" aria-modal="true" aria-label="Điều hướng"
                className="fixed inset-y-0 left-0 w-[280px] bg-sheet shadow-raised overflow-y-auto flex flex-col p-3 gap-4">
                {sideBody}
              </div>
            </div>
          )}

          <OfflineModeBanner />
          <BackupBanner />

          <main id="main" tabIndex={-1} className="flex-1 px-4 sm:px-8 py-6 sm:py-8 focus:outline-none">
            <div className="mx-auto w-full max-w-6xl">
              {/* key theo địa chỉ: đổi ví là dựng lại trang, không sót trạng thái biểu mẫu của ví trước. */}
              <Outlet key={wallet.address} />
            </div>
          </main>

          <footer className="border-t border-rule text-sm text-muted px-4 sm:px-8 py-5">
            {footerText}
          </footer>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <a className="skip-link" href="#main">Bỏ qua điều hướng</a>
      <span className="sr-only" role="status" aria-live="polite">{announce}</span>

      <header className="sticky top-0 z-40 bg-sheet border-b border-rule">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-3 flex items-center gap-4">
          {brand}

          <nav className="hidden md:flex items-center gap-1 ml-4" aria-label="Điều hướng chính">
            {links.map((l) => (
              <NavLink key={l.to} to={l.to} end={l.end}
                className={({ isActive }) =>
                  `rounded-ctrl px-3 py-2 text-[15px] ${
                    isActive ? "bg-primary-soft text-primary font-semibold" : "text-ink-2 hover:bg-paper"
                  }`}>
                {l.label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            <Link className="btn-primary hidden md:inline-flex" to="/wallet">Mở ví</Link>
            {menuBtn("btn-secondary md:hidden inline-flex items-center gap-1.5")}
          </div>
        </div>
        <div className="h-[3px] bg-mark" />

        {open && (
          <div id="mobile-nav" ref={mobileRef} className="md:hidden bg-sheet border-b border-rule">
            <nav className="mx-auto max-w-6xl px-4 sm:px-6" aria-label="Điều hướng chính">
              {links.map((l) => (
                <NavLink key={l.to} to={l.to} end={l.end}
                  className={({ isActive }) =>
                    `flex items-center min-h-[48px] border-b border-rule ${isActive ? "text-primary font-semibold" : "text-ink-2"}`}>
                  {l.label}
                </NavLink>
              ))}
              <Link className="flex items-center min-h-[48px] border-b border-rule font-semibold text-primary" to="/wallet">
                Mở ví
              </Link>
            </nav>
            <div className="mx-auto max-w-6xl px-4 sm:px-6 py-4 flex flex-wrap items-center gap-x-4 gap-y-3">
              <BackendSwitch />
            </div>
          </div>
        )}
      </header>

      <OfflineModeBanner />
      <BackupBanner />

      <main id="main" tabIndex={-1} className="flex-1 mx-auto w-full max-w-6xl px-4 sm:px-6 py-6 sm:py-10 focus:outline-none">
        {/* key theo địa chỉ: đổi ví là dựng lại trang, không sót trạng thái biểu mẫu của ví trước. */}
        <Outlet key="khach" />
      </main>

      <footer className="bg-sheet border-t border-rule text-sm text-muted">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-6 flex flex-wrap gap-x-6 gap-y-3 items-center justify-between">
          <span>{footerText}</span>
          <BackendSwitch />
        </div>
      </footer>
    </div>
  );
}
