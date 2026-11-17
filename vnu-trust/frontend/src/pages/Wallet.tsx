import { useId, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWallet } from "../hooks/useWallet";
import { useTitle } from "../hooks/useTitle";
import { createWallet, importWallet, restoreFromMnemonic, previewFromMnemonic,
  exportKeystore, importKeystoreFile, deleteKeystore,
  checkPassphraseStrength, type Role, type UnlockedWallet } from "../lib/wallet";
import { isValidMnemonic, normalizeMnemonic } from "../lib/mnemonic";
import MnemonicPanel from "../components/MnemonicPanel";
import { TabBar, TabPanel, type TabDef } from "../components/Tabs";
import { markBackup } from "../lib/backup";
import { api } from "../lib/api";
import { registerEntity } from "../lib/auth";
import { ApiError } from "../lib/api";
import { Card, Alert, Mono, Spinner, Empty, roleLabel } from "../components/ui";

const ROLES: { value: Role; desc: string }[] = [
  { value: "holder", desc: "Nhận, lưu giữ và chia sẻ văn bằng của mình" },
  { value: "issuer", desc: "Chỉ chọn khi địa chỉ đã được quản trị viên phê duyệt trên chuỗi" },
  { value: "verifier", desc: "Kiểm tra tính xác thực của văn bằng" },
  { value: "admin", desc: "Chỉ chọn khi địa chỉ đã được quản trị gốc cấp quyền trên chuỗi" },
];

const WALLET_TABS: TabDef[] = [
  { id: "unlock", label: "Mở ví" },
  { id: "create", label: "Tạo ví mới" },
  { id: "import", label: "Khôi phục ví" },
];

export default function WalletPage() {
  useTitle("Ví");
  const { keystores, loading, unlock, adopt, refreshKeystores, wallet } = useWallet();
  const [tab, setTab] = useState<"unlock" | "create" | "import">("unlock");
  const nav = useNavigate();

  if (loading) return <Spinner label="Đang đọc ví trong trình duyệt…" />;

  if (wallet) {
    return (
      <div className="max-w-3xl space-y-6">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Ví của bạn</h1>
        <Alert tone="ok" title="Ví đang mở">
          Bạn đang đăng nhập với tên <strong>{wallet.label}</strong>.
        </Alert>
        <button className="btn-primary" onClick={() => nav(`/${wallet.role}`)}>
          Vào khu vực làm việc
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Ví của bạn</h1>
        <p className="mt-2 text-muted max-w-prose">
          Khoá riêng được tạo và mã hoá ngay trong trình duyệt này. Mật khẩu không bao giờ rời khỏi máy.
        </p>
      </header>

      <TabBar tabs={WALLET_TABS} active={tab} onSelect={(id) => setTab(id as "unlock" | "create" | "import")} />

      <TabPanel id={tab}>
        <div className="sheet p-5 sm:p-6">
          {tab === "unlock" && (
            <UnlockPanel keystores={keystores} onUnlock={unlock} onDeleted={refreshKeystores}
              onEmpty={() => setTab("create")} />
          )}
          {tab === "create" && <CreatePanel onDone={adopt} />}
          {tab === "import" && <ImportPanel onDone={adopt} onRestored={refreshKeystores} />}
        </div>
      </TabPanel>
    </div>
  );
}

function UnlockPanel({ keystores, onUnlock, onDeleted, onEmpty }: {
  keystores: Awaited<ReturnType<typeof import("../lib/wallet").listKeystores>>;
  onUnlock: (a: string, p: string) => Promise<unknown>;
  onDeleted: () => Promise<void>;
  onEmpty: () => void;
}) {
  const [selected, setSelected] = useState(keystores[0]?.address ?? "");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();
  const uid = useId();

  if (keystores.length === 0) {
    return (
      <Empty title="Chưa có ví nào trên trình duyệt này"
        hint="Tạo ví mới, hoặc khôi phục từ tệp sao lưu nếu bạn đã có ví ở máy khác."
        action={<button className="btn-primary" onClick={onEmpty}>Tạo ví mới</button>} />
    );
  }

  return (
    <form
      className="space-y-4"
      onSubmit={async (e) => {
        e.preventDefault();
        setErr(""); setBusy(true);
        try {
          const w = await onUnlock(selected, pass);
          setPass("");
          nav(`/${(w as { role: Role }).role}`);
        } catch (e2) {
          setErr(e2 instanceof ApiError && e2.status === 401
            ? "Ví hợp lệ nhưng chưa có tài khoản trên máy chủ. Khôi phục bằng 12 từ ở tab Khôi phục ví để đăng ký lại."
            : (e2 as Error).message);
        } finally { setBusy(false); }
      }}
    >
      <div>
        <label className="label" htmlFor={`${uid}-ks`}>Chọn ví</label>
        <select id={`${uid}-ks`} className="input" value={selected} onChange={(e) => setSelected(e.target.value)}>
          {keystores.map((k) => (
            <option key={k.address} value={k.address}>
              {k.label}, {roleLabel(k.role)}, {k.address.slice(0, 10)}…{k.address.slice(-6)}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label className="label" htmlFor={`${uid}-pw`}>Mật khẩu ví</label>
        <input id={`${uid}-pw`} type="password" className="input" value={pass} autoComplete="current-password"
          onChange={(e) => setPass(e.target.value)} placeholder="Mật khẩu bạn đặt khi tạo ví" />
      </div>
      {err && <Alert tone="bad">{err}</Alert>}
      <div className="flex flex-wrap items-center gap-3">
        <button className="btn-primary" disabled={busy || !pass}>
          {busy ? "Đang mở…" : "Mở ví"}
        </button>
        <button type="button" className="btn-secondary"
          onClick={async () => {
            const ks = keystores.find((k) => k.address === selected);
            if (!ks) return;
            const blob = await exportKeystore(selected);
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = `vnu-trust-${ks.label}-${selected.slice(0, 8)}.json`;
            a.click(); URL.revokeObjectURL(url);
            markBackup(selected, "keystoreAt"); // P4.3
          }}>
          Tải tệp sao lưu
        </button>
        <button type="button" className="btn-quiet !text-son"
          onClick={async () => {
            if (!confirm("Xoá ví này khỏi trình duyệt? Không khôi phục được nếu bạn chưa sao lưu.")) return;
            await deleteKeystore(selected);
            await onDeleted();
            setSelected("");
          }}>
          Xoá ví khỏi máy này
        </button>
      </div>
    </form>
  );
}

function StrengthNote({ strength }: { strength: { ok: boolean; message: string } | null }) {
  if (!strength) return null;
  return (
    <p className={`mt-1.5 text-sm ${strength.ok ? "text-ink" : "text-son"}`}>
      {strength.message}
    </p>
  );
}

function CreatePanel({ onDone }: { onDone: (w: UnlockedWallet) => Promise<void> }) {
  const [role, setRole] = useState<Role>("holder");
  const [label, setLabel] = useState("");
  const [email, setEmail] = useState("");
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();
  const [created, setCreated] = useState<UnlockedWallet | null>(null);
  const uid = useId();

  const strength = pass ? checkPassphraseStrength(pass) : null;

  // Ví đã tạo xong nhưng chưa cho vào hệ thống: bắt chép 12 từ trước đã.
  if (created?.mnemonic) {
    return (
      <Card title="Cụm từ khôi phục của bạn"
        subtitle="Bước bắt buộc. Đây là thứ duy nhất đăng nhập được ở máy khác.">
        <MnemonicPanel
          mnemonic={created.mnemonic}
          onConfirmed={() => {
            markBackup(created.address, "mnemonicAt"); // P4.3: đã chép và nhập lại đúng 12 từ
            void onDone(created).then(() => nav(`/${created.role}`));
          }}
        />
      </Card>
    );
  }

  return (
    <form
      className="space-y-5"
      onSubmit={async (e) => {
        e.preventDefault();
        setErr("");
        if (pass !== pass2) return setErr("Hai ô mật khẩu không khớp");
        setBusy(true);
        try {
          const w = await createWallet({ passphrase: pass, role, label: label.trim() });
          await registerEntity(w, email.trim() || undefined);
          // Chưa đăng nhập vội — hiện 12 từ và bắt xác nhận đã chép trước.
          setCreated(w);
        } catch (e2) {
          setErr((e2 as Error).message);
        } finally { setBusy(false); }
      }}
    >
      <fieldset>
        <legend className="label">Vai trò</legend>
        <div className="mt-1 grid gap-2">
          {ROLES.map((r) => (
            <label key={r.value}
              className={`flex gap-3 items-start rounded-sheet border p-3 cursor-pointer ${
                role === r.value ? "border-primary ring-1 ring-primary bg-primary-soft/40" : "border-rule"
              }`}>
              <input type="radio" name="role" className="mt-1.5" checked={role === r.value}
                onChange={() => setRole(r.value)} />
              <span>
                <span className="block font-semibold">{roleLabel(r.value)}</span>
                <span className="block text-sm text-muted mt-0.5">{r.desc}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      <div>
        <label className="label" htmlFor={`${uid}-lb`}>Tên hiển thị</label>
        <input id={`${uid}-lb`} className="input" value={label} onChange={(e) => setLabel(e.target.value)}
          placeholder="Nguyễn Văn A, hoặc Trường ĐH Công nghệ" required minLength={2} />
      </div>

      <div>
        <label className="label" htmlFor={`${uid}-em`}>Email (không bắt buộc)</label>
        <input id={`${uid}-em`} type="email" className="input" value={email} onChange={(e) => setEmail(e.target.value)}
          placeholder="a@vnu.edu.vn" />
      </div>

      <div className="grid sm:grid-cols-2 gap-3">
        <div>
          <label className="label" htmlFor={`${uid}-p1`}>Mật khẩu ví</label>
          <input id={`${uid}-p1`} type="password" className="input" value={pass} autoComplete="new-password"
            onChange={(e) => setPass(e.target.value)} required />
          <StrengthNote strength={strength} />
        </div>
        <div>
          <label className="label" htmlFor={`${uid}-p2`}>Nhập lại mật khẩu</label>
          <input id={`${uid}-p2`} type="password" className="input" value={pass2} autoComplete="new-password"
            onChange={(e) => setPass2(e.target.value)} required />
        </div>
      </div>

      <Alert tone="info" title="Mật khẩu và cụm từ khôi phục là hai thứ khác nhau">
        <strong>Mật khẩu</strong> chỉ mở ví trên chính máy này. Quên mật khẩu thì vào tab Khôi phục ví,
        nhập 12 từ và đặt mật khẩu mới (không cần xoá ví trước).
        <br />
        <strong>Cụm từ 12 từ</strong> (hiện ở bước sau) mới là thứ đăng nhập được ở máy khác.
        Chúng tôi không lưu cả hai và không thể đặt lại.
      </Alert>

      {err && <Alert tone="bad">{err}</Alert>}
      <button className="btn-primary" disabled={busy || !strength?.ok}>
        {busy ? "Đang tạo…" : "Tạo ví"}
      </button>
    </form>
  );
}

function ImportPanel({ onDone, onRestored }: {
  onDone: (w: UnlockedWallet) => Promise<void>;
  onRestored: () => Promise<void>;
}) {
  const [mode, setMode] = useState<"phrase" | "file" | "key">("phrase");
  const [privKey, setPrivKey] = useState("");
  const [role, setRole] = useState<Role>("holder");
  const [label, setLabel] = useState("");
  const [pass, setPass] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const uid = useId();

  const modes: { id: "phrase" | "file" | "key"; label: string }[] = [
    { id: "phrase", label: "Bằng 12 từ" },
    { id: "file", label: "Từ tệp sao lưu" },
    { id: "key", label: "Từ khoá riêng" },
  ];

  return (
    <div className="space-y-4">
      <p className="text-muted max-w-prose">
        Dùng 12 từ khôi phục, tệp sao lưu hoặc khoá riêng của ví đã tạo ở máy khác.
      </p>
      <div className="flex flex-wrap gap-2" role="group" aria-label="Cách khôi phục">
        {modes.map((m) => (
          <button key={m.id} type="button" aria-pressed={mode === m.id}
            className={`rounded-ctrl border px-4 min-h-[44px] text-[15px] font-semibold ${
              mode === m.id ? "bg-primary-soft text-primary border-primary" : "bg-sheet text-ink-2 border-pencil"
            }`}
            onClick={() => setMode(m.id)}>
            {m.label}
          </button>
        ))}
      </div>

      {mode === "phrase" ? (
        <PhrasePanel onDone={onDone} />
      ) : mode === "file" ? (
        <div className="space-y-3">
          <p className="text-sm text-muted">
            Tệp sao lưu vẫn ở dạng đã mã hoá. Sau khi nạp, hãy sang tab Mở ví và nhập mật khẩu.
          </p>
          <div>
            <label className="label" htmlFor={`${uid}-file`}>Tệp sao lưu (.json)</label>
            <input id={`${uid}-file`} type="file" accept="application/json" className="input"
              onChange={async (e) => {
                setErr(""); setMsg("");
                const f = e.target.files?.[0];
                if (!f) return;
                try {
                  const rec = await importKeystoreFile(await f.text());
                  await onRestored();
                  setMsg(`Đã nạp ví "${rec.label}". Chuyển sang tab Mở ví để đăng nhập.`);
                } catch (e2) { setErr((e2 as Error).message); }
              }} />
          </div>
          <div role="status" aria-live="polite">{msg && <Alert tone="ok">{msg}</Alert>}</div>
          {err && <Alert tone="bad">{err}</Alert>}
        </div>
      ) : (
        <form className="space-y-4"
          onSubmit={async (e) => {
            e.preventDefault(); setErr("");
            try {
              const w = await importWallet(privKey, pass, role, label.trim());
              await onDone(w);
            } catch (e2) { setErr((e2 as Error).message); }
          }}>
          <Alert tone="warn" title="Chỉ nhập khoá riêng trên thiết bị bạn tin tưởng">
            Khoá riêng cho phép ký thay bạn. Không dán khoá này ở máy công cộng.
          </Alert>
          <div>
            <label className="label" htmlFor={`${uid}-pk`}>Khoá riêng Ed25519</label>
            {/* type="password" + tắt tự điền: khoá riêng không vào lịch sử biểu mẫu,
                không bị kiểm chính tả gửi đi, không hiện rõ khi chia sẻ màn hình (W-10). */}
            <input id={`${uid}-pk`} className="input hex" type="password" autoComplete="off" spellCheck={false}
              value={privKey} onChange={(e) => setPrivKey(e.target.value)}
              placeholder="0x…" required />
          </div>
          <div className="grid sm:grid-cols-2 gap-3">
            <div>
              <label className="label" htmlFor={`${uid}-rl`}>Vai trò</label>
              <select id={`${uid}-rl`} className="input" value={role} onChange={(e) => setRole(e.target.value as Role)}>
                {ROLES.map((r) => <option key={r.value} value={r.value}>{roleLabel(r.value)}</option>)}
              </select>
            </div>
            <div>
              <label className="label" htmlFor={`${uid}-lb2`}>Tên hiển thị</label>
              <input id={`${uid}-lb2`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
            </div>
          </div>
          <div>
            <label className="label" htmlFor={`${uid}-np`}>Mật khẩu mới cho ví</label>
            <input id={`${uid}-np`} type="password" className="input" value={pass} autoComplete="new-password"
              onChange={(e) => setPass(e.target.value)} required />
          </div>
          {err && <Alert tone="bad">{err}</Alert>}
          <button className="btn-primary">Khôi phục ví</button>
        </form>
      )}
    </div>
  );
}


/**
 * Đăng nhập trên thiết bị mới bằng 12 từ.
 *
 * Khoá được sinh lại từ chính cụm từ nên ra đúng địa chỉ cũ. Sau đó hỏi máy chủ
 * xem địa chỉ này đã ghi danh chưa: nếu rồi thì lấy luôn vai trò và tên cũ,
 * người dùng không phải nhớ và cũng không thể khai sai.
 */
function PhrasePanel({ onDone }: { onDone: (w: UnlockedWallet) => Promise<void> }) {
  const [phrase, setPhrase] = useState("");
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  // Tuyến công khai không trả tên hiển thị (P-05) — chỉ vai trò và DID.
  const [found, setFound] = useState<{ address: string; did: string; role: Role; label: string | null } | null>(null);
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const nav = useNavigate();
  const uid = useId();

  const words = normalizeMnemonic(phrase).split(" ").filter(Boolean);
  const phraseOk = words.length === 12 && isValidMnemonic(phrase);
  const strength = pass ? checkPassphraseStrength(pass) : null;

  async function lookup() {
    setErr(""); setBusy(true); setChecked(false); setFound(null);
    try {
      const { address } = previewFromMnemonic(phrase);
      try {
        const e = await api.get<{ address: string; did: string; role: Role; label: string | null }>(
          `/entities/by-address/${address}`,
        );
        setFound(e);
      } catch {
        // Chưa ghi danh trên máy chủ này — vẫn khôi phục được ví, chỉ là chưa có hồ sơ.
        setFound(null);
      }
      setChecked(true);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <Alert tone="info" title="Không cần chép tệp, không cần máy chủ giữ tài khoản">
        Khoá riêng được <strong>sinh lại</strong> từ chính 12 từ của bạn. Máy chủ chỉ lưu phần
        công khai (địa chỉ, DID, vai trò) như một cuốn danh bạ. Không có mật khẩu hay khoá
        riêng nào được lưu ở đó.
      </Alert>

      <div>
        <label className="label" htmlFor={`${uid}-phrase`}>Cụm từ khôi phục (12 từ, cách nhau bởi dấu cách)</label>
        <textarea
          id={`${uid}-phrase`}
          className="input min-h-[90px]"
          value={phrase}
          spellCheck={false}
          autoComplete="off"
          placeholder="ví dụ: effort avocado clap ..."
          onChange={(e) => { setPhrase(e.target.value); setChecked(false); setFound(null); }}
        />
        <p className={`mt-1.5 text-sm ${phraseOk ? "text-ink" : words.length ? "text-son" : "text-muted"}`}>
          {words.length === 0
            ? "Nhập đủ 12 từ"
            : phraseOk
              ? "Cụm từ hợp lệ"
              : `Đã nhập ${words.length}/12 từ${words.length === 12 ? ", nhưng mã kiểm tra không khớp, xem lại chính tả" : ""}`}
        </p>
      </div>

      {!checked ? (
        <button className="btn-primary" disabled={!phraseOk || busy} onClick={lookup}>
          {busy ? "Đang kiểm tra…" : "Kiểm tra cụm từ"}
        </button>
      ) : (
        <>
          {found ? (
            <Alert tone="ok" title={`Tìm thấy tài khoản ${roleLabel(found.role)} đã ghi danh`}>
              Địa chỉ <Mono value={found.address} />
            </Alert>
          ) : (
            <Alert tone="warn" title="Cụm từ hợp lệ nhưng chưa có hồ sơ trên máy chủ">
              Có thể bạn chưa đăng ký, hoặc đang trỏ vào một máy chủ khác. Ví vẫn khôi phục
              được, nhưng cần đăng ký lại hồ sơ sau khi vào.
            </Alert>
          )}

          <form
            className="space-y-4"
            onSubmit={async (e) => {
              e.preventDefault();
              setErr("");
              if (pass !== pass2) { setErr("Hai ô mật khẩu không khớp"); return; }
              setBusy(true);
              try {
                const w = await restoreFromMnemonic(
                  phrase, pass,
                  found?.role ?? "holder",
                  found?.label ?? "Ví khôi phục",
                  undefined,
                  found?.did,
                );
                // Khôi phục được bằng 12 từ nghĩa là người dùng đang giữ chúng (P4.3).
                markBackup(w.address, "mnemonicAt");
                markBackup(w.address, "checkedAt");
                await onDone(w);
                nav(`/${w.role}`);
              } catch (e2) {
                setErr((e2 as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <p className="text-sm text-muted">
              Đặt mật khẩu mới để mã hoá ví trên <strong>thiết bị này</strong>. Mật khẩu là
              cục bộ cho từng máy, không cần trùng với máy cũ.
            </p>
            <div className="grid sm:grid-cols-2 gap-3">
              <div>
                <label className="label" htmlFor={`${uid}-rp1`}>Mật khẩu cho máy này</label>
                <input id={`${uid}-rp1`} type="password" className="input" value={pass}
                  autoComplete="new-password" onChange={(e) => setPass(e.target.value)} required />
                <StrengthNote strength={strength} />
              </div>
              <div>
                <label className="label" htmlFor={`${uid}-rp2`}>Nhập lại mật khẩu</label>
                <input id={`${uid}-rp2`} type="password" className="input" value={pass2}
                  autoComplete="new-password" onChange={(e) => setPass2(e.target.value)} required />
              </div>
            </div>
            {err && <Alert tone="bad">{err}</Alert>}
            <div className="flex flex-wrap gap-3">
              <button type="button" className="btn-secondary" onClick={() => { setChecked(false); setFound(null); }}>
                Nhập lại cụm từ
              </button>
              <button className="btn-primary" disabled={busy || !strength?.ok}>
                {busy ? "Đang khôi phục…" : "Khôi phục và đăng nhập"}
              </button>
            </div>
          </form>
        </>
      )}

      {err && !checked && <Alert tone="bad">{err}</Alert>}
    </div>
  );
}
