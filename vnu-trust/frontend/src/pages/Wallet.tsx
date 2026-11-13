import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWallet } from "../hooks/useWallet";
import { createWallet, importWallet, restoreFromMnemonic, previewFromMnemonic,
  exportKeystore, importKeystoreFile, deleteKeystore,
  checkPassphraseStrength, type Role, type UnlockedWallet } from "../lib/wallet";
import { isValidMnemonic, normalizeMnemonic } from "../lib/mnemonic";
import MnemonicPanel from "../components/MnemonicPanel";
import { markBackup } from "../lib/backup";
import { api } from "../lib/api";
import { registerEntity } from "../lib/auth";
import { ApiError } from "../lib/api";
import { Card, Alert, Mono, Spinner, Empty } from "../components/ui";

const ROLES: { value: Role; label: string; desc: string }[] = [
  { value: "holder", label: "Người sở hữu", desc: "Nhận, lưu giữ và chia sẻ văn bằng của mình" },
  { value: "issuer", label: "Đơn vị cấp bằng", desc: "Chỉ chọn khi địa chỉ đã được admin phê duyệt trên chuỗi" },
  { value: "verifier", label: "Bên xác minh", desc: "Kiểm tra tính xác thực của văn bằng" },
  { value: "admin", label: "Quản trị viên", desc: "Chỉ chọn khi địa chỉ đã được root cấp quyền trên chuỗi" },
];

export default function WalletPage() {
  const { keystores, loading, unlock, adopt, refreshKeystores, wallet } = useWallet();
  const [tab, setTab] = useState<"unlock" | "create" | "import">("unlock");
  const nav = useNavigate();

  if (loading) return <Spinner label="Đang đọc ví trong trình duyệt…" />;

  if (wallet) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-10">
        <Alert tone="ok" title="Ví đang mở">
          Bạn đang đăng nhập với vai trò <strong>{wallet.label}</strong>.
        </Alert>
        <button className="btn-primary mt-4" onClick={() => nav(`/${wallet.role}`)}>
          Vào khu vực làm việc
        </button>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-10">
      <h1 className="text-2xl font-bold text-ink-900">Ví danh tính</h1>
      <p className="mt-2 text-sm text-ink-600 leading-relaxed">
        Khoá riêng của bạn được tạo và mã hoá <strong>ngay trong trình duyệt</strong>, lưu trong
        IndexedDB của chính máy này. Máy chủ không bao giờ nhận được khoá riêng hay mật khẩu —
        đăng nhập bằng cách ký một chuỗi ngẫu nhiên dùng một lần.
      </p>

      <div className="mt-6 flex gap-1 p-1 bg-ink-100 rounded-xl w-fit" role="tablist">
        {([["unlock", "Mở ví"], ["create", "Tạo ví mới"], ["import", "Đăng nhập máy khác"]] as const).map(
          ([k, label]) => (
            <button
              key={k}
              role="tab"
              aria-selected={tab === k}
              onClick={() => setTab(k)}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition ${
                tab === k ? "bg-white text-ink-900 shadow-sm" : "text-ink-600 hover:text-ink-900"
              }`}
            >
              {label}
            </button>
          ),
        )}
      </div>

      <div className="mt-5">
        {tab === "unlock" && (
          <UnlockPanel keystores={keystores} onUnlock={unlock} onDeleted={refreshKeystores}
            onEmpty={() => setTab("create")} />
        )}
        {tab === "create" && <CreatePanel onDone={adopt} />}
        {tab === "import" && <ImportPanel onDone={adopt} onRestored={refreshKeystores} />}
      </div>
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

  if (keystores.length === 0) {
    return (
      <Card>
        <Empty title="Chưa có ví nào trên trình duyệt này"
          hint="Tạo ví mới, hoặc khôi phục từ tệp sao lưu nếu bạn đã có ví ở máy khác."
          action={<button className="btn-primary" onClick={onEmpty}>Tạo ví mới</button>} />
      </Card>
    );
  }

  return (
    <Card title="Mở ví đã có">
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
              ? "Ví hợp lệ nhưng tài khoản chưa đăng ký trên máy chủ."
              : (e2 as Error).message);
          } finally { setBusy(false); }
        }}
      >
        <div>
          <label className="label" htmlFor="ks">Chọn ví</label>
          <select id="ks" className="input" value={selected} onChange={(e) => setSelected(e.target.value)}>
            {keystores.map((k) => (
              <option key={k.address} value={k.address}>
                {k.label} — {k.role} — {k.address.slice(0, 10)}…{k.address.slice(-6)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="pw">Mật khẩu ví</label>
          <input id="pw" type="password" className="input" value={pass} autoComplete="current-password"
            onChange={(e) => setPass(e.target.value)} placeholder="Mật khẩu bạn đặt khi tạo ví" />
        </div>
        {err && <Alert tone="bad">{err}</Alert>}
        <div className="flex items-center gap-3">
          <button className="btn-primary" disabled={busy || !pass}>
            {busy ? "Đang mở…" : "Mở ví & đăng nhập"}
          </button>
          <button type="button" className="btn-ghost"
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
            Tải bản sao lưu
          </button>
          <button type="button" className="btn-ghost !text-rose-600"
            onClick={async () => {
              if (!confirm("Xoá ví này khỏi trình duyệt? Không khôi phục được nếu bạn chưa sao lưu.")) return;
              await deleteKeystore(selected);
              await onDeleted();
              setSelected("");
            }}>
            Xoá khỏi máy
          </button>
        </div>
      </form>
    </Card>
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

  const strength = pass ? checkPassphraseStrength(pass) : null;

  // Ví đã tạo xong nhưng chưa cho vào hệ thống: bắt chép 12 từ trước đã.
  if (created?.mnemonic) {
    return (
      <Card title="Cụm từ khôi phục của bạn"
        subtitle="Bước bắt buộc — đây là thứ duy nhất đăng nhập được ở máy khác">
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
    <Card title="Tạo ví mới" subtitle="Toàn bộ quá trình diễn ra trong trình duyệt của bạn">
      <form
        className="space-y-4"
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
        <div>
          <span className="label">Vai trò</span>
          <div className="grid sm:grid-cols-2 gap-2">
            {ROLES.map((r) => (
              <label key={r.value}
                className={`flex gap-3 items-start rounded-xl border p-3 cursor-pointer transition ${
                  role === r.value ? "border-brand-500 bg-brand-50/60 ring-2 ring-brand-100" : "border-ink-200 hover:bg-ink-50"
                }`}>
                <input type="radio" name="role" className="mt-1" checked={role === r.value}
                  onChange={() => setRole(r.value)} />
                <span>
                  <span className="block text-sm font-semibold text-ink-900">{r.label}</span>
                  <span className="block text-xs text-ink-500 mt-0.5">{r.desc}</span>
                </span>
              </label>
            ))}
          </div>
        </div>

        <div>
          <label className="label" htmlFor="lb">Tên hiển thị</label>
          <input id="lb" className="input" value={label} onChange={(e) => setLabel(e.target.value)}
            placeholder="Nguyễn Văn A — hoặc — Trường ĐH Công nghệ" required minLength={2} />
        </div>

        <div>
          <label className="label" htmlFor="em">Email (không bắt buộc)</label>
          <input id="em" type="email" className="input" value={email} onChange={(e) => setEmail(e.target.value)}
            placeholder="a@vnu.edu.vn" />
        </div>

        <div className="grid sm:grid-cols-2 gap-3">
          <div>
            <label className="label" htmlFor="p1">Mật khẩu ví</label>
            <input id="p1" type="password" className="input" value={pass} autoComplete="new-password"
              onChange={(e) => setPass(e.target.value)} required />
            {strength && (
              <p className={`mt-1.5 text-xs ${strength.ok ? "text-emerald-600" : "text-amber-600"}`}>
                {strength.message}
              </p>
            )}
          </div>
          <div>
            <label className="label" htmlFor="p2">Nhập lại mật khẩu</label>
            <input id="p2" type="password" className="input" value={pass2} autoComplete="new-password"
              onChange={(e) => setPass2(e.target.value)} required />
          </div>
        </div>

        <Alert tone="info" title="Mật khẩu và cụm từ khôi phục là hai thứ khác nhau">
          <strong>Mật khẩu</strong> chỉ mở ví trên chính máy này — quên thì vào "Khôi phục", nhập
          12 từ và đặt mật khẩu mới (không cần xoá ví trước).
          <br />
          <strong>Cụm từ 12 từ</strong> (hiện ở bước sau) mới là thứ đăng nhập được ở máy khác.
          Chúng tôi không lưu cả hai và không thể đặt lại.
        </Alert>

        {err && <Alert tone="bad">{err}</Alert>}
        <button className="btn-primary" disabled={busy || !strength?.ok}>
          {busy ? "Đang tạo…" : "Tạo ví & đăng ký"}
        </button>
      </form>
    </Card>
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

  return (
    <Card title="Khôi phục ví">
      <div className="flex flex-wrap gap-2 mb-4">
        <button className={mode === "phrase" ? "btn-primary" : "btn-ghost"} onClick={() => setMode("phrase")}>
          Bằng 12 từ
        </button>
        <button className={mode === "file" ? "btn-primary" : "btn-ghost"} onClick={() => setMode("file")}>
          Từ tệp sao lưu
        </button>
        <button className={mode === "key" ? "btn-primary" : "btn-ghost"} onClick={() => setMode("key")}>
          Từ khoá riêng
        </button>
      </div>

      {mode === "phrase" ? (
        <PhrasePanel onDone={onDone} />
      ) : mode === "file" ? (
        <div className="space-y-3">
          <p className="text-sm text-ink-600">
            Tệp sao lưu vẫn ở dạng đã mã hoá. Sau khi nạp, hãy sang thẻ “Mở ví” và nhập mật khẩu.
          </p>
          <input type="file" accept="application/json" className="input"
            onChange={async (e) => {
              setErr(""); setMsg("");
              const f = e.target.files?.[0];
              if (!f) return;
              try {
                const rec = await importKeystoreFile(await f.text());
                await onRestored();
                setMsg(`Đã nạp ví "${rec.label}". Chuyển sang thẻ “Mở ví” để đăng nhập.`);
              } catch (e2) { setErr((e2 as Error).message); }
            }} />
          {msg && <Alert tone="ok">{msg}</Alert>}
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
            <label className="label" htmlFor="pk">Khoá riêng Ed25519</label>
            {/* type="password" + tắt tự điền: khoá riêng không vào lịch sử biểu mẫu,
                không bị kiểm chính tả gửi đi, không hiện rõ khi chia sẻ màn hình (W-10). */}
            <input id="pk" className="input mono" type="password" autoComplete="off" spellCheck={false}
              value={privKey} onChange={(e) => setPrivKey(e.target.value)}
              placeholder="0x…" required />
          </div>
          <div className="grid sm:grid-cols-2 gap-3">
            <div>
              <label className="label" htmlFor="rl">Vai trò</label>
              <select id="rl" className="input" value={role} onChange={(e) => setRole(e.target.value as Role)}>
                {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
              </select>
            </div>
            <div>
              <label className="label" htmlFor="lb2">Tên hiển thị</label>
              <input id="lb2" className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
            </div>
          </div>
          <div>
            <label className="label" htmlFor="np">Mật khẩu mới cho ví</label>
            <input id="np" type="password" className="input" value={pass} autoComplete="new-password"
              onChange={(e) => setPass(e.target.value)} required />
          </div>
          {err && <Alert tone="bad">{err}</Alert>}
          <button className="btn-primary">Khôi phục ví</button>
        </form>
      )}
    </Card>
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
        công khai (địa chỉ, DID, vai trò) như một cuốn danh bạ — không có mật khẩu, không có
        khoá riêng nào được lưu ở đó.
      </Alert>

      <div>
        <label className="label" htmlFor="phrase">Cụm từ khôi phục (12 từ, cách nhau bởi dấu cách)</label>
        <textarea
          id="phrase"
          className="input mono min-h-[90px]"
          value={phrase}
          spellCheck={false}
          autoComplete="off"
          placeholder="ví dụ: effort avocado clap ..."
          onChange={(e) => { setPhrase(e.target.value); setChecked(false); setFound(null); }}
        />
        <p className={`mt-1.5 text-xs ${phraseOk ? "text-emerald-600" : words.length ? "text-amber-600" : "text-ink-400"}`}>
          {words.length === 0
            ? "Nhập đủ 12 từ"
            : phraseOk
              ? "Cụm từ hợp lệ"
              : `Đã nhập ${words.length}/12 từ${words.length === 12 ? " — nhưng mã kiểm tra không khớp, xem lại chính tả" : ""}`}
        </p>
      </div>

      {!checked ? (
        <button className="btn-primary" disabled={!phraseOk || busy} onClick={lookup}>
          {busy ? "Đang kiểm tra…" : "Kiểm tra cụm từ"}
        </button>
      ) : (
        <>
          {found ? (
            <Alert tone="ok" title={`Tìm thấy tài khoản ${found.role} đã ghi danh`}>
              Vai trò <strong>{found.role}</strong> · <Mono value={found.address} />
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
            <p className="text-sm text-ink-600">
              Đặt mật khẩu mới để mã hoá ví trên <strong>thiết bị này</strong>. Mật khẩu là
              cục bộ cho từng máy, không cần trùng với máy cũ.
            </p>
            <div className="grid sm:grid-cols-2 gap-3">
              <div>
                <label className="label" htmlFor="rp1">Mật khẩu cho máy này</label>
                <input id="rp1" type="password" className="input" value={pass}
                  autoComplete="new-password" onChange={(e) => setPass(e.target.value)} required />
                {strength && (
                  <p className={`mt-1.5 text-xs ${strength.ok ? "text-emerald-600" : "text-amber-600"}`}>
                    {strength.message}
                  </p>
                )}
              </div>
              <div>
                <label className="label" htmlFor="rp2">Nhập lại mật khẩu</label>
                <input id="rp2" type="password" className="input" value={pass2}
                  autoComplete="new-password" onChange={(e) => setPass2(e.target.value)} required />
              </div>
            </div>
            {err && <Alert tone="bad">{err}</Alert>}
            <div className="flex gap-3">
              <button type="button" className="btn-ghost" onClick={() => { setChecked(false); setFound(null); }}>
                Nhập lại cụm từ
              </button>
              <button className="btn-primary" disabled={busy || !strength?.ok}>
                {busy ? "Đang khôi phục…" : "Khôi phục & đăng nhập"}
              </button>
            </div>
          </form>
        </>
      )}

      {err && !checked && <Alert tone="bad">{err}</Alert>}
    </div>
  );
}
