import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Credential } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { useChainTx, useMe } from "../hooks/useChain";
import { useTitle } from "../hooks/useTitle";
import { canonicalize, signMessage, sha3_256Hex } from "../lib/wallet";
import { vcIdHash } from "../lib/vcid";
import { ENTRY, bytesArg, hashArg, u64Arg, vcIdFromEvents } from "../lib/chain";
import { ISSUABLE_VC_TYPES, maskLabel } from "../lib/constants";
import { Section, StatusBadge, RoleStatusBadge, Alert, Spinner, Empty, Mono, Ledger, Field, Badge, Row } from "../components/ui";
import { TabBar, TabPanel, useTabs } from "../components/Tabs";
import TxProgress, { SignSheet } from "../components/ChainTx";
import GasPanel from "../components/GasPanel";
import ReviewPanel from "../components/ReviewPanel";
import { openCredential, sealCredential } from "../lib/vcStore";
import { StatusBar, MonthlyBars, BarList, type MonthPoint } from "../components/charts";

interface Stats {
  active: number; suspended: number; expired: number; revoked: number; total: number;
  byMonth: MonthPoint[];
  byType: { vcType: number; label: string; count: number }[];
}

/**
 * Khu vực của đơn vị cấp bằng.
 *
 * Toàn bộ vòng cấp văn bằng chạy trong trình duyệt: ký nội dung → ghim IPFS →
 * ví ký `issue_vc` → chờ chuỗi xác nhận → đọc **số hiệu thật** từ sự kiện
 * `VCIssuedEvent` → gửi cho backend ghi chỉ mục. Không còn ô "Mã giao dịch".
 */
export default function Issuer() {
  useTitle("Cấp văn bằng");
  const me = useMe();
  const stats = useQuery({ queryKey: ["issuer", "stats"], queryFn: () => api.get<Stats>("/issuer/stats") });

  const { active, select, visible } = useTabs([
    { id: "cap", label: "Cấp văn bằng mới" },
    { id: "da-cap", label: "Văn bằng đã cấp", count: stats.data?.total },
    // Chỉ issuer có bit uỷ quyền (do root cấp) mới cấp được sub-issuer.
    { id: "uy-quyen", label: "Uỷ quyền", hidden: !me.data?.onChain.canDelegate },
  ]);

  const on = me.data?.onChain;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Cấp văn bằng</h1>
        <p className="text-muted mt-2 max-w-prose">Văn bằng bạn cấp được ghi lên sổ đăng ký trên chuỗi.</p>
      </header>

      {on && !on.hasActiveDid && (
        <Alert tone="warn" title="Ví này chưa đăng ký DID">
          Sổ đăng ký trên chuỗi kiểm tra DID của <strong>cả</strong> đơn vị cấp lẫn người nhận trước khi cho cấp
          văn bằng. Sang <Link className="link" to="/account">trang Tài khoản</Link> để
          đăng ký trước.
        </Alert>
      )}
      {on && on.hasActiveDid && !on.isActiveIssuer && (
        <Alert tone="bad" title="Ví này chưa có quyền cấp bằng trên chuỗi">
          Ví này chưa được quản trị viên phê duyệt làm đơn vị cấp bằng trên chuỗi. Chưa có quyền thì giao dịch
          cấp văn bằng sẽ bị sổ đăng ký từ chối.
        </Alert>
      )}

      {stats.data && (
        <>
          <Ledger items={[
            { label: "Còn hiệu lực", value: stats.data.active },
            { label: "Tạm ngưng", value: stats.data.suspended },
            { label: "Đã thu hồi", value: stats.data.revoked },
            { label: "Tổng đã cấp", value: stats.data.total },
          ]} />
          {stats.data.total > 0 && (
            <div className="grid lg:grid-cols-3 gap-4">
              <div className="sheet p-5 min-w-0">
                <h3 className="text-base font-semibold mb-3">Văn bằng cấp theo tháng</h3>
                <MonthlyBars data={stats.data.byMonth} />
              </div>
              <div className="sheet p-5 min-w-0">
                <h3 className="text-base font-semibold mb-3">Theo loại văn bằng</h3>
                <BarList items={stats.data.byType.map((t) => ({ key: String(t.vcType), label: t.label, count: t.count }))} />
              </div>
              <div className="sheet p-5 min-w-0">
                <h3 className="text-base font-semibold mb-3">Tình trạng văn bằng đã cấp</h3>
                <StatusBar counts={stats.data} />
              </div>
            </div>
          )}
        </>
      )}

      <TabBar tabs={visible} active={active} onSelect={select} />

      {active === "cap" && (
        <TabPanel id="cap">
          <div className="space-y-6">
            <GasPanel compact />
            <IssueCard />
          </div>
        </TabPanel>
      )}
      {active === "da-cap" && <TabPanel id="da-cap"><IssuedList onNew={() => select("cap")} /></TabPanel>}
      {active === "uy-quyen" && <TabPanel id="uy-quyen"><DelegationPanel /></TabPanel>}
    </div>
  );
}

interface Delegation {
  canDelegate: boolean;
  delegableMask: number;
  expiresAt: number;
  subIssuers: { address: string; label: string | null; vcTypeMask: number; expiresAt: number; status: string }[];
  source: string;
}

/**
 * Cấp và quản lý sub-issuer qua uỷ quyền (approve_issuer do chính issuer ký).
 *
 * Luật do hợp đồng quyết định, giao diện chỉ dựng sẵn cho đúng:
 *  - loại văn bằng của sub-issuer phải nằm trong phạm vi của mình, không có bit uỷ quyền;
 *  - hạn không vượt hạn của mình (mình có hạn thì sub-issuer bắt buộc có hạn);
 *  - chỉ cấp được cho địa chỉ chưa từng là issuer;
 *  - kèm chứng thư uỷ quyền (CID + hash) — ghim lên IPFS trước khi ký.
 * Sub-issuer mất quyền ngay khi quyền của mình bị tạm ngưng, thu hồi hay hết hạn (M-02).
 */
function DelegationPanel() {
  const qc = useQueryClient();
  const tx = useChainTx();
  const { wallet } = useWallet();
  const info = useQuery({ queryKey: ["issuer", "delegation"], queryFn: () => api.get<Delegation>("/issuer/delegation") });
  const [address, setAddress] = useState("");
  const [mask, setMask] = useState(0);
  const [expiresAt, setExpiresAt] = useState("");
  const [reason, setReason] = useState("");
  // Thao tác gần nhất, để thông báo đúng động từ và hiện tiến trình ở đúng khung.
  const [lastAct, setLastAct] = useState<"approve" | "suspended" | "revoked" | null>(null);

  if (info.isLoading) return <Spinner />;
  if (!info.data) return <Alert tone="bad" title="Không đọc được quyền uỷ quyền">{String(info.error ?? "")}</Alert>;
  const d = info.data;
  const myExpiry = d.expiresAt;
  const expiresUnix = expiresAt ? Math.floor(new Date(expiresAt).getTime() / 1000) : 0;
  const expiryOk = myExpiry === 0 || (expiresUnix !== 0 && expiresUnix <= myExpiry);
  const types = ISSUABLE_VC_TYPES.filter((t) => (d.delegableMask & t.bit) !== 0);

  const approve = () => {
    setLastAct("approve");
    void tx.run({
      fn: ENTRY.approveIssuer,
      args: async () => {
        const doc = {
          type: "VNUDelegationCredential",
          issuer: wallet?.did ?? "",
          issuerAddress: wallet?.address ?? "",
          subject: address.trim(),
          vcTypeMask: mask,
          expiresAt: expiresUnix,
          approvedAt: new Date().toISOString(),
        };
        const { cid } = await api.post<{ cid: string }>("/ipfs/pin", { json: doc, name: `delegation-${address.trim().slice(0, 10)}` });
        return [address.trim(), u64Arg(mask), bytesArg(cid), hashArg(sha3_256Hex(doc)), u64Arg(expiresUnix)];
      },
      index: async (out) => {
        const r = await api.post("/issuer/sub-issuers", { address: address.trim(), vcTypeMask: mask, expiresAt: expiresUnix, txHash: out.hash });
        setAddress(""); setMask(0); setExpiresAt("");
        qc.invalidateQueries({ queryKey: ["issuer", "delegation"] });
        return r;
      },
    });
  };

  const setStatus = (target: string, status: "suspended" | "revoked") => {
    setLastAct(status);
    void tx.run({
      fn: status === "suspended" ? ENTRY.suspendIssuer : ENTRY.revokeIssuer,
      args: [target, bytesArg(reason.trim())],
      index: async (out) => {
        const r = await api.post(`/issuer/sub-issuers/${encodeURIComponent(target)}/status`, { status, reason: reason.trim(), txHash: out.hash });
        setReason("");
        qc.invalidateQueries({ queryKey: ["issuer", "delegation"] });
        return r;
      },
    });
  };

  const statusPhase = lastAct === "suspended" || lastAct === "revoked";

  return (
    <div className="space-y-6">
      <SignSheet tx={tx} phase={statusPhase ? "draft" : undefined}>
        <h2 className="text-lg font-semibold">Uỷ quyền cho đơn vị khác</h2>
        <dl className="mt-3 space-y-1">
          <Row label="Phạm vi được giao">{maskLabel(d.delegableMask)}</Row>
          <Row label="Hạn của bạn">{myExpiry === 0 ? "Vĩnh viễn" : new Date(myExpiry * 1000).toLocaleString("vi-VN")}</Row>
        </dl>
        <div className="mt-5 grid md:grid-cols-2 gap-4">
          <Field label="Địa chỉ ví đơn vị được uỷ quyền (đã đăng ký DID, chưa từng là đơn vị cấp bằng)" value={address} onChange={setAddress} mono placeholder="0x…" />
          <Field label={myExpiry === 0 ? "Hạn (để trống = vĩnh viễn)" : "Hạn (bắt buộc, không vượt hạn của bạn)"} value={expiresAt} type="datetime-local" onChange={setExpiresAt} />
        </div>
        <fieldset className="mt-4 min-w-0">
          <legend className="label mb-2">Loại văn bằng được giao</legend>
          <div className="flex flex-wrap gap-4">
            {types.map((t) => (
              <label key={t.bit} className="flex items-center gap-2">
                <input type="checkbox" className="w-5 h-5" checked={(mask & t.bit) !== 0} onChange={(e) => setMask(e.target.checked ? mask | t.bit : mask & ~t.bit)} />
                {t.label}
              </label>
            ))}
          </div>
        </fieldset>
        {!expiryOk && <div className="mt-3"><Alert tone="warn" title="Hạn không hợp lệ">Đơn vị được uỷ quyền không được có hạn dài hơn hạn uỷ quyền của bạn.</Alert></div>}
        <div className="mt-5 space-y-4">
          <button className="btn-primary" type="button"
            disabled={tx.busy || mask === 0 || address.trim().length < 3 || !expiryOk} onClick={approve}>
            Ký và uỷ quyền
          </button>
          {!statusPhase && <TxProgress tx={tx} okTitle="Đã uỷ quyền" />}
        </div>
      </SignSheet>

      <Section title="Đơn vị được uỷ quyền do bạn cấp" description="Bạn tạm ngưng hoặc thu hồi được; kích hoạt lại thì nhờ quản trị viên.">
        {d.subIssuers.length === 0 ? <Empty title="Chưa uỷ quyền cho đơn vị nào" /> : (
          <div className="space-y-4">
            <SignSheet tx={tx} phase={statusPhase ? undefined : "draft"}>
              <Field label="Lý do (bắt buộc khi tạm ngưng hoặc thu hồi uỷ quyền)" value={reason} onChange={setReason} placeholder="Hết hợp đồng cộng tác" />
              {statusPhase && (
                <div className="mt-4">
                  <TxProgress tx={tx} okTitle={lastAct === "suspended" ? "Đã tạm ngưng uỷ quyền" : "Đã thu hồi uỷ quyền"} />
                </div>
              )}
            </SignSheet>
            <div className="overflow-x-auto">
              <table className="table">
                <thead><tr><th>Địa chỉ</th><th>Phạm vi</th><th>Hạn</th><th>Trạng thái</th><th></th></tr></thead>
                <tbody>
                  {d.subIssuers.map((s) => (
                    <tr key={s.address}>
                      <td><Mono value={s.address} />{s.label && <div className="text-sm text-muted">{s.label}</div>}</td>
                      <td>{maskLabel(s.vcTypeMask)}</td>
                      <td>{s.expiresAt === 0 ? "Vĩnh viễn" : new Date(s.expiresAt * 1000).toLocaleDateString("vi-VN")}</td>
                      <td><RoleStatusBadge status={s.status} /></td>
                      <td className="text-right whitespace-nowrap space-x-2">
                        <button className="btn-secondary" type="button" disabled={tx.busy || reason.trim().length < 2 || s.status !== "active"}
                          onClick={() => setStatus(s.address, "suspended")}>Tạm ngưng uỷ quyền</button>
                        <button className="btn-danger" type="button" disabled={tx.busy || reason.trim().length < 2 || s.status === "revoked"}
                          onClick={() => setStatus(s.address, "revoked")}>Thu hồi uỷ quyền</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Section>
      {d.subIssuers.length > 0 && <ReviewPanel mode="parent" issuers={d.subIssuers} />}
    </div>
  );
}

export interface CredentialForm {
  holderAddress: string; holderDid: string; studentId: string; degreeName: string;
  faculty: string; gpa: string; year: string; vcType: number; expiresAt: string;
}

/**
 * Dựng nội dung văn bằng + các giá trị neo lên chuỗi. Dùng chung cho cấp mới và
 * cấp lại (C3) để hai đường cho ra cùng một cấu trúc; văn bằng cấp lại mang
 * thêm `vnu:replaces` trỏ về văn bằng cũ — liên kết đó cũng nằm trên chuỗi.
 */
function buildCredential(
  wallet: NonNullable<ReturnType<typeof useWallet>["wallet"]>,
  form: CredentialForm,
  replaces: string | null,
) {
  const vcId = `urn:uuid:${crypto.randomUUID()}`;
  const issuedAt = new Date().toISOString();
  const expiresIso = form.expiresAt ? new Date(form.expiresAt).toISOString() : null;
  const expiresUnix = form.expiresAt ? Math.floor(new Date(form.expiresAt).getTime() / 1000) : 0;

  const vc: Record<string, unknown> = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      { vnu: "https://vnu.edu.vn/credentials/v1#" },
    ],
    id: vcId,
    type: ["VerifiableCredential", "VNUDegreeCredential"],
    issuer: wallet.did,
    issuanceDate: issuedAt,
    credentialSubject: {
      id: form.holderDid,
      "vnu:studentId": form.studentId,
      "vnu:degreeName": form.degreeName,
      "vnu:faculty": form.faculty,
      "vnu:gpa": form.gpa,
      "vnu:graduationYear": form.year,
    },
  };
  if (expiresIso) vc.expirationDate = expiresIso;
  if (replaces) vc["vnu:replaces"] = replaces;

  return {
    vcId, issuedAt, expiresIso, expiresUnix, vc,
    contentHash: sha3_256Hex(vc),
    vcIdHash: vcIdHash(vcId),
    proofValue: signMessage(wallet, canonicalize(vc)),
  };
}

function IssueCard() {
  const { wallet } = useWallet();
  const qc = useQueryClient();
  const tx = useChainTx();
  const [onChainId, setOnChainId] = useState<number | null>(null);

  const [form, setForm] = useState<CredentialForm>({
    holderAddress: "", holderDid: "", studentId: "", degreeName: "",
    faculty: "", gpa: "", year: String(new Date().getFullYear()), vcType: 1,
    // Để trống = văn bằng vĩnh viễn. Hợp lý với bằng tốt nghiệp, nhưng thẻ sinh
    // viên và chứng chỉ ngắn hạn thì nên có hạn (F-09).
    expiresAt: "",
  });
  const set = (k: keyof typeof form, v: string | number) => setForm((f) => ({ ...f, [k]: v }));

  const issue = () => {
    if (!wallet) return;
    setOnChainId(null);
    const { vcId, issuedAt, expiresIso, expiresUnix, vc, contentHash, vcIdHash, proofValue } =
      buildCredential(wallet, form, null);
    let cid = "";

    void tx.run({
      fn: ENTRY.issueVc,
      args: async () => {
        if (expiresIso && expiresIso <= issuedAt) {
          throw new Error("Thời điểm hết hạn phải sau thời điểm cấp");
        }
        // P3: nội dung KHÔNG rời trình duyệt dạng rõ — niêm phong cho holder và chính
        // mình rồi chỉ ghim phong bì (P-04: trước đây IPFS giữ toàn văn dạng rõ).
        cid = await sealCredential(vc, vcIdHash, form.holderAddress.trim(), wallet);
        return [
          form.holderAddress.trim(),
          u64Arg(form.vcType),
          hashArg(vcIdHash),
          bytesArg(cid),
          hashArg(contentHash),
          u64Arg(expiresUnix),
        ];
      },
      index: async (out) => {
        // Số hiệu thật do hợp đồng cấp, đọc từ sự kiện trong phản hồi giao dịch.
        // Trường này từng bị ghi cứng bằng 0 vì giao diện không tự gửi giao dịch
        // nên chẳng bao giờ thấy phản hồi.
        const chainId = vcIdFromEvents(out);
        setOnChainId(chainId);
        const r = await api.post<Credential>("/issuer/credentials", {
          vcId,
          onChainVcId: chainId ?? 0,
          holderDid: form.holderDid,
          holderAddress: form.holderAddress.trim(),
          vcType: form.vcType,
          ipfsCid: cid,
          vcIdHash, contentHash, proofValue,
          issuedAt, expiresAt: expiresIso,
          txHash: out.hash,
        });
        setForm((f) => ({
          ...f, holderAddress: "", holderDid: "", studentId: "", degreeName: "", expiresAt: "",
        }));
        qc.invalidateQueries({ queryKey: ["issuer"] });
        return r;
      },
    });
  };

  return (
    <SignSheet tx={tx}>
      <h2 className="text-lg font-semibold">Văn bằng mới</h2>
      <p className="text-muted max-w-prose mt-1">
        Ký bằng khoá riêng trong trình duyệt, lưu nội dung đã mã hoá lên IPFS, rồi ghi lên chuỗi chỉ bằng một lần bấm.
      </p>
      <form className="mt-5 space-y-6" onSubmit={(e) => { e.preventDefault(); issue(); }}>
        <fieldset className="min-w-0">
          <legend className="text-base font-semibold mb-3">Người nhận</legend>
          <div className="grid md:grid-cols-2 gap-4">
            <Field label="Địa chỉ ví người nhận" value={form.holderAddress} mono required
              onChange={(v) => set("holderAddress", v)} placeholder="0x…"
              hint="Người nhận phải đã đăng ký DID, nếu chưa thì sổ đăng ký từ chối." />
            <Field label="DID người nhận" value={form.holderDid} mono required
              onChange={(v) => set("holderDid", v)} placeholder="did:vnu:holder:0x…" />
            <Field label="Mã sinh viên" value={form.studentId} required
              onChange={(v) => set("studentId", v)} placeholder="21020123" />
          </div>
        </fieldset>

        <fieldset className="min-w-0">
          <legend className="text-base font-semibold mb-3">Nội dung văn bằng</legend>
          <div className="grid md:grid-cols-2 gap-4">
            <Field label="Tên văn bằng" value={form.degreeName} required
              onChange={(v) => set("degreeName", v)} placeholder="Cử nhân Công nghệ thông tin" />
            <Field label="Khoa hoặc trường" value={form.faculty}
              onChange={(v) => set("faculty", v)} placeholder="Trường Đại học Công nghệ" />
            <Field label="Điểm trung bình" value={form.gpa}
              onChange={(v) => set("gpa", v)} placeholder="3.42" />
            <Field label="Năm tốt nghiệp" value={form.year} onChange={(v) => set("year", v)} />

            <div>
              <label className="label" htmlFor="vt">Loại văn bằng</label>
              <select id="vt" className="input" value={form.vcType}
                onChange={(e) => set("vcType", Number(e.target.value))}>
                {ISSUABLE_VC_TYPES.map((t) => <option key={t.bit} value={t.bit}>{t.label}</option>)}
              </select>
            </div>

            <div className="md:col-span-2">
              <Field label="Hạn dùng (để trống = vĩnh viễn)" value={form.expiresAt} type="datetime-local"
                onChange={(v) => set("expiresAt", v)}
                hint="Bằng tốt nghiệp thì để trống. Thẻ sinh viên và chứng chỉ ngắn hạn nên đặt hạn." />
            </div>
          </div>
        </fieldset>

        <div className="space-y-4">
          <button className="btn-primary" disabled={tx.busy}>
            {tx.busy ? tx.label : "Ký và cấp văn bằng"}
          </button>
          <TxProgress tx={tx} okTitle="Đã cấp văn bằng" />
          {tx.step === "done" && (
            onChainId !== null ? (
              <Alert tone="ok" title="Số hiệu trên chuỗi">
                Số hiệu văn bằng trên chuỗi: <span className="hex">{onChainId}</span>.
              </Alert>
            ) : (
              <Alert tone="warn" title="Chưa đọc được số hiệu trên chuỗi">
                Văn bằng đã ghi vào chỉ mục nhưng chưa lấy được số hiệu trên chuỗi, thường do đang chạy chế độ không
                nối chuỗi. Thiếu số hiệu này thì sau không thu hồi trên chuỗi được.
              </Alert>
            )
          )}
        </div>
      </form>
    </SignSheet>
  );
}

/** Danh sách văn bằng đã cấp, kèm thao tác tạm ngưng / thu hồi tự ký. */
function IssuedList({ onNew }: { onNew: () => void }) {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [target, setTarget] = useState<Credential | null>(null);
  const [reissuing, setReissuing] = useState<Credential | null>(null);
  const [reason, setReason] = useState("");
  const [kind, setKind] = useState<"revoke" | "suspend">("suspend");

  const list = useQuery({
    queryKey: ["issuer", "credentials"],
    queryFn: () => api.get<Credential[]>("/issuer/credentials"),
  });

  const act = (k: "revoke" | "suspend") => {
    // Số hiệu bắt đầu từ 0: kiểm `== null`, không kiểm truthy (id 0 là falsy).
    if (target?.on_chain_vc_id == null) return;
    setKind(k);
    void tx.run({
      fn: k === "revoke" ? ENTRY.revokeVc : ENTRY.suspendVc,
      args: [u64Arg(target.on_chain_vc_id), bytesArg(reason.trim())],
      index: async (out) => {
        const r = await api.post(
          `/issuer/credentials/${encodeURIComponent(target.vc_id)}/${k}`,
          { reason: reason.trim(), txHash: out.hash },
        );
        setTarget(null); setReason("");
        qc.invalidateQueries({ queryKey: ["issuer"] });
        return r;
      },
    });
  };

  if (list.isLoading) return <Spinner />;
  if (!list.data?.length) {
    return (
      <Empty title="Chưa cấp văn bằng nào"
        hint="Văn bằng bạn cấp sẽ hiện ở đây, kèm nút đổi trạng thái và cấp lại."
        action={<button type="button" className="btn-secondary" onClick={onNew}>Cấp văn bằng mới</button>} />
    );
  }

  const okTitle = kind === "revoke" ? "Đã thu hồi văn bằng" : "Đã tạm ngưng văn bằng";

  return (
    <Section title="Văn bằng đã cấp">
      <div className="overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th>Văn bằng</th><th>Người nhận</th><th>Số hiệu</th>
              <th>Ngày cấp</th><th>Trạng thái</th><th></th>
            </tr>
          </thead>
          <tbody>
            {list.data.map((c) => (
              <tr key={c.vc_id}>
                {/* P3: máy chủ chỉ giữ loại + ngày; tên đầy đủ nằm trong phong bì mã hoá. */}
                <td className="font-semibold">{maskLabel(c.vc_type)}</td>
                <td><Mono value={c.holder_did} /></td>
                <td className="hex">{c.on_chain_vc_id ?? "không có"}</td>
                <td>{new Date(c.issued_at).toLocaleDateString("vi-VN")}</td>
                <td><StatusBadge status={c.status} /></td>
                <td className="text-right whitespace-nowrap space-x-1">
                  {c.replaced_by_vc_id && <Badge tone="muted">đã cấp lại</Badge>}
                  {c.status === "active" && !c.replaced_by_vc_id && c.on_chain_vc_id != null && (
                    <button type="button" className="btn-quiet"
                      onClick={() => { setReissuing(c); setTarget(null); }}>
                      Cấp lại
                    </button>
                  )}
                  {c.status !== "revoked" && (
                    <button type="button" className="btn-quiet"
                      onClick={() => { setTarget(c); setReissuing(null); setReason(""); tx.reset(); }}>
                      Đổi trạng thái
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {target && (
        <SignSheet tx={tx} className="mt-5">
          <h3 className="text-base font-semibold">Đổi trạng thái văn bằng</h3>
          <p className="mt-2">
            Văn bằng <Mono value={target.vc_id} />, số hiệu trên chuỗi{" "}
            <span className="hex">{target.on_chain_vc_id ?? "không có"}</span>.
          </p>

          {target.on_chain_vc_id == null ? (
            <div className="mt-4">
              <Alert tone="warn" title="Không thao tác trên chuỗi được">
                Bản ghi này không có số hiệu trên chuỗi (cấp từ thời giao diện còn ghi cứng số 0), nên
                không thu hồi hay tạm ngưng trên chuỗi được.
              </Alert>
            </div>
          ) : (
            <div className="mt-4 space-y-4">
              <Field label="Lý do (ghi vào nhật ký kiểm toán)" value={reason} onChange={setReason}
                placeholder="Cấp nhầm thông tin" />
              <div className="flex flex-wrap gap-3">
                <button className="btn-secondary" type="button"
                  disabled={reason.trim().length < 2 || tx.busy || target.status !== "active"}
                  onClick={() => act("suspend")}>Ký và tạm ngưng</button>
                <button className="btn-danger" type="button"
                  disabled={reason.trim().length < 2 || tx.busy}
                  onClick={() => act("revoke")}>Ký và thu hồi</button>
                <button className="btn-quiet" type="button"
                  onClick={() => setTarget(null)}>Đóng</button>
              </div>
              <p className="text-sm text-muted">
                Thu hồi là vĩnh viễn; tạm ngưng thì quản trị viên kích hoạt lại được. Đơn vị cấp bằng <strong>không</strong> tự
                kích hoạt lại được văn bằng đã tạm ngưng, để không ai tự ngưng rồi tự bật mà né kiểm toán.
              </p>
              <TxProgress tx={tx} okTitle={okTitle} />
            </div>
          )}
        </SignSheet>
      )}

      {!target && <div className="mt-4"><TxProgress tx={tx} okTitle={okTitle} /></div>}
      {reissuing && <ReissuePanel old={reissuing} onClose={() => setReissuing(null)} />}
    </Section>
  );
}

interface Migration { old_address: string; new_address: string; old_did: string; new_did: string; note: string }

/**
 * Cấp lại văn bằng (reissue_vc, C3): MỘT giao dịch cấp văn bằng mới, thu hồi văn
 * bằng cũ với lý do "replaced" và ghi liên kết cũ → mới trên chuỗi. Người xác
 * minh văn bằng cũ sẽ thấy "đã được thay bằng …".
 *
 * Holder mất khoá (P4.2): admin khoá/thu hồi DID cũ và ghi nhận ví mới; khi đó
 * bảng này đề xuất ví mới. Hợp đồng chỉ cho đổi holder khi DID cũ không còn
 * hoạt động — issuer không chuyển được văn bằng của một người đang dùng ví.
 */
function ReissuePanel({ old, onClose }: { old: Credential; onClose: () => void }) {
  const { wallet } = useWallet();
  const qc = useQueryClient();
  const tx = useChainTx();
  const [form, setForm] = useState<CredentialForm>({
    holderAddress: old.holder_address, holderDid: old.holder_did,
    studentId: "", degreeName: "", faculty: "", gpa: "", year: "", vcType: old.vc_type, expiresAt: "",
  });
  const set = (k: keyof CredentialForm, v: string) => setForm((f) => ({ ...f, [k]: v }));
  // P3: điền sẵn bằng cách GIẢI MÃ văn bằng cũ — issuer đã cấp là một người nhận của
  // phong bì. Issuer cha (không phải người nhận) thì nhập lại từ hồ sơ gốc.
  const opened = useQuery({
    queryKey: ["issuer", "open", old.vc_id],
    queryFn: () => openCredential(old, wallet!),
    enabled: !!wallet, retry: false, staleTime: Infinity,
  });
  useEffect(() => {
    const subj = (opened.data?.plain.credentialSubject ?? null) as Record<string, unknown> | null;
    if (!subj) return;
    setForm((f) => ({
      ...f, studentId: String(subj["vnu:studentId"] ?? ""), degreeName: String(subj["vnu:degreeName"] ?? ""),
      faculty: String(subj["vnu:faculty"] ?? ""), gpa: String(subj["vnu:gpa"] ?? ""),
      year: String(subj["vnu:graduationYear"] ?? ""),
    }));
  }, [opened.data]);
  const migration = useQuery({
    queryKey: ["issuer", "migration", old.holder_address],
    queryFn: () => api.get<Migration | null>(`/issuer/holders/${old.holder_address}/migration`),
  });
  const movedTo = migration.data ?? null;
  const changingHolder = form.holderAddress.trim().toLowerCase() !== old.holder_address.toLowerCase();

  const reissue = () => {
    if (!wallet || old.on_chain_vc_id == null) return;
    const built = buildCredential(wallet, form, old.vc_id);
    let cid = "";
    void tx.run({
      fn: ENTRY.reissueVc,
      args: async () => {
        cid = await sealCredential(built.vc, built.vcIdHash, form.holderAddress.trim(), wallet);
        return [
          u64Arg(old.on_chain_vc_id!),
          form.holderAddress.trim(),
          u64Arg(form.vcType),
          hashArg(built.vcIdHash),
          bytesArg(cid),
          hashArg(built.contentHash),
          u64Arg(built.expiresUnix),
        ];
      },
      index: async (out) => {
        const r = await api.post<Credential>(`/issuer/credentials/${encodeURIComponent(old.vc_id)}/reissue`, {
          vcId: built.vcId,
          onChainVcId: vcIdFromEvents(out) ?? 0,
          holderDid: form.holderDid.trim(),
          holderAddress: form.holderAddress.trim(),
          vcType: form.vcType,
          ipfsCid: cid,
          vcIdHash: built.vcIdHash, contentHash: built.contentHash, proofValue: built.proofValue,
          issuedAt: built.issuedAt, expiresAt: built.expiresIso,
          txHash: out.hash,
        });
        qc.invalidateQueries({ queryKey: ["issuer"] });
        return r;
      },
    });
  };

  return (
    <SignSheet tx={tx} className="mt-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-base font-semibold">Cấp lại văn bằng</h3>
          <p className="mt-2 max-w-prose">
            Cấp lại văn bằng <Mono value={old.vc_id} />, số hiệu <span className="hex">{old.on_chain_vc_id}</span>.
            Văn bằng cũ sẽ bị thu hồi với lý do đã được thay thế, trong cùng giao dịch.
          </p>
        </div>
        <button type="button" className="btn-quiet" onClick={onClose}>Đóng</button>
      </div>

      <div className="mt-4 space-y-4">
        {opened.isError && (
          <Alert tone="warn" title="Không giải mã được văn bằng cũ">
            Ví này không nằm trong danh sách người đọc của văn bằng cũ (thường gặp khi bạn là đơn vị
            cấp trên). Hãy nhập lại nội dung từ hồ sơ gốc.
          </Alert>
        )}
        {opened.data && opened.data.problems.length > 0 && (
          <Alert tone="bad" title="Văn bằng cũ không khớp bản neo">{opened.data.problems.join("; ")}</Alert>
        )}
        {movedTo && !changingHolder && (
          <Alert tone="info" title="Người học đã chuyển sang ví mới">
            Quản trị viên đã ghi nhận ví <Mono value={movedTo.new_address} /> thay cho ví cũ ({movedTo.note}).{" "}
            <button type="button" className="link"
              onClick={() => setForm((f) => ({ ...f, holderAddress: movedTo.new_address, holderDid: movedTo.new_did }))}>
              Cấp sang ví mới
            </button>
          </Alert>
        )}

        <div className="grid md:grid-cols-2 gap-4">
          <Field label="Địa chỉ ví người nhận" value={form.holderAddress} mono required
            onChange={(v) => set("holderAddress", v)}
            hint={changingHolder ? "Đổi ví chỉ được khi DID của ví cũ đã bị khoá hoặc thu hồi." : undefined} />
          <Field label="DID người nhận" value={form.holderDid} mono required onChange={(v) => set("holderDid", v)} />
          <Field label="Mã sinh viên" value={form.studentId} required onChange={(v) => set("studentId", v)} />
          <Field label="Tên văn bằng" value={form.degreeName} required onChange={(v) => set("degreeName", v)} />
          <Field label="Khoa hoặc trường" value={form.faculty} onChange={(v) => set("faculty", v)} />
          <Field label="Điểm trung bình" value={form.gpa} onChange={(v) => set("gpa", v)} />
          <Field label="Năm tốt nghiệp" value={form.year} onChange={(v) => set("year", v)} />
          <Field label="Loại văn bằng (giữ nguyên)" value={maskLabel(form.vcType)} onChange={() => {}} disabled />
          <div className="md:col-span-2">
            <Field label="Hạn dùng (để trống = vĩnh viễn)" value={form.expiresAt} type="datetime-local"
              onChange={(v) => set("expiresAt", v)} />
          </div>
        </div>
        <button className="btn-primary" type="button" disabled={tx.busy || !wallet} onClick={reissue}>
          {tx.busy ? tx.label : "Ký và cấp lại"}
        </button>
        <TxProgress tx={tx} okTitle="Đã cấp lại văn bằng" />
      </div>
    </SignSheet>
  );
}
