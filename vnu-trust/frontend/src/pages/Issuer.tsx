import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Credential } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { useChainTx, useMe } from "../hooks/useChain";
import { canonicalize, signMessage, sha3_256Hex } from "../lib/wallet";
import { ENTRY, bytesArg, hashArg, u64Arg, vcIdFromEvents } from "../lib/chain";
import { ISSUABLE_VC_TYPES, maskLabel } from "../lib/constants";
import { Card, StatusBadge, Alert, Spinner, Empty, Mono, Stat, Field, Badge } from "../components/ui";
import { TabBar, useTabs } from "../components/Tabs";
import TxProgress from "../components/ChainTx";
import GasPanel from "../components/GasPanel";
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
  const me = useMe();
  const stats = useQuery({ queryKey: ["issuer", "stats"], queryFn: () => api.get<Stats>("/issuer/stats") });

  const { active, select, visible } = useTabs([
    { id: "cap", label: "Cấp văn bằng" },
    { id: "da-cap", label: "Văn bằng đã cấp", count: stats.data?.total },
    // Chỉ issuer có bit uỷ quyền (do root cấp) mới cấp được sub-issuer.
    { id: "uy-quyen", label: "Uỷ quyền", hidden: !me.data?.onChain.canDelegate },
  ]);

  const on = me.data?.onChain;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-ink-900">Đơn vị cấp bằng</h1>
        <p className="text-sm text-ink-600 mt-1">Cấp và quản lý văn bằng đã phát hành.</p>
      </header>

      {on && !on.hasActiveDid && (
        <Alert tone="warn" title="Ví này chưa đăng ký DID">
          Hợp đồng kiểm DID của <strong>cả</strong> đơn vị cấp lẫn người nhận trước khi cho cấp
          văn bằng. Sang <Link className="underline" to="/account">Danh tính &amp; gas</Link> để
          đăng ký trước.
        </Alert>
      )}
      {on && on.hasActiveDid && !on.isActiveIssuer && (
        <Alert tone="bad" title="Ví này chưa có quyền issuer trên chuỗi">
          Quyền cấp bằng do quản trị viên phê duyệt bằng{" "}
          <span className="mono">authority::approve_issuer</span>. Chưa có quyền thì giao dịch
          cấp văn bằng sẽ bị hợp đồng từ chối.
        </Alert>
      )}

      {stats.data && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <Stat label="Đang hiệu lực" value={stats.data.active} />
            <Stat label="Tạm ngưng" value={stats.data.suspended} />
            <Stat label="Đã thu hồi" value={stats.data.revoked} />
            <Stat label="Tổng đã cấp" value={stats.data.total} />
          </div>
          {stats.data.total > 0 && (
            <div className="grid lg:grid-cols-3 gap-4">
              <Card title="Văn bằng cấp theo tháng" className="lg:col-span-2">
                <MonthlyBars data={stats.data.byMonth} />
              </Card>
              <Card title="Theo loại văn bằng">
                <BarList items={stats.data.byType.map((t) => ({ key: String(t.vcType), label: t.label, count: t.count }))} />
              </Card>
              <Card title="Tình trạng văn bằng đã cấp" className="lg:col-span-3">
                <StatusBar counts={stats.data} />
              </Card>
            </div>
          )}
        </>
      )}

      <TabBar tabs={visible} active={active} onSelect={select} />

      {active === "cap" && (
        <>
          <GasPanel />
          <IssueCard />
        </>
      )}
      {active === "da-cap" && <IssuedList />}
      {active === "uy-quyen" && <DelegationPanel />}
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

  if (info.isLoading) return <Spinner />;
  if (!info.data) return <Alert tone="bad" title="Không đọc được quyền uỷ quyền">{String(info.error ?? "")}</Alert>;
  const d = info.data;
  const myExpiry = d.expiresAt;
  const expiresUnix = expiresAt ? Math.floor(new Date(expiresAt).getTime() / 1000) : 0;
  const expiryOk = myExpiry === 0 || (expiresUnix !== 0 && expiresUnix <= myExpiry);
  const types = ISSUABLE_VC_TYPES.filter((t) => (d.delegableMask & t.bit) !== 0);

  const approve = () =>
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

  const setStatus = (target: string, status: "suspended" | "revoked") =>
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

  return (
    <div className="space-y-6">
      <Card title="Cấp sub-issuer"
        subtitle={`Phạm vi được giao: ${maskLabel(d.delegableMask)} · Hạn của bạn: ${myExpiry === 0 ? "vĩnh viễn" : new Date(myExpiry * 1000).toLocaleString("vi-VN")}`}>
        <div className="grid sm:grid-cols-2 gap-4">
          <Field label="Địa chỉ ví sub-issuer (đã đăng ký DID, chưa từng là issuer)" value={address} onChange={setAddress} mono placeholder="0x…" />
          <Field label={myExpiry === 0 ? "Hạn (để trống = vĩnh viễn)" : "Hạn (bắt buộc, không vượt hạn của bạn)"} value={expiresAt} type="datetime-local" onChange={setExpiresAt} />
        </div>
        <div className="mt-4 flex flex-wrap gap-4">
          {types.map((t) => (
            <label key={t.bit} className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={(mask & t.bit) !== 0} onChange={(e) => setMask(e.target.checked ? mask | t.bit : mask & ~t.bit)} />
              {t.label}
            </label>
          ))}
        </div>
        {!expiryOk && <div className="mt-3"><Alert tone="warn" title="Hạn không hợp lệ">Sub-issuer không được có hạn dài hơn hạn uỷ quyền của bạn.</Alert></div>}
        <button className="btn-primary mt-4" type="button"
          disabled={tx.busy || mask === 0 || address.trim().length < 3 || !expiryOk} onClick={approve}>
          Ký &amp; cấp sub-issuer
        </button>
      </Card>

      <Card title="Sub-issuer do bạn cấp" subtitle="Bạn tạm ngưng hoặc thu hồi được; kích hoạt lại thì nhờ quản trị viên.">
        {d.subIssuers.length === 0 ? <Empty title="Chưa cấp sub-issuer nào" /> : (
          <>
            <Field label="Lý do (bắt buộc khi tạm ngưng / thu hồi)" value={reason} onChange={setReason} placeholder="Hết hợp đồng cộng tác" />
            <table className="w-full text-sm mt-4">
              <thead><tr className="text-left text-ink-500"><th>Địa chỉ</th><th>Phạm vi</th><th>Hạn</th><th>Trạng thái</th><th /></tr></thead>
              <tbody>
                {d.subIssuers.map((s) => (
                  <tr key={s.address} className="border-t border-ink-100">
                    <td className="py-2"><Mono value={s.address} />{s.label && <div className="text-xs text-ink-500">{s.label}</div>}</td>
                    <td>{maskLabel(s.vcTypeMask)}</td>
                    <td>{s.expiresAt === 0 ? "Vĩnh viễn" : new Date(s.expiresAt * 1000).toLocaleDateString("vi-VN")}</td>
                    <td><Badge tone={s.status === "active" ? "ok" : s.status === "suspended" ? "warn" : "muted"}>{s.status}</Badge></td>
                    <td className="text-right space-x-2 whitespace-nowrap">
                      <button className="btn-ghost" type="button" disabled={tx.busy || reason.trim().length < 2 || s.status !== "active"}
                        onClick={() => setStatus(s.address, "suspended")}>Tạm ngưng</button>
                      <button className="btn-danger" type="button" disabled={tx.busy || reason.trim().length < 2 || s.status === "revoked"}
                        onClick={() => setStatus(s.address, "revoked")}>Thu hồi</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </Card>
      <TxProgress tx={tx} okTitle="Đã cập nhật uỷ quyền" />
    </div>
  );
}

function IssueCard() {
  const { wallet } = useWallet();
  const qc = useQueryClient();
  const tx = useChainTx();
  const [onChainId, setOnChainId] = useState<number | null>(null);

  const [form, setForm] = useState({
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

    const contentHash = sha3_256Hex(vc);
    const vcIdHash = sha3_256Hex(vcId);
    const proofValue = signMessage(wallet, canonicalize(vc));
    let cid = "";

    void tx.run({
      fn: ENTRY.issueVc,
      args: async () => {
        if (expiresIso && expiresIso <= issuedAt) {
          throw new Error("Thời điểm hết hạn phải sau thời điểm cấp");
        }
        const pinned = await api.post<{ cid: string }>("/ipfs/pin", {
          // Tên pin trung tính: Pinata lưu tên này làm siêu dữ liệu công khai với
          // chủ tài khoản — "vc-<MSSV>" từng làm lộ mã sinh viên (P-04).
          json: vc, name: `vc-${vcId.slice(-12)}`,
        });
        cid = pinned.cid;
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
          vcIdHash, contentHash, proofValue, vcJson: vc,
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
    <Card title="Cấp văn bằng mới"
      subtitle="Ký bằng khoá riêng trong trình duyệt, ghim lên IPFS, rồi neo lên chuỗi — một lần bấm.">
      <form className="grid sm:grid-cols-2 gap-4" onSubmit={(e) => { e.preventDefault(); issue(); }}>
        <Field label="Địa chỉ ví người nhận" value={form.holderAddress} mono required
          onChange={(v) => set("holderAddress", v)} placeholder="0x…"
          hint="Người nhận phải đã đăng ký DID — hợp đồng từ chối nếu chưa." />
        <Field label="DID người nhận" value={form.holderDid} mono required
          onChange={(v) => set("holderDid", v)} placeholder="did:vnu:holder:0x…" />
        <Field label="Mã sinh viên" value={form.studentId} required
          onChange={(v) => set("studentId", v)} placeholder="21020123" />
        <Field label="Tên văn bằng" value={form.degreeName} required
          onChange={(v) => set("degreeName", v)} placeholder="Cử nhân Công nghệ thông tin" />
        <Field label="Khoa / Trường" value={form.faculty}
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

        <div className="sm:col-span-2">
          <Field label="Hạn dùng (để trống = vĩnh viễn)" value={form.expiresAt} type="datetime-local"
            onChange={(v) => set("expiresAt", v)}
            hint="Bằng tốt nghiệp thì để trống. Thẻ sinh viên và chứng chỉ ngắn hạn nên đặt hạn." />
        </div>

        <div className="sm:col-span-2 space-y-4">
          <button className="btn-primary" disabled={tx.busy}>
            {tx.busy ? tx.label : "Ký & cấp văn bằng"}
          </button>
          <TxProgress tx={tx} okTitle="Đã cấp văn bằng" />
          {tx.step === "done" && (
            onChainId !== null ? (
              <Alert tone="ok" title="Số hiệu trên chuỗi">
                Hợp đồng cấp số <span className="mono">{onChainId}</span> cho văn bằng này (đọc từ
                sự kiện <span className="mono">VCIssuedEvent</span>).
              </Alert>
            ) : (
              <Alert tone="warn" title="Chưa đọc được số hiệu trên chuỗi">
                Văn bằng đã ghi vào chỉ mục nhưng không lấy được{" "}
                <span className="mono">VCIssuedEvent</span> — thường là do đang chạy chế độ không
                nối chuỗi. Không có số hiệu này thì sau không thu hồi trên chuỗi được.
              </Alert>
            )
          )}
        </div>
      </form>
    </Card>
  );
}

/** Danh sách văn bằng đã cấp, kèm thao tác tạm ngưng / thu hồi tự ký. */
function IssuedList() {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [target, setTarget] = useState<Credential | null>(null);
  const [reason, setReason] = useState("");

  const list = useQuery({
    queryKey: ["issuer", "credentials"],
    queryFn: () => api.get<Credential[]>("/issuer/credentials"),
  });

  const act = (kind: "revoke" | "suspend") => {
    if (!target?.on_chain_vc_id) return;
    void tx.run({
      fn: kind === "revoke" ? ENTRY.revokeVc : ENTRY.suspendVc,
      args: [u64Arg(target.on_chain_vc_id), bytesArg(reason.trim())],
      index: async (out) => {
        const r = await api.post(
          `/issuer/credentials/${encodeURIComponent(target.vc_id)}/${kind}`,
          { reason: reason.trim(), txHash: out.hash },
        );
        setTarget(null); setReason("");
        qc.invalidateQueries({ queryKey: ["issuer"] });
        return r;
      },
    });
  };

  if (list.isLoading) return <Card><Spinner /></Card>;
  if (!list.data?.length) return <Card><Empty title="Chưa cấp văn bằng nào" /></Card>;

  return (
    <Card title="Văn bằng đã cấp">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase tracking-wide text-ink-400">
            <tr>
              <th className="py-2">Văn bằng</th><th>Người nhận</th><th>Số hiệu</th>
              <th>Ngày cấp</th><th>Trạng thái</th><th></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-100">
            {list.data.map((c) => (
              <tr key={c.vc_id}>
                <td className="py-2.5 font-medium text-ink-800">
                  {String((c.vc_json as Record<string, Record<string, unknown>>)
                    ?.credentialSubject?.["vnu:degreeName"] ?? "—")}
                </td>
                <td><Mono value={c.holder_did} /></td>
                <td className="mono text-ink-600">{c.on_chain_vc_id ?? "—"}</td>
                <td className="text-ink-600">{new Date(c.issued_at).toLocaleDateString("vi-VN")}</td>
                <td><StatusBadge status={c.status} /></td>
                <td className="text-right">
                  {c.status !== "revoked" && (
                    <button type="button" className="btn-ghost !px-3 !py-1.5 text-xs"
                      onClick={() => { setTarget(c); setReason(""); tx.reset(); }}>
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
        <div className="mt-5 rounded-xl border border-ink-200 bg-ink-50/60 p-4 space-y-4">
          <p className="text-sm text-ink-700">
            Văn bằng <Mono value={target.vc_id} /> · số hiệu trên chuỗi{" "}
            <span className="mono">{target.on_chain_vc_id ?? "không có"}</span>
          </p>

          {!target.on_chain_vc_id ? (
            <Alert tone="warn" title="Không thao tác trên chuỗi được">
              Bản ghi này không có số hiệu on-chain (cấp từ thời giao diện còn ghi cứng số 0), nên
              không gọi được <span className="mono">revoke_vc</span>.
            </Alert>
          ) : (
            <>
              <Field label="Lý do (ghi vào nhật ký kiểm toán)" value={reason} onChange={setReason}
                placeholder="Cấp nhầm thông tin" />
              <div className="flex flex-wrap gap-3">
                <button className="btn-ghost" type="button"
                  disabled={reason.trim().length < 2 || tx.busy || target.status !== "active"}
                  onClick={() => act("suspend")}>Tạm ngưng</button>
                <button className="btn-danger" type="button"
                  disabled={reason.trim().length < 2 || tx.busy}
                  onClick={() => act("revoke")}>Thu hồi</button>
                <button className="btn-ghost !text-ink-500" type="button"
                  onClick={() => setTarget(null)}>Đóng</button>
              </div>
              <p className="text-xs text-ink-400">
                Đơn vị cấp bằng <strong>không</strong> tự kích hoạt lại được văn bằng đã tạm ngưng —
                việc đó chỉ admin làm, để không ai tự ngưng rồi tự bật né kiểm toán.
              </p>
            </>
          )}
        </div>
      )}

      <div className="mt-4"><TxProgress tx={tx} okTitle="Đã đổi trạng thái văn bằng" /></div>
    </Card>
  );
}
