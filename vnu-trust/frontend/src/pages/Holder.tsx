import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { api, type Credential, type ShareToken } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { canonicalize, signMessage, sha3_256Hex } from "../lib/wallet";
import { Card, StatusBadge, Alert, Spinner, Empty, Mono, Badge } from "../components/ui";

export default function Holder() {
  const { wallet } = useWallet();
  const qc = useQueryClient();
  const [picked, setPicked] = useState<string[]>([]);
  const [ttl, setTtl] = useState(3600);
  const [qr, setQr] = useState<{ url: string; link: string; expiresAt: string } | null>(null);
  const [err, setErr] = useState("");

  const creds = useQuery({
    queryKey: ["holder", "credentials"],
    queryFn: () => api.get<Credential[]>("/holder/credentials"),
  });
  const shares = useQuery({
    queryKey: ["holder", "shares"],
    queryFn: () => api.get<ShareToken[]>("/holder/shares"),
  });

  const share = useMutation({
    mutationFn: async () => {
      if (!wallet) throw new Error("Ví chưa mở");
      const selected = (creds.data ?? []).filter((c) => picked.includes(c.vc_id));

      const vp = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        type: ["VerifiablePresentation"],
        holder: wallet.did,
        verifiableCredential: selected.map((c) => c.vc_json),
        created: new Date().toISOString(),
      };

      // Ký ngay trong trình duyệt — khoá riêng không rời khỏi máy.
      const proofValue = signMessage(wallet, canonicalize(vp));
      const vpHash = sha3_256Hex(vp);
      const { cid } = await api.post<{ cid: string }>("/ipfs/pin", { json: vp, name: `vp-${Date.now()}` });

      return api.post<{ vp: unknown; share: { token: string; expiresAt: string } }>(
        "/holder/presentations",
        {
          vpId: `urn:uuid:${crypto.randomUUID()}`,
          verifierDid: null,
          vcIds: picked,
          ipfsCid: cid,
          vpHash,
          proofValue,
          challenge: null,
          ttlSeconds: ttl,
        },
      );
    },
    onSuccess: async (res) => {
      const link = `${location.origin}/verify/${res.share.token}`;
      setQr({ url: await QRCode.toDataURL(link, { width: 320, margin: 1 }), link, expiresAt: res.share.expiresAt });
      setPicked([]);
      setErr("");
      qc.invalidateQueries({ queryKey: ["holder", "shares"] });
    },
    onError: (e) => setErr((e as Error).message),
  });

  const revoke = useMutation({
    mutationFn: (token: string) => api.del(`/holder/shares/${token}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["holder", "shares"] }),
  });

  if (creds.isLoading) return <Spinner label="Đang tải văn bằng của bạn…" />;

  const active = (creds.data ?? []).filter((c) => (c.effective?.status ?? c.status) === "active");

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-ink-900">Văn bằng của tôi</h1>
        <p className="text-sm text-ink-600 mt-1">
          {active.length} văn bằng đang hiệu lực trên tổng số {creds.data?.length ?? 0}.
        </p>
      </header>

      {creds.data?.length === 0 ? (
        <Card><Empty title="Chưa có văn bằng nào"
          hint="Khi đơn vị đào tạo cấp bằng cho DID của bạn, văn bằng sẽ hiện ở đây." /></Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {creds.data!.map((c) => {
            const st = c.effective?.status ?? c.status;
            const selectable = st === "active";
            return (
              <article key={c.vc_id}
                className={`card p-5 transition ${picked.includes(c.vc_id) ? "ring-2 ring-brand-400" : ""}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="font-bold text-ink-900 truncate">
                      {String((c.vc_json as Record<string, Record<string, unknown>>)?.credentialSubject?.["vnu:degreeName"]
                        ?? (c.vc_json as Record<string, unknown>)?.name ?? "Văn bằng")}
                    </h3>
                    <p className="text-xs text-ink-500 mt-1">
                      Cấp ngày {new Date(c.issued_at).toLocaleDateString("vi-VN")}
                    </p>
                  </div>
                  <StatusBadge status={st} />
                </div>

                {c.effective?.drift && (
                  <div className="mt-3">
                    <Alert tone="warn" title="Lệch trạng thái">
                      Trạng thái trên chuỗi khác với dữ liệu ứng dụng. Giá trị hiển thị lấy theo chuỗi.
                    </Alert>
                  </div>
                )}

                <dl className="mt-4 space-y-2 text-xs">
                  <div className="flex gap-2"><dt className="text-ink-400 w-20 shrink-0">Đơn vị cấp</dt>
                    <dd><Mono value={c.issuer_did} /></dd></div>
                  <div className="flex gap-2"><dt className="text-ink-400 w-20 shrink-0">IPFS</dt>
                    <dd><Mono value={c.ipfs_cid} /></dd></div>
                  <div className="flex gap-2"><dt className="text-ink-400 w-20 shrink-0">Giao dịch</dt>
                    <dd><Mono value={c.tx_hash} /></dd></div>
                </dl>

                <label className={`mt-4 flex items-center gap-2 text-sm ${selectable ? "cursor-pointer" : "opacity-50"}`}>
                  <input type="checkbox" disabled={!selectable} checked={picked.includes(c.vc_id)}
                    onChange={(e) => setPicked((p) =>
                      e.target.checked ? [...p, c.vc_id] : p.filter((x) => x !== c.vc_id))} />
                  {selectable ? "Chọn để chia sẻ" : "Không thể chia sẻ khi chưa hiệu lực"}
                </label>
              </article>
            );
          })}
        </div>
      )}

      {picked.length > 0 && (
        <Card title={`Chia sẻ ${picked.length} văn bằng`}
          subtitle="Tạo mã QR có thời hạn. Người nhận chỉ xem được đúng những gì bạn chọn.">
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label className="label" htmlFor="ttl">Thời hạn</label>
              <select id="ttl" className="input !w-44" value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
                <option value={900}>15 phút</option>
                <option value={3600}>1 giờ</option>
                <option value={86400}>1 ngày</option>
                <option value={604800}>7 ngày</option>
              </select>
            </div>
            <button className="btn-primary" disabled={share.isPending} onClick={() => share.mutate()}>
              {share.isPending ? "Đang tạo…" : "Tạo mã chia sẻ"}
            </button>
          </div>
          {err && <div className="mt-3"><Alert tone="bad">{err}</Alert></div>}
        </Card>
      )}

      {qr && (
        <Card title="Mã chia sẻ đã sẵn sàng">
          <div className="flex flex-col sm:flex-row gap-6 items-start">
            <img src={qr.url} alt="Mã QR chia sẻ văn bằng" className="rounded-xl border border-ink-200" width={220} />
            <div className="min-w-0 space-y-3">
              <p className="text-sm text-ink-600">Đưa mã này cho bên cần xác minh. Hết hạn lúc{" "}
                <strong>{new Date(qr.expiresAt).toLocaleString("vi-VN")}</strong>.</p>
              <Mono value={qr.link} truncate={false} />
              <button className="btn-ghost" onClick={() => navigator.clipboard?.writeText(qr.link)}>
                Sao chép liên kết
              </button>
            </div>
          </div>
        </Card>
      )}

      <Card title="Liên kết đã chia sẻ" subtitle="Bạn có thể thu hồi bất cứ lúc nào">
        {shares.data?.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-ink-400">
                <tr><th className="py-2">Mã</th><th>Hết hạn</th><th>Lượt xem</th><th>Trạng thái</th><th></th></tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {shares.data.map((s) => {
                  const expired = new Date(s.expires_at).getTime() <= Date.now();
                  return (
                    <tr key={s.token}>
                      <td className="py-2.5"><Mono value={s.token} /></td>
                      <td className="text-ink-600">{new Date(s.expires_at).toLocaleString("vi-VN")}</td>
                      <td className="tabular-nums text-ink-600">{s.view_count}</td>
                      <td>{s.revoked_at ? <Badge tone="bad">Đã thu hồi</Badge>
                        : expired ? <Badge tone="muted">Hết hạn</Badge> : <Badge tone="ok">Đang hoạt động</Badge>}</td>
                      <td className="text-right">
                        {!s.revoked_at && !expired && (
                          <button className="text-rose-600 text-xs font-semibold hover:underline"
                            onClick={() => revoke.mutate(s.token)}>Thu hồi</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Chưa chia sẻ lần nào" hint="Chọn văn bằng ở trên để tạo mã QR." />
        )}
      </Card>
    </div>
  );
}
