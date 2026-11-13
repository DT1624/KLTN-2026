import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { api, type Credential, type ShareToken } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { canonicalize, signMessage, sha3_256Hex } from "../lib/wallet";
import { openCredential, sealPresentation, type OpenedCredential } from "../lib/vcStore";
import { maskLabel } from "../lib/constants";
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
  // P3: máy chủ chỉ giữ siêu dữ liệu; trình duyệt giải mã từng phong bì bằng khoá riêng
  // đang mở trong ví rồi TỰ KIỂM với hash neo trên chuỗi.
  const ids = (creds.data ?? []).map((c) => c.vc_id).join(",");
  const opened = useQuery({
    queryKey: ["holder", "opened", ids, wallet?.address],
    queryFn: async () => {
      const out = new Map<string, OpenedCredential | { error: string }>();
      await Promise.all((creds.data ?? []).map(async (c) => {
        try { out.set(c.vc_id, await openCredential(c, wallet!)); }
        catch (e) { out.set(c.vc_id, { error: (e as Error).message }); }
      }));
      return out;
    },
    enabled: !!wallet && !!creds.data?.length, staleTime: Infinity,
  });
  const plainOf = (id: string) => {
    const o = opened.data?.get(id);
    return o && "plain" in o && o.problems.length === 0 ? o.plain : null;
  };

  const share = useMutation({
    mutationFn: async () => {
      if (!wallet) throw new Error("Ví chưa mở");
      const selected = (creds.data ?? []).filter((c) => picked.includes(c.vc_id));

      const vp = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        type: ["VerifiablePresentation"],
        holder: wallet.did,
        verifiableCredential: selected.map((c) => {
          const plain = plainOf(c.vc_id);
          if (!plain) throw new Error(`Chưa giải mã được (hoặc văn bằng lỗi): ${c.vc_id}`);
          return plain;
        }),
        created: new Date().toISOString(),
      };

      // Ký ngay trong trình duyệt — khoá riêng không rời khỏi máy.
      const proofValue = signMessage(wallet, canonicalize(vp));
      const vpHash = sha3_256Hex(vp);
      // P3: chỉ ghim bản trình bày ĐÃ MÃ HOÁ; khoá nằm trong fragment liên kết, máy chủ không nhận.
      const { cid, key } = await sealPresentation(vp);

      const res = await api.post<{ vp: unknown; share: { token: string; expiresAt: string } }>(
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
      return { ...res, key };
    },
    onSuccess: async (res) => {
      // Trình duyệt KHÔNG gửi phần sau dấu # lên máy chủ — khoá giải mã chỉ đi theo liên kết.
      const link = `${location.origin}/verify/${res.share.token}#k=${res.key}`;
      setQr({ url: await QRCode.toDataURL(link, { width: 320, margin: 1 }), link, expiresAt: res.share.expiresAt });
      setPicked([]);
      setErr("");
      qc.invalidateQueries({ queryKey: ["holder", "shares"] });
    },
    onError: (e) => setErr((e as Error).message),
  });

  const revoke = useMutation({
    mutationFn: (token: string) => api.del(`/holder/shares/${encodeURIComponent(token)}`),
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
            const o = opened.data?.get(c.vc_id);
            // Chỉ trình bày được văn bằng đang hiệu lực, đã giải mã và khớp bản neo.
            const selectable = st === "active" && plainOf(c.vc_id) !== null;
            return (
              <article key={c.vc_id}
                className={`card p-5 transition ${picked.includes(c.vc_id) ? "ring-2 ring-brand-400" : ""}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="font-bold text-ink-900 truncate">
                      {String((plainOf(c.vc_id)?.credentialSubject as Record<string, unknown> | undefined)?.["vnu:degreeName"]
                        ?? maskLabel(c.vc_type))}
                    </h3>
                    <p className="text-xs text-ink-500 mt-1">
                      Cấp ngày {new Date(c.issued_at).toLocaleDateString("vi-VN")}
                    </p>
                    {c.replaces_vc_id && (
                      <p className="text-xs text-brand-700 mt-1">Văn bằng này thay cho <Mono value={c.replaces_vc_id} /></p>
                    )}
                    {c.replaced_by_vc_id && (
                      <p className="text-xs text-amber-700 mt-1">Đã được thay bằng <Mono value={c.replaced_by_vc_id} /></p>
                    )}
                  </div>
                  <StatusBadge status={st} />
                </div>

                {o && "error" in o && (
                  <div className="mt-3"><Alert tone="warn" title="Chưa giải mã được">{o.error}</Alert></div>
                )}
                {o && "problems" in o && o.problems.length > 0 && (
                  <div className="mt-3"><Alert tone="bad" title="Văn bằng lỗi — nội dung không khớp bản neo">
                    {o.problems.join("; ")}. Hãy liên hệ đơn vị cấp bằng.
                  </Alert></div>
                )}
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
