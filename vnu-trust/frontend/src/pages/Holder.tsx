import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { api, type Credential, type ShareToken } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { useTitle } from "../hooks/useTitle";
import { canonicalize, signMessage, sha3_256Hex } from "../lib/wallet";
import { openCredential, sealPresentation, type OpenedCredential } from "../lib/vcStore";
import { maskLabel } from "../lib/constants";
import { Section, Ledger, StatusBadge, Alert, Spinner, Empty, Mono, Badge } from "../components/ui";
import { SplitPane } from "../components/Tabs";
import Rosette from "../components/Rosette";

export default function Holder() {
  useTitle("Văn bằng của tôi");
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
  if (creds.isError) {
    return (
      <Alert tone="bad" title="Không tải được văn bằng">
        <p>{creds.error instanceof Error ? creds.error.message : String(creds.error)}</p>
        <button type="button" className="btn-secondary mt-3" onClick={() => { void creds.refetch(); }}>Thử lại</button>
      </Alert>
    );
  }

  const active = (creds.data ?? []).filter((c) => (c.effective?.status ?? c.status) === "active");

  const openShares = (shares.data ?? []).filter(
    (s) => !s.revoked_at && new Date(s.expires_at).getTime() > Date.now(),
  ).length;

  const side = (
    <section aria-labelledby="share-h" className="sheet p-5 sm:p-6 space-y-4">
      <h2 id="share-h" className="text-lg font-semibold">Chia sẻ</h2>

      {picked.length === 0 ? (
        <p className="text-muted max-w-prose">Chọn một hoặc nhiều văn bằng bên trái để tạo liên kết.</p>
      ) : (
        <div className="space-y-4">
          <div>
            <p>{picked.length} văn bằng đã chọn</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {picked.map((id) => <Rosette key={id} seed={id} size={40} title="Hoa văn đối chiếu" />)}
            </div>
          </div>
          <div>
            <label className="label" htmlFor="ttl">Thời hạn</label>
            <select id="ttl" className="input" value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
              <option value={900}>15 phút</option>
              <option value={3600}>1 giờ</option>
              <option value={86400}>1 ngày</option>
              <option value={604800}>7 ngày</option>
            </select>
          </div>
          <button className="btn-primary" disabled={share.isPending} onClick={() => share.mutate()}>
            {share.isPending ? "Đang tạo…" : "Tạo liên kết chia sẻ"}
          </button>
        </div>
      )}

      {err && <Alert tone="bad">{err}</Alert>}

      {qr && (
        <div role="status" aria-live="polite" className="border-t border-rule pt-4 space-y-3">
          <h3 className="text-base font-semibold">Liên kết đã sẵn sàng</h3>
          <img src={qr.url} alt="Mã QR của liên kết chia sẻ" className="border border-rule rounded-sheet" width={220} />
          <p className="text-sm text-muted">
            Hết hạn lúc <strong>{new Date(qr.expiresAt).toLocaleString("vi-VN")}</strong>.
            Người nhận mở liên kết sẽ thấy đúng các hoa văn này khi xác minh.
          </p>
          <Mono value={qr.link} truncate={false} />
          <button className="btn-secondary" onClick={() => navigator.clipboard?.writeText(qr.link)}>
            Sao chép liên kết
          </button>
        </div>
      )}
    </section>
  );

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Văn bằng của tôi</h1>
        <p className="text-muted mt-2 max-w-prose">
          {creds.data?.length ?? 0} văn bằng, {active.length} còn hiệu lực.
        </p>
      </header>

      {(creds.data?.length ?? 0) > 0 && (
        <Ledger items={[
          { label: "Còn hiệu lực", value: active.length },
          { label: "Tổng văn bằng", value: creds.data?.length ?? 0 },
          ...(shares.data ? [{ label: "Liên kết đang mở", value: openShares }] : []),
        ]} />
      )}

      {creds.data?.length === 0 ? (
        <Empty title="Chưa có văn bằng nào"
          hint="Khi đơn vị đào tạo cấp văn bằng cho DID của bạn, văn bằng sẽ hiện ở đây."
          action={<Link to="/account" className="btn-secondary">Xem DID của tôi</Link>} />
      ) : (
        <SplitPane side={side}>
          <div className="space-y-5">
            {(creds.data ?? []).map((c) => {
              const st = c.effective?.status ?? c.status;
              const o = opened.data?.get(c.vc_id);
              // Chỉ trình bày được văn bằng đang hiệu lực, đã giải mã và khớp bản neo.
              const selectable = st === "active" && plainOf(c.vc_id) !== null;
              const isPicked = picked.includes(c.vc_id);
              return (
                <article key={c.vc_id}
                  className={`sheet p-5 ${isPicked ? "border-primary ring-1 ring-primary" : ""}`}>
                  <div className="grid grid-cols-[auto_minmax(0,1fr)_72px] gap-4">
                    <div className="pt-1">
                      <label>
                        <input type="checkbox" className="w-5 h-5" disabled={!selectable} checked={isPicked}
                          onChange={(e) => setPicked((p) =>
                            e.target.checked ? [...p, c.vc_id] : p.filter((x) => x !== c.vc_id))} />
                        <span className="sr-only">
                          {selectable ? "Chọn để chia sẻ" : "Chưa chia sẻ được khi văn bằng chưa còn hiệu lực"}
                        </span>
                      </label>
                    </div>

                    <div className="min-w-0 space-y-2">
                      <h3 className="text-base font-semibold">
                        {String((plainOf(c.vc_id)?.credentialSubject as Record<string, unknown> | undefined)?.["vnu:degreeName"]
                          ?? maskLabel(c.vc_type))}
                      </h3>
                      <p className="text-sm text-muted break-words">
                        Đơn vị cấp <Mono value={c.issuer_did} />
                      </p>
                      <p className="text-sm text-muted">
                        Cấp ngày {new Date(c.issued_at).toLocaleDateString("vi-VN")}
                        {c.expires_at && `, hết hạn ngày ${new Date(c.expires_at).toLocaleDateString("vi-VN")}`}
                      </p>
                      <div><StatusBadge status={st} /></div>
                      {!selectable && (
                        <p className="text-sm text-muted">Chưa chia sẻ được khi văn bằng chưa còn hiệu lực</p>
                      )}
                      {c.replaces_vc_id && (
                        <p className="text-sm">Văn bằng này thay cho <Mono value={c.replaces_vc_id} /></p>
                      )}
                      {c.replaced_by_vc_id && (
                        <p className="text-sm">Đã được thay bằng <Mono value={c.replaced_by_vc_id} /></p>
                      )}
                    </div>

                    <div className="shrink-0">
                      <Rosette seed={c.vc_id} size={72} title="Hoa văn đối chiếu" />
                    </div>
                  </div>

                  {o && "error" in o && (
                    <div className="mt-4"><Alert tone="warn" title="Chưa giải mã được">{o.error}</Alert></div>
                  )}
                  {o && "problems" in o && o.problems.length > 0 && (
                    <div className="mt-4"><Alert tone="bad" title="Văn bằng lỗi, nội dung không khớp bản neo">
                      {o.problems.join("; ")}. Hãy liên hệ đơn vị cấp bằng.
                    </Alert></div>
                  )}
                  {c.effective?.drift && (
                    <div className="mt-4">
                      <Alert tone="warn" title="Lệch trạng thái">
                        Trạng thái trên chuỗi khác với dữ liệu ứng dụng. Giá trị hiển thị lấy theo chuỗi.
                      </Alert>
                    </div>
                  )}

                  <details className="mt-4 border-t border-rule pt-3">
                    <summary className="cursor-pointer text-sm font-semibold">Chi tiết kỹ thuật</summary>
                    <dl className="mt-3 space-y-2 text-sm">
                      <div className="flex flex-wrap gap-x-3 gap-y-1">
                        <dt className="label shrink-0">Mã nội dung (CID)</dt>
                        <dd className="min-w-0"><Mono value={c.ipfs_cid} /></dd>
                      </div>
                      <div className="flex flex-wrap gap-x-3 gap-y-1">
                        <dt className="label shrink-0">Mã giao dịch</dt>
                        <dd className="min-w-0"><Mono value={c.tx_hash} /></dd>
                      </div>
                    </dl>
                  </details>
                </article>
              );
            })}

            <Section title="Liên kết đã chia sẻ" description="Bạn có thể thu hồi liên kết bất cứ lúc nào.">
              {shares.data?.length ? (
                <div className="overflow-x-auto">
                  <table className="table">
                    <thead>
                      <tr><th>Mã</th><th>Hết hạn</th><th>Lượt xem</th><th>Trạng thái</th><th></th></tr>
                    </thead>
                    <tbody>
                      {shares.data.map((s) => {
                        const expired = new Date(s.expires_at).getTime() <= Date.now();
                        return (
                          <tr key={s.token}>
                            <td><Mono value={s.token} /></td>
                            <td>{new Date(s.expires_at).toLocaleString("vi-VN")}</td>
                            <td className="tabular-nums">{s.view_count}</td>
                            <td>{s.revoked_at ? <Badge tone="bad">Đã thu hồi</Badge>
                              : expired ? <Badge tone="muted">Hết hạn</Badge> : <Badge tone="ok">Đang hoạt động</Badge>}</td>
                            <td className="text-right">
                              {!s.revoked_at && !expired && (
                                <button className="btn-quiet text-son" onClick={() => revoke.mutate(s.token)}>
                                  Thu hồi liên kết
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty title="Chưa chia sẻ lần nào" hint="Chọn văn bằng ở trên để tạo liên kết." />
              )}
            </Section>
          </div>
        </SplitPane>
      )}
    </div>
  );
}
