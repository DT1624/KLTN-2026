import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Credential } from "../lib/api";
import { useChainTx } from "../hooks/useChain";
import { ENTRY, bytesArg, u64Arg } from "../lib/chain";
import { maskLabel } from "../lib/constants";
import { Card, Alert, Mono, Field, StatusBadge, Spinner, Empty, Badge } from "./ui";
import TxProgress from "./ChainTx";

/** Trần mỗi lô — khớp MAX_BATCH trong vc_registry.move và hai backend. */
const MAX_BATCH = 100;

interface BatchResult { changed: string[]; skipped: string[]; stale: string[] }

/**
 * Xem xét văn bằng theo lô (C2, nâng cấp 13/11/2026).
 *
 * Thu hồi một đơn vị cấp bằng KHÔNG làm văn bằng họ đã cấp mất hiệu lực — đó là
 * văn bằng thật của người học. Cấp trên mở danh sách, chọn những văn bằng cần
 * xử lý rồi ký MỘT giao dịch:
 *  - admin: `admin_suspend_vcs` / `admin_revoke_vcs`, với văn bằng của bất kỳ ai;
 *  - issuer cha: `delegator_*_vcs`, chỉ văn bằng do sub-issuer của mình cấp.
 * Hợp đồng bỏ qua mục đã ở trạng thái đích / đã thu hồi / hết hạn (khi tạm ngưng)
 * thay vì làm hỏng cả lô — kết quả báo rõ mục nào đổi, mục nào bị bỏ qua.
 */
export default function ReviewPanel({ mode, issuers }: {
  mode: "admin" | "parent";
  /** Gợi ý địa chỉ (issuer cha: danh sách sub-issuer của mình). */
  issuers?: { address: string; label: string | null }[];
}) {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [address, setAddress] = useState("");
  const [query, setQuery] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [reason, setReason] = useState("");
  const [result, setResult] = useState<BatchResult | null>(null);

  const listPath = mode === "admin"
    ? `/admin/issuers/${query}/credentials`
    : `/issuer/review/${query}/credentials`;
  const list = useQuery({
    queryKey: ["review", mode, query],
    queryFn: () => api.get<Credential[]>(listPath),
    enabled: /^0x[0-9a-fA-F]{64}$/.test(query),
  });

  // Chỉ chọn được văn bằng có số hiệu on-chain và chưa thu hồi.
  const selectable = useMemo(
    () => (list.data ?? []).filter((c) => c.on_chain_vc_id != null && c.status !== "revoked"),
    [list.data],
  );
  const chosen = selectable.filter((c) => picked.has(c.vc_id));
  const tooMany = chosen.length > MAX_BATCH;

  const toggle = (id: string) => setPicked((s) => {
    const n = new Set(s);
    if (n.has(id)) n.delete(id); else n.add(id);
    return n;
  });

  const act = (action: "suspend" | "revoke") => {
    // Hợp đồng đòi id TĂNG DẦN NGHIÊM NGẶT; backend đối chiếu đúng thứ tự này.
    const rows = [...chosen].sort((a, b) => (a.on_chain_vc_id ?? 0) - (b.on_chain_vc_id ?? 0));
    const fn = mode === "admin"
      ? (action === "revoke" ? ENTRY.adminRevokeVcs : ENTRY.adminSuspendVcs)
      : (action === "revoke" ? ENTRY.delegatorRevokeVcs : ENTRY.delegatorSuspendVcs);
    setResult(null);
    void tx.run({
      fn,
      args: [rows.map((r) => u64Arg(r.on_chain_vc_id!)), bytesArg(reason.trim())],
      index: async (out) => {
        const r = await api.post<BatchResult>(mode === "admin" ? "/admin/credentials/batch" : "/issuer/review/batch", {
          action, vcIds: rows.map((x) => x.vc_id), reason: reason.trim(), txHash: out.hash,
        });
        setResult(r);
        setPicked(new Set());
        qc.invalidateQueries({ queryKey: ["review"] });
        qc.invalidateQueries({ queryKey: [mode === "admin" ? "admin" : "issuer"] });
        return r;
      },
    });
  };

  const valid = /^0x[0-9a-fA-F]{64}$/.test(address.trim());

  return (
    <Card
      title={mode === "admin" ? "Xem xét văn bằng của một đơn vị" : "Xem xét văn bằng của đơn vị cấp dưới"}
      subtitle={mode === "admin"
        ? "Dùng sau khi thu hồi/tạm ngưng một đơn vị: văn bằng họ đã cấp vẫn hiệu lực cho tới khi được xem xét."
        : "Tạm ngưng/thu hồi văn bằng do sub-issuer của bạn cấp. Kích hoạt lại chỉ admin làm được."}>
      <form className="flex flex-col sm:flex-row gap-3 sm:items-end"
        onSubmit={(e) => { e.preventDefault(); setQuery(address.trim().toLowerCase()); setPicked(new Set()); setResult(null); tx.reset(); }}>
        <div className="flex-1">
          <Field label="Địa chỉ đơn vị cấp bằng" value={address} onChange={setAddress} mono required placeholder="0x…" />
        </div>
        <button className="btn-primary sm:w-36" type="submit" disabled={!valid}>Mở danh sách</button>
      </form>
      {issuers && issuers.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {issuers.map((s) => (
            <button key={s.address} type="button" className="btn-ghost !px-3 !py-1 text-xs"
              onClick={() => { setAddress(s.address); setQuery(s.address.toLowerCase()); setPicked(new Set()); setResult(null); }}>
              {s.label ?? s.address.slice(0, 10) + "…"}
            </button>
          ))}
        </div>
      )}

      {list.isLoading && <div className="mt-4"><Spinner /></div>}
      {list.error && <div className="mt-4"><Alert tone="bad" title="Không mở được danh sách">{(list.error as Error).message}</Alert></div>}
      {list.data && list.data.length === 0 && <div className="mt-4"><Empty title="Đơn vị này chưa cấp văn bằng nào" /></div>}

      {list.data && list.data.length > 0 && (
        <div className="mt-5 space-y-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-ink-600">
              {list.data.length} văn bằng · chọn được {selectable.length} · đã chọn <strong>{chosen.length}</strong>
            </span>
            <button type="button" className="btn-ghost !px-3 !py-1 text-xs"
              onClick={() => setPicked(chosen.length === selectable.length ? new Set() : new Set(selectable.slice(0, MAX_BATCH).map((c) => c.vc_id)))}>
              {chosen.length === selectable.length && selectable.length > 0 ? "Bỏ chọn" : `Chọn tối đa ${MAX_BATCH}`}
            </button>
          </div>
          <div className="overflow-x-auto max-h-96">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-ink-400">
                <tr><th></th><th className="py-2">Số hiệu</th><th>Loại</th><th>Người sở hữu</th><th>Ngày cấp</th><th>Trạng thái</th></tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {list.data.map((c) => {
                  const can = c.on_chain_vc_id != null && c.status !== "revoked";
                  return (
                    <tr key={c.vc_id}>
                      <td className="pr-2">
                        <input type="checkbox" disabled={!can} checked={picked.has(c.vc_id)} onChange={() => toggle(c.vc_id)}
                          aria-label={`Chọn văn bằng ${c.on_chain_vc_id ?? c.vc_id}`} />
                      </td>
                      <td className="py-2 mono text-ink-600">{c.on_chain_vc_id ?? "—"}</td>
                      <td>{maskLabel(c.vc_type)}</td>
                      <td><Mono value={c.holder_did} /></td>
                      <td className="text-ink-600">{new Date(c.issued_at).toLocaleDateString("vi-VN")}</td>
                      <td className="space-x-1"><StatusBadge status={c.status} />
                        {c.replaced_by_vc_id && <Badge tone="muted">đã thay</Badge>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {tooMany && <Alert tone="warn" title="Quá nhiều mục">Mỗi giao dịch xử lý tối đa {MAX_BATCH} văn bằng — hãy chia lô.</Alert>}
          <Field label="Lý do (ghi lên chuỗi và vào nhật ký kiểm toán)" value={reason} onChange={setReason}
            placeholder="Xem xét sau khi thu hồi quyền cấp bằng của đơn vị" />
          <div className="flex flex-wrap gap-3">
            <button className="btn-ghost" type="button"
              disabled={!chosen.length || tooMany || reason.trim().length < 2 || tx.busy}
              onClick={() => act("suspend")}>Ký &amp; tạm ngưng {chosen.length || ""} mục</button>
            <button className="btn-danger" type="button"
              disabled={!chosen.length || tooMany || reason.trim().length < 2 || tx.busy}
              onClick={() => act("revoke")}>Ký &amp; thu hồi {chosen.length || ""} mục</button>
          </div>
          <TxProgress tx={tx} okTitle="Đã xử lý lô văn bằng" />
          {result && (
            <Alert tone={result.stale.length ? "warn" : "ok"} title="Kết quả">
              Đã đổi {result.changed.length} · bỏ qua {result.skipped.length} (đã ở trạng thái đích, đã thu hồi hoặc hết hạn)
              {result.stale.length > 0 && <> · {result.stale.length} mục đã bị thao tác khác chen vào — tải lại danh sách</>}
            </Alert>
          )}
        </div>
      )}
    </Card>
  );
}
