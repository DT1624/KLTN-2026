import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type ChainStats } from "../lib/api";
import { Card, Stat, Alert, Spinner, Mono, StatusBadge } from "../components/ui";

interface LookupResult {
  kind: "did" | "address" | "cid" | "vcId" | "txHash";
  result: Record<string, unknown>;
}

const KIND_LABEL: Record<string, string> = {
  did: "Định danh phi tập trung (DID)",
  address: "Địa chỉ ví",
  cid: "Nội dung trên IPFS",
  vcId: "Mã chứng chỉ",
  txHash: "Giao dịch trên chuỗi",
};

export default function Home() {
  const [q, setQ] = useState("");
  const [submitted, setSubmitted] = useState("");

  const stats = useQuery({
    queryKey: ["stats"],
    queryFn: () => api.get<ChainStats>("/stats"),
    staleTime: 30_000,
  });

  const lookup = useQuery({
    queryKey: ["lookup", submitted],
    queryFn: () => api.get<LookupResult>(`/lookup?q=${encodeURIComponent(submitted)}`),
    enabled: submitted.length > 2,
    retry: false,
  });

  return (
    <div className="mx-auto max-w-5xl px-4 py-10 sm:py-16">
      <div className="text-center animate-fade-up">
        <span className="chip bg-brand-50 text-brand-700 ring-1 ring-brand-200">
          Movement Network · Chuẩn W3C DID &amp; Verifiable Credentials
        </span>
        <h1 className="mt-5 text-4xl sm:text-5xl font-bold tracking-tight text-ink-900">
          Tra cứu <span className="text-brand-600">danh tính</span> và{" "}
          <span className="text-accent-600">văn bằng</span> số
        </h1>
        <p className="mt-4 text-ink-600 max-w-2xl mx-auto leading-relaxed">
          Mọi văn bằng do ĐHQGHN cấp đều được neo lên blockchain. Dán DID, địa chỉ ví,
          mã CID, mã chứng chỉ hoặc mã giao dịch để kiểm chứng ngay — không cần đăng nhập.
        </p>
      </div>

      <form
        className="mt-8 flex flex-col sm:flex-row gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          setSubmitted(q.trim());
        }}
      >
        <input
          className="input flex-1 !py-3.5 text-[0.95rem]"
          placeholder="did:vnu:holder:0x… · 0x… · bafkrei… · urn:uuid:…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          aria-label="Ô tra cứu định danh"
        />
        <button className="btn-primary !py-3.5 !px-7" type="submit" disabled={q.trim().length < 3}>
          Tra cứu
        </button>
      </form>

      {submitted && (
        <div className="mt-6">
          {lookup.isFetching && <Spinner label="Đang tra cứu trên chuỗi…" />}
          {lookup.isError && (
            <Alert tone="bad" title="Không tra cứu được">
              {(lookup.error as Error).message}
            </Alert>
          )}
          {lookup.data && <LookupCard data={lookup.data} />}
        </div>
      )}

      <div className="mt-12 grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.isLoading ? (
          <div className="col-span-full"><Spinner label="Đang đọc số liệu từ chuỗi…" /></div>
        ) : stats.isError ? (
          <div className="col-span-full">
            <Alert tone="warn" title="Chưa đọc được số liệu từ chuỗi">
              {(stats.error as Error).message}
            </Alert>
          </div>
        ) : (
          <>
            <Stat label="Định danh" value={stats.data!.dids} hint="DID đã đăng ký" />
            <Stat label="Văn bằng" value={stats.data!.credentials} hint="VC đã cấp" />
            <Stat label="Đơn vị cấp" value={stats.data!.issuers} hint="issuer được uỷ quyền" />
            <Stat label="Quản trị" value={stats.data!.admins} hint="admin đang hoạt động" />
          </>
        )}
      </div>

      {stats.data && (
        <p className="mt-4 text-center text-xs text-ink-400">
          Hợp đồng <Mono value={stats.data.contract} /> · chain id {stats.data.chainId} · phiên bản sổ cái{" "}
          {stats.data.ledgerVersion}
        </p>
      )}

      <div className="mt-12 grid sm:grid-cols-3 gap-4">
        <RoleCard to="/wallet" emoji="🎓" title="Người sở hữu"
          desc="Giữ văn bằng trong ví trình duyệt, chia sẻ bằng mã QR có hạn." />
        <RoleCard to="/wallet" emoji="🏛️" title="Đơn vị cấp bằng"
          desc="Cấp và thu hồi văn bằng, mọi thao tác đều neo lên chuỗi." />
        <RoleCard to="/verify" emoji="🔍" title="Bên xác minh"
          desc="Quét mã, kiểm 7 bước: chữ ký, toàn vẹn, hiệu lực, tin cậy." />
      </div>
    </div>
  );
}

function RoleCard({ to, emoji, title, desc }: { to: string; emoji: string; title: string; desc: string }) {
  return (
    <Link to={to} className="card p-5 hover:shadow-lift transition-shadow group">
      <div className="text-2xl">{emoji}</div>
      <h3 className="mt-3 font-bold text-ink-900 group-hover:text-brand-700 transition-colors">{title}</h3>
      <p className="mt-1 text-sm text-ink-500 leading-relaxed">{desc}</p>
    </Link>
  );
}

function LookupCard({ data }: { data: LookupResult }) {
  const r = data.result;
  return (
    <Card title={KIND_LABEL[data.kind] ?? data.kind} className="animate-fade-up">
      {data.kind === "did" || data.kind === "address" ? (
        <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <Row label="DID"><Mono value={String(r.did)} truncate={false} /></Row>
          <Row label="Trạng thái"><StatusBadge status={String(r.status)} /></Row>
          <Row label="Nguồn dữ liệu">{r.source === "chain" ? "Đọc trực tiếp từ chuỗi" : "Bộ nhớ đệm ứng dụng"}</Row>
          <Row label="Phiên bản">{String(r.version)}</Row>
          <Row label="CID tài liệu"><Mono value={String(r.documentCid)} /></Row>
          <Row label="Toàn vẹn tài liệu">
            {r.integrityOk === true ? <span className="text-emerald-700 font-semibold">Khớp hash trên chuỗi</span>
              : r.integrityOk === false ? <span className="text-rose-700 font-semibold">Hash KHÔNG khớp</span>
              : <span className="text-ink-400">Chưa tải được tài liệu để đối chiếu</span>}
          </Row>
        </dl>
      ) : data.kind === "txHash" ? (
        <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <Row label="Mã giao dịch"><Mono value={String(r.hash)} /></Row>
          <Row label="Kết quả">
            {r.success ? <span className="text-emerald-700 font-semibold">Thành công</span>
              : <span className="text-rose-700 font-semibold">Thất bại — {String(r.vmStatus)}</span>}
          </Row>
          <Row label="Người gửi"><Mono value={String(r.sender)} /></Row>
          <Row label="Hàm được gọi"><span className="mono">{String(r.function ?? "—")}</span></Row>
        </dl>
      ) : data.kind === "vcId" ? (
        <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <Row label="Mã chứng chỉ"><Mono value={String(r.vcId)} /></Row>
          <Row label="Trạng thái"><StatusBadge status={String(r.status)} /></Row>
          <Row label="Loại">{String(r.typeLabel)}</Row>
          <Row label="Đơn vị cấp"><Mono value={String(r.issuerDid)} /></Row>
        </dl>
      ) : data.kind === "cid" && r.private ? (
        // Máy chủ chỉ trả nội dung CID khi đó là DID Document. Nội dung văn bằng
        // là dữ liệu cá nhân — người giữ chia sẻ qua liên kết xác minh của mình.
        <p className="text-sm text-ink-600">
          CID <span className="mono">{String(r.cid)}</span> không phải tài liệu DID công khai. Nội dung
          văn bằng là dữ liệu cá nhân nên không hiển thị ở ô tra cứu — người giữ văn bằng chia sẻ qua
          liên kết xác minh.
        </p>
      ) : (
        <pre className="mono bg-ink-50 rounded-xl p-4 overflow-x-auto max-h-96 text-xs">
          {JSON.stringify(r.content ?? r, null, 2)}
        </pre>
      )}
    </Card>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wide text-ink-400">{label}</dt>
      <dd className="mt-1 text-ink-800">{children}</dd>
    </div>
  );
}
