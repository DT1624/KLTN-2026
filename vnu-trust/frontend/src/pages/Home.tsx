import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { api, type ChainStats } from "../lib/api";
import { parseShareInput } from "../lib/vcStore";
import { useTitle } from "../hooks/useTitle";
import { Alert, Spinner, Mono, StatusBadge, Row, Section, Ledger } from "../components/ui";
import { IconCheck, IconCross } from "../components/icons";
import Rosette from "../components/Rosette";

interface LookupResult {
  kind: "did" | "address" | "cid" | "vcId" | "txHash";
  result: Record<string, unknown>;
}

const KIND_LABEL: Record<string, string> = {
  did: "Định danh phi tập trung (DID)",
  address: "Địa chỉ ví",
  cid: "Nội dung trên IPFS",
  vcId: "Mã văn bằng",
  txHash: "Giao dịch trên chuỗi",
};

export default function Home() {
  useTitle("Tra cứu");
  const navigate = useNavigate();
  const inputId = useId();
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

  function onSubmit(value: string) {
    // Liên kết chia sẻ dán nhầm vào ô tra cứu: chuyển sang trang xác minh.
    if (value.includes("/verify/") || value.includes("#k=")) {
      const { token, key } = parseShareInput(value);
      if (token && key) {
        navigate(`/verify/${encodeURIComponent(token)}#k=${key}`);
        return;
      }
    }
    setSubmitted(value);
  }

  return (
    <div className="space-y-8">
      <section className="bg-sheet rounded-lg2 shadow-raised border border-rule p-6 sm:p-10 grid md:grid-cols-[minmax(0,1fr)_240px] gap-10 items-center">
        <div>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">
            Kiểm tra văn bằng ĐHQGHN trong vài giây
          </h1>
          <p className="text-lg text-ink-2 mt-3 max-w-[56ch]">
            Dán liên kết người học gửi cho bạn. Trình duyệt tự giải mã văn bằng và đối chiếu với sổ đăng ký
            trên chuỗi. Cũng tra được mã DID, địa chỉ ví, mã văn bằng hoặc mã giao dịch. Không cần tài khoản.
          </p>
          <form
            className="mt-8 flex flex-col sm:flex-row gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              onSubmit(q.trim());
            }}
          >
            <label htmlFor={inputId} className="sr-only">Liên kết hoặc mã cần tra</label>
            <input
              id={inputId}
              className="input flex-1"
              placeholder="Dán liên kết hoặc mã cần tra"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            <button className="btn-primary" type="submit" disabled={q.trim().length < 3}>
              Kiểm tra
            </button>
          </form>
        </div>
        <div className="hidden sm:block">
          <Rosette seed={stats.data?.contract ?? "VNU-Trust"} size={240} title="Hoa văn của sổ đăng ký" />
          <p className="mt-3 text-sm text-muted max-w-[26ch]">
            Hoa văn sinh từ địa chỉ sổ đăng ký trên chuỗi. Mọi văn bằng thật đều được ghi tại đó.
          </p>
        </div>
      </section>

      {submitted && (
        <div role="status" aria-live="polite">
          {lookup.isFetching && <Spinner label="Đang tra cứu trên chuỗi…" />}
          {lookup.isError && (
            <Alert tone="bad" title="Không tra cứu được">
              {(lookup.error as Error).message}
            </Alert>
          )}
          {lookup.data && <LookupCard data={lookup.data} />}
        </div>
      )}

      <section className="sheet p-5 sm:p-6" role="status" aria-live="polite">
        {stats.isLoading ? (
          <Spinner label="Đang đọc số liệu từ chuỗi…" />
        ) : stats.isError ? (
          <p className="text-lg">Chưa đọc được số liệu từ chuỗi. Tải lại trang để thử lại.</p>
        ) : (
          <Ledger
            items={[
              { label: "Danh tính", value: stats.data!.dids },
              { label: "Văn bằng", value: stats.data!.credentials },
              { label: "Đơn vị cấp bằng", value: stats.data!.issuers },
              { label: "Quản trị viên", value: stats.data!.admins },
            ]}
          />
        )}
        {stats.data && (
          <p className="mt-4 text-sm text-muted">
            Sổ đăng ký <Mono value={stats.data.contract} /> trên Movement testnet, chain id {stats.data.chainId},
            phiên bản sổ cái {stats.data.ledgerVersion}.
          </p>
        )}
      </section>

      <Section title="Ai làm gì trong hệ thống">
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {ROLE_STEPS.map((s, i) => (
            <li key={s.title} className="rounded-sheet border border-rule p-4">
              <span className="w-6 h-6 rounded-full bg-primary-soft text-primary text-sm font-semibold grid place-items-center tabular-nums">
                {i + 1}
              </span>
              <p className="mt-2 font-semibold">{s.title}</p>
              <p className="mt-1 text-sm text-muted">{s.desc}</p>
            </li>
          ))}
        </ol>
        <div className="mt-5 flex flex-wrap gap-3">
          <Link to="/wallet" className="btn-primary">Mở ví</Link>
          <Link to="/verify" className="btn-secondary">Xác minh văn bằng</Link>
        </div>
      </Section>
    </div>
  );
}

const ROLE_STEPS: { title: string; desc: string }[] = [
  { title: "Quản trị gốc", desc: "Giữ quyền cao nhất trên chuỗi, cấp và thu hồi quản trị viên." },
  { title: "Quản trị viên", desc: "Duyệt đơn vị cấp bằng và kiểm duyệt danh tính, văn bằng." },
  { title: "Đơn vị cấp bằng", desc: "Cấp, tạm ngưng và thu hồi văn bằng bằng giao dịch có chữ ký." },
  { title: "Người học", desc: "Giữ văn bằng trong ví và chia sẻ bằng liên kết có thời hạn." },
  { title: "Nhà tuyển dụng", desc: "Mở liên kết người học gửi và xem kết quả bảy phép kiểm." },
];

function LookupCard({ data }: { data: LookupResult }) {
  const r = data.result;
  const isDid = data.kind === "did" || data.kind === "address";
  return (
    <section className="sheet p-5 sm:p-6">
      <div className="flex items-center gap-4 mb-4">
        {isDid && <Rosette seed={String(r.did)} size={64} />}
        <h2 className="text-lg font-semibold">{KIND_LABEL[data.kind] ?? data.kind}</h2>
      </div>
      {isDid ? (
        <dl className="space-y-3">
          <Row label="DID"><Mono value={String(r.did)} truncate={false} /></Row>
          <Row label="Trạng thái"><StatusBadge status={String(r.status)} /></Row>
          <Row label="Nguồn dữ liệu">{r.source === "chain" ? "Đọc trực tiếp từ chuỗi" : "Bộ nhớ đệm ứng dụng"}</Row>
          <Row label="Phiên bản">{String(r.version)}</Row>
          <Row label="Mã nội dung tài liệu"><Mono value={String(r.documentCid)} /></Row>
          <Row label="Toàn vẹn tài liệu">
            {r.integrityOk === true ? (
              <span className="inline-flex items-center gap-1.5"><IconCheck />Nội dung khớp mã băm trên chuỗi</span>
            ) : r.integrityOk === false ? (
              <span className="inline-flex items-center gap-1.5 text-son font-semibold">
                <IconCross />Nội dung không khớp mã băm trên chuỗi
              </span>
            ) : (
              <span className="text-muted">Chưa tải được tài liệu để đối chiếu</span>
            )}
          </Row>
        </dl>
      ) : data.kind === "txHash" ? (
        <dl className="space-y-3">
          <Row label="Mã giao dịch"><Mono value={String(r.hash)} /></Row>
          <Row label="Kết quả">
            {r.success ? <span className="font-semibold">Thành công</span>
              : <span className="text-son font-semibold">Thất bại: {String(r.vmStatus)}</span>}
          </Row>
          <Row label="Người gửi"><Mono value={String(r.sender)} /></Row>
          <Row label="Hàm được gọi"><span className="hex">{String(r.function ?? "Không rõ")}</span></Row>
        </dl>
      ) : data.kind === "vcId" ? (
        <dl className="space-y-3">
          <Row label="Mã văn bằng"><Mono value={String(r.vcId)} /></Row>
          <Row label="Trạng thái"><StatusBadge status={String(r.status)} /></Row>
          <Row label="Loại">{String(r.typeLabel)}</Row>
          <Row label="Đơn vị cấp"><Mono value={String(r.issuerDid)} /></Row>
        </dl>
      ) : data.kind === "cid" && r.private ? (
        // Máy chủ chỉ trả nội dung CID khi đó là DID Document. Nội dung văn bằng
        // là dữ liệu cá nhân — người giữ chia sẻ qua liên kết xác minh của mình.
        <p className="max-w-prose">
          Mã nội dung <span className="hex">{String(r.cid)}</span> không phải tài liệu DID công khai. Nội dung
          văn bằng là dữ liệu cá nhân nên không hiển thị ở ô tra cứu. Người giữ văn bằng chia sẻ qua
          liên kết xác minh.
        </p>
      ) : (
        <details>
          <summary className="cursor-pointer text-sm text-muted">Dữ liệu gốc</summary>
          <pre className="hex bg-tint rounded-ctrl p-4 mt-2 overflow-x-auto max-h-96">
            {JSON.stringify(r.content ?? r, null, 2)}
          </pre>
        </details>
      )}
    </section>
  );
}
