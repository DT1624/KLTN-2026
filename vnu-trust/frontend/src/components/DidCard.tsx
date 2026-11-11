import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type ResolvedDid } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { useChainTx, useMe } from "../hooks/useChain";
import { ENTRY, bytesArg, hashArg } from "../lib/chain";
import { sha3_256Hex } from "../lib/wallet";
import { Card, Alert, Mono, Badge } from "./ui";
import TxProgress from "./ChainTx";

/**
 * Đăng ký danh tính DID — TỰ KÝ, không dán mã giao dịch.
 *
 * Đây là bước đầu tiên bắt buộc của mọi tài khoản: hợp đồng đòi DID đang hoạt
 * động ở hầu hết các hàm. `issue_vc` kiểm DID của **cả** issuer lẫn người nhận,
 * `approve_issuer` kiểm DID của người được cấp quyền, còn mọi hàm admin đều
 * kiểm DID của người gọi. Chưa có DID thì bấm gì cũng hỏng.
 *
 * Trình tự: dựng DID Document → ghim IPFS lấy CID → ví ký `register_did` →
 * chờ chuỗi xác nhận → gửi mã giao dịch thật cho backend ghi chỉ mục.
 */
export default function DidCard() {
  const { wallet } = useWallet();
  const me = useMe();
  const qc = useQueryClient();
  const tx = useChainTx();

  const existing = useQuery({
    queryKey: ["did", "self", wallet?.address],
    queryFn: () => api.get<ResolvedDid>(`/did/by-address/${wallet!.address}`),
    enabled: Boolean(wallet),
    retry: false,
  });

  if (!wallet) return null;

  const onChainOk = me.data?.onChain.hasActiveDid ?? false;
  const registered = Boolean(existing.data) || onChainOk;

  async function register() {
    if (!wallet) return;
    const doc = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ],
      id: wallet.did,
      controller: wallet.did,
      verificationMethod: [
        {
          id: `${wallet.did}#key-1`,
          type: "Ed25519VerificationKey2020",
          controller: wallet.did,
          publicKeyHex: wallet.publicKeyHex,
        },
      ],
      authentication: [`${wallet.did}#key-1`],
      assertionMethod: [`${wallet.did}#key-1`],
      created: new Date().toISOString(),
    };

    // Hash phải tính trên chính đối tượng sẽ ghim, bằng đúng phép tuần tự hoá
    // tất định mà backend dùng — lệch một khoảng trắng là hỏng bước toàn vẹn.
    const documentHash = sha3_256Hex(doc);
    let cid = "";

    await tx.run({
      fn: ENTRY.registerDid,
      // Ghim IPFS nằm trong bước chuẩn bị để lỗi ghim cũng hiện ngay tại thẻ này.
      args: async () => {
        const pinned = await api.post<{ cid: string }>("/ipfs/pin", {
          json: doc,
          name: `did-${wallet.address.slice(0, 10)}`,
        });
        cid = pinned.cid;
        return [bytesArg(wallet.did), bytesArg(cid), hashArg(documentHash)];
      },
      index: async (out) =>
        api.post("/did/save", {
          did: wallet.did,
          documentCid: cid,
          documentHash,
          docJson: doc,
          txHash: out.hash,
        }),
    });

    qc.invalidateQueries({ queryKey: ["did"] });
    qc.invalidateQueries({ queryKey: ["me"] });
  }

  return (
    <Card title="Danh tính DID"
      subtitle="Định danh của bạn trên chuỗi. Mọi thao tác khác đều yêu cầu DID còn hoạt động.">
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Mono value={wallet.did} truncate={false} />
          {registered
            ? <Badge tone="ok">Đã đăng ký</Badge>
            : <Badge tone="warn">Chưa đăng ký</Badge>}
          {registered && (onChainOk
            ? <Badge tone="info">Đang hoạt động trên chuỗi</Badge>
            : <Badge tone="muted">Chưa thấy trên chuỗi</Badge>)}
        </div>

        {existing.data && (
          <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-2 text-sm">
            <div>
              <dt className="text-ink-400 text-xs uppercase tracking-wide">CID tài liệu</dt>
              <dd><Mono value={existing.data.documentCid} /></dd>
            </div>
            <div>
              <dt className="text-ink-400 text-xs uppercase tracking-wide">Toàn vẹn nội dung</dt>
              <dd>
                {existing.data.integrityOk === null
                  ? <Badge tone="muted">Chưa kiểm được</Badge>
                  : existing.data.integrityOk
                    ? <Badge tone="ok">Khớp bản neo</Badge>
                    : <Badge tone="bad">Nội dung đã bị sửa</Badge>}
              </dd>
            </div>
          </dl>
        )}

        {!registered && (
          <>
            <Alert tone="info" title="Cần đăng ký một lần duy nhất">
              Trình duyệt sẽ dựng DID Document chứa khoá công khai của bạn, ghim lên IPFS, rồi
              ví <strong>tự ký</strong> giao dịch <span className="mono">register_did</span>. Bạn
              không phải nhập mã giao dịch nào.
            </Alert>
            <button className="btn-primary" type="button" disabled={tx.busy}
              onClick={() => void register()}>
              {tx.busy ? tx.label : "Đăng ký DID"}
            </button>
          </>
        )}

        <TxProgress tx={tx} okTitle="Đã đăng ký DID" />
      </div>
    </Card>
  );
}
