import { api, session, type Role } from "./api";
import { signMessage, type UnlockedWallet } from "./wallet";

/**
 * Đăng nhập theo cơ chế thách thức - đáp ứng.
 * Không có mật khẩu nào rời khỏi trình duyệt; chỉ chữ ký được gửi đi.
 */
/**
 * Chuỗi được ký khi đăng nhập — phải khớp từng ký tự với challengeMessage() ở
 * backend TypeScript và ChallengeMessage() ở backend Go (bất biến #5).
 */
export function challengeMessage(address: string, nonce: string): string {
  return ["VNU-Trust xac thuc dang nhap", `dia chi: ${address}`, `nonce: ${nonce}`].join("\n");
}

/** Hình dạng nonce hai backend phát ra: uuid + "." + 32 hex. */
const NONCE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[0-9a-f]{32}$/;

export async function login(wallet: UnlockedWallet): Promise<{ token: string; role: Role }> {
  const { nonce, message } = await api.post<{ nonce: string; message: string; expiresAt: string }>(
    "/auth/challenge",
    { address: wallet.address },
  );
  // Ví TỰ dựng chuỗi cần ký, không ký nguyên văn thứ máy chủ gửi về (W-02).
  // Ký mù chuỗi của máy chủ thì máy chủ bị chiếm có thể đưa một bản trình bày
  // (VP) hay văn bằng bất kỳ vào ô "message" — chữ ký đăng nhập dùng chung khoá
  // nên chính nó thành proofValue hợp lệ cho tài liệu giả.
  const expected = challengeMessage(wallet.address, nonce);
  if (!NONCE_RE.test(nonce) || message !== expected) {
    throw new Error("Máy chủ yêu cầu ký một chuỗi không phải thông điệp đăng nhập — đã từ chối ký");
  }
  const signature = signMessage(wallet, expected);
  const res = await api.post<{ token: string; entity: { role: Role } }>("/auth/verify", {
    address: wallet.address,
    nonce,
    signature,
  });
  session.set(res.token);
  return { token: res.token, role: res.entity.role };
}

export async function registerEntity(wallet: UnlockedWallet, email?: string): Promise<void> {
  await api.post("/entities/register", {
    address: wallet.address,
    publicKeyHex: wallet.publicKeyHex,
    did: wallet.did,
    role: wallet.role,
    label: wallet.label,
    ...(email ? { email } : {}),
  });
}

export const logout = () => session.clear();
