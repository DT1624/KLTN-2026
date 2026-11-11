import { api, session, type Role } from "./api";
import { signMessage, type UnlockedWallet } from "./wallet";

/**
 * Đăng nhập theo cơ chế thách thức - đáp ứng.
 * Không có mật khẩu nào rời khỏi trình duyệt; chỉ chữ ký được gửi đi.
 */
export async function login(wallet: UnlockedWallet): Promise<{ token: string; role: Role }> {
  const { nonce, message } = await api.post<{ nonce: string; message: string; expiresAt: string }>(
    "/auth/challenge",
    { address: wallet.address },
  );
  const signature = signMessage(wallet, message);
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
