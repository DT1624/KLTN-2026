import type { Request, Response, NextFunction } from "express";
import { verifyToken } from "../services/auth.service.js";
import { unauthorized, forbidden } from "../utils/errors.js";
import { isActiveAdmin, isActiveIssuer } from "../chain/registry.js";
import { ttlKeyed } from "../utils/ttl-cache.js";
import { queryOne } from "../db/pool.js";
import type { Role } from "../types/index.js";

export function requireAuth(req: Request, _res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return next(unauthorized());
  try {
    req.user = verifyToken(header.slice(7).trim());
    next();
  } catch (e) {
    next(e);
  }
}

/**
 * Chặn theo vai trò hiện hành trong chỉ mục, không theo vai trò ghi trong JWT:
 * token sống tới 8 giờ, admin vừa bị thu hồi không được đọc tiếp dữ liệu.
 */
export function requireRole(...roles: Role[]) {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) throw unauthorized();
      const row = await queryOne<{ role: Role }>("SELECT role FROM entities WHERE address = $1", [
        req.user.address,
      ]);
      if (!row) throw unauthorized("Tài khoản không còn trong hệ thống");
      req.user.role = row.role;
      if (!roles.includes(row.role)) throw forbidden(`Yêu cầu vai trò: ${roles.join(" hoặc ")}`);
      next();
    } catch (e) {
      next(e);
    }
  };
}

/**
 * Kiểm tra quyền thật trên chuỗi, không chỉ dựa vào JWT.
 * Dùng cho các thao tác nhạy cảm — JWT chỉ nói người dùng *khai* là gì,
 * chuỗi mới nói họ *thực sự* có quyền gì.
 */
/**
 * P5 (13/11/2026): mọi tuyến admin hỏi `is_active_admin` ở MỖI yêu cầu (V1) — một vòng
 * fullnode mỗi lần. Đệm theo địa chỉ ROLE_CACHE_MS. Cửa sổ rủi ro: người vừa bị thu hồi
 * quyền ngoài ứng dụng còn đọc được tuyến admin tối đa ROLE_CACHE_MS. Thao tác GHI không
 * bị ảnh hưởng: giao dịch của họ vẫn bị hợp đồng từ chối, và backend vẫn xác minh giao
 * dịch + hỏi lại trạng thái chuỗi (quyết định #19, không đệm). Khớp backend Go.
 */
export const ROLE_CACHE_MS = 5_000;
const cachedIsAdmin = ttlKeyed(ROLE_CACHE_MS, (a) => isActiveAdmin(a));
const cachedIsIssuer = ttlKeyed(ROLE_CACHE_MS, (a) => isActiveIssuer(a));

export function requireOnChainRole(kind: "admin" | "issuer") {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) throw unauthorized();
      const okOnChain = kind === "admin"
        ? await cachedIsAdmin(req.user.address)
        : await cachedIsIssuer(req.user.address);
      if (!okOnChain) {
        throw forbidden(
          kind === "admin"
            ? "Địa chỉ này không phải admin đang hoạt động trên chuỗi"
            : "Địa chỉ này chưa được cấp quyền issuer trên chuỗi hoặc quyền đã hết hiệu lực",
        );
      }
      next();
    } catch (e) {
      next(e);
    }
  };
}
