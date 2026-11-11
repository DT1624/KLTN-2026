import type { Request, Response, NextFunction } from "express";
import { verifyToken } from "../services/auth.service.js";
import { unauthorized, forbidden } from "../utils/errors.js";
import { isActiveAdmin, isActiveIssuer } from "../chain/registry.js";
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
export function requireOnChainRole(kind: "admin" | "issuer") {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) throw unauthorized();
      const okOnChain =
        kind === "admin"
          ? await isActiveAdmin(req.user.address)
          : await isActiveIssuer(req.user.address);
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
