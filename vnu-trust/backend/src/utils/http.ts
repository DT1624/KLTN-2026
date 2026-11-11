import type { Response } from "express";
import { AppError } from "./errors.js";


export interface Envelope<T> {
  success: boolean;
  data: T | null;
  error: string | null;
  timestamp: string;
}

export const ok = <T>(data: T): Envelope<T> => ({
  success: true,
  data,
  error: null,
  timestamp: new Date().toISOString(),
});

export const fail = (error: string): Envelope<never> => ({
  success: false,
  data: null,
  error,
  timestamp: new Date().toISOString(),
});

export const sendOk = <T>(res: Response, data: T, status = 200) =>
  res.status(status).json(ok(data));

/**
 * Lấy tham số đường dẫn và bảo đảm có giá trị. Với `noUncheckedIndexedAccess`
 * thì `req.params.x` có kiểu `string | undefined`, nên cần chốt lại một chỗ
 * thay vì rải `!` khắp các route.
 */
export function param(params: Record<string, string | undefined>, name: string): string {
  const v = params[name];
  if (typeof v !== "string" || v.length === 0) {
    throw new AppError(400, `Thiếu tham số đường dẫn "${name}"`, "BAD_REQUEST");
  }
  return v;
}
