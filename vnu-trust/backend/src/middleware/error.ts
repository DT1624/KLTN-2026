import type { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";
import { AppError } from "../utils/errors.js";
import { fail } from "../utils/http.js";
import { logger } from "../utils/logger.js";
import { cfg } from "../config/index.js";

export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json(fail(`Không có tuyến ${req.method} ${req.path}`));
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  if (err instanceof ZodError) {
    const detail = err.issues.map((i) => `${i.path.join(".") || "(gốc)"}: ${i.message}`).join("; ");
    res.status(400).json(fail(`Dữ liệu không hợp lệ — ${detail}`));
    return;
  }

  // Lỗi của body-parser: JSON hỏng → 400, quá giới hạn → 413 — giống bản Go.
  // Trước đây rơi xuống nhánh 500 và (ngoài production) trả nguyên thông điệp của
  // trình phân tích (L-02).
  const bp = (err as { type?: string } | null)?.type;
  if (bp === "entity.parse.failed") {
    res.status(400).json(fail("Thân yêu cầu không phải JSON hợp lệ"));
    return;
  }
  if (bp === "entity.too.large") {
    res.status(413).json(fail("Thân yêu cầu vượt quá 2 MB"));
    return;
  }

  if (err instanceof AppError) {
    // Lỗi 4xx là lỗi phía người dùng, không cần ghi log mức error.
    if (err.status >= 500) logger.error({ err, path: req.path }, err.message);
    else logger.debug({ err: err.message, path: req.path }, "Từ chối yêu cầu");
    res.status(err.status).json(fail(err.message));
    return;
  }

  // Vi phạm ràng buộc duy nhất của Postgres.
  if (typeof err === "object" && err !== null && (err as { code?: string }).code === "23505") {
    res.status(409).json(fail("Dữ liệu đã tồn tại (vi phạm ràng buộc duy nhất)"));
    return;
  }

  logger.error({ err, path: req.path }, "Lỗi không lường trước");
  res
    .status(500)
    .json(fail(cfg.NODE_ENV === "production" ? "Lỗi máy chủ" : String((err as Error)?.message ?? err)));
}
