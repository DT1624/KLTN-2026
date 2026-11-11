/**
 * Lỗi nghiệp vụ có mã HTTP đi kèm. Mọi lỗi ném ra từ tầng service đều
 * nên là AppError để middleware xử lý lỗi biết trả mã nào, thay vì
 * quy hết về 500 như cách làm cũ.
 */
export class AppError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code: string,
    public readonly detail?: unknown,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export const badRequest = (msg: string, detail?: unknown) =>
  new AppError(400, msg, "BAD_REQUEST", detail);
export const unauthorized = (msg = "Chưa xác thực") =>
  new AppError(401, msg, "UNAUTHORIZED");
export const forbidden = (msg = "Không đủ quyền") =>
  new AppError(403, msg, "FORBIDDEN");
export const notFound = (msg = "Không tìm thấy") =>
  new AppError(404, msg, "NOT_FOUND");
export const conflict = (msg: string) =>
  new AppError(409, msg, "CONFLICT");
export const gone = (msg: string) =>
  new AppError(410, msg, "GONE");
export const upstream = (msg: string, detail?: unknown) =>
  new AppError(502, msg, "UPSTREAM_ERROR", detail);
