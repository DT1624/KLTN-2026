import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { pinoHttp } from "pino-http";
import { cfg } from "./config/index.js";
import { logger } from "./utils/logger.js";
import { sendOk, fail } from "./utils/http.js";
import { errorHandler, notFoundHandler } from "./middleware/error.js";
import { badRequest } from "./utils/errors.js";

import authRoutes from "./routes/auth.routes.js";
import entitiesRoutes from "./routes/entities.routes.js";
import didRoutes from "./routes/did.routes.js";
import issuerRoutes from "./routes/issuer.routes.js";
import holderRoutes from "./routes/holder.routes.js";
import verifyRoutes from "./routes/verify.routes.js";
import adminRoutes from "./routes/admin.routes.js";
import authorityRoutes from "./routes/authority.routes.js";
import publicRoutes from "./routes/public.routes.js";

export function createApp() {
  const app = express();

  app.set("trust proxy", cfg.TRUST_PROXY_HOPS);
  app.use(helmet());
  app.use(
    cors({
      origin: cfg.FRONTEND_ORIGIN.split(",").map((s) => s.trim()),
      credentials: true,
    }),
  );
  // Ký tự NUL: Postgres từ chối trong TEXT/JSONB, để lọt xuống là 500 (L-03).
  // Bắt chuỗi thoát \u0000 trên thân thô — cùng biểu thức với bản Go.
  app.use(express.json({
    limit: "2mb",
    verify: (req, _res, buf) => {
      if (/(^|[^\\])(\\\\)*\\u0000/.test(buf.toString("utf8"))) (req as { hasNul?: boolean }).hasNul = true;
    },
  }));
  app.use((req, _res, next) =>
    (req as { hasNul?: boolean }).hasNul ? next(badRequest("Dữ liệu không được chứa ký tự NUL (\\u0000)")) : next());
  app.use(pinoHttp({ logger, autoLogging: { ignore: (req: { url?: string }) => req.url === "/health" } }));

  // Giới hạn chung, các tuyến nhạy cảm còn có giới hạn riêng chặt hơn.
  app.use(rateLimit({
    windowMs: 60_000,
    limit: cfg.RATE_LIMIT_PER_MIN,
    standardHeaders: true,
    legacyHeaders: false,
    // Cùng phong bì JSON như mọi lỗi khác và như bản Go (trước đây: văn bản thuần — P-08).
    handler: (_req, res) => { res.status(429).json(fail("Quá nhiều yêu cầu, thử lại sau")); },
  }));

  // /health cho hạ tầng (probe của Docker/Kubernetes), /api/health cho giao diện
  // vì proxy của frontend chỉ chuyển tiếp các đường dẫn dưới /api.
  const health = (_req: express.Request, res: express.Response) =>
    // verifyOnChain nói rõ máy chủ có đang kiểm chứng trên chuỗi hay không.
    // Công khai ra để giao diện cảnh báo được và để bộ kiểm thử biết đang ở
    // chế độ nào — chạy không kiểm chứng mà im lặng là chỗ dễ nhầm nhất.
    sendOk(res, {
      status: "ok",
      backend: "typescript",
      uptime: process.uptime(),
      verifyOnChain: cfg.VERIFY_ONCHAIN,
    });
  app.get("/health", health);
  app.get("/api/health", health);

  app.use("/api/auth", authRoutes);
  app.use("/api/entities", entitiesRoutes);
  app.use("/api/did", didRoutes);
  app.use("/api/issuer", issuerRoutes);
  app.use("/api/holder", holderRoutes);
  app.use("/api/verify", verifyRoutes);
  app.use("/api/admin", adminRoutes);
  app.use("/api/authority", authorityRoutes);
  app.use("/api", publicRoutes);

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
