import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { pinoHttp } from "pino-http";
import { cfg } from "./config/index.js";
import { logger } from "./utils/logger.js";
import { sendOk } from "./utils/http.js";
import { errorHandler, notFoundHandler } from "./middleware/error.js";

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

  app.set("trust proxy", 1);
  app.use(helmet());
  app.use(
    cors({
      origin: cfg.FRONTEND_ORIGIN.split(",").map((s) => s.trim()),
      credentials: true,
    }),
  );
  app.use(express.json({ limit: "2mb" }));
  app.use(pinoHttp({ logger, autoLogging: { ignore: (req: { url?: string }) => req.url === "/health" } }));

  // Giới hạn chung, các tuyến nhạy cảm còn có giới hạn riêng chặt hơn.
  app.use(rateLimit({
    windowMs: 60_000,
    limit: cfg.RATE_LIMIT_PER_MIN,
    standardHeaders: true,
    legacyHeaders: false,
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
