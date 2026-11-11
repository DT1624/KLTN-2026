import pino from "pino";
import { cfg } from "../config/index.js";

export const logger = pino({
  level: cfg.LOG_LEVEL,
  transport:
    cfg.NODE_ENV === "development"
      ? { target: "pino-pretty", options: { colorize: true, translateTime: "HH:MM:ss" } }
      : undefined,
  // Không bao giờ ghi các trường nhạy cảm vào log.
  redact: {
    paths: [
      "req.headers.authorization",
      "req.headers.cookie",
      "*.privateKey",
      "*.private_key",
      "*.passphrase",
      "*.PINATA_JWT",
    ],
    censor: "[đã ẩn]",
  },
});
