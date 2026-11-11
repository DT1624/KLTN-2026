import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Hai đường proxy riêng để giao diện đổi backend ngay lúc chạy mà không
    // phải build lại. Đường dẫn API phía sau hoàn toàn giống nhau.
    proxy: {
      "/api-ts": { target: "http://localhost:4000", changeOrigin: true, rewrite: (p) => p.replace(/^\/api-ts/, "/api") },
      "/api-go": { target: "http://localhost:4001", changeOrigin: true, rewrite: (p) => p.replace(/^\/api-go/, "/api") },
      "/api":    { target: "http://localhost:4000", changeOrigin: true },
    },
  },
  build: {
    // Tách thư viện ít đổi ra chunk riêng để trình duyệt cache được qua các lần triển khai.
    rollupOptions: {
      output: {
        manualChunks: {
          crypto: ["@noble/curves/ed25519", "@noble/hashes/sha3"],
          react: ["react", "react-dom", "react-router-dom"],
          query: ["@tanstack/react-query"],
          qr: ["qrcode"],
        },
      },
    },
  },
});
