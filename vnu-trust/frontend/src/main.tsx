import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { WalletProvider } from "./hooks/useWallet";
import { CHAIN } from "./lib/chain";
import { rosetteSvg } from "./lib/rosette";
import "@fontsource-variable/inter-tight";
import "./styles/index.css";

// Favicon = hoa văn sinh từ địa chỉ hợp đồng (cùng seed với logo).
const favicon = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
if (favicon) {
  favicon.href =
    "data:image/svg+xml," +
    encodeURIComponent(rosetteSvg(CHAIN.contract || "VNU-Trust", { size: 64, detail: 0.35, color: "#034EA1" }));
}

const qc = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 10_000 },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <WalletProvider>
          <App />
        </WalletProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
