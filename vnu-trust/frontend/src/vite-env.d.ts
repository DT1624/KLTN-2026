/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
  /** URL đầy đủ của từng backend khi triển khai, vd. https://x.onrender.com/api. */
  readonly VITE_API_TS_URL?: string;
  readonly VITE_API_GO_URL?: string;
  /** Thông số chuỗi — sinh ra từ `chain.env` bởi `scripts/sync-chain-env.sh`. */
  readonly VITE_CONTRACT_ADDRESS?: string;
  readonly VITE_CHAIN_FULLNODE?: string;
  readonly VITE_CHAIN_ID?: string;
  readonly VITE_CHAIN_FAUCET?: string;
  readonly VITE_CHAIN_EXPLORER?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
