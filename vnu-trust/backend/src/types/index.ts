export type Role = "root" | "admin" | "issuer" | "holder" | "verifier";
export type DidStatus = "active" | "suspended" | "revoked";
export type VcStatus = "active" | "suspended" | "expired" | "revoked";

export interface JwtPayload {
  address: string;
  did: string;
  role: Role;
  /** Phát hành lúc — dùng để vô hiệu hoá token cũ khi cần. */
  iat?: number;
  exp?: number;
}

export interface EntityRow {
  id: string;
  address: string;
  public_key_hex: string;
  did: string;
  role: Role;
  label: string;
  email: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface DidDocumentRow {
  id: string;
  entity_id: string;
  did: string;
  document_cid: string;
  document_hash: string;
  doc_json: Record<string, unknown>;
  version: number;
  status: DidStatus;
  tx_hash: string;
  created_at: Date;
  updated_at: Date;
}

export interface CredentialRow {
  id: string;
  vc_id: string;
  on_chain_vc_id: number | null;
  issuer_did: string;
  issuer_address: string;
  holder_did: string;
  holder_address: string;
  vc_type: number;
  ipfs_cid: string;
  vc_id_hash: string;
  content_hash: string;
  proof_value: string;
  status: VcStatus;
  status_reason: string | null;
  issued_at: Date;
  expires_at: Date | null;
  tx_hash: string;
  status_tx_hash: string | null;
  /** C3: vc_id của văn bằng mà văn bằng này thay thế / văn bằng thay cho nó. */
  replaces_vc_id: string | null;
  replaced_by_vc_id: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface PresentationRow {
  id: string;
  vp_id: string;
  holder_did: string;
  verifier_did: string | null;
  vc_ids: string[];
  ipfs_cid: string;
  vp_hash: string;
  proof_value: string;
  challenge: string | null;
  created_at: Date;
}

export interface ShareTokenRow {
  token: string;
  vp_id: string;
  holder_did: string;
  ipfs_cid: string;
  expires_at: Date;
  revoked_at: Date | null;
  view_count: number;
  created_at: Date;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}
