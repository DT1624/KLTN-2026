-- ============================================================
-- VNU-Trust — lược đồ CSDL dùng chung cho backend TypeScript và Go
-- Nguyên tắc: blockchain là nguồn sự thật. Bảng ở đây chỉ là chỉ mục
-- để truy vấn nhanh; mọi bản ghi tham chiếu on-chain đều lưu tx_hash
-- đã được backend xác minh với fullnode trước khi ghi.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------- Kiểu liệt kê ----------
DO $$ BEGIN
  CREATE TYPE entity_role   AS ENUM ('root','admin','issuer','holder','verifier');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE did_status    AS ENUM ('active','suspended','revoked');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE vc_status     AS ENUM ('active','suspended','expired','revoked');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---------- Thực thể ----------
-- Một địa chỉ ví = một thực thể. public_key_hex dùng để xác minh chữ ký
-- challenge khi đăng nhập; khóa riêng KHÔNG BAO GIỜ rời khỏi trình duyệt.
CREATE TABLE IF NOT EXISTS entities (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  address         TEXT        NOT NULL UNIQUE,
  public_key_hex  TEXT        NOT NULL,
  did             TEXT        NOT NULL UNIQUE,
  role            entity_role NOT NULL,
  label           TEXT        NOT NULL,
  email           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_entities_role ON entities(role);

-- ---------- Challenge đăng nhập ----------
CREATE TABLE IF NOT EXISTS auth_challenges (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  address     TEXT        NOT NULL,
  nonce       TEXT        NOT NULL UNIQUE,
  used        BOOLEAN     NOT NULL DEFAULT FALSE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_challenges_lookup
  ON auth_challenges(address, used, expires_at DESC);

-- ---------- Tài liệu DID ----------
CREATE TABLE IF NOT EXISTS did_documents (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id     UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  did           TEXT        NOT NULL UNIQUE,
  document_cid  TEXT        NOT NULL,
  document_hash TEXT        NOT NULL,
  doc_json      JSONB       NOT NULL,
  version       INTEGER     NOT NULL DEFAULT 1,
  status        did_status  NOT NULL DEFAULT 'active',
  tx_hash       TEXT        NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Chứng chỉ khả kiểm (VC) ----------
CREATE TABLE IF NOT EXISTS credentials (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vc_id            TEXT        NOT NULL UNIQUE,
  on_chain_vc_id   BIGINT,
  issuer_did       TEXT        NOT NULL,
  issuer_address   TEXT        NOT NULL,
  holder_did       TEXT        NOT NULL,
  holder_address   TEXT        NOT NULL,
  vc_type          INTEGER     NOT NULL,
  ipfs_cid         TEXT        NOT NULL,
  vc_id_hash       TEXT        NOT NULL,
  content_hash     TEXT        NOT NULL,
  proof_value      TEXT        NOT NULL,
  vc_json          JSONB       NOT NULL,
  status           vc_status   NOT NULL DEFAULT 'active',
  status_reason    TEXT,
  issued_at        TIMESTAMPTZ NOT NULL,
  expires_at       TIMESTAMPTZ,
  tx_hash          TEXT        NOT NULL,
  status_tx_hash   TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vc_holder ON credentials(holder_did, status);
CREATE INDEX IF NOT EXISTS idx_vc_issuer ON credentials(issuer_did, status);

-- ---------- Bản trình bày khả kiểm (VP) ----------
CREATE TABLE IF NOT EXISTS presentations (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vp_id         TEXT        NOT NULL UNIQUE,
  holder_did    TEXT        NOT NULL,
  verifier_did  TEXT,
  vc_ids        TEXT[]      NOT NULL,
  ipfs_cid      TEXT        NOT NULL,
  vp_hash       TEXT        NOT NULL,
  proof_value   TEXT        NOT NULL,
  challenge     TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vp_holder ON presentations(holder_did);

-- ---------- Liên kết chia sẻ (QR) ----------
CREATE TABLE IF NOT EXISTS share_tokens (
  token       TEXT PRIMARY KEY,
  vp_id       TEXT        NOT NULL REFERENCES presentations(vp_id) ON DELETE CASCADE,
  holder_did  TEXT        NOT NULL,
  ipfs_cid    TEXT        NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked_at  TIMESTAMPTZ,
  view_count  INTEGER     NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_share_holder ON share_tokens(holder_did);

-- ---------- Kết quả xác minh ----------
CREATE TABLE IF NOT EXISTS verifications (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vp_id             TEXT        NOT NULL,
  verifier_address  TEXT        NOT NULL,
  overall_valid     BOOLEAN     NOT NULL,
  report            JSONB       NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_verif_verifier ON verifications(verifier_address, created_at DESC);

-- ---------- Nội dung IPFS ở chế độ mock ----------
-- Chế độ IPFS_PROVIDER=mock trước đây giữ nội dung đã ghim trong BỘ NHỚ TIẾN
-- TRÌNH. Hệ quả là hai lỗi thật, cùng một gốc:
--   1. Khởi động lại backend là mất sạch nội dung đã ghim, nên mọi DID/VC cũ
--      resolve ra `integrityOk: null` — giao diện báo "không kiểm được toàn vẹn"
--      cho đúng thứ mà cả hệ thống sinh ra để bảo đảm.
--   2. Nội dung ghim qua backend TypeScript thì backend Go không thấy và ngược
--      lại, nên hai backend KHÔNG thực sự thay thế được cho nhau.
-- Lưu vào CSDL dùng chung là cách khôi phục đúng tính chất của IPFS thật:
-- định địa chỉ theo nội dung, bền, và ai cũng đọc được.
-- Bảng này KHÔNG dùng khi IPFS_PROVIDER=pinata.
CREATE TABLE IF NOT EXISTS ipfs_objects (
  cid         TEXT        PRIMARY KEY,
  content     JSONB       NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Nhật ký kiểm toán ----------
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  actor       TEXT        NOT NULL,
  action      TEXT        NOT NULL,
  target      TEXT,
  detail      JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor, created_at DESC);
