package db

import "time"

type Entity struct {
	ID           string    `json:"id"`
	Address      string    `json:"address"`
	PublicKeyHex string    `json:"public_key_hex"`
	DID          string    `json:"did"`
	Role         string    `json:"role"`
	Label        string    `json:"label"`
	Email        *string   `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type DIDDocument struct {
	ID           string         `json:"id"`
	EntityID     string         `json:"entity_id"`
	DID          string         `json:"did"`
	DocumentCID  string         `json:"document_cid"`
	DocumentHash string         `json:"document_hash"`
	DocJSON      map[string]any `json:"doc_json"`
	Version      int            `json:"version"`
	Status       string         `json:"status"`
	TxHash       string         `json:"tx_hash"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

type Credential struct {
	ID            string     `json:"id"`
	VCID          string     `json:"vc_id"`
	OnChainVCID   *int64     `json:"on_chain_vc_id"`
	IssuerDID     string     `json:"issuer_did"`
	IssuerAddress string     `json:"issuer_address"`
	HolderDID     string     `json:"holder_did"`
	HolderAddress string     `json:"holder_address"`
	VCType        int        `json:"vc_type"`
	IPFSCid       string     `json:"ipfs_cid"`
	VCIDHash      string     `json:"vc_id_hash"`
	ContentHash   string     `json:"content_hash"`
	ProofValue    string     `json:"proof_value"`
	Status        string     `json:"status"`
	StatusReason  *string    `json:"status_reason"`
	IssuedAt      time.Time  `json:"issued_at"`
	ExpiresAt     *time.Time `json:"expires_at"`
	TxHash        string     `json:"tx_hash"`
	StatusTxHash  *string    `json:"status_tx_hash"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	// C3: vc_id của văn bằng mà văn bằng này thay thế / văn bằng thay cho nó.
	ReplacesVCID   *string `json:"replaces_vc_id"`
	ReplacedByVCID *string `json:"replaced_by_vc_id"`
}

type Presentation struct {
	ID          string    `json:"id"`
	VPID        string    `json:"vp_id"`
	HolderDID   string    `json:"holder_did"`
	VerifierDID *string   `json:"verifier_did"`
	VCIDs       []string  `json:"vc_ids"`
	IPFSCid     string    `json:"ipfs_cid"`
	VPHash      string    `json:"vp_hash"`
	ProofValue  string    `json:"proof_value"`
	Challenge   *string   `json:"challenge"`
	CreatedAt   time.Time `json:"created_at"`
}

type ShareToken struct {
	Token     string     `json:"token"`
	VPID      string     `json:"vp_id"`
	HolderDID string     `json:"holder_did"`
	IPFSCid   string     `json:"ipfs_cid"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	ViewCount int        `json:"view_count"`
	CreatedAt time.Time  `json:"created_at"`
}
