module governance::errors {
    // ========== Authority ==========

    const E_NOT_ROOT_ADMIN:             u64 = 1001;
    const E_NOT_ADMIN:                  u64 = 1002;
    const E_ADMIN_ALREADY_EXISTS:       u64 = 1003;
    const E_ISSUER_ALREADY_EXISTS:      u64 = 1004;
    const E_ISSUER_NOT_FOUND:           u64 = 1005;
    const E_ISSUER_NOT_ACTIVE:          u64 = 1006;
    const E_ISSUER_NOT_SUSPENDED:       u64 = 1007;
    const E_ISSUER_ALREADY_REVOKED:     u64 = 1008;
    const E_ADMIN_ALREADY_REVOKED:      u64 = 1009;
    const E_ADMIN_NOT_ACTIVE:           u64 = 1010;
    const E_NOT_AUTHORIZED:             u64 = 1011;
    const E_ISSUER_CAP_EXPIRED:         u64 = 1012;
    const E_UNAUTHORIZED_VC_TYPE:       u64 = 1013;

    // ========== Identity ==========

    const E_DID_ALREADY_REGISTERED:     u64 = 2001;
    const E_DID_NOT_FOUND:              u64 = 2002;
    const E_DID_NOT_ACTIVE:             u64 = 2003;
    const E_DID_NOT_SUSPENDED:          u64 = 2004;
    const E_DID_ALREADY_REVOKED:        u64 = 2005;
    const E_OWNER_NOT_EXISTS:           u64 = 2006;
    const E_OWNER_HAS_DID:              u64 = 2007;
    const E_INVALID_CID:                u64 = 2008;
    const E_STABLE_DID_VERSION:         u64 = 2009;

    // ========== Credential ==========

    const E_VC_NOT_FOUND:               u64 = 3001;
    const E_VC_NOT_ACTIVE:              u64 = 3002;
    const E_VC_NOT_SUSPENDED:           u64 = 3003;
    const E_VC_ALREADY_REVOKED:         u64 = 3004;
    const E_VC_ALREADY_EXPIRED:         u64 = 3005;
    const E_NOT_VC_ISSUER:              u64 = 3006;
    const E_NOT_VC_HOLDER:              u64 = 3007;
    const E_HOLDER_DID_NOT_ACTIVE:      u64 = 3008;
    const E_VC_ALREADY_EXISTS:          u64 = 3009;


    // ========== Utils ==========
    const E_HASH_WRONG_LENGTH:          u64 = 4001;
    const E_HASH_MISMATCH:              u64 = 4002;
    const E_INVALID_ID:                 u64 = 4003;

    // ========== Public accessors ==========

    // === Authority ===
    public fun not_root_admin(): u64            { E_NOT_ROOT_ADMIN }
    public fun not_admin(): u64                 { E_NOT_ADMIN }//
    public fun admin_already_exists(): u64      { E_ADMIN_ALREADY_EXISTS }
    public fun issuer_already_exists(): u64     { E_ISSUER_ALREADY_EXISTS}
    public fun issuer_not_found(): u64          { E_ISSUER_NOT_FOUND }
    public fun issuer_not_active(): u64         { E_ISSUER_NOT_ACTIVE }
    public fun issuer_not_suspended(): u64      { E_ISSUER_NOT_SUSPENDED }
    public fun issuer_already_revoked(): u64    { E_ISSUER_ALREADY_REVOKED }
    public fun admin_already_revoked(): u64     { E_ADMIN_ALREADY_REVOKED }
    public fun admin_not_active(): u64          { E_ADMIN_NOT_ACTIVE }
    public fun not_authorized(): u64            { E_NOT_AUTHORIZED }
    public fun issuer_cap_expired(): u64        { E_ISSUER_CAP_EXPIRED }
    public fun unauthorized_vc_type(): u64      { E_UNAUTHORIZED_VC_TYPE }

    // === Identity ===
    public fun did_already_registered(): u64    { E_DID_ALREADY_REGISTERED }
    public fun did_not_found(): u64             { E_DID_NOT_FOUND }
    public fun did_not_active(): u64            { E_DID_NOT_ACTIVE }
    public fun did_not_suspended(): u64         { E_DID_NOT_SUSPENDED }
    public fun did_already_revoked(): u64       { E_DID_ALREADY_REVOKED }
    public fun owner_not_exists(): u64          { E_OWNER_NOT_EXISTS }
    public fun owner_has_did(): u64             { E_OWNER_HAS_DID }
    public fun invalid_cid(): u64               { E_INVALID_CID }
    public fun stable_did_version(): u64        { E_STABLE_DID_VERSION }


    // === Credential ===

    public fun vc_not_found(): u64              { E_VC_NOT_FOUND }
    public fun vc_not_active(): u64             { E_VC_NOT_ACTIVE }
    public fun vc_not_suspended(): u64          { E_VC_NOT_SUSPENDED }
    public fun vc_already_revoked(): u64        { E_VC_ALREADY_REVOKED }
    public fun vc_already_expired(): u64        { E_VC_ALREADY_EXPIRED }
    public fun not_vc_issuer(): u64             { E_NOT_VC_ISSUER }
    public fun not_vc_holder(): u64             { E_NOT_VC_HOLDER }
    public fun vc_already_exists(): u64         { E_VC_ALREADY_EXISTS }

    // === Utils ===

    public fun hash_wrong_length(): u64         { E_HASH_WRONG_LENGTH }
    public fun hash_mismatch(): u64             { E_HASH_MISMATCH }
    public fun invalid_id(): u64                { E_INVALID_ID }
}