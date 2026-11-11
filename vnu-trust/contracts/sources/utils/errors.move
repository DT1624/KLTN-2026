module vnu::errors {
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
    const E_NO_PENDING_ROOT:            u64 = 1014;
    const E_NOT_PENDING_ROOT:           u64 = 1015;
    const E_ROLE_CONFLICT:              u64 = 1016;
    const E_CANNOT_DELEGATE:            u64 = 1017;
    /// Admin thuong khong duoc tac dong len DID cua root hoac admin dang hoat dong.
    const E_PROTECTED_TARGET:           u64 = 1018;

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
    const E_NOT_SELF_SUSPENDED:         u64 = 2010;
    /// Chuoi DID phai co dang "did:..." va ket thuc bang dia chi chu so huu.
    const E_DID_NOT_BOUND_TO_OWNER:     u64 = 2011;
    /// DID do chinh chu tu khoa thi chi chu moi mo lai.
    const E_OWNER_LOCKED:               u64 = 2012;

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
    /// Issuer khong duoc tu cap van bang cho chinh minh.
    const E_SELF_ISSUE:                 u64 = 3010;


    // ========== Utils ==========
    const E_HASH_WRONG_LENGTH:          u64 = 4001;
    const E_HASH_MISMATCH:              u64 = 4002;
    const E_INVALID_ID:                 u64 = 4003;
    const E_INVALID_PAGE:               u64 = 4004;
    const E_RESULT_TOO_LARGE:           u64 = 4005;

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
    public fun no_pending_root(): u64           { E_NO_PENDING_ROOT }
    public fun not_pending_root(): u64          { E_NOT_PENDING_ROOT }
    public fun role_conflict(): u64             { E_ROLE_CONFLICT }
    public fun cannot_delegate(): u64           { E_CANNOT_DELEGATE }
    public fun protected_target(): u64          { E_PROTECTED_TARGET }

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
    public fun not_self_suspended(): u64        { E_NOT_SELF_SUSPENDED }
    public fun did_not_bound_to_owner(): u64    { E_DID_NOT_BOUND_TO_OWNER }
    public fun owner_locked(): u64              { E_OWNER_LOCKED }


    // === Credential ===

    public fun vc_not_found(): u64              { E_VC_NOT_FOUND }
    public fun vc_not_active(): u64             { E_VC_NOT_ACTIVE }
    public fun vc_not_suspended(): u64          { E_VC_NOT_SUSPENDED }
    public fun vc_already_revoked(): u64        { E_VC_ALREADY_REVOKED }
    public fun vc_already_expired(): u64        { E_VC_ALREADY_EXPIRED }
    public fun not_vc_issuer(): u64             { E_NOT_VC_ISSUER }
    public fun not_vc_holder(): u64             { E_NOT_VC_HOLDER }
    public fun vc_already_exists(): u64         { E_VC_ALREADY_EXISTS }
    public fun self_issue(): u64                { E_SELF_ISSUE }

    // === Utils ===

    public fun hash_wrong_length(): u64         { E_HASH_WRONG_LENGTH }
    public fun hash_mismatch(): u64             { E_HASH_MISMATCH }
    public fun invalid_id(): u64                { E_INVALID_ID }
    public fun invalid_page(): u64              { E_INVALID_PAGE }
    public fun result_too_large(): u64          { E_RESULT_TOO_LARGE }
}