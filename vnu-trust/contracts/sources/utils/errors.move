/// Toan bo ma abort cua goi. Giao dien dich ma theo SO (frontend/src/lib/chain.ts),
/// vi vm_status chi kem ma hex, khong kem ten hang so.
/// Mot so ham truy cap khong con duoc dung trong goi nhung la `public` nen phai
/// giu lai de nang cap `compatible` khong bi tu choi.
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
    /// Sub-issuer duoc cap qua uy quyen ma issuer cha khong con hop le.
    const E_DELEGATOR_NOT_ACTIVE:       u64 = 1019;
    /// vc_type_mask phai khac 0 va chi gom cac bit da dinh nghia; vc_type phai dung MOT bit.
    const E_INVALID_VC_TYPE:            u64 = 1020;
    /// De cu root khong hop le: dia chi 0x0 hoac chinh root hien tai.
    const E_INVALID_ROOT_CANDIDATE:     u64 = 1021;

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
    /// C1: DID da thu hoi la vinh vien - dia chi do khong dang ky lai duoc.
    const E_DID_PERMANENTLY_REVOKED:    u64 = 2013;

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
    /// C2: lo rong, qua 100 muc, hoac co id trung.
    const E_INVALID_BATCH:              u64 = 3011;
    /// C3: VC cu da co ban thay the.
    const E_VC_ALREADY_REPLACED:        u64 = 3012;
    /// C3: doi holder khi DID cua holder cu van ACTIVE.
    const E_HOLDER_STILL_ACTIVE:        u64 = 3013;
    /// C3: nguoi goi khong phai issuer goc / issuer cha cua VC cu.
    const E_NOT_REISSUER:               u64 = 3014;
    /// C3: VC moi khong hop le de noi (trung id, khac loai, khong ACTIVE, da noi).
    const E_INVALID_REPLACEMENT:        u64 = 3015;
    /// C2: VC khong do sub-issuer cua nguoi goi cap.
    const E_NOT_PARENT_ISSUER:          u64 = 3016;


    // ========== Utils ==========
    const E_HASH_WRONG_LENGTH:          u64 = 4001;
    const E_HASH_MISMATCH:              u64 = 4002;
    const E_INVALID_ID:                 u64 = 4003;
    const E_INVALID_PAGE:               u64 = 4004;
    const E_RESULT_TOO_LARGE:           u64 = 4005;
    /// Resource bo sung khi nang cap da duoc khoi tao.
    const E_ALREADY_INITIALIZED:        u64 = 4006;
    /// Resource them khi nang cap chua duoc khoi tao bang entry init_*.
    const E_NOT_INITIALIZED:            u64 = 4007;

    // ========== Public accessors ==========

    // === Authority ===
    public fun not_root_admin(): u64            { E_NOT_ROOT_ADMIN }
    public fun not_admin(): u64                 { E_NOT_ADMIN }
    public fun admin_already_exists(): u64      { E_ADMIN_ALREADY_EXISTS }
    public fun issuer_already_exists(): u64     { E_ISSUER_ALREADY_EXISTS }
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
    public fun delegator_not_active(): u64      { E_DELEGATOR_NOT_ACTIVE }
    public fun invalid_vc_type(): u64           { E_INVALID_VC_TYPE }
    public fun invalid_root_candidate(): u64    { E_INVALID_ROOT_CANDIDATE }

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
    public fun did_permanently_revoked(): u64   { E_DID_PERMANENTLY_REVOKED }


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
    public fun invalid_batch(): u64             { E_INVALID_BATCH }
    public fun vc_already_replaced(): u64       { E_VC_ALREADY_REPLACED }
    public fun holder_still_active(): u64       { E_HOLDER_STILL_ACTIVE }
    public fun not_reissuer(): u64              { E_NOT_REISSUER }
    public fun invalid_replacement(): u64       { E_INVALID_REPLACEMENT }
    public fun not_parent_issuer(): u64         { E_NOT_PARENT_ISSUER }

    // === Utils ===

    public fun hash_wrong_length(): u64         { E_HASH_WRONG_LENGTH }
    public fun hash_mismatch(): u64             { E_HASH_MISMATCH }
    public fun invalid_id(): u64                { E_INVALID_ID }
    public fun invalid_page(): u64              { E_INVALID_PAGE }
    public fun result_too_large(): u64          { E_RESULT_TOO_LARGE }
    public fun already_initialized(): u64       { E_ALREADY_INITIALIZED }
    public fun not_initialized(): u64           { E_NOT_INITIALIZED }
}