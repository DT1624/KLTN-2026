/// Vong doi van bang (VC). Tren chuoi chi luu hash va CID, noi dung nam tren IPFS.
///
///   issue_vc --> ACTIVE --(issuer suspend_vc / admin_suspend_vc)--> SUSPENDED
///                  ^                                                   |
///                  +-------------- admin_reinstate_vc (chi admin) -----+
///   ACTIVE | SUSPENDED --(issuer revoke_vc / admin_revoke_vc)--> REVOKED (vinh vien)
///   ACTIVE | SUSPENDED --(now >= expires_at)--> EXPIRED  (tinh khi doc, khong ghi)
///
/// EXPIRED chi chuyen tiep duoc sang REVOKED: thu hoi la loi tuyen bo vinh vien
/// ve gian lan, khong duoc het han truoc khi kip tuyen bo.
module vnu::vc_registry {

    use std::signer;
    use std::vector;
    use aptos_std::smart_table::{Self, SmartTable};
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use vnu::constants;
    use vnu::did_registry;
    use vnu::authority;
    use vnu::errors;

    // ========== Constants ==========

    const VC_STATUS_ACTIVE:     u8 = 1;
    const VC_STATUS_SUSPENDED:  u8 = 2;
    /// Khong bao gio duoc GHI - chi xuat hien trong ket qua doc.
    const VC_STATUS_EXPIRED:    u8 = 3;
    const VC_STATUS_REVOKED:    u8 = 4;

    const MAX_VIEW_ITEMS:       u64 = 500;
    const MAX_PAGE_LIMIT:       u64 = 200;

    // ========== Structs ==========

    struct VCRecord has copy, drop, store {
        id: u64,
        issuer_addr: address,
        holder_addr: address,
        /// SHA3-256 cua chuoi vc_id - khong luu vc_id dang ro.
        vc_id_hash: vector<u8>,
        content_cid: vector<u8>,
        /// SHA3-256 cua toan bo noi dung VC.
        content_hash: vector<u8>,
        /// Dung MOT bit loai van bang.
        vc_type: u64,
        /// Trang thai DA GHI (ACTIVE / SUSPENDED / REVOKED). Doc qua view thi
        /// truong nay da duoc thay bang trang thai co hieu luc.
        status: u8,
        issued_at: u64,
        /// 0 = vinh vien
        expires_at: u64,
        revoked_at: u64,
        status_reason: vector<u8>,
    }

    struct VCRegistry has key {
        vc_count: u64,
        vcs: SmartTable<u64, VCRecord>,
        hash_to_id: SmartTable<vector<u8>, u64>,
        /// Tong da tung cap, khong bao gio giam.
        issuer_vc_count: SmartTable<address, u64>,
        holder_vc_count: SmartTable<address, u64>,
        /// So VC dang o trang thai GHI la ACTIVE: giam khi tam ngung/thu hoi,
        /// tang khi kich hoat lai. Khong tru VC het han (het han khong phai
        /// mot giao dich), nen day la CAN TREN cua so VC con hieu luc.
        issuer_live_vc_count: SmartTable<address, u64>,
        holder_live_vc_count: SmartTable<address, u64>,
    }

    // ========== Events ==========

    #[event]
    struct VCIssuedEvent has drop, store {
        id: u64,
        issuer_addr: address,
        issuer_did: vector<u8>,
        holder_addr: address,
        holder_did: vector<u8>,
        vc_id_hash: vector<u8>,
        content_cid: vector<u8>,
        vc_type: u64,
        issued_at: u64,
        expires_at: u64,
    }

    #[event]
    struct VCStatusChangedEvent has drop, store {
        id: u64,
        holder_addr: address,
        new_status: u8,
        reason: vector<u8>,
        changed_by: address,
        at: u64,
    }

    // ========== Init ==========

    fun init_module(publisher: &signer) {
        move_to(publisher, VCRegistry {
            vc_count: 0,
            vcs: smart_table::new(),
            hash_to_id: smart_table::new(),
            issuer_vc_count: smart_table::new(),
            holder_vc_count: smart_table::new(),
            issuer_live_vc_count: smart_table::new(),
            holder_live_vc_count: smart_table::new(),
        })
    }

    // ========== Entry functions ==========

    /// Issuer cap VC cho holder.
    /// - holder khac issuer, holder co DID ACTIVE;
    /// - issuer dang hop le (DID, vai tro, han, issuer cha) va `vc_type` la
    ///   MOT bit nam trong mask cua issuer;
    /// - hai hash dung 32 byte, CID hop le, `vc_id_hash` chua tung dung;
    /// - `expires_at` = 0 (vinh vien) hoac o tuong lai.
    /// DID cua issuer/holder lay tu dia chi, khong nhan tu tham so.
    public entry fun issue_vc(
        issuer: &signer,
        holder_addr: address,
        vc_type: u64,
        vc_id_hash: vector<u8>,
        content_cid: vector<u8>,
        content_hash: vector<u8>,
        expires_at: u64,
    ) acquires VCRegistry {
        let issuer_addr = signer::address_of(issuer);
        let now = timestamp::now_seconds();
        assert_issue_input(issuer_addr, holder_addr, vc_type, &vc_id_hash, &content_cid, &content_hash, expires_at, now);

        authority::assert_is_active_issuer(issuer_addr, vc_type);
        let issuer_did = did_registry::get_active_did_string(issuer_addr);
        let holder_did = did_registry::get_active_did_string(holder_addr);

        let reg = borrow_global_mut<VCRegistry>(@vnu);
        assert!(!smart_table::contains(&reg.hash_to_id, vc_id_hash), errors::vc_already_exists());

        let id = reg.vc_count;
        smart_table::add(&mut reg.vcs, id, VCRecord {
            id,
            issuer_addr,
            holder_addr,
            vc_id_hash,
            content_cid,
            content_hash,
            vc_type,
            status: VC_STATUS_ACTIVE,
            issued_at: now,
            expires_at,
            revoked_at: 0,
            status_reason: b"",
        });
        smart_table::add(&mut reg.hash_to_id, vc_id_hash, id);
        reg.vc_count = id + 1;
        increment(&mut reg.issuer_vc_count, issuer_addr);
        increment(&mut reg.holder_vc_count, holder_addr);
        add_live(reg, issuer_addr, holder_addr);

        event::emit(VCIssuedEvent {
            id,
            issuer_addr,
            issuer_did,
            holder_addr,
            holder_did,
            vc_id_hash,
            content_cid,
            vc_type,
            issued_at: now,
            expires_at,
        });
    }

    /// Issuer tam ngung VC cua chinh minh. Khong tu kich hoat lai duoc.
    public entry fun suspend_vc(issuer: &signer, vc_id: u64, reason: vector<u8>) acquires VCRegistry {
        set_status(signer::address_of(issuer), false, vc_id, VC_STATUS_SUSPENDED, reason);
    }

    /// Issuer thu hoi VC cua chinh minh (ke ca khi da het han uy quyen).
    public entry fun revoke_vc(issuer: &signer, vc_id: u64, reason: vector<u8>) acquires VCRegistry {
        set_status(signer::address_of(issuer), false, vc_id, VC_STATUS_REVOKED, reason);
    }

    public entry fun admin_suspend_vc(admin: &signer, vc_id: u64, reason: vector<u8>) acquires VCRegistry {
        set_status(signer::address_of(admin), true, vc_id, VC_STATUS_SUSPENDED, reason);
    }

    /// Chi admin kich hoat lai: issuer tu ngung roi tu bat la ne kiem toan.
    public entry fun admin_reinstate_vc(admin: &signer, vc_id: u64, reason: vector<u8>) acquires VCRegistry {
        set_status(signer::address_of(admin), true, vc_id, VC_STATUS_ACTIVE, reason);
    }

    public entry fun admin_revoke_vc(admin: &signer, vc_id: u64, reason: vector<u8>) acquires VCRegistry {
        set_status(signer::address_of(admin), true, vc_id, VC_STATUS_REVOKED, reason);
    }

    // ========== Views ==========

    #[view]
    /// Trang thai co hieu luc (co tinh het han).
    public fun get_vc_status(vc_id: u64): u8 acquires VCRegistry {
        record_status(&get_vc_by_id(vc_id))
    }

    #[view]
    /// Ban ghi VC voi `status` la trang thai co hieu luc. Khong abort khi VC
    /// het han hay bi thu hoi - ben xac minh tu danh gia.
    public fun get_vc_by_id(vc_id: u64): VCRecord acquires VCRegistry {
        let reg = borrow_global<VCRegistry>(@vnu);
        assert!(smart_table::contains(&reg.vcs, vc_id), errors::vc_not_found());
        with_effective_status(*smart_table::borrow(&reg.vcs, vc_id), timestamp::now_seconds())
    }

    #[view]
    public fun get_vc_id_by_hash(vc_id_hash: vector<u8>): u64 acquires VCRegistry {
        let reg = borrow_global<VCRegistry>(@vnu);
        assert!(smart_table::contains(&reg.hash_to_id, vc_id_hash), errors::vc_not_found());
        *smart_table::borrow(&reg.hash_to_id, vc_id_hash)
    }

    #[view]
    /// `true` khi VC ton tai, dang co hieu luc VA `claimed_hash` khop ban neo.
    public fun verify_integrity(vc_id: u64, claimed_hash: vector<u8>): bool acquires VCRegistry {
        let reg = borrow_global<VCRegistry>(@vnu);
        if (!smart_table::contains(&reg.vcs, vc_id)) return false;
        let record = smart_table::borrow(&reg.vcs, vc_id);
        effective_status(record, timestamp::now_seconds()) == VC_STATUS_ACTIVE
            && record.content_hash == claimed_hash
    }

    #[view]
    /// (tong issuer da cap, tong holder da nhan) - khong giam khi thu hoi.
    public fun get_counts(issuer: address, holder: address): (u64, u64) acquires VCRegistry {
        let reg = borrow_global<VCRegistry>(@vnu);
        (count_of(&reg.issuer_vc_count, issuer), count_of(&reg.holder_vc_count, holder))
    }

    #[view]
    /// (so VC cua issuer, cua holder dang ghi la ACTIVE) - xem chu thich VCRegistry.
    public fun get_live_counts(issuer: address, holder: address): (u64, u64) acquires VCRegistry {
        let reg = borrow_global<VCRegistry>(@vnu);
        (count_of(&reg.issuer_live_vc_count, issuer), count_of(&reg.holder_live_vc_count, holder))
    }

    #[view]
    public fun total_vcs(): u64 acquires VCRegistry {
        borrow_global<VCRegistry>(@vnu).vc_count
    }

    #[view]
    /// Moi vc_id_hash. Vuot 500 thi abort, dung ban phan trang.
    public fun get_vcs(): vector<vector<u8>> acquires VCRegistry {
        let reg = borrow_global<VCRegistry>(@vnu);
        assert!(smart_table::length(&reg.hash_to_id) <= MAX_VIEW_ITEMS, errors::result_too_large());
        smart_table::keys(&reg.hash_to_id)
    }

    #[view]
    /// VC co id trong [start, start + limit), theo thu tu id, trang thai co hieu luc.
    public fun get_vcs_paginated(start: u64, limit: u64): vector<VCRecord> acquires VCRegistry {
        assert!(limit > 0 && limit <= MAX_PAGE_LIMIT, errors::invalid_page());
        let reg = borrow_global<VCRegistry>(@vnu);
        let now = timestamp::now_seconds();
        let out = vector::empty<VCRecord>();
        let id = start;
        while (vector::length(&out) < limit && id < reg.vc_count) {
            vector::push_back(&mut out, with_effective_status(*smart_table::borrow(&reg.vcs, id), now));
            id = id + 1;
        };
        out
    }

    // Truy cap truong cua VCRecord tu ngoai module (cac truong la rieng tu).
    public fun record_status(record: &VCRecord): u8 { record.status }
    public fun record_expires_at(record: &VCRecord): u64 { record.expires_at }
    public fun record_id(record: &VCRecord): u64 { record.id }
    public fun record_holder(record: &VCRecord): address { record.holder_addr }
    public fun record_issuer(record: &VCRecord): address { record.issuer_addr }

    // ========== Internal ==========

    /// Het han tinh khi doc va lan ca tam ngung; chi REVOKED dung tren no.
    fun effective_status(record: &VCRecord, now: u64): u8 {
        if (record.status != VC_STATUS_REVOKED && record.expires_at != 0 && now >= record.expires_at) {
            VC_STATUS_EXPIRED
        } else {
            record.status
        }
    }

    fun with_effective_status(record: VCRecord, now: u64): VCRecord {
        record.status = effective_status(&record, now);
        record
    }

    /// Kiem dau vao cua issue_vc, khong doc storage. Thu tu va ma loi:
    /// E_SELF_ISSUE, E_INVALID_VC_TYPE, E_HASH_WRONG_LENGTH (vc_id_hash roi
    /// content_hash), E_INVALID_CID (tai did_registry), E_VC_ALREADY_EXPIRED.
    fun assert_issue_input(
        issuer_addr: address,
        holder_addr: address,
        vc_type: u64,
        vc_id_hash: &vector<u8>,
        content_cid: &vector<u8>,
        content_hash: &vector<u8>,
        expires_at: u64,
        now: u64,
    ) {
        assert!(holder_addr != issuer_addr, errors::self_issue());
        assert!(constants::is_single_vc_type(vc_type), errors::invalid_vc_type());
        assert!(vector::length(vc_id_hash) == 32, errors::hash_wrong_length());
        assert!(vector::length(content_hash) == 32, errors::hash_wrong_length());
        did_registry::assert_valid_cid(content_cid);
        assert!(expires_at == 0 || expires_at > now, errors::vc_already_expired());
    }

    /// Duong doi trang thai duy nhat cho ca issuer va admin.
    ///   admin : root hoac admin dang hoat dong, moi VC.
    ///   issuer: chi VC do minh cap; DID ACTIVE, vai tro chua bi tam ngung/thu hoi.
    fun set_status(caller: address, as_admin: bool, vc_id: u64, new_status: u8, reason: vector<u8>) acquires VCRegistry {
        if (as_admin) authority::assert_is_active_admin(caller);
        let reg = borrow_global_mut<VCRegistry>(@vnu);
        assert!(smart_table::contains(&reg.vcs, vc_id), errors::vc_not_found());
        let now = timestamp::now_seconds();
        let record = smart_table::borrow_mut(&mut reg.vcs, vc_id);
        if (!as_admin) {
            assert!(record.issuer_addr == caller, errors::not_vc_issuer());
            authority::assert_can_manage_own_vcs(caller);
        };
        assert_vc_transition(record, new_status, now);

        let was_live = record.status == VC_STATUS_ACTIVE;
        let (issuer_addr, holder_addr) = (record.issuer_addr, record.holder_addr);
        record.status = new_status;
        record.status_reason = reason;
        if (new_status == VC_STATUS_REVOKED) record.revoked_at = now;

        // Chuyen sang ACTIVE chi xay ra tu SUSPENDED, nen `is_live` keo theo `!was_live`.
        let is_live = new_status == VC_STATUS_ACTIVE;
        if (was_live && !is_live) {
            remove_live(reg, issuer_addr, holder_addr);
        } else if (is_live) {
            add_live(reg, issuer_addr, holder_addr);
        };

        event::emit(VCStatusChangedEvent { id: vc_id, holder_addr, new_status, reason, changed_by: caller, at: now });
    }

    /// Luat chuyen trang thai VC. Thu tu va ma loi:
    ///   da REVOKED                         -> E_VC_ALREADY_REVOKED
    ///   khong phai thu hoi ma da het han   -> E_VC_ALREADY_EXPIRED
    ///   -> SUSPENDED tu khac ACTIVE        -> E_VC_NOT_ACTIVE
    ///   -> ACTIVE tu khac SUSPENDED        -> E_VC_NOT_SUSPENDED
    fun assert_vc_transition(record: &VCRecord, new_status: u8, now: u64) {
        assert!(record.status != VC_STATUS_REVOKED, errors::vc_already_revoked());
        if (new_status != VC_STATUS_REVOKED) {
            assert!(effective_status(record, now) != VC_STATUS_EXPIRED, errors::vc_already_expired());
        };
        if (new_status == VC_STATUS_SUSPENDED) {
            assert!(record.status == VC_STATUS_ACTIVE, errors::vc_not_active());
        } else if (new_status == VC_STATUS_ACTIVE) {
            assert!(record.status == VC_STATUS_SUSPENDED, errors::vc_not_suspended());
        };
    }

    /// Them mot VC "song" vao bo dem cua ca issuer va holder. Khong abort.
    fun add_live(reg: &mut VCRegistry, issuer_addr: address, holder_addr: address) {
        increment(&mut reg.issuer_live_vc_count, issuer_addr);
        increment(&mut reg.holder_live_vc_count, holder_addr);
    }

    /// Bot mot VC "song" khoi bo dem cua ca issuer va holder. Khong abort.
    fun remove_live(reg: &mut VCRegistry, issuer_addr: address, holder_addr: address) {
        decrement(&mut reg.issuer_live_vc_count, issuer_addr);
        decrement(&mut reg.holder_live_vc_count, holder_addr);
    }

    fun count_of(table: &SmartTable<address, u64>, addr: address): u64 {
        *smart_table::borrow_with_default(table, addr, &0)
    }

    fun increment(table: &mut SmartTable<address, u64>, addr: address) {
        let c = smart_table::borrow_mut_with_default(table, addr, 0);
        *c = *c + 1;
    }

    /// Khong bao gio abort: bo dem chi la so thong ke, khong duoc phep chan
    /// mot thao tac thu hoi ke ca khi no tung bi lech.
    fun decrement(table: &mut SmartTable<address, u64>, addr: address) {
        let c = smart_table::borrow_mut_with_default(table, addr, 0);
        if (*c > 0) *c = *c - 1;
    }

    // ========== Test-only ==========

    #[test_only]
    public fun initialize_for_test(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    /// Ban ghi DA GHI (status chua tinh het han).
    public fun stored_record(vc_id: u64): VCRecord acquires VCRegistry {
        *smart_table::borrow(&borrow_global<VCRegistry>(@vnu).vcs, vc_id)
    }

    #[test_only]
    public fun record_fields(r: &VCRecord): (u64, address, address, vector<u8>, vector<u8>, vector<u8>, u64, u8, u64, u64, u64, vector<u8>) {
        (r.id, r.issuer_addr, r.holder_addr, r.vc_id_hash, r.content_cid, r.content_hash, r.vc_type,
         r.status, r.issued_at, r.expires_at, r.revoked_at, r.status_reason)
    }

    #[test_only]
    public fun vc_issued_event(
        id: u64, issuer_addr: address, issuer_did: vector<u8>, holder_addr: address, holder_did: vector<u8>,
        vc_id_hash: vector<u8>, content_cid: vector<u8>, vc_type: u64, issued_at: u64, expires_at: u64,
    ): VCIssuedEvent {
        VCIssuedEvent { id, issuer_addr, issuer_did, holder_addr, holder_did, vc_id_hash, content_cid, vc_type, issued_at, expires_at }
    }

    #[test_only]
    public fun vc_status_changed_event(id: u64, holder_addr: address, new_status: u8, reason: vector<u8>, changed_by: address, at: u64): VCStatusChangedEvent {
        VCStatusChangedEvent { id, holder_addr, new_status, reason, changed_by, at }
    }
}
