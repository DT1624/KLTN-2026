/// Vong doi DID.
///
///   register_did ----> ACTIVE <----------------------------+
///                        |  suspend_own_did (chu tu khoa)   | reactivate_own_did (chi chu)
///                        |----------------------> SUSPENDED(by chu)
///                        |  admin_suspend_did               |  admin_suspend_did = tiep quan
///                        |----------------------> SUSPENDED(by admin) -- admin_reactivate_did --> ACTIVE
///                        |  admin_revoke_did (tu ACTIVE hoac SUSPENDED)
///                        +----------------------> REVOKED  (vinh vien; chu duoc dang ky DID MOI)
///
/// Ai duoc goi cac ham admin_* va bao ve root/admin la viec cua `authority`.
module vnu::did_registry {

    use std::bcs;
    use std::signer;
    use std::vector;
    use aptos_std::smart_table;
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use vnu::constants;
    use vnu::errors;

    friend vnu::authority;
    friend vnu::vc_registry;

    // ========== Constants ==========

    const DID_STATUS_ACTIVE:    u8 = 1;
    const DID_STATUS_SUSPENDED: u8 = 2;
    const DID_STATUS_REVOKED:   u8 = 3;

    /// Gia tri `suspended_by` khi DID khong bi tam ngung.
    const NOBODY:               address = @0x0;

    /// Moi chuoi DID cua he thong deu thuoc phuong thuc nay.
    const DID_PREFIX:           vector<u8> = b"did:vnu:";
    /// "did:vnu:" + phan giua + "0x" + 64 hex. 128 la du rong ma van chan rac.
    const MAX_DID_LEN:          u64 = 128;

    /// Khong ep mot ho CID cu the (v0 `Qm...` va v1 `bafy...` deu hop le),
    /// chi chan cac gia tri khong the nao la CID that.
    const MIN_CID_LEN:          u64 = 10;
    const MAX_CID_LEN:          u64 = 128;

    const MAX_VIEW_ITEMS:       u64 = 500;
    const MAX_PAGE_LIMIT:       u64 = 200;

    // ========== Structs ==========

    struct DIDRecord has copy, drop, store {
        id: u64,
        owner: address,
        /// vd "did:vnu:holder:0x<64 hex>" - luon ket thuc bang dia chi chu so huu
        did_string: vector<u8>,
        /// CID cua DID Document tren IPFS
        document_cid: vector<u8>,
        /// SHA3-256 cua DID Document (32 byte)
        document_hash: vector<u8>,
        status: u8,
        created_at: u64,
        updated_at: u64,
        version: u64,
        /// Ai da dat DID ve SUSPENDED; @0x0 neu khong bi tam ngung.
        suspended_by: address,
    }

    struct DIDRegistry has key {
        /// So DID da tung dang ky, cung la id cua DID tiep theo.
        did_count: u64,
        dids: smart_table::SmartTable<u64, DIDRecord>,
        did_string_to_id: smart_table::SmartTable<vector<u8>, u64>,
        /// Tro toi DID HIEN HANH cua dia chi (DID cu bi thu hoi van nam trong `dids`).
        owner_to_id: smart_table::SmartTable<address, u64>,
    }

    // ========== Events ==========

    #[event]
    struct DIDRegisteredEvent has drop, store {
        id: u64,
        owner: address,
        did_string: vector<u8>,
        document_cid: vector<u8>,
        at: u64,
    }

    #[event]
    struct DIDDocumentUpdatedEvent has drop, store {
        id: u64,
        owner: address,
        new_document_cid: vector<u8>,
        new_version: u64,
        at: u64,
    }

    #[event]
    struct DIDStatusChangedEvent has drop, store {
        id: u64,
        owner: address,
        changed_by: address,
        new_status: u8,
        reason: vector<u8>,
        at: u64,
    }

    // ========== Init ==========

    fun init_module(publisher: &signer) {
        move_to(
            publisher,
            DIDRegistry {
                did_count: 0,
                dids: smart_table::new<u64, DIDRecord>(),
                did_string_to_id: smart_table::new<vector<u8>, u64>(),
                owner_to_id: smart_table::new<address, u64>(),
            }
        );
    }

    // ========== Entry functions (chu so huu) ==========

    /// Dang ky DID cho chinh nguoi ky.
    /// - `did_string`: "did:vnu:...<dia chi nguoi ky>", toi da 128 byte, chua tung dung.
    /// - Moi dia chi chi co MOT DID hien hanh; chi dang ky lai duoc khi DID cu
    ///   da bi thu hoi. Thu hoi DID cung thu hoi moi vai tro (xem authority),
    ///   nen dang ky lai chi cho mot danh tinh tran, nhu mot dia chi moi.
    public entry fun register_did(
        owner: &signer,
        did_string: vector<u8>,
        document_cid: vector<u8>,
        document_hash: vector<u8>,
    ) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        assert_valid_did_string(&did_string, owner_addr);
        assert_valid_cid(&document_cid);
        assert!(vector::length(&document_hash) == 32, errors::hash_wrong_length());

        let reg = borrow_global_mut<DIDRegistry>(@vnu);
        let version = 1;
        if (smart_table::contains(&reg.owner_to_id, owner_addr)) {
            let prev = record_of(reg, owner_addr);
            assert!(prev.status == DID_STATUS_REVOKED, errors::owner_has_did());
            version = prev.version + 1;
        };
        assert!(
            !smart_table::contains(&reg.did_string_to_id, did_string),
            errors::did_already_registered()
        );

        let id = reg.did_count;
        let now = timestamp::now_seconds();
        smart_table::add(&mut reg.dids, id, DIDRecord {
            id,
            owner: owner_addr,
            did_string,
            document_cid,
            document_hash,
            status: DID_STATUS_ACTIVE,
            created_at: now,
            updated_at: now,
            version,
            suspended_by: NOBODY,
        });
        smart_table::add(&mut reg.did_string_to_id, did_string, id);
        smart_table::upsert(&mut reg.owner_to_id, owner_addr, id);
        reg.did_count = id + 1;

        event::emit(DIDRegisteredEvent { id, owner: owner_addr, did_string, document_cid, at: now });
    }

    /// Chu so huu thay DID Document (xoay khoa, them khoa...).
    /// `expected_version` chong ghi de khi hai thiet bi cung cap nhat.
    public entry fun update_did_document(
        owner: &signer,
        new_document_cid: vector<u8>,
        new_document_hash: vector<u8>,
        expected_version: u64,
    ) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        assert_valid_cid(&new_document_cid);
        assert!(vector::length(&new_document_hash) == 32, errors::hash_wrong_length());

        let record = record_of_mut(borrow_global_mut<DIDRegistry>(@vnu), owner_addr);
        assert!(record.status == DID_STATUS_ACTIVE, errors::did_not_active());
        assert!(record.version == expected_version, errors::stable_did_version());

        let now = timestamp::now_seconds();
        record.document_cid = new_document_cid;
        record.document_hash = new_document_hash;
        record.version = record.version + 1;
        record.updated_at = now;

        event::emit(DIDDocumentUpdatedEvent {
            id: record.id,
            owner: owner_addr,
            new_document_cid,
            new_version: record.version,
            at: now,
        });
    }

    /// Chu so huu tu khoa DID cua minh (vd nghi lo khoa). Trong luc khoa, moi
    /// vai tro cua dia chi nay deu khong dung duoc va khong nhan VC moi.
    public entry fun suspend_own_did(owner: &signer) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        set_status(owner_addr, DID_STATUS_SUSPENDED, owner_addr, constants::REASON_TYPE_OTHER());
    }

    /// Ten cu cua `suspend_own_did`. Giu lai vi ham `public entry` khong xoa
    /// duoc khi nang cap.
    public entry fun deactivate_did(owner: &signer) acquires DIDRegistry {
        suspend_own_did(owner);
    }

    /// Chu so huu mo lai DID do CHINH MINH khoa. DID bi admin khoa (ke ca khi
    /// admin tiep quan mot khoa cua chu) thi chi admin mo duoc.
    public entry fun reactivate_own_did(owner: &signer) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        let record = record_of(borrow_global<DIDRegistry>(@vnu), owner_addr);
        assert!(record.status == DID_STATUS_SUSPENDED, errors::did_not_suspended());
        assert!(record.suspended_by == owner_addr, errors::not_self_suspended());
        set_status(owner_addr, DID_STATUS_ACTIVE, owner_addr, constants::REASON_TYPE_OTHER());
    }

    // ========== Friend functions (authority kiem quyen truoc khi goi) ==========

    /// Admin khoa DID. Neu chu da tu khoa thi admin TIEP QUAN khoa do: DID van
    /// SUSPENDED nhung tu nay chi admin mo duoc. Khong co buoc nay, nguoi sap
    /// bi ky luat chi can tu khoa truoc la admin het cach khoa cuong che (M-08).
    public(friend) fun admin_suspend_did(
        admin_addr: address,
        target_owner: address,
        reason: vector<u8>,
    ) acquires DIDRegistry {
        set_status(target_owner, DID_STATUS_SUSPENDED, admin_addr, reason);
    }

    /// Admin mo DID do admin khoa. DID chu tu khoa thi admin KHONG mo thay.
    public(friend) fun admin_reactivate_did(
        admin_addr: address,
        target_owner: address,
        reason: vector<u8>,
    ) acquires DIDRegistry {
        // DID ACTIVE co suspended_by = @0x0 nen qua duoc dong nay va bi
        // set_status chan bang E_DID_NOT_SUSPENDED.
        let locker = record_of(borrow_global<DIDRegistry>(@vnu), target_owner).suspended_by;
        assert!(locker != target_owner, errors::owner_locked());
        set_status(target_owner, DID_STATUS_ACTIVE, admin_addr, reason);
    }

    public(friend) fun admin_revoke_did(
        admin_addr: address,
        target_owner: address,
        reason: vector<u8>,
    ) acquires DIDRegistry {
        set_status(target_owner, DID_STATUS_REVOKED, admin_addr, reason);
    }

    /// Abort neu dia chi khong co DID hien hanh dang ACTIVE.
    public(friend) fun assert_owner_active(owner: address) acquires DIDRegistry {
        get_active_did_string(owner);
    }

    /// Chuoi DID hien hanh cua dia chi; abort neu DID khong ACTIVE.
    public(friend) fun get_active_did_string(owner: address): vector<u8> acquires DIDRegistry {
        let record = record_of(borrow_global<DIDRegistry>(@vnu), owner);
        assert!(record.status == DID_STATUS_ACTIVE, errors::did_not_active());
        record.did_string
    }

    /// Luat CID dung chung cho DID Document, noi dung VC va VC uy quyen.
    public(friend) fun assert_valid_cid(cid: &vector<u8>) {
        let len = vector::length(cid);
        assert!(len >= MIN_CID_LEN && len <= MAX_CID_LEN, errors::invalid_cid());
    }

    // ========== Views ==========

    #[view]
    /// (did_string, document_cid, document_hash, status, version)
    public fun resolve_did(did_string: vector<u8>): (vector<u8>, vector<u8>, vector<u8>, u8, u64) acquires DIDRegistry {
        let r = get_did(did_string);
        (r.did_string, r.document_cid, r.document_hash, r.status, r.version)
    }

    #[view]
    public fun resolve_did_by_owner(owner: address): (vector<u8>, vector<u8>, vector<u8>, u8, u64) acquires DIDRegistry {
        let r = get_did_by_owner(owner);
        (r.did_string, r.document_cid, r.document_hash, r.status, r.version)
    }

    #[view]
    public fun get_did(did_string: vector<u8>): DIDRecord acquires DIDRegistry {
        let reg = borrow_global<DIDRegistry>(@vnu);
        assert!(smart_table::contains(&reg.did_string_to_id, did_string), errors::did_not_found());
        *smart_table::borrow(&reg.dids, *smart_table::borrow(&reg.did_string_to_id, did_string))
    }

    #[view]
    public fun get_did_by_owner(owner: address): DIDRecord acquires DIDRegistry {
        *record_of(borrow_global<DIDRegistry>(@vnu), owner)
    }

    #[view]
    public fun has_active_did(owner: address): bool acquires DIDRegistry {
        let reg = borrow_global<DIDRegistry>(@vnu);
        smart_table::contains(&reg.owner_to_id, owner)
            && record_of(reg, owner).status == DID_STATUS_ACTIVE
    }

    #[view]
    public fun total_dids(): u64 acquires DIDRegistry {
        borrow_global<DIDRegistry>(@vnu).did_count
    }

    #[view]
    /// Moi chuoi DID (ke ca DID cu da thu hoi). Vuot 500 thi abort, dung ban phan trang.
    public fun get_dids(): vector<vector<u8>> acquires DIDRegistry {
        let reg = borrow_global<DIDRegistry>(@vnu);
        assert!(smart_table::length(&reg.did_string_to_id) <= MAX_VIEW_ITEMS, errors::result_too_large());
        smart_table::keys(&reg.did_string_to_id)
    }

    #[view]
    public fun get_owners(): vector<address> acquires DIDRegistry {
        let reg = borrow_global<DIDRegistry>(@vnu);
        assert!(smart_table::length(&reg.owner_to_id) <= MAX_VIEW_ITEMS, errors::result_too_large());
        smart_table::keys(&reg.owner_to_id)
    }

    #[view]
    /// Cac DID co id trong [start, start + limit), theo thu tu id.
    public fun get_dids_paginated(start: u64, limit: u64): vector<DIDRecord> acquires DIDRegistry {
        assert!(limit > 0 && limit <= MAX_PAGE_LIMIT, errors::invalid_page());
        let reg = borrow_global<DIDRegistry>(@vnu);
        let out = vector::empty<DIDRecord>();
        let id = start;
        // Dung `id < did_count` lam dieu kien dung, khong tinh `start + limit`
        // de start gan u64::MAX khong gay tran so.
        while (vector::length(&out) < limit && id < reg.did_count) {
            vector::push_back(&mut out, *smart_table::borrow(&reg.dids, id));
            id = id + 1;
        };
        out
    }

    // ========== Internal ==========

    /// Ban ghi DID hien hanh cua dia chi; abort E_OWNER_NOT_EXISTS neu chua co.
    fun record_of(reg: &DIDRegistry, owner: address): &DIDRecord {
        assert!(smart_table::contains(&reg.owner_to_id, owner), errors::owner_not_exists());
        smart_table::borrow(&reg.dids, *smart_table::borrow(&reg.owner_to_id, owner))
    }

    fun record_of_mut(reg: &mut DIDRegistry, owner: address): &mut DIDRecord {
        assert!(smart_table::contains(&reg.owner_to_id, owner), errors::owner_not_exists());
        let id = *smart_table::borrow(&reg.owner_to_id, owner);
        smart_table::borrow_mut(&mut reg.dids, id)
    }

    /// Bang chuyen trang thai duy nhat cua DID:
    ///   -> REVOKED   : tu ACTIVE hoac SUSPENDED
    ///   -> SUSPENDED : tu ACTIVE; hoac tiep quan khoa cua chu (nguoi khoa moi khac chu)
    ///   -> ACTIVE    : tu SUSPENDED (ai duoc mo do ham goi kiem)
    fun set_status(
        target_owner: address,
        new_status: u8,
        changed_by: address,
        reason: vector<u8>,
    ) acquires DIDRegistry {
        let record = record_of_mut(borrow_global_mut<DIDRegistry>(@vnu), target_owner);
        assert!(record.status != DID_STATUS_REVOKED, errors::did_already_revoked());
        if (new_status == DID_STATUS_SUSPENDED) {
            let takeover = record.status == DID_STATUS_SUSPENDED
                && record.suspended_by == target_owner
                && changed_by != target_owner;
            assert!(record.status == DID_STATUS_ACTIVE || takeover, errors::did_not_active());
        } else if (new_status == DID_STATUS_ACTIVE) {
            assert!(record.status == DID_STATUS_SUSPENDED, errors::did_not_suspended());
        };

        let now = timestamp::now_seconds();
        record.status = new_status;
        record.suspended_by = if (new_status == DID_STATUS_SUSPENDED) changed_by else NOBODY;
        record.updated_at = now;

        event::emit(DIDStatusChangedEvent {
            id: record.id,
            owner: target_owner,
            changed_by,
            new_status,
            reason,
            at: now,
        });
    }

    /// "did:vnu:" + ... + dia chi chu so huu (0x + 64 hex thuong), toi da 128 byte.
    /// Rang buoc hau to chan viec chiem truoc DID cua nguoi khac.
    fun assert_valid_did_string(did: &vector<u8>, owner: address) {
        let prefix = DID_PREFIX;
        let suffix = address_hex(owner);
        let (n, p, m) = (vector::length(did), vector::length(&prefix), vector::length(&suffix));
        assert!(n >= p + m && n <= MAX_DID_LEN, errors::did_not_bound_to_owner());
        let i = 0;
        while (i < p) {
            assert!(*vector::borrow(did, i) == *vector::borrow(&prefix, i), errors::did_not_bound_to_owner());
            i = i + 1;
        };
        let j = 0;
        while (j < m) {
            assert!(*vector::borrow(did, n - m + j) == *vector::borrow(&suffix, j), errors::did_not_bound_to_owner());
            j = j + 1;
        };
    }

    /// Dia chi dang "0x" + 64 hex chu thuong.
    fun address_hex(addr: address): vector<u8> {
        let digits = b"0123456789abcdef";
        let out = b"0x";
        let bytes = bcs::to_bytes(&addr);
        let i = 0;
        while (i < vector::length(&bytes)) {
            let b = (*vector::borrow(&bytes, i) as u64);
            vector::push_back(&mut out, *vector::borrow(&digits, b / 16));
            vector::push_back(&mut out, *vector::borrow(&digits, b % 16));
            i = i + 1;
        };
        out
    }

    // ========== Test-only ==========

    #[test_only]
    public fun initialize_for_test(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public fun address_hex_for_test(addr: address): vector<u8> { address_hex(addr) }

    #[test_only]
    public fun status_of(owner: address): u8 acquires DIDRegistry {
        get_did_by_owner(owner).status
    }

    #[test_only]
    public fun suspended_by_of(owner: address): address acquires DIDRegistry {
        get_did_by_owner(owner).suspended_by
    }

    #[test_only]
    public fun version_of(owner: address): u64 acquires DIDRegistry {
        get_did_by_owner(owner).version
    }

    #[test_only]
    public fun did_id_of(owner: address): u64 acquires DIDRegistry {
        get_did_by_owner(owner).id
    }

    #[test_only]
    public fun record_fields(r: &DIDRecord): (u64, address, vector<u8>, vector<u8>, vector<u8>, u8, u64, u64, u64, address) {
        (r.id, r.owner, r.did_string, r.document_cid, r.document_hash, r.status, r.created_at, r.updated_at, r.version, r.suspended_by)
    }

    #[test_only]
    public fun did_registered_event(id: u64, owner: address, did_string: vector<u8>, document_cid: vector<u8>, at: u64): DIDRegisteredEvent {
        DIDRegisteredEvent { id, owner, did_string, document_cid, at }
    }

    #[test_only]
    public fun did_document_updated_event(id: u64, owner: address, new_document_cid: vector<u8>, new_version: u64, at: u64): DIDDocumentUpdatedEvent {
        DIDDocumentUpdatedEvent { id, owner, new_document_cid, new_version, at }
    }

    #[test_only]
    public fun did_status_changed_event(id: u64, owner: address, changed_by: address, new_status: u8, reason: vector<u8>, at: u64): DIDStatusChangedEvent {
        DIDStatusChangedEvent { id, owner, changed_by, new_status, reason, at }
    }
}
