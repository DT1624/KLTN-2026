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

    // DID status
    const DID_STATUS_ACTIVE:    u8 = 1;
    const DID_STATUS_SUSPENDED: u8 = 2;
    const DID_STATUS_REVOKED:   u8 = 3;

    /// Khong ai tam ngung DID nay (dung cho truong `suspended_by`).
    const NOBODY:               address = @0x0;

    // F-06: CID rong -> DID "active" nhung khong resolve duoc tai lieu nao.
    // Khong ep dung mot ho CID cu the (v0 `Qm...` va v1 `bafy...` deu hop le),
    // chi chan cac gia tri khong the nao la CID that.
    const MIN_CID_LEN:          u64 = 10;
    const MAX_CID_LEN:          u64 = 128;

    // F-10: tran an toan cho view liet ke toan bo / view phan trang.
    const MAX_VIEW_ITEMS:       u64 = 500;
    const MAX_PAGE_LIMIT:       u64 = 200;

    // ========== Structs ==========

    struct DIDRecord has copy, drop, store {
        id: u64,
        owner: address,
        // e.g: did:vnu:0x24545147abcde
        did_string: vector<u8>,
        // cid from pin did document in IPFS
        document_cid: vector<u8>,
        // SHA3-256(DID Document JSON) (256 bits = 32 bytes = 64 hex characters)
        document_hash: vector<u8>,
        status: u8,
        created_at: u64,
        updated_at: u64,
        version: u64,
        // F-07: ai da dat DID nay ve SUSPENDED. Chu so huu tu khoa thi tu mo
        // duoc; admin khoa thi phai admin mo. @0x0 = khong bi tam ngung.
        suspended_by: address,
    }

    struct DIDRegistry has key {
        did_count: u64,
        dids: smart_table::SmartTable<u64, DIDRecord>,
        did_string_to_id: smart_table::SmartTable<vector<u8>, u64>,
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

    // ========== Functions ==========

    fun init_module(root: &signer) {
        move_to(
            root,
            DIDRegistry {
                did_count: 0,
                dids: smart_table::new<u64, DIDRecord>(),
                did_string_to_id: smart_table::new<vector<u8>, u64>(),
                owner_to_id: smart_table::new<address, u64>(),
            }
        );
    }

    // === Public entry functions ===

    // Anyone can register a unique DID
    // did_string must be unique, document_cid is IPFS CID of DID Document
    // hash is SHA3-256 of that document (32 bytes)
    public entry fun register_did(
        owner: &signer,
        did_string: vector<u8>,
        document_cid: vector<u8>,
        document_hash: vector<u8>,
    ) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        assert!(
            vector::length(&document_hash) == 32,
            errors::hash_wrong_length()
        );
        // F-06: truoc day cho co comment "assert CID minimum length sanity
        // check" ma khong he co assert nao.
        assert_valid_cid(&document_cid);
        assert!(
            !vector::is_empty(&did_string),
            errors::did_not_found()
        );
        assert_did_bound_to_owner(&did_string, owner_addr);

        let did_registry = borrow_mut_did_registry();

        // F-05: DID bi thu hoi PHAI dang ky lai duoc bang DID moi. Kich ban
        // that la LO KHOA RIENG: dung ra nguoi dung thu hoi DID cu roi dang ky
        // DID moi bang khoa moi; truoc day lam vay la mat dia chi vinh vien.
        let prev_version = 0;
        let is_new_owner = !smart_table::contains(&did_registry.owner_to_id, owner_addr);
        if (!is_new_owner) {
            let prev_id = *smart_table::borrow(&did_registry.owner_to_id, owner_addr);
            assert!(
                smart_table::contains(&did_registry.dids, prev_id),
                errors::invalid_id()
            );
            let prev = smart_table::borrow(&did_registry.dids, prev_id);
            assert!(
                prev.status == DID_STATUS_REVOKED,
                errors::owner_has_did()
            );
            prev_version = prev.version;
        };

        assert!(
            !smart_table::contains(&did_registry.did_string_to_id, did_string),
            errors::did_already_registered()
        );

        let id = did_registry.did_count;
        let now = timestamp::now_seconds();
        let did_record = DIDRecord {
            id,
            owner: owner_addr,
            did_string,
            document_cid,
            document_hash,
            status: DID_STATUS_ACTIVE,
            created_at: now,
            updated_at: now,
            version: prev_version + 1,
            suspended_by: NOBODY,
        };
        smart_table::add(&mut did_registry.dids, id, did_record);
        smart_table::add(&mut did_registry.did_string_to_id, did_string, id);
        // upsert: ban ghi DID cu van nam trong `dids` -> giu nguyen vet kiem toan
        smart_table::upsert(&mut did_registry.owner_to_id, owner_addr, id);
        did_registry.did_count = id + 1;

        event::emit(
            DIDRegisteredEvent {
                id,
                owner: owner_addr,
                did_string,
                document_cid,
                at: now,
            }
        )
    }

    /// Owner updates DID Document (rotate key, add key ...)
    /// expected_version: prevents lost-update
    public entry fun update_did_document(
        owner: &signer,
        new_document_cid: vector<u8>,
        new_document_hash: vector<u8>,
        expected_version: u64,
    ) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        let did_registry = borrow_mut_did_registry();
        assert!(
            smart_table::contains(&did_registry.owner_to_id, owner_addr),
            errors::owner_not_exists()
        );
        let id = *smart_table::borrow(&did_registry.owner_to_id, owner_addr);
        assert!(
            smart_table::contains(&did_registry.dids, id),
            errors::invalid_id()
        );
        let record = smart_table::borrow_mut(&mut did_registry.dids, id);
        assert!(
            record.status == DID_STATUS_ACTIVE,
            errors::did_not_active()
        );
        assert!(
            record.version == expected_version,
            errors::stable_did_version()
        );
        assert!(
            vector::length(&new_document_hash) == 32,
            errors::hash_wrong_length()
        );
        assert_valid_cid(&new_document_cid);
        let now = timestamp::now_seconds();
        record.document_cid = new_document_cid;
        record.document_hash = new_document_hash;
        record.version = record.version + 1;
        record.updated_at = now;

        event::emit(
            DIDDocumentUpdatedEvent {
                id: record.id,
                owner: owner_addr,
                new_document_cid,
                new_version: record.version,
                at: now,
            }
        )
    }

    /// Owner voluntarily suspends their own DID.
    /// Suspended DIDs cannot issue or hold new VCs.
    /// Existing VCs remain valid until explicitly revoked.
    /// Ten cu `deactivate_did` gay hieu nham: no dat SUSPENDED chu khong phai
    /// REVOKED. Giu lai lam bi danh de khong vo ABI da trien khai.
    public entry fun suspend_own_did(
        owner: &signer,
    ) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        assert_owner_active(owner_addr);
        internal_set_did_status(owner_addr, DID_STATUS_SUSPENDED, owner_addr, constants::REASON_TYPE_OTHER());
    }

    /// Bi danh cua `suspend_own_did` - giu ten cu cho ABI da trien khai.
    public entry fun deactivate_did(
        owner: &signer,
    ) acquires DIDRegistry {
        suspend_own_did(owner);
    }

    /// F-07: chu so huu TU MO LAI DID minh tu khoa.
    /// Chi mo duoc neu chinh minh la nguoi da khoa - DID bi admin khoa thi van
    /// phai admin mo, neu khong ai bi ky luat cung tu go duoc.
    /// Day la tinh than Self-Sovereign Identity: tam khoa DID cua minh roi phai
    /// di xin admin mo lai la sai ngay tu goc.
    public entry fun reactivate_own_did(
        owner: &signer,
    ) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        let did_registry = borrow_did_registry();
        assert!(
            smart_table::contains(&did_registry.owner_to_id, owner_addr),
            errors::owner_not_exists()
        );
        let id = *smart_table::borrow(&did_registry.owner_to_id, owner_addr);
        assert!(
            smart_table::contains(&did_registry.dids, id),
            errors::invalid_id()
        );
        let record = smart_table::borrow(&did_registry.dids, id);
        assert!(
            record.status == DID_STATUS_SUSPENDED,
            errors::did_not_suspended()
        );
        assert!(
            record.suspended_by == owner_addr,
            errors::not_self_suspended()
        );
        internal_set_did_status(owner_addr, DID_STATUS_ACTIVE, owner_addr, constants::REASON_TYPE_OTHER());
    }

    // === Friend functions ===

    public(friend) fun admin_suspend_did(
        admin_addr: address,
        target_owner: address,
        reason: vector<u8>,
    ) acquires DIDRegistry {
        internal_set_did_status(target_owner, DID_STATUS_SUSPENDED, admin_addr, reason);
    }

    public(friend) fun admin_reactivate_did(
        admin_addr: address,
        target_owner: address,
        reason: vector<u8>,
    ) acquires DIDRegistry {
        // F-12: chu tu khoa (vd nghi lo khoa) thi admin khong duoc mo thay.
        assert!(suspended_by(target_owner) != target_owner, errors::owner_locked());
        internal_set_did_status(target_owner, DID_STATUS_ACTIVE, admin_addr, reason);
    }

    //
    public(friend) fun admin_revoke_did(
        admin_addr: address,
        target_owner: address,
        reason: vector<u8>,
    ) acquires DIDRegistry {
        internal_set_did_status(target_owner, DID_STATUS_REVOKED, admin_addr, reason);
    }

    public(friend) fun assert_owner_active(owner: address) acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        assert!(
            smart_table::contains(&did_registry.owner_to_id, owner),
            errors::owner_not_exists()
        );
        let id = *smart_table::borrow(&did_registry.owner_to_id, owner);
        assert!(
            smart_table::contains(&did_registry.dids, id),
            errors::invalid_id()
        );
        let record = smart_table::borrow(&did_registry.dids, id);
        assert!(
            record.status == DID_STATUS_ACTIVE,
            errors::did_not_active()
        );
    }

    public(friend) fun assert_did_string_active(did_string: vector<u8>) acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        assert!(
            smart_table::contains(&did_registry.did_string_to_id, did_string),
            errors::did_not_found()
        );
        let id = *smart_table::borrow(&did_registry.did_string_to_id, did_string);
        assert!(
            smart_table::contains(&did_registry.dids, id),
            errors::invalid_id()
        );
        let record = smart_table::borrow(&did_registry.dids, id);
        assert!(
            record.status == DID_STATUS_ACTIVE,
            errors::did_not_active()
        );
    }

    public(friend) fun get_active_did_string(owner: address): vector<u8> acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        assert!(
            smart_table::contains(&did_registry.owner_to_id, owner),
            errors::owner_not_exists()
        );
        let id = *smart_table::borrow(&did_registry.owner_to_id, owner);
        assert!(
            smart_table::contains(&did_registry.dids, id),
            errors::invalid_id()
        );
        let record = smart_table::borrow(&did_registry.dids, id);
        assert!(
            record.status == DID_STATUS_ACTIVE,
            errors::did_not_active()
        );
        record.did_string
    }

    // === View Functions ===

    #[view]
    public fun resolve_did(did_string: vector<u8>): (vector<u8>, vector<u8>, vector<u8>, u8, u64) acquires DIDRegistry {
        let record = record_by_did_string(did_string);
        (record.did_string, record.document_cid, record.document_hash, record.status, record.version)
    }

    #[view]
    public fun resolve_did_by_owner(owner: address): (vector<u8>, vector<u8>, vector<u8>, u8, u64) acquires DIDRegistry {
        let record = record_by_owner(owner);
        (record.did_string, record.document_cid, record.document_hash, record.status, record.version)
    }

    // Ban ghi DID day du - cho man hinh quan tri va bo lap chi muc.
    #[view]
    public fun get_did(did_string: vector<u8>): DIDRecord acquires DIDRegistry {
        record_by_did_string(did_string)
    }

    #[view]
    public fun get_did_by_owner(owner: address): DIDRecord acquires DIDRegistry {
        record_by_owner(owner)
    }

    #[view]
    public fun has_active_did(owner: address): bool acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        if (!smart_table::contains(&did_registry.owner_to_id, owner)) {
            return false
        };
        let id = *smart_table::borrow(&did_registry.owner_to_id, owner);
        if(!smart_table::contains(&did_registry.dids, id)) {
            return false
        };
        let record = smart_table::borrow(&did_registry.dids, id);
        record.status == DID_STATUS_ACTIVE
    }

    #[view]
    public fun total_dids(): u64 acquires DIDRegistry {
        borrow_did_registry().did_count
    }

    // F-10: chi an toan khi bang con nho; vuot nguong thi abort ro rang de
    // nguoi goi chuyen sang ban phan trang.
    #[view]
    public fun get_dids(): vector<vector<u8>> acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        assert!(
            smart_table::length(&did_registry.did_string_to_id) <= MAX_VIEW_ITEMS,
            errors::result_too_large()
        );
        smart_table::keys(&did_registry.did_string_to_id)
    }

    #[view]
    public fun get_owners(): vector<address> acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        assert!(
            smart_table::length(&did_registry.owner_to_id) <= MAX_VIEW_ITEMS,
            errors::result_too_large()
        );
        smart_table::keys(&did_registry.owner_to_id)
    }

    // Phan trang theo id tang dan: on dinh, co thu tu, va khong bao gio nap
    // ca bang vao bo nho.
    #[view]
    public fun get_dids_paginated(start: u64, limit: u64): vector<DIDRecord> acquires DIDRegistry {
        assert!(limit > 0 && limit <= MAX_PAGE_LIMIT, errors::invalid_page());
        let did_registry = borrow_did_registry();
        let out = vector::empty<DIDRecord>();
        // Dem theo so phan tu con lai thay vi tinh `start + limit`: voi start
        // gan u64::MAX phep cong do se tran va abort bang loi so hoc kho hieu.
        let id = start;
        let taken = 0;
        while (taken < limit && id < did_registry.did_count) {
            if (smart_table::contains(&did_registry.dids, id)) {
                vector::push_back(&mut out, *smart_table::borrow(&did_registry.dids, id));
            };
            id = id + 1;
            taken = taken + 1;
        };
        out
    }

    // === Internal helpers ===

    /// F-12: chuoi DID phai bat dau "did:" va ket thuc bang dia chi chu so huu
    /// (0x + 64 hex thuong) - chan viec chiem truoc DID cua nguoi khac.
    fun assert_did_bound_to_owner(did: &vector<u8>, owner: address) {
        let prefix = b"did:";
        let suffix = address_hex(owner);
        let (n, m) = (vector::length(did), vector::length(&suffix));
        assert!(n > m + 4, errors::did_not_bound_to_owner());
        let i = 0;
        while (i < 4) {
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

    fun suspended_by(owner: address): address acquires DIDRegistry {
        let reg = borrow_did_registry();
        assert!(smart_table::contains(&reg.owner_to_id, owner), errors::owner_not_exists());
        smart_table::borrow(&reg.dids, *smart_table::borrow(&reg.owner_to_id, owner)).suspended_by
    }

    #[test_only]
    public fun address_hex_for_test(addr: address): vector<u8> { address_hex(addr) }

    fun assert_valid_cid(cid: &vector<u8>) {
        let len = vector::length(cid);
        assert!(len >= MIN_CID_LEN && len <= MAX_CID_LEN, errors::invalid_cid());
    }

    fun record_by_did_string(did_string: vector<u8>): DIDRecord acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        assert!(
            smart_table::contains(&did_registry.did_string_to_id, did_string),
            errors::did_not_found()
        );
        let id = *smart_table::borrow(&did_registry.did_string_to_id, did_string);
        // F-11a: cho nay truoc dung errors::invalid_cid() (2008) cho phep kiem
        // "khong tim thay id trong bang dids" - sai ma, gay hieu nham khi debug.
        assert!(
            smart_table::contains(&did_registry.dids, id),
            errors::invalid_id()
        );
        *smart_table::borrow(&did_registry.dids, id)
    }

    fun record_by_owner(owner: address): DIDRecord acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        assert!(
            smart_table::contains(&did_registry.owner_to_id, owner),
            errors::owner_not_exists()
        );
        let id = *smart_table::borrow(&did_registry.owner_to_id, owner);
        assert!(
            smart_table::contains(&did_registry.dids, id),
            errors::invalid_id()
        );
        *smart_table::borrow(&did_registry.dids, id)
    }

    fun internal_set_did_status(
        target_owner: address,
        new_status: u8,
        changed_by: address,
        reason: vector<u8>,
    ) acquires DIDRegistry {
        let did_registry = borrow_mut_did_registry();
        // Truoc day borrow thang, dia chi khong co DID se abort bang loi noi
        // bo cua smart_table thay vi mot ma loi co nghia.
        assert!(
            smart_table::contains(&did_registry.owner_to_id, target_owner),
            errors::owner_not_exists()
        );
        let id = *smart_table::borrow(&did_registry.owner_to_id, target_owner);
        assert!(
            smart_table::contains(&did_registry.dids, id),
            errors::invalid_id()
        );
        let record = smart_table::borrow_mut(&mut did_registry.dids, id);
        assert!(
            record.status != DID_STATUS_REVOKED,
            errors::did_already_revoked()
        );
        if (new_status == DID_STATUS_SUSPENDED) {
            assert!(
                record.status == DID_STATUS_ACTIVE,
                errors::did_not_active()
            );
        };
        if (new_status == DID_STATUS_ACTIVE) {
            assert!(
                record.status == DID_STATUS_SUSPENDED,
                errors::did_not_suspended()
            );
        };

        let now = timestamp::now_seconds();
        record.status = new_status;
        // Ghi lai AI tam ngung de sau nay biet ai duoc quyen mo lai (F-07).
        if (new_status == DID_STATUS_SUSPENDED) {
            record.suspended_by = changed_by;
        } else {
            record.suspended_by = NOBODY;
        };

        record.updated_at = now;

        event::emit(
            DIDStatusChangedEvent {
                id: record.id,
                owner: target_owner,
                changed_by,
                new_status,
                reason,
                at: now,
            }
        )
    }

    inline fun borrow_did_registry(): &DIDRegistry {
        borrow_global<DIDRegistry>(@vnu)
    }

    inline fun borrow_mut_did_registry(): &mut DIDRegistry {
        borrow_global_mut<DIDRegistry>(@vnu)
    }

    #[test_only]
    public fun initialize_for_test(root: &signer) {
        init_module(root);
    }

    #[test_only]
    fun build_did_registered_event(id: u64, owner: address, did_string: vector<u8>, document_cid: vector<u8>, at: u64): DIDRegisteredEvent {
        DIDRegisteredEvent {
            id,
            owner,
            did_string,
            document_cid,
            at
        }
    }

    #[test_only]
    public fun assert_did_registered_event_emitted(id: u64, owner: address, did_string: vector<u8>, document_cid: vector<u8>, at: u64) {
        let event = build_did_registered_event(id, owner, did_string, document_cid, at);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    fun build_did_document_updated_event(id: u64, owner: address, new_document_cid: vector<u8>, new_version: u64, at: u64): DIDDocumentUpdatedEvent {
        DIDDocumentUpdatedEvent {
            id,
            owner,
            new_document_cid,
            new_version,
            at
        }
    }

    #[test_only]
    public fun assert_did_document_updated_event_emitted(id: u64, owner: address, new_document_cid: vector<u8>, new_version: u64, at: u64) {
        let event = build_did_document_updated_event(id, owner, new_document_cid, new_version, at);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    fun build_did_status_changed_event(id: u64, owner: address, changed_by: address, new_status: u8, reason: vector<u8>, at: u64): DIDStatusChangedEvent {
        DIDStatusChangedEvent {
            id,
            owner,
            changed_by,
            new_status,
            reason,
            at
        }
    }

    #[test_only]
    public fun assert_did_status_changed_event_emitted(id: u64, owner: address, changed_by: address, new_status: u8, reason: vector<u8>, at: u64) {
        let event = build_did_status_changed_event(id, owner, changed_by, new_status, reason, at);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    public fun get_did_details_by_owner(owner: address): (u64, address, vector<u8>, vector<u8>, vector<u8>, u8, u64, u64, u64) acquires DIDRegistry {
        let record = record_by_owner(owner);
        (record.id, record.owner, record.did_string, record.document_cid, record.document_hash, record.status, record.created_at, record.updated_at, record.version)
    }

    #[test_only]
    public fun suspended_by_of(owner: address): address acquires DIDRegistry {
        record_by_owner(owner).suspended_by
    }

    #[test_only]
    public fun did_id_of(owner: address): u64 acquires DIDRegistry {
        record_by_owner(owner).id
    }
}
