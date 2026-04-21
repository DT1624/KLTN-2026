module governance::identity {

    use std::option;
    use std::signer;
    use std::vector;
    use aptos_std::smart_table;
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use governance::constants;
    use governance::errors;

    friend governance::authority;
    friend governance::credential;

    // ========== Constants ==========

    // DID status
    const DID_STATUS_ACTIVE:    u8 = 1;
    const DID_STATUS_SUSPENDED: u8 = 2;
    const DID_STATUS_REVOKED:   u8 = 3;

    // ========== Structs ==========

    struct DIDRecord has copy, drop, store {
        id: u64,
        owner: address,
        did_string: vector<u8>,
        document_cid: vector<u8>,
        document_hash: vector<u8>,
        status: u8,
        created_at: u64,
        updated_at: u64,
        version: u64,
    }

    struct DIDView has copy, drop {
        did: vector<u8>,
        owner: address,
        cid: vector<u8>,
        hash: vector<u8>,
        status: u8,
        created_at: u64,
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
    public entry fun registry_did(
        owner: &signer,
        did_string: vector<u8>,
        document_cid: vector<u8>,
        hash: vector<u8>,
    ) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        assert!(
            vector::length(&hash) == 32,
            errors::hash_wrong_length()
        );

        // assert CID minimum length sanity check
        let did_registry = borrow_mut_did_registry();
        assert!(
            !smart_table::contains(&did_registry.owner_to_id, owner_addr),
            errors::owner_has_did()
        );
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
            document_hash: hash,
            status: DID_STATUS_ACTIVE,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        smart_table::add(&mut did_registry.dids, id, did_record);
        smart_table::add(&mut did_registry.did_string_to_id, did_string, id);
        smart_table::add(&mut did_registry.owner_to_id, owner_addr, id);
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
        assert!(
            vector::length(&new_document_hash) == 32,
            errors::hash_wrong_length()
        );
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

    /// Owner voluntarily deactivates their DID.
    /// Deactivated DIDs cannot issue or hold new VCs.
    /// Existing VCs remain valid until explicitly revoked.
    public entry fun deactivate_did(
        owner: &signer,
    ) acquires DIDRegistry {
        let owner_addr = signer::address_of(owner);
        internal_set_did_status(owner_addr, DID_STATUS_SUSPENDED, owner_addr, constants::REASON_TYPE_OTHER());
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
    public fun resolve_did(did_string: vector<u8>): option::Option<DIDView> acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        if (!smart_table::contains(&did_registry.did_string_to_id, did_string)) {
            return option::none<DIDView>()
        };
        let id = *smart_table::borrow(&did_registry.did_string_to_id, did_string);

        if (!smart_table::contains(&did_registry.dids, id)) {
            return option::none<DIDView>()
        };
        let record = smart_table::borrow(&did_registry.dids, id);
        option::some(
            DIDView {
                did: record.did_string,
                owner: record.owner,
                cid: record.document_cid,
                hash: record.document_hash,
                status: record.status,
                created_at: record.created_at
            }
        )
    }

    #[view]
    public fun resolve_did_by_owner(owner: address): option::Option<DIDView> acquires DIDRegistry {
        let did_registry = borrow_did_registry();
        if (!smart_table::contains(&did_registry.owner_to_id, owner)) {
            return option::none<DIDView>()
        };
        let id = *smart_table::borrow(&did_registry.owner_to_id, owner);

        if (!smart_table::contains(&did_registry.dids, id)) {
            return option::none<DIDView>()
        };
        let record = smart_table::borrow(&did_registry.dids, id);
        option::some(
            DIDView {
                did: record.did_string,
                owner: record.owner,
                cid: record.document_cid,
                hash: record.document_hash,
                status: record.status,
                created_at: record.created_at
            }
        )
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

    // === Internal helpers ===

    fun internal_set_did_status(
        target_owner: address,
        new_status: u8,
        changed_by: address,
        reason: vector<u8>,
    ) acquires DIDRegistry {
        assert_owner_active(target_owner);
        let did_registry = borrow_mut_did_registry();
        let id = *smart_table::borrow(&did_registry.owner_to_id, target_owner);
        assert!(
            smart_table::contains(&did_registry.dids, id),
            errors::invalid_id()
        );
        let record = *smart_table::borrow_mut(&mut did_registry.dids, id);
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
        borrow_global<DIDRegistry>(@governance)
    }

    inline fun borrow_mut_did_registry(): &mut DIDRegistry {
        borrow_global_mut<DIDRegistry>(@governance)
    }

    #[test_only]
    public fun initialize(root: &signer) {
        init_module(root);
    }
}
