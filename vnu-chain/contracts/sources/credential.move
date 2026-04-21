module governance::credential {

    use std::signer;
    use std::vector;
    use aptos_std::smart_table;
    use aptos_std::smart_table::SmartTable;
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use governance::identity;
    use governance::authority;
    use governance::errors;

    // ========== Contants ==========

    // VC status
    const VC_STATUS_ACTIVE:             u8 = 1;
    const VC_STATUS_SUSPENDED:          u8 = 2;
    const VC_STATUS_EXPIRED:            u8 = 3;
    const VC_STATUS_REVOKED:            u8 = 4;

    // ========== Structs ==========

    struct VCRecord has copy, drop, store {
        id: u64,
        issuer_addr: address,
        holder_addr: address,
        // vc_id_hash = SHA3-256(vc_id string) to avoid storing vc_id
        vc_id_hash: vector<u8>,
        content_cid: vector<u8>,
        content_hash: vector<u8>,
        vc_type: u64,
        status: u8,
        issued_at: u64,
        expires_at: u64,
        revoked_at: u64,
        status_reason: vector<u8>,
    }

    struct VCRegistry has key {
        vc_count: u64,
        vcs: smart_table::SmartTable<u64, VCRecord>,
        // vc_id_hash to id
        hash_to_id: smart_table::SmartTable<vector<u8>, u64>,
        // issuer to VC count
        issuer_vc_count: smart_table::SmartTable<address, u64>,
        // holder to VC count
        holder_vc_count: smart_table::SmartTable<address, u64>,
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
        issuer_addr: address,
        new_status: u8,
        reason: vector<u8>,
        changed_by: address,
        at: u64,
    }

    // ========== Init ==========

    fun init_module(root: &signer) {
        move_to(
            root,
            VCRegistry {
                vc_count: 0,
                vcs: smart_table::new<u64, VCRecord>(),
                hash_to_id: smart_table::new<vector<u8>, u64>(),
                issuer_vc_count: smart_table::new<address, u64>(),
                holder_vc_count: smart_table::new<address, u64>()
            }
        )
    }

    // ========== Public entry functions ==========

    // == Issue a Verifiable Credential ===
    public entry fun issuer_vc(
        issuer: &signer,
        holder_addr: address,
        vc_type: u64,
        vc_id_hash: vector<u8>,
        content_cid: vector<u8>,
        content_hash: vector<u8>,

    ) acquires VCRegistry {
        // Step 1: authority check
        // Issuer approved (by admin) and type allowed (OR with vc_type_mask != 0)
        let issuer_addr = signer::address_of(issuer);
        authority::assert_is_active_issuer(issuer_addr, vc_type);

        // Step 2: derive issuer_did from address (not from input to prevents impersonation)
        let issuer_did = identity::get_active_did_string(issuer_addr);

        // Step 3: verify holder DID - assert this did active, can receive VC.
        let holder_did = identity::get_active_did_string(holder_addr);

        // Step 4: hash integrity (32 bytes)
        assert!(
            vector::length(&content_cid) == 32,
            errors::hash_wrong_length()
        );
        assert!(
            vector::length(&vc_id_hash) == 32,
            errors::hash_wrong_length()
        );

        // Step 5: no duplicate
        let vc_registry = borrow_mut_vc_registry();
        assert!(
            !smart_table::contains(&vc_registry.hash_to_id, vc_id_hash),
            errors::vc_already_exists()
        );

        let id = vc_registry.vc_count;
        let now = timestamp::now_seconds();
        let vc_record = VCRecord {
            id,
            issuer_addr,
            holder_addr,
            // vc_id_hash = SHA3-256(vc_id string) to avoid storing vc_id
            vc_id_hash,
            // fetch VC from IPFS bay content_cid
            content_cid,
            // content_hash = SHA3-256(full content VC)
            content_hash,
            vc_type,
            status: VC_STATUS_ACTIVE,
            issued_at: now,
            expires_at: 0,
            revoked_at: 0,
            status_reason: b"",
        };
        smart_table::add(&mut vc_registry.vcs, id, vc_record);
        smart_table::add(&mut vc_registry.hash_to_id, vc_id_hash, id);

        vc_registry.vc_count = id + 1;
        internal_increment_count(&mut vc_registry.issuer_vc_count, issuer_addr);
        internal_increment_count(&mut vc_registry.holder_vc_count, holder_addr);

        event::emit(
            VCIssuedEvent {
                id,
                issuer_addr,
                issuer_did,
                holder_addr,
                holder_did,
                vc_id_hash,
                content_cid,
                vc_type,
                issued_at: now,
                expires_at: 0,
            }
        );
    }

    // issuer operate
    public entry fun suspend_vc(
        issuer: &signer,
        vc_id: u64,
        reason: vector<u8>,
    ) acquires VCRegistry {
        let issuer_addr = signer::address_of(issuer);
        internal_issuer_set_vc_status(issuer_addr, vc_id, VC_STATUS_SUSPENDED, reason);
    }

    // Only the issuer who created it can revoke
    public entry fun revoke_vc(
        issuer: &signer,
        vc_id: u64,
        reason: vector<u8>,
    ) acquires VCRegistry {
        let issuer_addr = signer::address_of(issuer);
        internal_issuer_set_vc_status(issuer_addr, vc_id, VC_STATUS_REVOKED, reason);
    }

    // only admin operate
    public entry fun admin_suspend_vc(
        admin: &signer,
        vc_id: u64,
        reason: vector<u8>,
    ) acquires VCRegistry {
        let admin_addr = signer::address_of(admin);
        internal_admin_set_vc_status(admin_addr, vc_id, VC_STATUS_SUSPENDED, reason);
    }

    // only admin can reinstate a suspended VC
    // this prevents issuers from repeatedly suspending/reinstating as a way to bypass audit.
    public entry fun admin_reinstate_vc(
        admin: &signer,
        vc_id: u64,
        reason: vector<u8>,
    ) acquires VCRegistry {
        let admin_addr = signer::address_of(admin);
        internal_admin_set_vc_status(admin_addr, vc_id, VC_STATUS_ACTIVE, reason);
    }

    // admin can forcibly revoke any VC (fraud, legal order)
    public entry fun admin_revoke_vc(
        admin: &signer,
        vc_id: u64,
        reason: vector<u8>,
    ) acquires VCRegistry {
        let admin_addr = signer::address_of(admin);
        internal_admin_set_vc_status(admin_addr, vc_id, VC_STATUS_REVOKED, reason);
    }

    // ========== View functions ==========

    #[view]
    public fun get_vc_status(vc_id: u64): u8 acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        assert!(
            smart_table::contains(&vc_registry.vcs, vc_id),
            errors::invalid_id()
        );
        let record = smart_table::borrow(&vc_registry.vcs, vc_id);
        if (record.expires_at != 0 && timestamp::now_seconds() > record.expires_at) {
            return VC_STATUS_EXPIRED
        };
        record.status
    }

    #[view]
    public fun get_vc_by_id(vc_id: u64): VCRecord acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        assert!(
            smart_table::contains(&vc_registry.vcs, vc_id),
            errors::invalid_id()
        );
        let record = *smart_table::borrow(&vc_registry.vcs, vc_id);
        assert!(
            record.expires_at == 0 && timestamp::now_seconds() < record.expires_at,
            errors::vc_already_expired()
        );
        record
    }

    #[view]
    public fun get_vc_id_by_hash(vc_id_hash: vector<u8>): u64 acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        assert!(
            smart_table::contains(&vc_registry.hash_to_id, vc_id_hash),
            errors::vc_not_found()
        );
        *smart_table::borrow(&vc_registry.hash_to_id, vc_id_hash)
    }

    #[view]
    public fun verify_integrity(
        vc_id: u64,
        claimed_hash: vector<u8>,
    ): bool acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        // Make sure vc_id is present in vcs
        if (!smart_table::contains(&vc_registry.vcs, vc_id)) {
            return false
        };

        let record = smart_table::borrow(&vc_registry.vcs, vc_id);
        // ensure that caller is the issuer of th vc
        if (record.status != VC_STATUS_ACTIVE) {
            return false
        };
        if (record.expires_at != 0 && timestamp::now_seconds() > record.expires_at) {
            return false
        };
        record.content_hash == claimed_hash
    }

    #[view]
    public fun get_counts(
        issuer: address,
        holder: address,
    ): (u64, u64) acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        let ic = if (smart_table::contains(&vc_registry.issuer_vc_count, issuer)) {
            *smart_table::borrow(&vc_registry.issuer_vc_count, issuer)
        } else {0};
        let hc = if (smart_table::contains(&vc_registry.holder_vc_count, holder)) {
            *smart_table::borrow(&vc_registry.holder_vc_count, holder)
        } else {0};
        return (ic, hc)
    }

    #[view]
    public fun total_vcs(): u64 acquires VCRegistry {
        borrow_vc_registry().vc_count
    }

    // ========== Internal helpers ==========

    // Useds to set status VC to revoked, active to suspended; suspended to active
    // caller must is issuer
    fun internal_issuer_set_vc_status(
        caller: address,
        vc_id: u64,
        new_status: u8,
        reason: vector<u8>
    ) acquires VCRegistry {
        let vc_registry = borrow_mut_vc_registry();
        // Make sure vc_id is present in vcs
        assert!(
            smart_table::contains(&vc_registry.vcs, vc_id),
            errors::invalid_id()
        );
        let record = smart_table::borrow_mut(&mut vc_registry.vcs, vc_id);
        // ensure that caller is the issuer of th vc
        assert!(
            record.issuer_addr == caller,
            errors::not_vc_issuer(),
        );
        // ensure issuer is active
        authority::assert_is_active_issuer(caller, record.vc_type);
        // ensure this vc not revoked
        assert!(
            record.status != VC_STATUS_REVOKED,
            errors::vc_already_revoked()
        );
        // ensure this vc not expired
        assert!(
            record.status != VC_STATUS_EXPIRED,
            errors::vc_already_expired()
        );
        if (new_status == VC_STATUS_SUSPENDED) {
            assert!(
                record.status == VC_STATUS_ACTIVE,
                errors::vc_not_active()
            );
        };

        let now = timestamp::now_seconds();
        record.status = new_status;
        record.status_reason = reason;
        if (new_status == VC_STATUS_REVOKED) {
            record.revoked_at = now;
        };

        event::emit(
            VCStatusChangedEvent {
                id: vc_id,
                issuer_addr: record.issuer_addr,
                new_status,
                reason,
                changed_by: caller,
                at: now,
            }
        );
    }

    // Useds to set status VC to revoked, active to suspended; suspended to active
    // caller must is admin (root_admin)
    fun internal_admin_set_vc_status(
        caller: address,
        vc_id: u64,
        new_status: u8,
        reason: vector<u8>
    ) acquires VCRegistry {
        // ensure caller is admin/root admin
        authority::assert_is_active_admin(caller);
        let vc_registry = borrow_mut_vc_registry();
        // Make sure vc_id is present in vcs
        assert!(
            smart_table::contains(&vc_registry.vcs, vc_id),
            errors::vc_not_found()
        );
        let record = smart_table::borrow_mut(&mut vc_registry.vcs, vc_id);
        // ensure this vc not revoked
        assert!(
            record.status != VC_STATUS_REVOKED,
            errors::vc_already_revoked()
        );
        // ensure this vc not expired
        assert!(
            record.status != VC_STATUS_EXPIRED,
            errors::vc_already_expired()
        );
        if (new_status == VC_STATUS_ACTIVE) {
            assert!(
                record.status == VC_STATUS_SUSPENDED,
                errors::vc_not_suspended()
            );
        };
        if (new_status == VC_STATUS_SUSPENDED) {
            assert!(
                record.status == VC_STATUS_ACTIVE,
                errors::vc_not_active()
            );
        };

        let now = timestamp::now_seconds();
        record.status = new_status;
        record.status_reason = reason;
        if (new_status == VC_STATUS_REVOKED) {
            record.revoked_at = now;
        };

        event::emit(
            VCStatusChangedEvent {
                id: vc_id,
                issuer_addr: record.issuer_addr,
                new_status,
                reason,
                changed_by: caller,
                at: now,
            }
        );
    }

    fun internal_increment_count(
        table: &mut SmartTable<address, u64>,
        addr: address,
    ) {
        if (smart_table::contains(table, addr)) {
            let c = smart_table::borrow_mut(table, addr);
            *c = *c + 1;
        } else {
            smart_table::add(table, addr, 1);
        }
    }

    inline fun borrow_vc_registry(): &VCRegistry {
        borrow_global<VCRegistry>(@governance)
    }

    inline fun borrow_mut_vc_registry(): &mut VCRegistry {
        borrow_global_mut<VCRegistry>(@governance)
    }

}
