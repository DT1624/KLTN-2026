module governance::authority {

    use std::signer;
    use std::vector;
    use aptos_std::smart_table;
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use governance::did_registry;
    use governance::constants;
    use governance::errors;

    friend governance::vc_registry;

    // ========== Constants ==========

    // Issuer status
    const ISSUER_STATUS_ACTIVE:     u8 = 1;
    const ISSUER_STATUS_REVOKED:    u8 = 2;
    const ISSUER_STATUS_SUSPENDED:  u8 = 3;

    const ADMIN_STATUS_ACTIVE:      u8 = 1;
    const ADMIN_STATUS_REVOKED:     u8 = 2;

    // ========== Structs ==========

    struct RoleRecord has copy, drop, store {
        owner: address,
        version: u64,
        approved_by: address,
        approved_at: u64,
        vc_type_mask: u64,
        delegation_vc_cid: vector<u8>,
        delegation_vc_hash: vector<u8>,
        expires_at: u64,
        status: u8,
        status_reason: vector<u8>,
        status_updated_at: u64,
    }

    struct Authority has key {
        root_admin: address,
        roles: smart_table::SmartTable<u64, RoleRecord>,
        issuers: smart_table::SmartTable<address, u64>,
        admins: smart_table::SmartTable<address, u64>,
        issuer_count: u64,
        admin_count: u64,
    }

    // ========== Events ==========

    #[event]
    struct AdminGrantedEvent has drop, store {
        to: address,
        by: address,
        at: u64,
    }

    #[event]
    struct AdminRevokedEvent has drop, store {
        to: address,
        by: address,
        reason: vector<u8>,
        at: u64,
    }

    #[event]
    struct IssuerApprovedEvent has drop, store {
        issuer: address,
        by: address,
        vc_type_mask: u64,
        delegation_vc_cid: vector<u8>,
        at: u64,
        expires_at: u64,
    }

    #[event]
    struct IssuerStatusChangedEvent has drop, store {
        issuer: address,
        by: address,
        new_status: u8,
        reason: vector<u8>,
        at: u64,
    }

    #[event]
    struct IssuerRevokedEvent has drop, store {
        issuer: address,
        by: address,
        at: u64,
        reason: vector<u8>,
    }

    // ========== Functions ==========

    // === Init - run exactly once at publish time ===

    fun init_module(admin: &signer) {
        move_to(
            admin,
            Authority {
                root_admin: @governance,
                roles: smart_table::new<u64, RoleRecord>(),
                issuers: smart_table::new<address, u64>(),
                admins: smart_table::new<address, u64>(),
                issuer_count: 0,
                admin_count: 0,
            }
        );
    }

    // === Root-only entry functions ===
    // Admin not need vc delegation, can approve issuer, suspend, revoke DID, VC, Issuer
    public entry fun grant_admin(
        root: &signer,
        admin: address,
    ) acquires Authority {
        let authority = borrow_mut_authority();
        let root_addr = signer::address_of(root);
        assert!(
            root_addr == authority.root_admin,
            errors::not_root_admin()
        );
        // ensure admin had did
        did_registry::assert_owner_active(admin);
        assert!(
            !smart_table::contains(&authority.admins, admin),
            errors::admin_already_exists()
        );
        let now = timestamp::now_seconds();
        let admin_record = RoleRecord {
            owner: admin,
            version: 1,
            approved_by: root_addr,
            approved_at: now,
            vc_type_mask: constants::VC_TYPE_DELEGATION(),
            delegation_vc_cid: b"",
            delegation_vc_hash: b"",
            expires_at: 0,
            status: ADMIN_STATUS_ACTIVE,
            status_reason: b"",
            status_updated_at: now,
        };


        let id = authority.admin_count + authority.issuer_count;
        assert!(
            !smart_table::contains(&authority.roles, id),
            errors::invalid_id()
        );
        smart_table::add(&mut authority.roles, id, admin_record);
        smart_table::add(&mut authority.admins, admin, id);
        authority.admin_count = authority.admin_count + 1;

        event::emit(
            AdminGrantedEvent {
                to: admin,
                by: root_addr,
                at: now,
            }
        )
    }

    // only root can revoke admin
    public entry fun revoke_admin(
        root: &signer,
        admin: address,
        reason: vector<u8>,
    ) acquires Authority {
        let authority = borrow_mut_authority();
        let root_addr = signer::address_of(root);
        assert!(
            root_addr == authority.root_admin,
            errors::not_root_admin()
        );
        assert!(
            smart_table::contains(&authority.admins, admin),
            errors::not_admin()
        );

        let id = *smart_table::borrow(&authority.admins, admin);
        assert!(
            smart_table::contains(&authority.roles, id),
            errors::invalid_id()
        );
        let admin_record = smart_table::borrow_mut(&mut authority.roles, id);
        assert!(
            admin_record.status != ADMIN_STATUS_REVOKED,
            errors::admin_already_revoked()
        );
        let now = timestamp::now_seconds();
        admin_record.status = ADMIN_STATUS_REVOKED;
        admin_record.status_reason = reason;
        admin_record.status_updated_at = now;

        event::emit(
            AdminRevokedEvent {
                to: admin,
                by: root_addr,
                reason,
                at: now,
            }
        );
    }

    // only root or admin can approve issuer
    public entry fun approve_issuer(
        admin: &signer,
        issuer: address,
        vc_type_mask: u64,
        delegation_vc_cid: vector<u8>,
        delegation_vc_hash: vector<u8>,
        expires_at: u64,
    ) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_is_active_admin(admin_addr);

        let authority = borrow_mut_authority();
        did_registry::assert_owner_active(issuer);
        assert!(
            !smart_table::contains(&authority.issuers, issuer),
            errors::issuer_already_exists()
        );
        if(vc_type_mask & constants::VC_TYPE_DELEGATION() != 0) {
            assert!(
                admin_addr == authority.root_admin,
                errors::not_root_admin()
            );
        };
        assert!(
            vector::length(&delegation_vc_hash) == 32,
            errors::hash_wrong_length()
        );

        let now = timestamp::now_seconds();
        let issuer_record = RoleRecord {
            owner: issuer,
            version: 1,
            approved_by: admin_addr,
            approved_at: now,
            vc_type_mask,
            delegation_vc_cid,
            delegation_vc_hash,
            expires_at,
            status: ISSUER_STATUS_ACTIVE,
            status_reason: b"",
            status_updated_at: now,
        };

        let id = authority.admin_count + authority.issuer_count;
        smart_table::add(&mut authority.roles, id, issuer_record);
        smart_table::add(&mut authority.issuers, issuer, id);
        authority.issuer_count = authority.issuer_count + 1;

        event::emit(
            IssuerApprovedEvent {
                issuer,
                by: admin_addr,
                vc_type_mask,
                delegation_vc_cid,
                at: now,
                expires_at,
            }
        );
    }

    public entry fun suspend_issuer(
        admin: &signer,
        issuer: address,
        reason: vector<u8>,
    ) acquires Authority {
        internal_set_issuer_status(
            admin,
            issuer,
            ISSUER_STATUS_SUSPENDED,
            reason,
        );
    }

    public entry fun reactivate_issuer(
        admin: &signer,
        issuer: address,
        reason: vector<u8>,
    ) acquires Authority {
        internal_set_issuer_status(
            admin,
            issuer,
            ISSUER_STATUS_ACTIVE,
            reason
        );
    }

    public entry fun revoke_issuer(
        admin: &signer,
        issuer: address,
        reason: vector<u8>,
    ) acquires Authority {
        internal_set_issuer_status(
            admin,
            issuer,
            ISSUER_STATUS_REVOKED,
            reason,
        );
    }

    /// Admin-level forced suspend did
    public entry fun admin_suspend_did(
        admin: &signer,
        target_owner: address,
        reason: vector<u8>,
    ) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_is_active_admin(admin_addr);

        did_registry::admin_suspend_did(admin_addr, target_owner, reason);
    }

    /// only admin-level can reactivate did
    public entry fun admin_reactivate_did(
        admin: &signer,
        target_onwer: address,
        reason: vector<u8>,
    ) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_is_active_admin(admin_addr);

        did_registry::admin_reactivate_did(admin_addr, target_onwer, reason);
    }

    /// Admin-level forced revocation (fraud, court order, etc.)
    public entry fun admin_revoke_did(
        admin: &signer,
        target_onwer: address,
        reason: vector<u8>,
    ) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_is_active_admin(admin_addr);

        did_registry::admin_revoke_did(admin_addr, target_onwer, reason);
    }

    // === Friends functions - can called by identity and credential ===

    public(friend) fun assert_is_active_admin(
        admin: address
    ) acquires Authority {
        let authority = borrow_authority();
        if (admin == authority.root_admin) {
            return
        };

        did_registry::assert_owner_active(admin);
        if (smart_table::contains(&authority.admins, admin)) {
            let id = *smart_table::borrow(&authority.admins, admin);
            assert!(
                smart_table::contains(&authority.roles, id),
                errors::invalid_id()
            );
            let record = smart_table::borrow(&authority.roles, id);
            assert!(
                record.status == ADMIN_STATUS_ACTIVE,
                errors::admin_not_active()
            );
        } else {
            assert!(admin == authority.root_admin, errors::admin_not_active());
        };
    }

    // Aborts if issuer is not an active, non-expired issuer
    // authorized for the given vc_type bit (vc_type_mask)
    public(friend) fun assert_is_active_issuer(
        issuer: address,
        vc_type: u64
    ) acquires Authority {
        did_registry::assert_owner_active(issuer);
        let authority = borrow_authority();
        assert!(
            smart_table::contains(&authority.issuers, issuer),
            errors::issuer_not_found()
        );
        let id = *smart_table::borrow(&authority.issuers, issuer);
        let record = smart_table::borrow(&authority.roles, id);
        assert!(
            record.status == ISSUER_STATUS_ACTIVE,
            errors::issuer_not_active()
        );
        let now = timestamp::now_seconds();
        assert!(
            record.expires_at == 0 || record.expires_at > now,
            errors::issuer_cap_expired()
        );
        assert!(
            record.vc_type_mask & vc_type != 0,
            errors::unauthorized_vc_type()
        );
    }

    // === View functions ===

    #[view]
    public fun is_active_issuer(issuer: address): bool acquires Authority {
        let authority = borrow_authority();
        if(!smart_table::contains(&authority.issuers, issuer)) {
            return false
        };
        let id = *smart_table::borrow(&authority.issuers, issuer);
        let record = smart_table::borrow(&authority.roles, id);
        if (record.status != ISSUER_STATUS_ACTIVE) {
            return false
        };
        let now = timestamp::now_seconds();
        record.expires_at == 0 || record.expires_at > now
    }

    #[view]
    public fun is_active_admin(addr: address): bool acquires Authority {
        let authority = borrow_authority();
        if (addr == authority.root_admin) {
            return true
        };
        if (!smart_table::contains(&authority.admins, addr)) {
            return false
        };
        let id = *smart_table::borrow(&authority.admins, addr);
        if (!smart_table::contains(&authority.roles, id)) {
            return false
        };
        let record = smart_table::borrow(&authority.roles, id);
        record.status == ADMIN_STATUS_ACTIVE
    }

    // return (approved_by, vc_type_mask delegation_vc_cid, delegation_vc_hash, exxpires_at, status)
    #[view]
    public fun get_info(addr: address): (address, u64, vector<u8>, vector<u8>, u64, u8) acquires Authority {
        let authority = borrow_authority();
        assert!(
            smart_table::contains(&authority.issuers, addr) || smart_table::contains(&authority.admins, addr),
            errors::owner_not_exists()
        );
        let id = if (smart_table::contains(&authority.issuers, addr)) {
            *smart_table::borrow(&authority.issuers, addr)
        } else {
            *smart_table::borrow(&authority.admins, addr)
        };
        let record = *smart_table::borrow(&authority.roles, id);
        return (record.approved_by, record.vc_type_mask, record.delegation_vc_cid, record.delegation_vc_hash, record.expires_at, record.status)
    }

    #[view]
    public fun get_root_admin(): address acquires Authority {
        borrow_authority().root_admin
    }

    #[view]
    public fun stats(): (u64, u64) acquires Authority {
        let authority = borrow_authority();
        (authority.admin_count, authority.issuer_count)
    }

    // == Internal helpers ===

    fun internal_set_issuer_status(
        admin: &signer,
        issuer: address,
        new_status: u8,
        reason: vector<u8>,
    ) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_is_active_admin(admin_addr);

        let authority = borrow_mut_authority();
        assert!(
            smart_table::contains(&authority.issuers, issuer),
            errors::issuer_not_found()
        );

        let id = *smart_table::borrow(&authority.issuers, issuer);
        let record = smart_table::borrow_mut(&mut authority.roles, id);
        assert!(
            record.status != ISSUER_STATUS_REVOKED,
            errors::issuer_already_revoked()
        );
        if (new_status == ISSUER_STATUS_SUSPENDED) {
            assert!(
                record.status == ISSUER_STATUS_ACTIVE,
                errors::issuer_not_active()
            );
        };
        if (new_status == ISSUER_STATUS_ACTIVE) {
            assert!(
                record.status == ISSUER_STATUS_SUSPENDED,
                errors::issuer_not_suspended()
            );
        };
        let now = timestamp::now_seconds();
        record.status = new_status;
        record.status_reason = reason;
        record.status_updated_at = now;

        event::emit(
            IssuerStatusChangedEvent{
                issuer,
                by: admin_addr,
                new_status,
                reason,
                at: now,
            }
        );
    }

    inline fun borrow_authority(): &Authority {
        borrow_global<Authority>(@governance)
    }

    inline fun borrow_mut_authority(): &mut Authority {
        borrow_global_mut<Authority>(@governance)
    }

    #[test_only]
    public fun initialize_for_test(root: &signer) {
        init_module(root);
    }

    #[test_only]
    fun build_admin_granted_event(to: address, by: address, at: u64): AdminGrantedEvent {
        AdminGrantedEvent { 
            to, 
            by, 
            at 
        }
    }

    #[test_only]
    public fun assert_admin_granted_event_emitted(to: address, by: address, at: u64) {
        let event = build_admin_granted_event(to, by, at);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    fun build_admin_revoked_event(to: address, by: address, reason: vector<u8>, at: u64): AdminRevokedEvent {
        AdminRevokedEvent { 
            to, 
            by, 
            reason, 
            at 
        }
    }

    #[test_only]
    public fun assert_admin_revoked_event_emitted(to: address, by: address, reason: vector<u8>, at: u64) {
        let event = build_admin_revoked_event(to, by, reason, at);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    fun build_issuer_approved_event(
        issuer: address,
        by: address,
        vc_type_mask: u64,
        delegation_vc_cid: vector<u8>,
        at: u64,
        expires_at: u64,
    ): IssuerApprovedEvent {
        IssuerApprovedEvent { 
            issuer, 
            by, 
            vc_type_mask, 
            delegation_vc_cid, 
            at, 
            expires_at 
        }
    }

    #[test_only]
    public fun assert_issuer_approved_event_emitted(
        issuer: address,
        by: address,
        vc_type_mask: u64,
        delegation_vc_cid: vector<u8>,
        at: u64,
        expires_at: u64,
    ) {
        let event = build_issuer_approved_event(issuer, by, vc_type_mask, delegation_vc_cid, at, expires_at);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    fun build_issuer_status_changed_event(
        issuer: address,
        by: address,
        new_status: u8,
        reason: vector<u8>,
        at: u64,
    ): IssuerStatusChangedEvent {
        IssuerStatusChangedEvent { 
            issuer, 
            by, 
            new_status, 
            reason, 
            at 
        }
    }

    #[test_only]
    public fun assert_issuer_status_changed_event_emitted(
        issuer: address,
        by: address,
        new_status: u8,
        reason: vector<u8>,
        at: u64,
    ) {
        let event = build_issuer_status_changed_event(issuer, by, new_status, reason, at);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    fun build_issuer_revoked_event(issuer: address, by: address, at: u64, reason: vector<u8>): IssuerRevokedEvent {
        IssuerRevokedEvent { 
            issuer, 
            by, 
            at, 
            reason 
        }
    }

    #[test_only]
    public fun assert_issuer_revoked_event_emitted(issuer: address, by: address, at: u64, reason: vector<u8>) {
        let event = build_issuer_revoked_event(issuer, by, at, reason);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    public fun get_admin_details(addr: address): (address, address, u64, u64, u64, vector<u8>, vector<u8>, u64, u8, vector<u8>, u64) acquires Authority {
        let authority = borrow_authority();
        assert!(smart_table::contains(&authority.admins, addr), errors::not_admin());
        let id = *smart_table::borrow(&authority.admins, addr);
        let record = *smart_table::borrow(&authority.roles, id);
        (record.owner, record.approved_by, record.approved_at, record.version, record.vc_type_mask, record.delegation_vc_cid, record.delegation_vc_hash, record.expires_at, record.status, record.status_reason, record.status_updated_at)
    }

    #[test_only]
    public fun get_issuer_details(addr: address): (address, address, u64, u64, u64, vector<u8>, vector<u8>, u64, u8, vector<u8>, u64) acquires Authority {
        let authority = borrow_authority();
        assert!(smart_table::contains(&authority.issuers, addr), errors::issuer_not_found());
        let id = *smart_table::borrow(&authority.issuers, addr);
        let record = *smart_table::borrow(&authority.roles, id);
        (record.owner, record.approved_by, record.approved_at, record.version, record.vc_type_mask, record.delegation_vc_cid, record.delegation_vc_hash, record.expires_at, record.status, record.status_reason, record.status_updated_at)
    }
}
