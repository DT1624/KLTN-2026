module vnu::authority {

    use std::signer;
    use std::vector;
    use aptos_std::smart_table;
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use vnu::did_registry;
    use vnu::constants;
    use vnu::errors;

    friend vnu::vc_registry;

    // ========== Constants ==========

    // Issuer status
    const ISSUER_STATUS_ACTIVE:     u8 = 1;
    const ISSUER_STATUS_REVOKED:    u8 = 2;
    const ISSUER_STATUS_SUSPENDED:  u8 = 3;

    const ADMIN_STATUS_ACTIVE:      u8 = 1;
    const ADMIN_STATUS_REVOKED:     u8 = 2;

    /// Khong co dia chi nao dang cho nhan quyen root.
    const NO_PENDING_ROOT:          address = @0x0;

    /// Tran an toan cho view tra ve ca danh sach (F-10). Vuot nguong nay thi
    /// view that bai RO RANG thay vi vo am tham khi cham gioi han gas/phan hoi.
    const MAX_VIEW_ITEMS:           u64 = 500;
    /// Tran cho mot trang cua view phan trang.
    const MAX_PAGE_LIMIT:           u64 = 200;

    // ========== Structs ==========

    struct RoleRecord has copy, drop, store {
        owner: address,
        /// Tang moi lan dia chi nay duoc cap lai vai tro sau khi bi thu hoi (F-03/F-04).
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
        /// Dia chi da duoc de cu lam root nhung CHUA ky nhan (F-00).
        pending_root: address,
        roles: smart_table::SmartTable<u64, RoleRecord>,
        issuers: smart_table::SmartTable<address, u64>,
        admins: smart_table::SmartTable<address, u64>,
        /// So dia chi RIENG BIET da tung duoc cap vai tro (khong phai so dang hoat dong).
        issuer_count: u64,
        admin_count: u64,
        /// Bo sinh id chi tang, khong bao gio tai su dung (F-11c). Truoc day id
        /// duoc tinh bang admin_count + issuer_count nen chi dung nho trung hop:
        /// them bat ky thao tac nao khong tang counter la hai ban ghi dung id.
        next_role_id: u64,
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
    struct RootTransferProposedEvent has drop, store {
        from: address,
        to: address,
        at: u64,
    }

    #[event]
    struct RootTransferredEvent has drop, store {
        from: address,
        to: address,
        at: u64,
    }

    // ========== Functions ==========

    // === Init - run exactly once at publish time ===

    /// F-00: neu publish ma khong truyen `--named-addresses root_admin=0x...`
    /// (tuc @root_admin = 0x0) thi lay chinh nguoi publish lam root, thay vi
    /// dong bang he thong o mot dia chi khong ai giu khoa.
    fun init_module(publisher: &signer) {
        let root = if (@root_admin == @0x0) {
            signer::address_of(publisher)
        } else {
            @root_admin
        };
        move_to(
            publisher,
            Authority {
                root_admin: root,
                pending_root: NO_PENDING_ROOT,
                roles: smart_table::new<u64, RoleRecord>(),
                issuers: smart_table::new<address, u64>(),
                admins: smart_table::new<address, u64>(),
                issuer_count: 0,
                admin_count: 0,
                next_role_id: 0,
            }
        );
    }

    // === Root-only entry functions ===

    /// Chuyen quyen root HAI BUOC, buoc 1: root hien tai de cu nguoi nhan.
    /// Quyen chua doi o buoc nay. Chuyen mot buoc la bay mot chieu: chuyen
    /// nham sang dia chi khong ai giu khoa la khoa chet ca cay quyen luc.
    public entry fun propose_root(
        root: &signer,
        new_root: address,
    ) acquires Authority {
        let authority = borrow_mut_authority();
        let root_addr = signer::address_of(root);
        assert!(
            root_addr == authority.root_admin,
            errors::not_root_admin()
        );
        assert!(
            new_root != NO_PENDING_ROOT,
            errors::not_pending_root()
        );
        authority.pending_root = new_root;

        event::emit(
            RootTransferProposedEvent {
                from: root_addr,
                to: new_root,
                at: timestamp::now_seconds(),
            }
        );
    }

    /// Buoc 2: nguoi duoc de cu TU KY de nhan quyen. Chinh chu ky nay la bang
    /// chung ho dang giu khoa rieng cua dia chi do.
    public entry fun accept_root(
        new_root: &signer,
    ) acquires Authority {
        let authority = borrow_mut_authority();
        let new_root_addr = signer::address_of(new_root);
        assert!(
            authority.pending_root != NO_PENDING_ROOT,
            errors::no_pending_root()
        );
        assert!(
            new_root_addr == authority.pending_root,
            errors::not_pending_root()
        );
        let old_root = authority.root_admin;
        authority.root_admin = new_root_addr;
        authority.pending_root = NO_PENDING_ROOT;

        event::emit(
            RootTransferredEvent {
                from: old_root,
                to: new_root_addr,
                at: timestamp::now_seconds(),
            }
        );
    }

    /// Root huy de cu khi doi y hoac de cu nham.
    public entry fun cancel_root_transfer(
        root: &signer,
    ) acquires Authority {
        let authority = borrow_mut_authority();
        assert!(
            signer::address_of(root) == authority.root_admin,
            errors::not_root_admin()
        );
        assert!(
            authority.pending_root != NO_PENDING_ROOT,
            errors::no_pending_root()
        );
        authority.pending_root = NO_PENDING_ROOT;
    }

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

        // F-11d: mot dia chi khong the vua la admin dang hoat dong vua la issuer
        // dang hoat dong - get_info se che mat mot trong hai vai tro.
        assert!(
            !has_active_role(&authority.issuers, &authority.roles, admin, ISSUER_STATUS_ACTIVE),
            errors::role_conflict()
        );

        // F-03: admin bi thu hoi PHAI cap lai duoc. Truoc day chi mot dong
        // `assert!(!contains(admins, admin))` la khoa vinh vien.
        let prev_version = 0;
        let is_new_address = !smart_table::contains(&authority.admins, admin);
        if (!is_new_address) {
            let prev_id = *smart_table::borrow(&authority.admins, admin);
            let prev = smart_table::borrow(&authority.roles, prev_id);
            assert!(
                prev.status == ADMIN_STATUS_REVOKED,
                errors::admin_already_exists()
            );
            prev_version = prev.version;
        };

        let now = timestamp::now_seconds();
        let admin_record = RoleRecord {
            owner: admin,
            version: prev_version + 1,
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

        let id = authority.next_role_id;
        authority.next_role_id = id + 1;
        assert!(
            !smart_table::contains(&authority.roles, id),
            errors::invalid_id()
        );
        smart_table::add(&mut authority.roles, id, admin_record);
        // upsert: ban ghi cu van nam trong `roles` duoi id cu -> giu vet kiem toan
        smart_table::upsert(&mut authority.admins, admin, id);
        if (is_new_address) {
            authority.admin_count = authority.admin_count + 1;
        };

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

    /// Cap quyen issuer. Nguoi cap co the la:
    ///   - root / admin dang hoat dong: cap duoc moi vc_type_mask
    ///     (rieng bit VC_DELEGATION chi root moi cap duoc);
    ///   - issuer dang hoat dong VA co bit VC_DELEGATION (F-02): cap duoc
    ///     sub-issuer, nhung mask phai la TAP CON cua mask minh dang co va
    ///     han dung khong duoc vuot han uy quyen cua chinh minh.
    public entry fun approve_issuer(
        approver: &signer,
        issuer: address,
        vc_type_mask: u64,
        delegation_vc_cid: vector<u8>,
        delegation_vc_hash: vector<u8>,
        expires_at: u64,
    ) acquires Authority {
        let approver_addr = signer::address_of(approver);
        let by_delegation = assert_can_approve_issuer(approver_addr, vc_type_mask, expires_at);

        let authority = borrow_mut_authority();
        did_registry::assert_owner_active(issuer);

        // F-11d: khong cho mot dia chi giu dong thoi admin + issuer dang hoat dong
        assert!(
            !has_active_role(&authority.admins, &authority.roles, issuer, ADMIN_STATUS_ACTIVE),
            errors::role_conflict()
        );

        // F-04: issuer bi thu hoi PHAI approve lai duoc
        let prev_version = 0;
        let is_new_address = !smart_table::contains(&authority.issuers, issuer);
        // F-12: duong uy quyen khong duoc cap lai cho dia chi tung la issuer -
        // neu khong, issuer uy quyen go duoc quyet dinh thu hoi cua admin.
        assert!(!by_delegation || is_new_address, errors::not_authorized());
        if (!is_new_address) {
            let prev_id = *smart_table::borrow(&authority.issuers, issuer);
            let prev = smart_table::borrow(&authority.roles, prev_id);
            assert!(
                prev.status == ISSUER_STATUS_REVOKED,
                errors::issuer_already_exists()
            );
            prev_version = prev.version;
        };

        // Chi ROOT moi duoc cap bit uy quyen lai - giu nguyen tu ban goc.
        if (vc_type_mask & constants::VC_TYPE_DELEGATION() != 0) {
            assert!(
                approver_addr == authority.root_admin,
                errors::not_root_admin()
            );
        };

        // F-01: truoc day assert nay nam NGOAI khoi if nen MOI issuer deu bi
        // doi hash 32 byte, ke ca issuer thuong khong he co VC uy quyen nao.
        // Nay chi bat buoc khi that su co uy quyen: hoac issuer nay duoc cap
        // bit VC_DELEGATION, hoac chinh no duoc cap boi mot issuer uy quyen.
        let needs_delegation_proof =
            (vc_type_mask & constants::VC_TYPE_DELEGATION() != 0) || by_delegation;
        if (needs_delegation_proof) {
            assert!(
                vector::length(&delegation_vc_hash) == 32,
                errors::hash_wrong_length()
            );
            assert!(
                !vector::is_empty(&delegation_vc_cid),
                errors::invalid_cid()
            );
        } else {
            // Khong bat buoc, nhung neu co truyen thi van phai dung 32 byte:
            // nhan bua mot hash 7 byte roi im lang la cach tot nhat de sau nay
            // khong ai doi chieu duoc gi.
            assert!(
                vector::is_empty(&delegation_vc_hash)
                    || vector::length(&delegation_vc_hash) == 32,
                errors::hash_wrong_length()
            );
        };

        let now = timestamp::now_seconds();
        let issuer_record = RoleRecord {
            owner: issuer,
            version: prev_version + 1,
            approved_by: approver_addr,
            approved_at: now,
            vc_type_mask,
            delegation_vc_cid,
            delegation_vc_hash,
            expires_at,
            status: ISSUER_STATUS_ACTIVE,
            status_reason: b"",
            status_updated_at: now,
        };

        let id = authority.next_role_id;
        authority.next_role_id = id + 1;
        assert!(
            !smart_table::contains(&authority.roles, id),
            errors::invalid_id()
        );
        smart_table::add(&mut authority.roles, id, issuer_record);
        smart_table::upsert(&mut authority.issuers, issuer, id);
        if (is_new_address) {
            authority.issuer_count = authority.issuer_count + 1;
        };

        event::emit(
            IssuerApprovedEvent {
                issuer,
                by: approver_addr,
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
        assert_can_moderate_did(admin_addr, target_owner);

        did_registry::admin_suspend_did(admin_addr, target_owner, reason);
    }

    /// only admin-level can reactivate did
    public entry fun admin_reactivate_did(
        admin: &signer,
        target_owner: address,
        reason: vector<u8>,
    ) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_can_moderate_did(admin_addr, target_owner);

        did_registry::admin_reactivate_did(admin_addr, target_owner, reason);
    }

    /// Admin-level forced revocation (fraud, court order, etc.)
    public entry fun admin_revoke_did(
        admin: &signer,
        target_owner: address,
        reason: vector<u8>,
    ) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_can_moderate_did(admin_addr, target_owner);

        did_registry::admin_revoke_did(admin_addr, target_owner, reason);
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
        // F-11b: nhanh `else` cu la `assert!(admin == root_admin, ...)` - luon
        // sai vi root da return o tren. Viet thang la abort cho ro y.
        assert!(
            smart_table::contains(&authority.admins, admin),
            errors::admin_not_active()
        );
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
        // F-12: vc_type phai nam TRON trong mask. Truoc day chi can giao nhau
        // khac 0, nen issuer chi duoc cap cu nhan van cap duoc "cu nhan + tien si".
        assert!(
            vc_type != 0 && record.vc_type_mask & vc_type == vc_type,
            errors::unauthorized_vc_type()
        );
    }

    // === View functions ===

    #[view]
    public fun is_active_issuer(issuer: address): bool acquires Authority {
        // F-12: khop assert_is_active_issuer - DID bi thu hoi/khoa thi khong con tin cay.
        if (!did_registry::has_active_did(issuer)) {
            return false
        };
        let authority = borrow_authority();
        if(!smart_table::contains(&authority.issuers, issuer)) {
            return false
        };
        let id = *smart_table::borrow(&authority.issuers, issuer);
        if (!smart_table::contains(&authority.roles, id)) {
            return false
        };
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
        if (!did_registry::has_active_did(addr)) {
            return false
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

    // Issuer nay co duoc phep cap quyen cho issuer khac khong (F-02)?
    #[view]
    public fun can_delegate(addr: address): bool acquires Authority {
        let authority = borrow_authority();
        if (addr == authority.root_admin) {
            return true
        };
        if (!did_registry::has_active_did(addr)) {
            return false
        };
        if (smart_table::contains(&authority.admins, addr)) {
            let aid = *smart_table::borrow(&authority.admins, addr);
            if (smart_table::contains(&authority.roles, aid)) {
                let ar = smart_table::borrow(&authority.roles, aid);
                if (ar.status == ADMIN_STATUS_ACTIVE) {
                    return true
                };
            };
        };
        if (!smart_table::contains(&authority.issuers, addr)) {
            return false
        };
        let id = *smart_table::borrow(&authority.issuers, addr);
        if (!smart_table::contains(&authority.roles, id)) {
            return false
        };
        let record = smart_table::borrow(&authority.roles, id);
        if (record.status != ISSUER_STATUS_ACTIVE) {
            return false
        };
        let now = timestamp::now_seconds();
        if (record.expires_at != 0 && record.expires_at <= now) {
            return false
        };
        record.vc_type_mask & constants::VC_TYPE_DELEGATION() != 0
    }

    // return (approved_by, vc_type_mask, delegation_vc_cid, delegation_vc_hash, expires_at, status)
    #[view]
    public fun get_info(addr: address): (address, u64, vector<u8>, vector<u8>, u64, u8) acquires Authority {
        let record = role_of(addr);
        (record.approved_by, record.vc_type_mask, record.delegation_vc_cid, record.delegation_vc_hash, record.expires_at, record.status)
    }

    // Ban ghi vai tro day du - dung cho man hinh quan tri va bo lap chi muc.
    #[view]
    public fun get_role(addr: address): RoleRecord acquires Authority {
        role_of(addr)
    }

    #[view]
    public fun get_root_admin(): address acquires Authority {
        borrow_authority().root_admin
    }

    // @0x0 nghia la khong co de cu nao dang cho.
    #[view]
    public fun get_pending_root(): address acquires Authority {
        borrow_authority().pending_root
    }

    #[view]
    public fun stats(): (u64, u64) acquires Authority {
        let authority = borrow_authority();
        (authority.admin_count, authority.issuer_count)
    }

    #[view]
    public fun total_roles(): u64 acquires Authority {
        borrow_authority().next_role_id
    }

    // F-10: cac view liet ke toan bo chi an toan khi bang con nho. Vuot
    // MAX_VIEW_ITEMS thi abort co ma ro rang de nguoi goi chuyen sang ban
    // phan trang, thay vi vo am tham o gioi han gas.
    #[view]
    public fun get_issuers(): vector<address> acquires Authority {
        let authority = borrow_authority();
        assert!(
            smart_table::length(&authority.issuers) <= MAX_VIEW_ITEMS,
            errors::result_too_large()
        );
        smart_table::keys(&authority.issuers)
    }

    #[view]
    public fun get_admins(): vector<address> acquires Authority {
        let authority = borrow_authority();
        assert!(
            smart_table::length(&authority.admins) <= MAX_VIEW_ITEMS,
            errors::result_too_large()
        );
        smart_table::keys(&authority.admins)
    }

    // Phan trang theo id tang dan - on dinh va co thu tu, khac voi con tro
    // bucket cua smart_table (thu tu doi khi bang tai can bang lai).
    #[view]
    public fun get_roles_paginated(start: u64, limit: u64): vector<RoleRecord> acquires Authority {
        assert!(limit > 0 && limit <= MAX_PAGE_LIMIT, errors::invalid_page());
        let authority = borrow_authority();
        let out = vector::empty<RoleRecord>();
        // Dem theo so phan tu con lai thay vi tinh `start + limit`: voi start
        // gan u64::MAX phep cong do se tran va abort bang loi so hoc kho hieu.
        let id = start;
        let taken = 0;
        while (taken < limit && id < authority.next_role_id) {
            if (smart_table::contains(&authority.roles, id)) {
                vector::push_back(&mut out, *smart_table::borrow(&authority.roles, id));
            };
            id = id + 1;
            taken = taken + 1;
        };
        out
    }

    // == Internal helpers ===

    /// F-12: admin thuong khong duoc khoa/thu hoi DID cua root hay admin dang
    /// hoat dong - lam vay la lach luat "chi root moi thu hoi admin".
    fun assert_can_moderate_did(caller: address, target: address) acquires Authority {
        assert_is_active_admin(caller);
        let authority = borrow_authority();
        assert!(target != authority.root_admin, errors::protected_target());
        if (caller != authority.root_admin) {
            assert!(
                !has_active_role(&authority.admins, &authority.roles, target, ADMIN_STATUS_ACTIVE),
                errors::protected_target()
            );
        };
    }

    /// Xac dinh nguoi goi co quyen cap issuer khong.
    /// Tra ve `true` neu cap qua UY QUYEN (issuer co bit VC_DELEGATION),
    /// `false` neu cap voi tu cach root/admin.
    fun assert_can_approve_issuer(
        approver: address,
        requested_mask: u64,
        requested_expires_at: u64,
    ): bool acquires Authority {
        let authority = borrow_authority();
        if (approver == authority.root_admin) {
            return false
        };

        // Moi nguoi cap khong phai root deu phai co DID dang hoat dong.
        did_registry::assert_owner_active(approver);

        if (smart_table::contains(&authority.admins, approver)) {
            let id = *smart_table::borrow(&authority.admins, approver);
            assert!(
                smart_table::contains(&authority.roles, id),
                errors::invalid_id()
            );
            let record = smart_table::borrow(&authority.roles, id);
            assert!(
                record.status == ADMIN_STATUS_ACTIVE,
                errors::admin_not_active()
            );
            return false
        };

        // F-02: nhanh uy quyen. Truoc day contract co du khung (bit
        // VC_DELEGATION, hai truong delegation_vc_*) nhung khong ham nao doc
        // bit do de phan quyen - no chi la du lieu trang tri.
        assert!(
            smart_table::contains(&authority.issuers, approver),
            errors::admin_not_active()
        );
        let id = *smart_table::borrow(&authority.issuers, approver);
        assert!(
            smart_table::contains(&authority.roles, id),
            errors::invalid_id()
        );
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
            record.vc_type_mask & constants::VC_TYPE_DELEGATION() != 0,
            errors::cannot_delegate()
        );
        // Khong leo thang quyen: mask cua sub-issuer phai nam tron trong mask cha.
        assert!(
            requested_mask & record.vc_type_mask == requested_mask,
            errors::unauthorized_vc_type()
        );
        // Han uy quyen cua sub-issuer khong duoc vuot han cua nguoi cap.
        if (record.expires_at != 0) {
            assert!(
                requested_expires_at != 0 && requested_expires_at <= record.expires_at,
                errors::issuer_cap_expired()
            );
        };
        true
    }

    /// Dia chi nay co ban ghi o trang thai `active_status` trong bang chi muc
    /// da cho khong? Dung de phat hien xung dot vai tro (F-11d).
    fun has_active_role(
        index: &smart_table::SmartTable<address, u64>,
        roles: &smart_table::SmartTable<u64, RoleRecord>,
        addr: address,
        active_status: u8,
    ): bool {
        if (!smart_table::contains(index, addr)) {
            return false
        };
        let id = *smart_table::borrow(index, addr);
        if (!smart_table::contains(roles, id)) {
            return false
        };
        smart_table::borrow(roles, id).status == active_status
    }

    /// Tra ve ban ghi vai tro hien hanh cua mot dia chi. Uu tien ban ghi issuer
    /// vi do la vai tro co han dung va mask - phan hay bi tra cuu nhat.
    fun role_of(addr: address): RoleRecord acquires Authority {
        let authority = borrow_authority();
        let has_issuer = smart_table::contains(&authority.issuers, addr);
        let has_admin = smart_table::contains(&authority.admins, addr);
        assert!(has_issuer || has_admin, errors::owner_not_exists());

        // Uu tien ban ghi DANG HOAT DONG. Mot dia chi tung la issuer roi bi thu
        // hoi va nay la admin thi phai tra ve vai tro admin - vai tro cu da chet
        // khong duoc che mat vai tro hien tai (cung ho voi F-11d).
        if (has_issuer) {
            let iid = *smart_table::borrow(&authority.issuers, addr);
            assert!(
                smart_table::contains(&authority.roles, iid),
                errors::invalid_id()
            );
            let issuer_record = smart_table::borrow(&authority.roles, iid);
            if (issuer_record.status == ISSUER_STATUS_ACTIVE || !has_admin) {
                return *issuer_record
            };
        };

        let aid = *smart_table::borrow(&authority.admins, addr);
        assert!(
            smart_table::contains(&authority.roles, aid),
            errors::invalid_id()
        );
        *smart_table::borrow(&authority.roles, aid)
    }

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
        assert!(
            smart_table::contains(&authority.roles, id),
            errors::invalid_id()
        );
        let record = smart_table::borrow_mut(&mut authority.roles, id);
        // Da thu hoi thi khong quay lai bang duong nay nua - phai approve_issuer
        // lai (F-04), khi do ban ghi moi duoc tao voi version + 1.
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
        borrow_global<Authority>(@vnu)
    }

    inline fun borrow_mut_authority(): &mut Authority {
        borrow_global_mut<Authority>(@vnu)
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
    fun build_root_transfer_proposed_event(from: address, to: address, at: u64): RootTransferProposedEvent {
        RootTransferProposedEvent {
            from,
            to,
            at,
        }
    }

    #[test_only]
    public fun assert_root_transfer_proposed_event_emitted(from: address, to: address, at: u64) {
        let event = build_root_transfer_proposed_event(from, to, at);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    fun build_root_transferred_event(from: address, to: address, at: u64): RootTransferredEvent {
        RootTransferredEvent {
            from,
            to,
            at,
        }
    }

    #[test_only]
    public fun assert_root_transferred_event_emitted(from: address, to: address, at: u64) {
        let event = build_root_transferred_event(from, to, at);
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

    #[test_only]
    public fun role_id_of_issuer(addr: address): u64 acquires Authority {
        *smart_table::borrow(&borrow_authority().issuers, addr)
    }

    #[test_only]
    public fun role_id_of_admin(addr: address): u64 acquires Authority {
        *smart_table::borrow(&borrow_authority().admins, addr)
    }

    #[test_only]
    public fun next_role_id_for_test(): u64 acquires Authority {
        borrow_authority().next_role_id
    }
}
