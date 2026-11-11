module vnu::vc_registry {

    use std::signer;
    use std::vector;
    use aptos_std::smart_table;
    use aptos_std::smart_table::SmartTable;
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use vnu::did_registry;
    use vnu::authority;
    use vnu::errors;

    // ========== Contants ==========

    // VC status
    const VC_STATUS_ACTIVE:             u8 = 1;
    const VC_STATUS_SUSPENDED:          u8 = 2;
    const VC_STATUS_EXPIRED:            u8 = 3;
    const VC_STATUS_REVOKED:            u8 = 4;

    // F-06: content_cid rong -> VC khong lay ve duoc noi dung de doi chieu hash.
    const MIN_CID_LEN:                  u64 = 10;
    const MAX_CID_LEN:                  u64 = 128;

    // F-10
    const MAX_VIEW_ITEMS:               u64 = 500;
    const MAX_PAGE_LIMIT:               u64 = 200;

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
        // 0 = vinh vien. Bang tot nghiep thi vinh vien la hop ly, nhung VC uy
        // quyen va the sinh vien thi bat buoc phai co han (F-09).
        expires_at: u64,
        revoked_at: u64,
        status_reason: vector<u8>,
    }

    struct VCRegistry has key {
        vc_count: u64,
        vcs: smart_table::SmartTable<u64, VCRecord>,
        // vc_id_hash to id
        hash_to_id: smart_table::SmartTable<vector<u8>, u64>,
        // F-11e: hai bang duoi la TONG DA TUNG CAP, khong bao gio giam.
        // issuer to VC count
        issuer_vc_count: smart_table::SmartTable<address, u64>,
        // holder to VC count
        holder_vc_count: smart_table::SmartTable<address, u64>,
        // ...con hai bang nay la SO DANG CO HIEU LUC: giam khi thu hoi VA khi
        // tam ngung, tang lai khi phuc hoi. Giao dien hien "so van bang" phai
        // dung bo nay, neu khong se dem ca nhung tam da bi thu hoi.
        issuer_live_vc_count: smart_table::SmartTable<address, u64>,
        holder_live_vc_count: smart_table::SmartTable<address, u64>,
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

    fun init_module(root: &signer) {
        move_to(
            root,
            VCRegistry {
                vc_count: 0,
                vcs: smart_table::new<u64, VCRecord>(),
                hash_to_id: smart_table::new<vector<u8>, u64>(),
                issuer_vc_count: smart_table::new<address, u64>(),
                holder_vc_count: smart_table::new<address, u64>(),
                issuer_live_vc_count: smart_table::new<address, u64>(),
                holder_live_vc_count: smart_table::new<address, u64>(),
            }
        )
    }

    // ========== Public entry functions ==========

    // == Issue a Verifiable Credential ===
    // F-09: `expires_at` la tham so THAT (0 = vinh vien). Truoc day no bi ghi
    // cung bang 0 nen toan bo nhanh xu ly het han la ma chet: VC_STATUS_EXPIRED
    // khong bao gio duoc ghi, hai assert chan no khong bao gio dung.
    public entry fun issue_vc(
        issuer: &signer,
        holder_addr: address,
        vc_type: u64,
        vc_id_hash: vector<u8>,
        content_cid: vector<u8>,
        content_hash: vector<u8>,
        expires_at: u64,
    ) acquires VCRegistry {
        // Step 1: authority check
        // Issuer approved (by admin) and type allowed (OR with vc_type_mask != 0)
        let issuer_addr = signer::address_of(issuer);
        // F-12: issuer tu cap van bang cho chinh minh la xung dot loi ich.
        assert!(holder_addr != issuer_addr, errors::self_issue());
        authority::assert_is_active_issuer(issuer_addr, vc_type);

        // Step 2: derive issuer_did from address (not from input to prevents impersonation)
        let issuer_did = did_registry::get_active_did_string(issuer_addr);

        // Step 3: verify holder DID - assert this did active, can receive VC.
        let holder_did = did_registry::get_active_did_string(holder_addr);

        // Step 4: hash + CID integrity
        assert!(
            vector::length(&vc_id_hash) == 32,
            errors::hash_wrong_length()
        );
        assert!(
            vector::length(&content_hash) == 32,
            errors::hash_wrong_length()
        );
        let cid_len = vector::length(&content_cid);
        assert!(
            cid_len >= MIN_CID_LEN && cid_len <= MAX_CID_LEN,
            errors::invalid_cid()
        );

        let now = timestamp::now_seconds();
        // Cap mot VC da het han ngay tu luc cap la vo nghia - chan tu dau.
        assert!(
            expires_at == 0 || expires_at > now,
            errors::vc_already_expired()
        );

        // Step 5: no duplicate
        let vc_registry = borrow_mut_vc_registry();
        assert!(
            !smart_table::contains(&vc_registry.hash_to_id, vc_id_hash),
            errors::vc_already_exists()
        );

        let id = vc_registry.vc_count;
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
            expires_at,
            revoked_at: 0,
            status_reason: b"",
        };
        smart_table::add(&mut vc_registry.vcs, id, vc_record);
        smart_table::add(&mut vc_registry.hash_to_id, vc_id_hash, id);

        vc_registry.vc_count = id + 1;
        internal_increment_count(&mut vc_registry.issuer_vc_count, issuer_addr);
        internal_increment_count(&mut vc_registry.holder_vc_count, holder_addr);
        internal_increment_count(&mut vc_registry.issuer_live_vc_count, issuer_addr);
        internal_increment_count(&mut vc_registry.holder_live_vc_count, holder_addr);

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
                expires_at,
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
        effective_status(record, timestamp::now_seconds())
    }

    // F-09: truoc day view nay ABORT khi VC het han. Sai ve nguyen tac - ham
    // view phai TRA VE ban ghi de ben xac minh tu danh gia, chu khong phai tu
    // choi tra loi. Nay tra ve ban ghi voi `status` da tinh ca yeu to het han.
    #[view]
    public fun get_vc_by_id(vc_id: u64): VCRecord acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        assert!(
            smart_table::contains(&vc_registry.vcs, vc_id),
            errors::invalid_id()
        );
        let record = *smart_table::borrow(&vc_registry.vcs, vc_id);
        record.status = effective_status(&record, timestamp::now_seconds());
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
        // Chi VC dang co hieu luc moi duoc coi la "toan ven va dung hieu luc"
        if (effective_status(record, timestamp::now_seconds()) != VC_STATUS_ACTIVE) {
            return false
        };
        record.content_hash == claimed_hash
    }

    // Tong da tung cap (khong giam khi thu hoi).
    #[view]
    public fun get_counts(
        issuer: address,
        holder: address,
    ): (u64, u64) acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        (
            count_of(&vc_registry.issuer_vc_count, issuer),
            count_of(&vc_registry.holder_vc_count, holder),
        )
    }

    // F-11e: so VC DANG CO HIEU LUC - dung cho giao dien, tranh dem ca VC da bi
    // thu hoi hoac tam ngung. Luu y: so nay KHONG tru VC het han, vi het han la
    // thuoc tinh theo thoi gian chu khong phai mot thao tac ghi - khong ai gui
    // giao dich vao dung giay no het han de giam bo dem. Vi vay day la CAN TREN
    // cua so VC con hieu luc, khong phai con so chinh xac.
    #[view]
    public fun get_live_counts(
        issuer: address,
        holder: address,
    ): (u64, u64) acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        (
            count_of(&vc_registry.issuer_live_vc_count, issuer),
            count_of(&vc_registry.holder_live_vc_count, holder),
        )
    }

    #[view]
    public fun total_vcs(): u64 acquires VCRegistry {
        borrow_vc_registry().vc_count
    }

    #[view]
    public fun get_vcs(): vector<vector<u8>> acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        assert!(
            smart_table::length(&vc_registry.hash_to_id) <= MAX_VIEW_ITEMS,
            errors::result_too_large()
        );
        smart_table::keys(&vc_registry.hash_to_id)
    }

    #[view]
    public fun get_vcs_paginated(start: u64, limit: u64): vector<VCRecord> acquires VCRegistry {
        assert!(limit > 0 && limit <= MAX_PAGE_LIMIT, errors::invalid_page());
        let vc_registry = borrow_vc_registry();
        let now = timestamp::now_seconds();
        let out = vector::empty<VCRecord>();
        // Dem theo so phan tu con lai thay vi tinh `start + limit`: voi start
        // gan u64::MAX phep cong do se tran va abort bang loi so hoc kho hieu.
        let id = start;
        let taken = 0;
        while (taken < limit && id < vc_registry.vc_count) {
            if (smart_table::contains(&vc_registry.vcs, id)) {
                let record = *smart_table::borrow(&vc_registry.vcs, id);
                record.status = effective_status(&record, now);
                vector::push_back(&mut out, record);
            };
            id = id + 1;
            taken = taken + 1;
        };
        out
    }

    // ========== Internal helpers ==========

    /// Trang thai co hieu luc tai thoi diem `now`. VC_STATUS_EXPIRED khong bao
    /// gio duoc GHI vao storage - het han la mot su kien theo thoi gian, khong
    /// phai mot thao tac ai do thuc hien. Vi vay no duoc TINH khi doc.
    fun effective_status(record: &VCRecord, now: u64): u8 {
        if (record.status == VC_STATUS_ACTIVE
            && record.expires_at != 0
            && now >= record.expires_at) {
            return VC_STATUS_EXPIRED
        };
        record.status
    }

    // Useds to set status VC to revoked, active to suspended; suspended to active
    // caller must is issuer
    fun internal_issuer_set_vc_status(
        caller: address,
        vc_id: u64,
        new_status: u8,
        reason: vector<u8>
    ) acquires VCRegistry {
        // F-08: chi can DID cua issuer con hoat dong. TRUOC DAY cho nay goi
        // authority::assert_is_active_issuer(caller, record.vc_type), ma ham do
        // kiem ca han uy quyen - nen issuer HET HAN khong the thu hoi chinh
        // nhung VC minh da cap: bang cap sai se "active" mai.
        // Nguyen tac: CAP MOI can quyen con hieu luc, THU HOI thi khong.
        // Thu hoi luon phai de hon cap.
        did_registry::assert_owner_active(caller);

        let vc_registry = borrow_mut_vc_registry();
        // Make sure vc_id is present in vcs
        assert!(
            smart_table::contains(&vc_registry.vcs, vc_id),
            errors::invalid_id()
        );
        let now = timestamp::now_seconds();
        let record = smart_table::borrow_mut(&mut vc_registry.vcs, vc_id);
        // ensure that caller is the issuer of th vc
        assert!(
            record.issuer_addr == caller,
            errors::not_vc_issuer(),
        );
        let (issuer_addr, holder_addr) = (record.issuer_addr, record.holder_addr);
        let was_live = counts_as_live(record.status);
        assert_transition_allowed(record, new_status, now);

        record.status = new_status;
        record.status_reason = reason;
        if (new_status == VC_STATUS_REVOKED) {
            record.revoked_at = now;
        };

        apply_live_delta(vc_registry, issuer_addr, holder_addr, was_live, new_status);

        event::emit(
            VCStatusChangedEvent {
                id: vc_id,
                holder_addr,
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
        let now = timestamp::now_seconds();
        let record = smart_table::borrow_mut(&mut vc_registry.vcs, vc_id);
        let (issuer_addr, holder_addr) = (record.issuer_addr, record.holder_addr);
        let was_live = counts_as_live(record.status);
        assert_transition_allowed(record, new_status, now);

        record.status = new_status;
        record.status_reason = reason;
        if (new_status == VC_STATUS_REVOKED) {
            record.revoked_at = now;
        };

        apply_live_delta(vc_registry, issuer_addr, holder_addr, was_live, new_status);

        event::emit(
            VCStatusChangedEvent {
                id: vc_id,
                holder_addr,
                new_status,
                reason,
                changed_by: caller,
                at: now,
            }
        );
    }

    /// Luat chuyen trang thai dung chung cho ca duong issuer va duong admin -
    /// truoc day hai ham chep tay gan giong nhau nen de lech.
    fun assert_transition_allowed(record: &VCRecord, new_status: u8, now: u64) {
        assert!(
            record.status != VC_STATUS_REVOKED,
            errors::vc_already_revoked()
        );
        let effective = effective_status(record, now);
        // VC da het han: tam ngung hay phuc hoi deu vo nghia. Nhung THU HOI thi
        // van phai cho - thu hoi la loi tuyen bo vinh vien ve gian lan, khong
        // duoc phep het han truoc khi kip tuyen bo.
        if (new_status != VC_STATUS_REVOKED) {
            assert!(
                effective != VC_STATUS_EXPIRED,
                errors::vc_already_expired()
            );
        };
        if (new_status == VC_STATUS_SUSPENDED) {
            assert!(
                record.status == VC_STATUS_ACTIVE,
                errors::vc_not_active()
            );
        };
        if (new_status == VC_STATUS_ACTIVE) {
            assert!(
                record.status == VC_STATUS_SUSPENDED,
                errors::vc_not_suspended()
            );
        };
    }

    /// Chi VC dang ACTIVE moi duoc tinh la con hieu luc. Tam ngung cung khong
    /// tinh - mot van bang dang bi treo thi khong dung de chung minh dieu gi.
    fun counts_as_live(status: u8): bool {
        status == VC_STATUS_ACTIVE
    }

    /// Dieu chinh bo dem "dang co hieu luc" theo mot lan doi trang thai.
    /// Gom vao mot cho de duong issuer va duong admin khong the lech nhau -
    /// truoc day hai ham chep tay gan giong nhau chinh la cho de sinh lech.
    fun apply_live_delta(
        vc_registry: &mut VCRegistry,
        issuer_addr: address,
        holder_addr: address,
        was_live: bool,
        new_status: u8,
    ) {
        let is_live = counts_as_live(new_status);
        if (was_live && !is_live) {
            internal_decrement_count(&mut vc_registry.issuer_live_vc_count, issuer_addr);
            internal_decrement_count(&mut vc_registry.holder_live_vc_count, holder_addr);
        } else if (!was_live && is_live) {
            internal_increment_count(&mut vc_registry.issuer_live_vc_count, issuer_addr);
            internal_increment_count(&mut vc_registry.holder_live_vc_count, holder_addr);
        };
    }

    fun count_of(table: &SmartTable<address, u64>, addr: address): u64 {
        if (smart_table::contains(table, addr)) {
            *smart_table::borrow(table, addr)
        } else {
            0
        }
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

    fun internal_decrement_count(
        table: &mut SmartTable<address, u64>,
        addr: address,
    ) {
        if (smart_table::contains(table, addr)) {
            let c = smart_table::borrow_mut(table, addr);
            if (*c > 0) {
                *c = *c - 1;
            };
        }
    }

    inline fun borrow_vc_registry(): &VCRegistry {
        borrow_global<VCRegistry>(@vnu)
    }

    inline fun borrow_mut_vc_registry(): &mut VCRegistry {
        borrow_global_mut<VCRegistry>(@vnu)
    }

    #[test_only]
    public fun initialize_for_test(root: &signer) {
        init_module(root);
    }

    #[test_only]
    fun build_vc_issued_event(
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
    ): VCIssuedEvent {
        VCIssuedEvent {
            id,
            issuer_addr,
            issuer_did,
            holder_addr,
            holder_did,
            vc_id_hash,
            content_cid,
            vc_type,
            issued_at,
            expires_at
        }
    }

    #[test_only]
    public fun assert_vc_issued_event_emitted(
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
    ) {
        let event = build_vc_issued_event(id, issuer_addr, issuer_did, holder_addr, holder_did, vc_id_hash, content_cid, vc_type, issued_at, expires_at);
        assert!(event::was_event_emitted(&event), 42);
    }

    #[test_only]
    fun build_vc_status_changed_event(
        id: u64,
        holder_addr: address,
        new_status: u8,
        reason: vector<u8>,
        changed_by: address,
        at: u64,
    ): VCStatusChangedEvent {
        VCStatusChangedEvent {
            id,
            holder_addr,
            new_status,
            reason,
            changed_by,
            at
        }
    }

    #[test_only]
    public fun assert_vc_status_changed_event_emitted(
        id: u64,
        holder_addr: address,
        new_status: u8,
        reason: vector<u8>,
        changed_by: address,
        at: u64,
    ) {
        let event = build_vc_status_changed_event(id, holder_addr, new_status, reason, changed_by, at);
        assert!(event::was_event_emitted(&event), 42);
    }

    // Truy cap truong cua VCRecord tu ngoai module (VCRecord tra ve tu view
    // nhung cac truong la rieng tu).
    // Khong phai #[view]: ham view khong nhan tham so kieu struct.
    public fun record_status(record: &VCRecord): u8 { record.status }

    public fun record_expires_at(record: &VCRecord): u64 { record.expires_at }

    public fun record_id(record: &VCRecord): u64 { record.id }

    public fun record_holder(record: &VCRecord): address { record.holder_addr }

    public fun record_issuer(record: &VCRecord): address { record.issuer_addr }

    #[test_only]
    public fun get_vc_details_by_id(vc_id: u64): (u64, address, address, vector<u8>, vector<u8>, vector<u8>, u64, u8, u64, u64, u64, vector<u8>) acquires VCRegistry {
        let vc_registry = borrow_vc_registry();
        assert!(smart_table::contains(&vc_registry.vcs, vc_id), errors::invalid_id());
        let record = *smart_table::borrow(&vc_registry.vcs, vc_id);
        (record.id, record.issuer_addr, record.holder_addr, record.vc_id_hash, record.content_cid, record.content_hash, record.vc_type, record.status, record.issued_at, record.expires_at, record.revoked_at, record.status_reason)
    }
}
