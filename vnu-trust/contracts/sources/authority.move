/// Cay quyen: root -> admin -> issuer -> sub-issuer (toi da mot tang uy quyen).
///
/// Bat bien:
///  1. Moi dia chi giu TOI DA MOT vai tro: root, admin con song, hoac issuer con
///     song ("con song" = chua bi thu hoi, ke ca dang tam ngung).
///  2. Moi vai tro tru root chi dung duoc khi DID cua dia chi dang ACTIVE.
///  3. Sub-issuer chi hop le khi BAN GHI issuer da cap no van hop le. Issuer cha
///     bi tam ngung/thu hoi/het han, hoac duoc cap lai thanh ban ghi moi, thi
///     moi sub-issuer cua ban ghi cu deu mat quyen.
///  4. Thu hoi DID bang admin_revoke_did thu hoi luon vai tro cua dia chi do,
///     nen dang ky DID moi khong lam vai tro song lai.
///  5. Moi lan cap lai tao ban ghi moi (version + 1); ban ghi cu giu lam vet.
module vnu::authority {

    use std::option::{Self, Option};
    use std::signer;
    use std::vector;
    use aptos_std::smart_table::{Self, SmartTable};
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use vnu::did_registry;
    use vnu::constants;
    use vnu::errors;

    friend vnu::vc_registry;

    // ========== Constants ==========

    /// Trang thai vai tro, dung chung cho admin va issuer. Admin chi co
    /// ACTIVE/REVOKED; issuer co them SUSPENDED.
    const ROLE_ACTIVE:              u8 = 1;
    const ROLE_REVOKED:             u8 = 2;
    const ROLE_SUSPENDED:           u8 = 3;

    /// `pending_root` bang gia tri nay nghia la khong co de cu nao.
    const NO_PENDING_ROOT:          address = @0x0;

    const MAX_VIEW_ITEMS:           u64 = 500;
    const MAX_PAGE_LIMIT:           u64 = 200;

    /// Ket qua cua cac ham danh gia: 0 = hop le, khac 0 = ma abort.
    const OK:                       u64 = 0;

    // ========== Structs ==========

    struct RoleRecord has copy, drop, store {
        owner: address,
        /// Lan cap thu may cho dia chi nay (cung loai vai tro).
        version: u64,
        approved_by: address,
        approved_at: u64,
        vc_type_mask: u64,
        /// VC uy quyen (CID + SHA3-256). Bat buoc khi co bit uy quyen hoac khi
        /// duoc cap qua uy quyen; con lai co the de trong.
        delegation_vc_cid: vector<u8>,
        delegation_vc_hash: vector<u8>,
        /// 0 = khong thoi han
        expires_at: u64,
        status: u8,
        status_reason: vector<u8>,
        status_updated_at: u64,
    }

    struct Authority has key {
        root_admin: address,
        /// Dia chi da duoc de cu lam root nhung chua ky nhan.
        pending_root: address,
        /// Moi ban ghi vai tro tung tao, theo id tang dan.
        roles: SmartTable<u64, RoleRecord>,
        /// Dia chi -> id ban ghi issuer HIEN HANH.
        issuers: SmartTable<address, u64>,
        /// Dia chi -> id ban ghi admin HIEN HANH.
        admins: SmartTable<address, u64>,
        /// So dia chi RIENG BIET tung la issuer / admin (khong giam khi thu hoi).
        issuer_count: u64,
        admin_count: u64,
        next_role_id: u64,
    }

    /// Them o ban nang cap 2 (bat bien 3). Sub-issuer -> id ban ghi issuer
    /// da cap no. Khoi tao bang `init_delegation_registry` sau khi nang cap.
    struct DelegationRegistry has key {
        parent_role_of: SmartTable<address, u64>,
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

    #[event]
    struct RootTransferCancelledEvent has drop, store {
        root: address,
        cancelled: address,
        at: u64,
    }

    // ========== Init / nang cap ==========

    /// Publish voi `root_admin=0x0` thi chinh nguoi publish lam root.
    fun init_module(publisher: &signer) {
        init_authority(publisher, @root_admin);
    }

    fun init_authority(publisher: &signer, configured_root: address) {
        let root = if (configured_root == @0x0) signer::address_of(publisher) else configured_root;
        move_to(publisher, Authority {
            root_admin: root,
            pending_root: NO_PENDING_ROOT,
            roles: smart_table::new(),
            issuers: smart_table::new(),
            admins: smart_table::new(),
            issuer_count: 0,
            admin_count: 0,
            next_role_id: 0,
        });
        move_to(publisher, DelegationRegistry { parent_role_of: smart_table::new() });
    }

    /// Chay MOT LAN sau khi nang cap tu ban chua co DelegationRegistry
    /// (`init_module` khong chay lai khi nang cap). Chi tai khoan publish goi duoc.
    public entry fun init_delegation_registry(publisher: &signer) {
        assert!(signer::address_of(publisher) == @vnu, errors::not_authorized());
        assert!(!exists<DelegationRegistry>(@vnu), errors::already_initialized());
        move_to(publisher, DelegationRegistry { parent_role_of: smart_table::new() });
    }

    // ========== Root ==========

    /// Chuyen root buoc 1: root de cu nguoi nhan. Quyen chua doi.
    /// Nguoi nhan khong duoc la root hien tai hay dang giu vai tro admin/issuer
    /// (bat bien 1).
    public entry fun propose_root(root: &signer, new_root: address) acquires Authority {
        let root_addr = signer::address_of(root);
        let a = borrow_global_mut<Authority>(@vnu);
        assert_root(a, root_addr);
        assert!(new_root != NO_PENDING_ROOT && new_root != root_addr, errors::invalid_root_candidate());
        assert!(!holds_live_role(a, new_root), errors::role_conflict());
        a.pending_root = new_root;
        event::emit(RootTransferProposedEvent { from: root_addr, to: new_root, at: timestamp::now_seconds() });
    }

    /// Buoc 2: chinh nguoi duoc de cu ky nhan - chu ky la bang chung giu khoa.
    public entry fun accept_root(new_root: &signer) acquires Authority {
        let new_root_addr = signer::address_of(new_root);
        let a = borrow_global_mut<Authority>(@vnu);
        assert!(a.pending_root != NO_PENDING_ROOT, errors::no_pending_root());
        assert!(new_root_addr == a.pending_root, errors::not_pending_root());
        // Kiem lai: tu luc de cu, dia chi nay co the vua duoc cap vai tro.
        assert!(!holds_live_role(a, new_root_addr), errors::role_conflict());
        let old_root = a.root_admin;
        a.root_admin = new_root_addr;
        a.pending_root = NO_PENDING_ROOT;
        event::emit(RootTransferredEvent { from: old_root, to: new_root_addr, at: timestamp::now_seconds() });
    }

    public entry fun cancel_root_transfer(root: &signer) acquires Authority {
        let root_addr = signer::address_of(root);
        let a = borrow_global_mut<Authority>(@vnu);
        assert_root(a, root_addr);
        assert!(a.pending_root != NO_PENDING_ROOT, errors::no_pending_root());
        let cancelled = a.pending_root;
        a.pending_root = NO_PENDING_ROOT;
        event::emit(RootTransferCancelledEvent { root: root_addr, cancelled, at: timestamp::now_seconds() });
    }

    // ========== Admin ==========

    /// Root cap quyen admin. Dich phai co DID ACTIVE, khong phai root, khong
    /// dang giu vai tro issuer (ke ca dang tam ngung - phai thu hoi truoc).
    public entry fun grant_admin(root: &signer, admin: address) acquires Authority {
        let root_addr = signer::address_of(root);
        let a = borrow_global_mut<Authority>(@vnu);
        assert_root(a, root_addr);
        did_registry::assert_owner_active(admin);
        assert!(admin != a.root_admin && !is_live(&a.issuers, &a.roles, admin), errors::role_conflict());
        assert!(!is_live(&a.admins, &a.roles, admin), errors::admin_already_exists());

        let now = timestamp::now_seconds();
        let version = next_version(&a.admins, &a.roles, admin);
        let record = new_role_record(admin, version, root_addr, now, 0, b"", b"", 0);
        if (version == 1) a.admin_count = a.admin_count + 1;
        add_record(&mut a.roles, &mut a.next_role_id, &mut a.admins, admin, record);

        event::emit(AdminGrantedEvent { to: admin, by: root_addr, at: now });
    }

    /// Chi root thu hoi admin.
    public entry fun revoke_admin(root: &signer, admin: address, reason: vector<u8>) acquires Authority {
        let root_addr = signer::address_of(root);
        let a = borrow_global_mut<Authority>(@vnu);
        assert_root(a, root_addr);
        assert!(smart_table::contains(&a.admins, admin), errors::not_admin());
        let record = current_mut(&a.admins, &mut a.roles, admin);
        assert!(record.status != ROLE_REVOKED, errors::admin_already_revoked());
        revoke_admin_record(record, root_addr, reason);
    }

    // ========== Issuer ==========

    /// Cap quyen issuer. Ba loai nguoi cap:
    ///   - root: moi mask hop le, ke ca bit uy quyen;
    ///   - admin dang hoat dong: moi mask hop le tru bit uy quyen;
    ///   - issuer dang hop le CO bit uy quyen: chi cap cho dia chi CHUA TUNG
    ///     la issuer, mask nam tron trong mask cua minh (nen khong co bit uy
    ///     quyen), han khong vuot han cua minh, va phai kem VC uy quyen.
    /// `expires_at` = 0 (vinh vien) hoac mot thoi diem trong tuong lai.
    public entry fun approve_issuer(
        approver: &signer,
        issuer: address,
        vc_type_mask: u64,
        delegation_vc_cid: vector<u8>,
        delegation_vc_hash: vector<u8>,
        expires_at: u64,
    ) acquires Authority, DelegationRegistry {
        let approver_addr = signer::address_of(approver);
        let now = timestamp::now_seconds();
        assert!(constants::is_valid_mask(vc_type_mask), errors::invalid_vc_type());
        assert!(expires_at == 0 || expires_at > now, errors::issuer_cap_expired());

        let a = borrow_global_mut<Authority>(@vnu);

        // Nguoi cap. `parent` co gia tri khi cap qua uy quyen.
        let parent = approver_parent_role(a, approver_addr, vc_type_mask, expires_at, now);
        let by_delegation = option::is_some(&parent);
        let grants_delegation = vc_type_mask & constants::VC_TYPE_DELEGATION() != 0;
        assert!(!grants_delegation || approver_addr == a.root_admin, errors::not_root_admin());
        assert_delegation_proof(grants_delegation || by_delegation, &delegation_vc_cid, &delegation_vc_hash);

        // Dich.
        did_registry::assert_owner_active(issuer);
        assert!(issuer != a.root_admin && !is_live(&a.admins, &a.roles, issuer), errors::role_conflict());
        assert!(!is_live(&a.issuers, &a.roles, issuer), errors::issuer_already_exists());
        let version = next_version(&a.issuers, &a.roles, issuer);
        // Issuer uy quyen khong duoc cap lai mot issuer da bi thu hoi - neu
        // khong, no go duoc quyet dinh thu hoi cua admin.
        assert!(!by_delegation || version == 1, errors::not_authorized());

        let record = new_role_record(
            issuer, version, approver_addr, now, vc_type_mask, delegation_vc_cid, delegation_vc_hash, expires_at
        );
        if (version == 1) a.issuer_count = a.issuer_count + 1;
        add_record(&mut a.roles, &mut a.next_role_id, &mut a.issuers, issuer, record);
        set_parent(issuer, parent);

        event::emit(IssuerApprovedEvent {
            issuer,
            by: approver_addr,
            vc_type_mask,
            delegation_vc_cid,
            at: now,
            expires_at,
        });
    }

    /// Admin, hoac issuer cha dang hop le voi sub-issuer cua minh.
    public entry fun suspend_issuer(caller: &signer, issuer: address, reason: vector<u8>) acquires Authority, DelegationRegistry {
        set_issuer_status(caller, issuer, ROLE_SUSPENDED, reason);
    }

    /// Chi admin. Issuer cha tu ngung roi tu bat lai la ne kiem soat.
    public entry fun reactivate_issuer(admin: &signer, issuer: address, reason: vector<u8>) acquires Authority, DelegationRegistry {
        set_issuer_status(admin, issuer, ROLE_ACTIVE, reason);
    }

    /// Admin, hoac issuer cha dang hop le voi sub-issuer cua minh.
    public entry fun revoke_issuer(caller: &signer, issuer: address, reason: vector<u8>) acquires Authority, DelegationRegistry {
        set_issuer_status(caller, issuer, ROLE_REVOKED, reason);
    }

    // ========== Kiem duyet DID (admin) ==========

    public entry fun admin_suspend_did(admin: &signer, target_owner: address, reason: vector<u8>) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_can_moderate_did(admin_addr, target_owner);
        did_registry::admin_suspend_did(admin_addr, target_owner, reason);
    }

    public entry fun admin_reactivate_did(admin: &signer, target_owner: address, reason: vector<u8>) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_can_moderate_did(admin_addr, target_owner);
        did_registry::admin_reactivate_did(admin_addr, target_owner, reason);
    }

    /// Thu hoi DID va MOI vai tro con song cua dia chi do (bat bien 4).
    public entry fun admin_revoke_did(admin: &signer, target_owner: address, reason: vector<u8>) acquires Authority {
        let admin_addr = signer::address_of(admin);
        assert_can_moderate_did(admin_addr, target_owner);
        did_registry::admin_revoke_did(admin_addr, target_owner, reason);

        let a = borrow_global_mut<Authority>(@vnu);
        if (is_live(&a.admins, &a.roles, target_owner)) {
            revoke_admin_record(current_mut(&a.admins, &mut a.roles, target_owner), admin_addr, reason);
        };
        if (is_live(&a.issuers, &a.roles, target_owner)) {
            set_issuer_record_status(current_mut(&a.issuers, &mut a.roles, target_owner), admin_addr, ROLE_REVOKED, reason);
        };
    }

    // ========== Friend (vc_registry) ==========

    /// Root, hoac admin ACTIVE co DID ACTIVE.
    public(friend) fun assert_is_active_admin(admin: address) acquires Authority {
        let e = admin_error(borrow_global<Authority>(@vnu), admin);
        assert!(e == OK, e);
    }

    /// Duoc cap VC loai `vc_type` (mot bit) ngay luc nay khong.
    public(friend) fun assert_is_active_issuer(issuer: address, vc_type: u64) acquires Authority, DelegationRegistry {
        let a = borrow_global<Authority>(@vnu);
        let e = issuer_error(a, issuer, timestamp::now_seconds());
        assert!(e == OK, e);
        assert!(current(&a.issuers, &a.roles, issuer).vc_type_mask & vc_type == vc_type, errors::unauthorized_vc_type());
    }

    /// Issuer tu tam ngung / thu hoi VC CUA MINH: can DID ACTIVE va vai tro
    /// chua bi tam ngung / thu hoi. Han uy quyen va trang thai issuer cha KHONG
    /// xet - thu hoi phai de hon cap; nhung khoa bi lo thi admin tam ngung
    /// issuer la chan duoc ke giu khoa pha cac VC that.
    public(friend) fun assert_can_manage_own_vcs(issuer: address) acquires Authority {
        did_registry::assert_owner_active(issuer);
        // Nguoi goi da duoc xac nhan la issuer cua VC, va bang `issuers` khong
        // bao gio xoa phan tu, nen ban ghi luon ton tai.
        let a = borrow_global<Authority>(@vnu);
        assert!(current(&a.issuers, &a.roles, issuer).status == ROLE_ACTIVE, errors::issuer_not_active());
    }

    // ========== Views ==========

    #[view]
    /// Issuer dang cap duoc VC (chua xet loai van bang).
    public fun is_active_issuer(issuer: address): bool acquires Authority, DelegationRegistry {
        issuer_error(borrow_global<Authority>(@vnu), issuer, timestamp::now_seconds()) == OK
    }

    #[view]
    /// Root hoac admin dang hoat dong.
    public fun is_active_admin(addr: address): bool acquires Authority {
        admin_error(borrow_global<Authority>(@vnu), addr) == OK
    }

    #[view]
    /// Dia chi nay goi `approve_issuer` duoc khong (root, admin, issuer uy quyen).
    public fun can_delegate(addr: address): bool acquires Authority, DelegationRegistry {
        let a = borrow_global<Authority>(@vnu);
        admin_error(a, addr) == OK || delegator_error(a, addr, timestamp::now_seconds()) == OK
    }

    #[view]
    /// (approved_by, vc_type_mask, delegation_vc_cid, delegation_vc_hash, expires_at, status)
    public fun get_info(addr: address): (address, u64, vector<u8>, vector<u8>, u64, u8) acquires Authority {
        let r = get_role(addr);
        (r.approved_by, r.vc_type_mask, r.delegation_vc_cid, r.delegation_vc_hash, r.expires_at, r.status)
    }

    #[view]
    /// Ban ghi vai tro hien hanh. Dia chi tung giu ca hai vai tro (lan luot)
    /// thi tra ve vai tro con song; neu ca hai da chet thi tra ve ban issuer.
    public fun get_role(addr: address): RoleRecord acquires Authority {
        let a = borrow_global<Authority>(@vnu);
        let has_issuer = smart_table::contains(&a.issuers, addr);
        let has_admin = smart_table::contains(&a.admins, addr);
        assert!(has_issuer || has_admin, errors::owner_not_exists());
        if (has_admin && (!has_issuer || is_live(&a.admins, &a.roles, addr))) {
            *current(&a.admins, &a.roles, addr)
        } else {
            *current(&a.issuers, &a.roles, addr)
        }
    }

    #[view]
    public fun get_root_admin(): address acquires Authority {
        borrow_global<Authority>(@vnu).root_admin
    }

    #[view]
    /// @0x0 = khong co de cu nao dang cho.
    public fun get_pending_root(): address acquires Authority {
        borrow_global<Authority>(@vnu).pending_root
    }

    #[view]
    /// Issuer cha cua mot sub-issuer (@0x0 neu khong duoc cap qua uy quyen).
    public fun get_delegator(issuer: address): address acquires Authority, DelegationRegistry {
        let parent = parent_role_of(issuer);
        if (option::is_none(&parent)) return @0x0;
        smart_table::borrow(&borrow_global<Authority>(@vnu).roles, *option::borrow(&parent)).owner
    }

    #[view]
    /// (so dia chi tung la admin, so dia chi tung la issuer) - khong giam khi thu hoi.
    public fun stats(): (u64, u64) acquires Authority {
        let a = borrow_global<Authority>(@vnu);
        (a.admin_count, a.issuer_count)
    }

    #[view]
    public fun total_roles(): u64 acquires Authority {
        borrow_global<Authority>(@vnu).next_role_id
    }

    #[view]
    /// Moi dia chi tung la issuer. Vuot 500 thi abort, dung ban phan trang.
    public fun get_issuers(): vector<address> acquires Authority {
        let a = borrow_global<Authority>(@vnu);
        assert!(smart_table::length(&a.issuers) <= MAX_VIEW_ITEMS, errors::result_too_large());
        smart_table::keys(&a.issuers)
    }

    #[view]
    public fun get_admins(): vector<address> acquires Authority {
        let a = borrow_global<Authority>(@vnu);
        assert!(smart_table::length(&a.admins) <= MAX_VIEW_ITEMS, errors::result_too_large());
        smart_table::keys(&a.admins)
    }

    #[view]
    /// Ban ghi vai tro co id trong [start, start + limit), theo thu tu id.
    public fun get_roles_paginated(start: u64, limit: u64): vector<RoleRecord> acquires Authority {
        assert!(limit > 0 && limit <= MAX_PAGE_LIMIT, errors::invalid_page());
        let a = borrow_global<Authority>(@vnu);
        let out = vector::empty<RoleRecord>();
        let id = start;
        while (vector::length(&out) < limit && id < a.next_role_id) {
            vector::push_back(&mut out, *smart_table::borrow(&a.roles, id));
            id = id + 1;
        };
        out
    }

    // ========== Danh gia quyen (tra ve ma loi, 0 = hop le) ==========

    fun admin_error(a: &Authority, addr: address): u64 {
        if (addr == a.root_admin) return OK;
        if (!did_registry::has_active_did(addr)) return errors::did_not_active();
        if (!smart_table::contains(&a.admins, addr)
            || current(&a.admins, &a.roles, addr).status != ROLE_ACTIVE) {
            return errors::admin_not_active()
        };
        OK
    }

    /// Issuer duoc cap VC ngay luc nay: DID ACTIVE, ban ghi ACTIVE, chua het
    /// han, va neu la sub-issuer thi ban ghi cha cung dang hop le.
    fun issuer_error(a: &Authority, addr: address, now: u64): u64 acquires DelegationRegistry {
        let e = own_issuer_error(a, addr, now);
        if (e != OK) return e;
        let parent = parent_role_of(addr);
        if (option::is_some(&parent) && parent_error(a, *option::borrow(&parent), now) != OK) {
            return errors::delegator_not_active()
        };
        OK
    }

    /// Issuer nay dang cap duoc sub-issuer khong.
    fun delegator_error(a: &Authority, addr: address, now: u64): u64 acquires DelegationRegistry {
        if (!smart_table::contains(&a.issuers, addr)) return errors::not_authorized();
        let e = issuer_error(a, addr, now);
        if (e != OK) return e;
        if (current(&a.issuers, &a.roles, addr).vc_type_mask & constants::VC_TYPE_DELEGATION() == 0) {
            return errors::cannot_delegate()
        };
        OK
    }

    /// Phan kiem tren chinh ban ghi issuer, khong xet cha.
    fun own_issuer_error(a: &Authority, addr: address, now: u64): u64 {
        if (!did_registry::has_active_did(addr)) return errors::did_not_active();
        if (!smart_table::contains(&a.issuers, addr)) return errors::issuer_not_found();
        let r = current(&a.issuers, &a.roles, addr);
        if (r.status != ROLE_ACTIVE) return errors::issuer_not_active();
        if (r.expires_at != 0 && r.expires_at <= now) return errors::issuer_cap_expired();
        OK
    }

    /// Ban ghi cha (theo id) con la ban ghi hien hanh cua chu no va con hop
    /// le. Khong can kiem lai bit uy quyen: mask cua mot ban ghi khong bao gio
    /// doi, va lien ket chi duoc tao khi ban ghi cha co bit do. Cha luon do
    /// root cap (chi root cap bit uy quyen) nen khong co cha nua.
    fun parent_error(a: &Authority, parent_role_id: u64, now: u64): u64 {
        let owner = smart_table::borrow(&a.roles, parent_role_id).owner;
        if (*smart_table::borrow(&a.issuers, owner) != parent_role_id) return errors::delegator_not_active();
        own_issuer_error(a, owner, now)
    }

    // ========== Internal ==========

    /// Kiem quyen cap issuer. Tra ve id ban ghi cua issuer cha neu cap qua uy
    /// quyen, `none` neu nguoi cap la root hoac admin.
    fun approver_parent_role(a: &Authority, approver: address, mask: u64, expires_at: u64, now: u64): Option<u64> acquires DelegationRegistry {
        if (approver == a.root_admin) return option::none();
        // Chi re nhanh admin khi ban ghi admin con song; cuu admin co the dang
        // la issuer uy quyen (M-05).
        if (is_live(&a.admins, &a.roles, approver)) {
            did_registry::assert_owner_active(approver);
            return option::none()
        };
        let e = delegator_error(a, approver, now);
        assert!(e == OK, e);
        let me = current(&a.issuers, &a.roles, approver);
        assert!(mask & me.vc_type_mask == mask, errors::unauthorized_vc_type());
        assert!(
            me.expires_at == 0 || (expires_at != 0 && expires_at <= me.expires_at),
            errors::issuer_cap_expired()
        );
        option::some(*smart_table::borrow(&a.issuers, approver))
    }

    /// Abort E_NOT_ROOT_ADMIN neu `addr` khong phai root hien tai.
    fun assert_root(a: &Authority, addr: address) {
        assert!(addr == a.root_admin, errors::not_root_admin());
    }

    /// Bang chung uy quyen (CID + SHA3-256 cua VC uy quyen): bat buoc khi
    /// `required`; neu khong thi tuy chon, nhung da truyen thi phai dung dinh
    /// dang. Abort E_INVALID_CID (tai did_registry) roi E_HASH_WRONG_LENGTH.
    fun assert_delegation_proof(required: bool, cid: &vector<u8>, hash: &vector<u8>) {
        if (required || !vector::is_empty(cid)) did_registry::assert_valid_cid(cid);
        if (required || !vector::is_empty(hash)) {
            assert!(vector::length(hash) == 32, errors::hash_wrong_length());
        };
    }

    /// Admin thuong khong duoc khoa/thu hoi DID cua root hay cua admin con
    /// song - lam vay la lach luat "chi root moi thu hoi admin".
    fun assert_can_moderate_did(caller: address, target: address) acquires Authority {
        let a = borrow_global<Authority>(@vnu);
        let e = admin_error(a, caller);
        assert!(e == OK, e);
        assert!(target != a.root_admin, errors::protected_target());
        assert!(caller == a.root_admin || !is_live(&a.admins, &a.roles, target), errors::protected_target());
    }

    fun set_issuer_status(caller: &signer, issuer: address, new_status: u8, reason: vector<u8>) acquires Authority, DelegationRegistry {
        let caller_addr = signer::address_of(caller);
        let now = timestamp::now_seconds();
        let a = borrow_global_mut<Authority>(@vnu);
        // Admin; hoac issuer cha dang hop le, nhung chi de tam ngung / thu hoi.
        let e = admin_error(a, caller_addr);
        if (e != OK && new_status != ROLE_ACTIVE && is_delegator_of(a, caller_addr, issuer, now)) e = OK;
        assert!(e == OK, e);
        assert!(smart_table::contains(&a.issuers, issuer), errors::issuer_not_found());
        let record = current_mut(&a.issuers, &mut a.roles, issuer);
        // Da thu hoi thi chi quay lai bang approve_issuer (ban ghi moi).
        assert!(record.status != ROLE_REVOKED, errors::issuer_already_revoked());
        if (new_status == ROLE_SUSPENDED) {
            assert!(record.status == ROLE_ACTIVE, errors::issuer_not_active());
        } else if (new_status == ROLE_ACTIVE) {
            assert!(record.status == ROLE_SUSPENDED, errors::issuer_not_suspended());
        };
        set_issuer_record_status(record, caller_addr, new_status, reason);
    }

    /// `caller` la issuer cha dang hop le cua ban ghi hien hanh cua `issuer`.
    fun is_delegator_of(a: &Authority, caller: address, issuer: address, now: u64): bool acquires DelegationRegistry {
        let parent = parent_role_of(issuer);
        option::is_some(&parent)
            && smart_table::borrow(&a.roles, *option::borrow(&parent)).owner == caller
            && parent_error(a, *option::borrow(&parent), now) == OK
    }

    fun parent_role_of(issuer: address): Option<u64> acquires DelegationRegistry {
        if (!exists<DelegationRegistry>(@vnu)) return option::none();
        let links = &borrow_global<DelegationRegistry>(@vnu).parent_role_of;
        if (smart_table::contains(links, issuer)) option::some(*smart_table::borrow(links, issuer)) else option::none()
    }

    /// Ghi/xoa lien ket cha cho ban ghi issuer vua tao.
    fun set_parent(issuer: address, parent: Option<u64>) acquires DelegationRegistry {
        if (option::is_some(&parent)) {
            let links = &mut borrow_global_mut<DelegationRegistry>(@vnu).parent_role_of;
            smart_table::upsert(links, issuer, option::destroy_some(parent));
        } else if (exists<DelegationRegistry>(@vnu)) {
            let links = &mut borrow_global_mut<DelegationRegistry>(@vnu).parent_role_of;
            if (smart_table::contains(links, issuer)) {
                smart_table::remove(links, issuer);
            };
        };
    }

    /// Co ban ghi admin hoac issuer chua bi thu hoi.
    fun holds_live_role(a: &Authority, addr: address): bool {
        is_live(&a.admins, &a.roles, addr) || is_live(&a.issuers, &a.roles, addr)
    }

    /// Ban ghi hien hanh trong `index` ton tai va chua bi thu hoi.
    fun is_live(index: &SmartTable<address, u64>, roles: &SmartTable<u64, RoleRecord>, addr: address): bool {
        smart_table::contains(index, addr) && current(index, roles, addr).status != ROLE_REVOKED
    }

    fun next_version(index: &SmartTable<address, u64>, roles: &SmartTable<u64, RoleRecord>, addr: address): u64 {
        if (smart_table::contains(index, addr)) current(index, roles, addr).version + 1 else 1
    }

    fun current(index: &SmartTable<address, u64>, roles: &SmartTable<u64, RoleRecord>, addr: address): &RoleRecord {
        smart_table::borrow(roles, *smart_table::borrow(index, addr))
    }

    fun current_mut(index: &SmartTable<address, u64>, roles: &mut SmartTable<u64, RoleRecord>, addr: address): &mut RoleRecord {
        smart_table::borrow_mut(roles, *smart_table::borrow(index, addr))
    }

    /// Ban ghi vai tro moi o trang thai ACTIVE, duyet tai thoi diem `now`.
    /// Khong abort.
    fun new_role_record(
        owner: address,
        version: u64,
        approved_by: address,
        now: u64,
        vc_type_mask: u64,
        delegation_vc_cid: vector<u8>,
        delegation_vc_hash: vector<u8>,
        expires_at: u64,
    ): RoleRecord {
        RoleRecord {
            owner,
            version,
            approved_by,
            approved_at: now,
            vc_type_mask,
            delegation_vc_cid,
            delegation_vc_hash,
            expires_at,
            status: ROLE_ACTIVE,
            status_reason: b"",
            status_updated_at: now,
        }
    }

    /// Them ban ghi moi va tro chi muc cua dia chi sang no. Ban ghi cu van nam
    /// trong `roles` lam vet kiem toan.
    fun add_record(
        roles: &mut SmartTable<u64, RoleRecord>,
        next_id: &mut u64,
        index: &mut SmartTable<address, u64>,
        addr: address,
        record: RoleRecord,
    ) {
        let id = *next_id;
        *next_id = id + 1;
        smart_table::add(roles, id, record);
        smart_table::upsert(index, addr, id);
    }

    /// Dat ban ghi admin ve REVOKED va phat AdminRevokedEvent. Ham goi da kiem
    /// quyen va trang thai. Khong abort.
    fun revoke_admin_record(record: &mut RoleRecord, by: address, reason: vector<u8>) {
        set_role_status(record, ROLE_REVOKED, reason);
        event::emit(AdminRevokedEvent { to: record.owner, by, reason, at: timestamp::now_seconds() });
    }

    /// Doi trang thai ban ghi issuer va phat IssuerStatusChangedEvent. Ham goi
    /// da kiem quyen va luat chuyen trang thai. Khong abort.
    fun set_issuer_record_status(record: &mut RoleRecord, by: address, new_status: u8, reason: vector<u8>) {
        set_role_status(record, new_status, reason);
        event::emit(IssuerStatusChangedEvent {
            issuer: record.owner, by, new_status, reason, at: timestamp::now_seconds(),
        });
    }

    fun set_role_status(record: &mut RoleRecord, status: u8, reason: vector<u8>) {
        record.status = status;
        record.status_reason = reason;
        record.status_updated_at = timestamp::now_seconds();
    }

    // ========== Test-only ==========

    #[test_only]
    public fun initialize_for_test(publisher: &signer) {
        init_module(publisher);
    }

    #[test_only]
    public fun initialize_with_root_for_test(publisher: &signer, configured_root: address) {
        init_authority(publisher, configured_root);
    }

    #[test_only]
    /// Trang thai cua goi TRUOC nang cap: co Authority, chua co DelegationRegistry.
    public fun initialize_legacy_for_test(publisher: &signer, root: address) {
        move_to(publisher, Authority {
            root_admin: root,
            pending_root: NO_PENDING_ROOT,
            roles: smart_table::new(),
            issuers: smart_table::new(),
            admins: smart_table::new(),
            issuer_count: 0,
            admin_count: 0,
            next_role_id: 0,
        });
    }

    #[test_only]
    public fun delegation_registry_exists(): bool { exists<DelegationRegistry>(@vnu) }

    #[test_only]
    public fun record_fields(r: &RoleRecord): (address, u64, address, u64, u64, vector<u8>, vector<u8>, u64, u8, vector<u8>, u64) {
        (r.owner, r.version, r.approved_by, r.approved_at, r.vc_type_mask, r.delegation_vc_cid,
         r.delegation_vc_hash, r.expires_at, r.status, r.status_reason, r.status_updated_at)
    }

    #[test_only]
    public fun admin_record(addr: address): RoleRecord acquires Authority {
        let a = borrow_global<Authority>(@vnu);
        *current(&a.admins, &a.roles, addr)
    }

    #[test_only]
    public fun issuer_record(addr: address): RoleRecord acquires Authority {
        let a = borrow_global<Authority>(@vnu);
        *current(&a.issuers, &a.roles, addr)
    }

    #[test_only]
    public fun role_status(r: &RoleRecord): u8 { r.status }

    #[test_only]
    public fun role_version(r: &RoleRecord): u64 { r.version }

    #[test_only]
    public fun role_owner(r: &RoleRecord): address { r.owner }

    #[test_only]
    public fun admin_granted_event(to: address, by: address, at: u64): AdminGrantedEvent {
        AdminGrantedEvent { to, by, at }
    }

    #[test_only]
    public fun admin_revoked_event(to: address, by: address, reason: vector<u8>, at: u64): AdminRevokedEvent {
        AdminRevokedEvent { to, by, reason, at }
    }

    #[test_only]
    public fun issuer_approved_event(issuer: address, by: address, vc_type_mask: u64, delegation_vc_cid: vector<u8>, at: u64, expires_at: u64): IssuerApprovedEvent {
        IssuerApprovedEvent { issuer, by, vc_type_mask, delegation_vc_cid, at, expires_at }
    }

    #[test_only]
    public fun issuer_status_changed_event(issuer: address, by: address, new_status: u8, reason: vector<u8>, at: u64): IssuerStatusChangedEvent {
        IssuerStatusChangedEvent { issuer, by, new_status, reason, at }
    }

    #[test_only]
    public fun root_transfer_proposed_event(from: address, to: address, at: u64): RootTransferProposedEvent {
        RootTransferProposedEvent { from, to, at }
    }

    #[test_only]
    public fun root_transferred_event(from: address, to: address, at: u64): RootTransferredEvent {
        RootTransferredEvent { from, to, at }
    }

    #[test_only]
    public fun root_transfer_cancelled_event(root: address, cancelled: address, at: u64): RootTransferCancelledEvent {
        RootTransferCancelledEvent { root, cancelled, at }
    }
}
