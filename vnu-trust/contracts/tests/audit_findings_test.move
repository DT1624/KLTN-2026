// Kich ban hoi quy cho cac phat hien trong docs/CONTRACT_AUDIT.md (F-xx),
// docs/SECURITY_REVIEW.md (M-xx) va docs/CONTRACT_REVIEW.md (R-xx, C-xx).
//
// Moi test ke lai mot cuoc tan cong / su co nhieu buoc xuyen module va khang
// dinh HANH VI AN TOAN. PASS = lo hong da dong va khong quay lai. Cac luat don
// le cua tung ham nam o ba bo dac ta *_test.move.
#[test_only]
module vnu::audit_findings_test {
    use aptos_framework::event;
    use vnu::authority;
    use vnu::did_registry;
    use vnu::errors;
    use vnu::vc_registry;
    use vnu::test_utils as t;

    // ---------------------------------------------------------------
    // M-01 / R-01 (Cao): DID bi thu hoi, chu dang ky DID moi -> vai tro
    // KHONG duoc song lai.
    // ---------------------------------------------------------------

    #[test]
    fun m01_fraudulent_issuer_reregistering_did_gets_no_role_back() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        authority::admin_revoke_did(&root, t::issuer1_addr(), b"fraud");

        did_registry::register_did(&i, t::did_with(b"did:vnu:v2:", t::issuer1_addr()), t::cid(), t::hash(2));
        assert!(did_registry::has_active_did(t::issuer1_addr()), 0);
        assert!(!authority::is_active_issuer(t::issuer1_addr()), 1);
        assert!(authority::role_status(&authority::issuer_record(t::issuer1_addr())) == t::role_revoked(), 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun m01_fraudulent_issuer_cannot_issue_after_reregistering() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        authority::admin_revoke_did(&root, t::issuer1_addr(), b"fraud");
        did_registry::register_did(&i, t::did_with(b"did:vnu:v2:", t::issuer1_addr()), t::cid(), t::hash(2));
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    fun m01_admin_reregistering_did_gets_no_role_back() {
        let root = t::setup();
        let a = t::admin(&root, t::admin1_addr());
        authority::admin_revoke_did(&root, t::admin1_addr(), b"compromised");
        did_registry::register_did(&a, t::did_with(b"did:vnu:v2:", t::admin1_addr()), t::cid(), t::hash(2));
        assert!(!authority::is_active_admin(t::admin1_addr()), 0);
        assert!(!authority::can_delegate(t::admin1_addr()), 1);
    }

    // ---------------------------------------------------------------
    // M-02: sub-issuer phu thuoc vao BAN GHI cua issuer cha.
    // ---------------------------------------------------------------

    #[test]
    fun m02_sub_issuer_follows_parent_state() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        let sub = t::issuer2_addr();
        assert!(authority::is_active_issuer(sub), 0);

        authority::suspend_issuer(&root, t::issuer1_addr(), b"audit");
        assert!(!authority::is_active_issuer(sub), 1);
        authority::reactivate_issuer(&root, t::issuer1_addr(), b"ok");
        assert!(authority::is_active_issuer(sub), 2);

        authority::admin_suspend_did(&root, t::issuer1_addr(), b"x");
        assert!(!authority::is_active_issuer(sub), 3);
        authority::admin_reactivate_did(&root, t::issuer1_addr(), b"x");
        assert!(authority::is_active_issuer(sub), 4);
    }

    #[test]
    fun m02_parent_expiry_ends_sub_issuer_even_if_sub_is_longer_lived_by_data() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 100);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), t::t0() + 100);
        t::advance(100);
        assert!(!authority::is_active_issuer(t::issuer2_addr()), 0);
    }

    #[test]
    fun m02_reapproving_parent_does_not_revive_old_children() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"fraud");
        // Root cap lai cho chinh dia chi do: ban ghi moi, con cu khong song lai.
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor() | t::delegation(), t::cid(), t::hash(9), 0);
        assert!(authority::is_active_issuer(t::issuer1_addr()), 0);
        assert!(!authority::is_active_issuer(t::issuer2_addr()), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DELEGATOR_NOT_ACTIVE, location = authority)]
    fun m02_sub_issuer_of_reapproved_parent_cannot_issue() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        let s = t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        authority::revoke_issuer(&root, t::issuer1_addr(), b"fraud");
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor() | t::delegation(), t::cid(), t::hash(9), 0);
        t::issue(&s, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    // ---------------------------------------------------------------
    // M-04 / R-05: moi dia chi giu toi da MOT vai tro.
    // ---------------------------------------------------------------

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun m04_suspended_issuer_cannot_be_made_admin_then_reactivated() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        authority::grant_admin(&root, t::issuer1_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun r05_root_cannot_also_be_issuer() {
        let root = t::setup();
        t::register(&root);
        authority::approve_issuer(&root, t::root_addr(), t::bachelor(), b"", b"", 0);
    }

    // ---------------------------------------------------------------
    // M-05: cuu admin co vai tro issuer uy quyen van dung duoc uy quyen.
    // ---------------------------------------------------------------

    #[test]
    fun m05_former_admin_delegation_is_consistent_with_view() {
        let root = t::setup();
        let a = t::admin(&root, t::admin1_addr());
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        authority::approve_issuer(&root, t::admin1_addr(), t::bachelor() | t::delegation(), t::cid(), t::hash(9), 0);
        assert!(authority::can_delegate(t::admin1_addr()), 0);
        t::sub_issuer(&a, t::issuer2_addr(), t::bachelor(), 0);
        assert!(authority::is_active_issuer(t::issuer2_addr()), 1);
    }

    // ---------------------------------------------------------------
    // M-06 / R-03: ke giu khoa issuer bi lo khong pha duoc van bang that,
    // nhung issuer trung thuc het han van don duoc van bang cap nham (F-08).
    // ---------------------------------------------------------------

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun m06_compromised_issuer_key_cannot_mass_revoke_after_suspension() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"key compromise");
        vc_registry::revoke_vc(&i, id, b"vandalism");
    }

    #[test]
    fun m06_admin_still_cleans_up_after_suspending_issuer() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"key compromise");
        vc_registry::admin_revoke_vc(&root, id, b"fraud");
        assert!(vc_registry::get_vc_status(id) == t::vc_revoked(), 0);
    }

    // ---------------------------------------------------------------
    // M-07 / R-06: khong tao duoc vai tro "chiem cho" vo nghia.
    // ---------------------------------------------------------------

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_VC_TYPE, location = authority)]
    fun m07_delegator_cannot_squat_address_with_empty_mask() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::user(t::admin1_addr());
        authority::approve_issuer(&d, t::admin1_addr(), 0, t::cid(), t::hash(8), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_CAP_EXPIRED, location = authority)]
    fun r06_issuer_cannot_be_born_expired() {
        let root = t::setup();
        t::advance(10);
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor(), b"", b"", t::t0() + 5);
    }

    // ---------------------------------------------------------------
    // M-08: tu khoa truoc khong con la cach ne khoa cuong che.
    // ---------------------------------------------------------------

    #[test]
    fun m08_self_lock_does_not_escape_admin_lock() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        did_registry::suspend_own_did(&i);
        authority::admin_suspend_did(&root, t::issuer1_addr(), b"discipline");
        assert!(did_registry::suspended_by_of(t::issuer1_addr()) == t::root_addr(), 0);
        assert!(event::was_event_emitted(&did_registry::did_status_changed_event(
            did_registry::did_id_of(t::issuer1_addr()), t::issuer1_addr(), t::root_addr(), t::did_suspended(), b"discipline", t::t0())), 1);
    }

    // ---------------------------------------------------------------
    // R-07 / F-12: khong chiem truoc duoc DID cua nguoi khac, khong dung
    // phuong thuc DID la.
    // ---------------------------------------------------------------

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_BOUND_TO_OWNER, location = did_registry)]
    fun r07_cannot_squat_victims_did() {
        t::setup();
        let attacker = t::account(t::random1_addr());
        did_registry::register_did(&attacker, t::did_for(t::holder1_addr()), t::cid(), t::hash(1));
    }

    // ---------------------------------------------------------------
    // F-00: root chuyen hai buoc; nguoi nhan phai tu ky.
    // ---------------------------------------------------------------

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_PENDING_ROOT, location = authority)]
    fun f00_root_cannot_be_pushed_onto_someone_without_their_signature() {
        let root = t::setup();
        authority::propose_root(&root, t::random1_addr());
        // Chinh root cung khong ky nhan thay duoc.
        authority::accept_root(&root);
    }

    // ---------------------------------------------------------------
    // F-03 / F-04 / F-11c: cap lai sau thu hoi tao ban ghi moi, id khong trung.
    // ---------------------------------------------------------------

    #[test]
    fun f03_f04_f11c_regrants_never_reuse_ids_and_keep_history() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());                     // id 0
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0); // id 1
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        authority::grant_admin(&root, t::admin1_addr());       // id 2
        authority::approve_issuer(&root, t::issuer1_addr(), t::master(), b"", b"", 0); // id 3
        assert!(authority::total_roles() == 4, 0);
        let all = authority::get_roles_paginated(0, 10);
        assert!(authority::role_status(std::vector::borrow(&all, 0)) == t::role_revoked(), 1);
        assert!(authority::role_status(std::vector::borrow(&all, 1)) == t::role_revoked(), 2);
        assert!(authority::role_version(std::vector::borrow(&all, 3)) == 2, 3);
    }

    // ---------------------------------------------------------------
    // F-09 + F-11e: het han va bo dem song.
    // ---------------------------------------------------------------

    #[test]
    fun f11e_live_counter_is_an_upper_bound_not_reduced_by_expiry() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, t::t0() + 10);
        t::advance(10);
        assert!(vc_registry::get_vc_status(id) == t::vc_expired(), 0);
        let (li, lh) = vc_registry::get_live_counts(t::issuer1_addr(), t::holder1_addr());
        assert!(li == 1 && lh == 1, 1);
        // Thu hoi VC het han van giam bo dem dung mot lan.
        vc_registry::revoke_vc(&i, id, b"x");
        let (li2, lh2) = vc_registry::get_live_counts(t::issuer1_addr(), t::holder1_addr());
        assert!(li2 == 0 && lh2 == 0, 2);
    }

    // ---------------------------------------------------------------
    // Nang cap: ban ghi sub-issuer chi duoc tao sau khi khoi tao registry.
    // ---------------------------------------------------------------

    #[test]
    #[expected_failure(major_status = 4008, location = authority)]
    fun upgrade_delegated_approval_needs_registry_initialized() {
        let fx = t::account(@aptos_framework);
        aptos_framework::timestamp::set_time_has_started_for_testing(&fx);
        let deployer = t::account(@vnu);
        did_registry::initialize_for_test(&deployer);
        authority::initialize_legacy_for_test(&deployer, t::root_addr());
        let root = t::account(t::root_addr());
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
    }

    #[test]
    fun upgrade_delegation_works_after_registry_initialized() {
        let fx = t::account(@aptos_framework);
        aptos_framework::timestamp::set_time_has_started_for_testing(&fx);
        let deployer = t::account(@vnu);
        did_registry::initialize_for_test(&deployer);
        authority::initialize_legacy_for_test(&deployer, t::root_addr());
        authority::init_delegation_registry(&deployer);
        let root = t::account(t::root_addr());
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        assert!(authority::get_delegator(t::issuer2_addr()) == t::issuer1_addr(), 0);
    }
}
