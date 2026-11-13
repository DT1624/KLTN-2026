// Dac ta cay quyen: root -> admin -> issuer -> sub-issuer.
#[test_only]
module vnu::authority_test {
    use std::vector;
    use aptos_framework::event;
    use vnu::authority;
    use vnu::did_registry;
    use vnu::errors;
    use vnu::test_utils as t;

    const FAR: u64 = 1000000;

    // ================= Khoi tao / nang cap =================

    #[test]
    fun init_with_zero_root_makes_publisher_root() {
        let deployer = t::account(@vnu);
        authority::initialize_with_root_for_test(&deployer, @0x0);
        assert!(authority::get_root_admin() == @vnu, 0);
        assert!(authority::get_pending_root() == @0x0, 1);
        assert!(authority::delegation_registry_exists(), 2);
        let (admins, issuers) = authority::stats();
        assert!(admins == 0 && issuers == 0 && authority::total_roles() == 0, 3);
    }

    #[test]
    fun init_with_configured_root_uses_it() {
        t::setup();
        assert!(authority::get_root_admin() == t::root_addr(), 0);
    }

    #[test]
    fun init_delegation_registry_creates_missing_registry_once() {
        let deployer = t::account(@vnu);
        authority::initialize_legacy_for_test(&deployer, t::root_addr());
        assert!(!authority::delegation_registry_exists(), 0);
        authority::init_delegation_registry(&deployer);
        assert!(authority::delegation_registry_exists(), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ALREADY_INITIALIZED, location = authority)]
    fun init_delegation_registry_cannot_run_twice() {
        t::setup();
        authority::init_delegation_registry(&t::signer_of(@vnu));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_AUTHORIZED, location = authority)]
    fun init_delegation_registry_only_by_publisher() {
        let root = t::setup();
        authority::init_delegation_registry(&root);
    }

    #[test]
    fun legacy_state_still_supports_non_delegated_flows() {
        // Goi truoc nang cap: chua co DelegationRegistry. Moi luong khong dung
        // uy quyen van phai chay truoc khi init_delegation_registry duoc goi.
        let fx = t::account(@aptos_framework);
        aptos_framework::timestamp::set_time_has_started_for_testing(&fx);
        let deployer = t::account(@vnu);
        did_registry::initialize_for_test(&deployer);
        authority::initialize_legacy_for_test(&deployer, t::root_addr());
        let root = t::account(t::root_addr());
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        assert!(authority::is_active_issuer(t::issuer1_addr()), 0);
        assert!(authority::get_delegator(t::issuer1_addr()) == @0x0, 1);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor(), b"", b"", 0);
        let _ = i;
    }

    // ================= Chuyen root =================

    #[test]
    fun root_transfer_two_steps() {
        let root = t::setup();
        let new_root = t::account(t::random1_addr());
        authority::propose_root(&root, t::random1_addr());
        assert!(authority::get_pending_root() == t::random1_addr(), 0);
        assert!(authority::get_root_admin() == t::root_addr(), 1);
        assert!(event::was_event_emitted(&authority::root_transfer_proposed_event(t::root_addr(), t::random1_addr(), t::t0())), 2);

        authority::accept_root(&new_root);
        assert!(authority::get_root_admin() == t::random1_addr(), 3);
        assert!(authority::get_pending_root() == @0x0, 4);
        assert!(event::was_event_emitted(&authority::root_transferred_event(t::root_addr(), t::random1_addr(), t::t0())), 5);
        // Root moi khong can DID van hanh dong duoc.
        t::user(t::admin1_addr());
        authority::grant_admin(&new_root, t::admin1_addr());
        assert!(authority::is_active_admin(t::admin1_addr()), 6);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun old_root_loses_power_after_transfer() {
        let root = t::setup();
        authority::propose_root(&root, t::random1_addr());
        authority::accept_root(&t::account(t::random1_addr()));
        t::user(t::admin1_addr());
        authority::grant_admin(&root, t::admin1_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun propose_root_only_by_root() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        authority::propose_root(&admin, t::random1_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_ROOT_CANDIDATE, location = authority)]
    fun propose_root_rejects_zero_address() {
        let root = t::setup();
        authority::propose_root(&root, @0x0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_ROOT_CANDIDATE, location = authority)]
    fun propose_root_rejects_current_root() {
        let root = t::setup();
        authority::propose_root(&root, t::root_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun propose_root_rejects_active_admin() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        authority::propose_root(&root, t::admin1_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun propose_root_rejects_suspended_issuer() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        authority::propose_root(&root, t::issuer1_addr());
    }

    #[test]
    fun propose_root_accepts_former_admin() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        authority::propose_root(&root, t::admin1_addr());
        authority::accept_root(&admin);
        assert!(authority::get_root_admin() == t::admin1_addr(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun accept_root_rejects_candidate_that_gained_a_role() {
        let root = t::setup();
        authority::propose_root(&root, t::issuer1_addr());
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::accept_root(&i);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NO_PENDING_ROOT, location = authority)]
    fun accept_root_without_proposal_fails() {
        t::setup();
        authority::accept_root(&t::account(t::random1_addr()));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_PENDING_ROOT, location = authority)]
    fun accept_root_by_other_address_fails() {
        let root = t::setup();
        authority::propose_root(&root, t::random1_addr());
        authority::accept_root(&t::account(t::holder1_addr()));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_PENDING_ROOT, location = authority)]
    fun new_proposal_replaces_previous_candidate() {
        let root = t::setup();
        authority::propose_root(&root, t::random1_addr());
        authority::propose_root(&root, t::holder1_addr());
        assert!(authority::get_pending_root() == t::holder1_addr(), 0);
        authority::accept_root(&t::account(t::random1_addr()));
    }

    #[test]
    fun cancel_root_transfer_clears_pending_and_emits_event() {
        let root = t::setup();
        authority::propose_root(&root, t::random1_addr());
        authority::cancel_root_transfer(&root);
        assert!(authority::get_pending_root() == @0x0, 0);
        assert!(event::was_event_emitted(&authority::root_transfer_cancelled_event(t::root_addr(), t::random1_addr(), t::t0())), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NO_PENDING_ROOT, location = authority)]
    fun accept_root_after_cancel_fails() {
        let root = t::setup();
        authority::propose_root(&root, t::random1_addr());
        authority::cancel_root_transfer(&root);
        authority::accept_root(&t::account(t::random1_addr()));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NO_PENDING_ROOT, location = authority)]
    fun cancel_root_transfer_without_proposal_fails() {
        let root = t::setup();
        authority::cancel_root_transfer(&root);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun cancel_root_transfer_only_by_root() {
        let root = t::setup();
        authority::propose_root(&root, t::random1_addr());
        authority::cancel_root_transfer(&t::account(t::random1_addr()));
    }

    // ================= grant_admin / revoke_admin =================

    #[test]
    fun grant_admin_creates_active_record() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        let r = authority::admin_record(t::admin1_addr());
        let (owner, version, by, at, mask, cid, hash, exp, status, reason, _) = authority::record_fields(&r);
        assert!(owner == t::admin1_addr() && version == 1 && by == t::root_addr() && at == t::t0(), 0);
        assert!(mask == 0 && cid == b"" && hash == b"" && exp == 0, 1);
        assert!(status == t::role_active() && reason == b"", 2);
        assert!(authority::is_active_admin(t::admin1_addr()), 3);
        let (admins, issuers) = authority::stats();
        assert!(admins == 1 && issuers == 0 && authority::total_roles() == 1, 4);
        assert!(event::was_event_emitted(&authority::admin_granted_event(t::admin1_addr(), t::root_addr(), t::t0())), 5);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun grant_admin_only_by_root() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        t::user(t::admin2_addr());
        authority::grant_admin(&admin, t::admin2_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun grant_admin_requires_target_did() {
        let root = t::setup();
        authority::grant_admin(&root, t::admin1_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun grant_admin_requires_active_target_did() {
        let root = t::setup();
        let s = t::user(t::admin1_addr());
        did_registry::suspend_own_did(&s);
        authority::grant_admin(&root, t::admin1_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun grant_admin_rejects_root() {
        let root = t::setup();
        t::register(&root);
        authority::grant_admin(&root, t::root_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun grant_admin_rejects_active_issuer() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::grant_admin(&root, t::issuer1_addr());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun grant_admin_rejects_suspended_issuer() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        authority::grant_admin(&root, t::issuer1_addr());
    }

    #[test]
    fun grant_admin_accepts_revoked_issuer() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        authority::grant_admin(&root, t::issuer1_addr());
        assert!(authority::is_active_admin(t::issuer1_addr()), 0);
        assert!(!authority::is_active_issuer(t::issuer1_addr()), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_ALREADY_EXISTS, location = authority)]
    fun grant_admin_twice_fails() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        authority::grant_admin(&root, t::admin1_addr());
    }

    #[test]
    fun grant_admin_again_after_revoke_creates_new_version() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        t::advance(10);
        authority::grant_admin(&root, t::admin1_addr());

        assert!(authority::role_version(&authority::admin_record(t::admin1_addr())) == 2, 0);
        assert!(authority::is_active_admin(t::admin1_addr()), 1);
        let (admins, _) = authority::stats();
        assert!(admins == 1 && authority::total_roles() == 2, 2);
        // Ban ghi cu con nguyen lam vet kiem toan.
        let all = authority::get_roles_paginated(0, 10);
        assert!(authority::role_status(vector::borrow(&all, 0)) == t::role_revoked(), 3);
        assert!(authority::role_status(vector::borrow(&all, 1)) == t::role_active(), 4);
    }

    #[test]
    fun revoke_admin_marks_record_and_emits_event() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        t::advance(5);
        authority::revoke_admin(&root, t::admin1_addr(), b"left");
        let (_, _, _, _, _, _, _, _, status, reason, updated) = authority::record_fields(&authority::admin_record(t::admin1_addr()));
        assert!(status == t::role_revoked() && reason == b"left" && updated == t::t0() + 5, 0);
        assert!(!authority::is_active_admin(t::admin1_addr()), 1);
        assert!(event::was_event_emitted(&authority::admin_revoked_event(t::admin1_addr(), t::root_addr(), b"left", t::t0() + 5)), 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun revoke_admin_only_by_root() {
        let root = t::setup();
        let a1 = t::admin(&root, t::admin1_addr());
        t::admin(&root, t::admin2_addr());
        authority::revoke_admin(&a1, t::admin2_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ADMIN, location = authority)]
    fun revoke_admin_unknown_fails() {
        let root = t::setup();
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_ALREADY_REVOKED, location = authority)]
    fun revoke_admin_twice_fails() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun revoked_admin_loses_admin_powers() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        authority::suspend_issuer(&admin, t::issuer1_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = authority)]
    fun admin_with_suspended_did_loses_admin_powers() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        did_registry::suspend_own_did(&admin);
        assert!(!authority::is_active_admin(t::admin1_addr()), 0);
        authority::suspend_issuer(&admin, t::issuer1_addr(), b"x");
    }

    // ================= approve_issuer: root / admin =================

    #[test]
    fun root_approves_issuer() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor() | t::master(), b"", b"", t::t0() + FAR);
        let (owner, version, by, at, mask, cid, hash, exp, status, _, _) = authority::record_fields(&authority::issuer_record(t::issuer1_addr()));
        assert!(owner == t::issuer1_addr() && version == 1 && by == t::root_addr() && at == t::t0(), 0);
        assert!(mask == 3 && cid == b"" && hash == b"" && exp == t::t0() + FAR, 1);
        assert!(status == t::role_active() && authority::is_active_issuer(t::issuer1_addr()), 2);
        assert!(authority::get_delegator(t::issuer1_addr()) == @0x0, 3);
        let (_, issuers) = authority::stats();
        assert!(issuers == 1, 4);
        assert!(event::was_event_emitted(&authority::issuer_approved_event(t::issuer1_addr(), t::root_addr(), 3, b"", t::t0(), t::t0() + FAR)), 5);
    }

    #[test]
    fun admin_approves_plain_issuer() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        t::user(t::issuer1_addr());
        authority::approve_issuer(&admin, t::issuer1_addr(), t::phd(), b"", b"", 0);
        assert!(authority::is_active_issuer(t::issuer1_addr()), 0);
    }

    #[test]
    fun root_can_grant_every_defined_bit() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), 63, t::cid(), t::hash(9), 0);
        assert!(authority::can_delegate(t::issuer1_addr()), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun admin_cannot_grant_delegation_bit() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        t::user(t::issuer1_addr());
        authority::approve_issuer(&admin, t::issuer1_addr(), t::bachelor() | t::delegation(), t::cid(), t::hash(9), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_AUTHORIZED, location = authority)]
    fun stranger_cannot_approve_issuer() {
        t::setup();
        let s = t::user(t::random1_addr());
        t::user(t::issuer1_addr());
        authority::approve_issuer(&s, t::issuer1_addr(), t::bachelor(), b"", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_CANNOT_DELEGATE, location = authority)]
    fun plain_issuer_cannot_approve_issuer() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::user(t::issuer2_addr());
        authority::approve_issuer(&i, t::issuer2_addr(), t::bachelor(), t::cid(), t::hash(8), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_VC_TYPE, location = authority)]
    fun approve_issuer_rejects_empty_mask() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), 0, b"", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_VC_TYPE, location = authority)]
    fun approve_issuer_rejects_undefined_bits() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), 64 | t::bachelor(), b"", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_CAP_EXPIRED, location = authority)]
    fun approve_issuer_rejects_expiry_now() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor(), b"", b"", t::t0());
    }

    #[test]
    fun approve_issuer_accepts_expiry_one_second_ahead() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 1);
        assert!(authority::is_active_issuer(t::issuer1_addr()), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = did_registry)]
    fun delegation_bit_requires_proof_cid() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor() | t::delegation(), b"", t::hash(9), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = authority)]
    fun delegation_bit_requires_proof_hash() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor() | t::delegation(), t::cid(), b"", 0);
    }

    #[test]
    fun plain_issuer_proof_is_optional_but_stored_when_given() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor(), t::cid(), t::hash(9), 0);
        let (_, _, _, _, _, cid, hash, _, _, _, _) = authority::record_fields(&authority::issuer_record(t::issuer1_addr()));
        assert!(cid == t::cid() && hash == t::hash(9), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = authority)]
    fun plain_issuer_optional_hash_must_be_32_bytes() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor(), b"", t::bytes(5, 0), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = did_registry)]
    fun plain_issuer_optional_cid_must_be_valid() {
        let root = t::setup();
        t::user(t::issuer1_addr());
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor(), b"abc", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun approve_issuer_requires_target_did() {
        let root = t::setup();
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor(), b"", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun approve_issuer_rejects_root() {
        let root = t::setup();
        t::register(&root);
        authority::approve_issuer(&root, t::root_addr(), t::bachelor(), b"", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun approve_issuer_rejects_active_admin() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        authority::approve_issuer(&root, t::admin1_addr(), t::bachelor(), b"", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_ALREADY_EXISTS, location = authority)]
    fun approve_issuer_rejects_active_issuer() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::approve_issuer(&root, t::issuer1_addr(), t::master(), b"", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_ALREADY_EXISTS, location = authority)]
    fun approve_issuer_rejects_suspended_issuer() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        authority::approve_issuer(&root, t::issuer1_addr(), t::master(), b"", b"", 0);
    }

    #[test]
    fun revoked_issuer_can_be_reapproved_with_new_record() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        authority::approve_issuer(&admin, t::issuer1_addr(), t::master(), b"", b"", 0);
        let (_, version, by, _, mask, _, _, _, status, _, _) = authority::record_fields(&authority::issuer_record(t::issuer1_addr()));
        assert!(version == 2 && by == t::admin1_addr() && mask == t::master() && status == t::role_active(), 0);
        let (_, issuers) = authority::stats();
        assert!(issuers == 1 && authority::total_roles() == 3, 1);
    }

    // ================= approve_issuer: uy quyen =================

    #[test]
    fun delegator_approves_sub_issuer() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor() | t::master(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), t::t0() + FAR);
        let (_, _, by, _, mask, cid, hash, exp, _, _, _) = authority::record_fields(&authority::issuer_record(t::issuer2_addr()));
        assert!(by == t::issuer1_addr() && mask == t::bachelor() && exp == t::t0() + FAR, 0);
        assert!(cid == t::cid() && hash == t::hash(8), 1);
        assert!(authority::get_delegator(t::issuer2_addr()) == t::issuer1_addr(), 2);
        assert!(authority::is_active_issuer(t::issuer2_addr()), 3);
        assert!(!authority::can_delegate(t::issuer2_addr()), 4);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_UNAUTHORIZED_VC_TYPE, location = authority)]
    fun sub_issuer_mask_must_be_subset_of_parent() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor() | t::phd(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun sub_issuer_cannot_receive_delegation_bit() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor() | t::delegation(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = did_registry)]
    fun sub_issuer_requires_delegation_proof() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::user(t::issuer2_addr());
        authority::approve_issuer(&d, t::issuer2_addr(), t::bachelor(), b"", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_CAP_EXPIRED, location = authority)]
    fun sub_issuer_of_expiring_parent_cannot_be_permanent() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 100);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_CAP_EXPIRED, location = authority)]
    fun sub_issuer_cannot_outlive_parent() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 100);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), t::t0() + 101);
    }

    #[test]
    fun sub_issuer_may_expire_with_parent() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 100);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), t::t0() + 100);
        assert!(authority::is_active_issuer(t::issuer2_addr()), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_AUTHORIZED, location = authority)]
    fun delegator_cannot_reapprove_revoked_issuer() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::issuer(&root, t::issuer2_addr(), t::bachelor(), 0);
        authority::revoke_issuer(&root, t::issuer2_addr(), b"fraud");
        authority::approve_issuer(&d, t::issuer2_addr(), t::bachelor(), t::cid(), t::hash(8), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_CAP_EXPIRED, location = authority)]
    fun expired_delegator_cannot_approve() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 10);
        t::advance(10);
        // Han 0 de qua phep kiem "han o tuong lai" va cham dung nhanh delegator het han.
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun suspended_delegator_cannot_approve() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = authority)]
    fun delegator_with_suspended_did_cannot_approve() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::user(t::issuer2_addr());
        did_registry::suspend_own_did(&d);
        authority::approve_issuer(&d, t::issuer2_addr(), t::bachelor(), t::cid(), t::hash(8), 0);
    }

    #[test]
    fun former_admin_can_use_delegation_role() {
        let root = t::setup();
        let s = t::admin(&root, t::admin1_addr());
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        authority::approve_issuer(&root, t::admin1_addr(), t::bachelor() | t::delegation(), t::cid(), t::hash(9), 0);
        assert!(authority::can_delegate(t::admin1_addr()), 0);
        t::sub_issuer(&s, t::issuer2_addr(), t::bachelor(), 0);
        assert!(authority::get_delegator(t::issuer2_addr()) == t::admin1_addr(), 1);
    }

    #[test]
    fun reapproval_by_root_detaches_sub_issuer_from_parent() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        authority::revoke_issuer(&root, t::issuer2_addr(), b"x");
        authority::approve_issuer(&root, t::issuer2_addr(), t::bachelor(), b"", b"", 0);
        assert!(authority::get_delegator(t::issuer2_addr()) == @0x0, 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        assert!(authority::is_active_issuer(t::issuer2_addr()), 1);
    }

    // ================= Trang thai issuer =================

    #[test]
    fun admin_suspends_reactivates_and_revokes_issuer() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        let a = t::issuer1_addr();
        t::issuer(&root, a, t::bachelor(), 0);

        authority::suspend_issuer(&admin, a, b"audit");
        assert!(authority::role_status(&authority::issuer_record(a)) == t::role_suspended(), 0);
        assert!(!authority::is_active_issuer(a), 1);
        assert!(event::was_event_emitted(&authority::issuer_status_changed_event(a, t::admin1_addr(), t::role_suspended(), b"audit", t::t0())), 2);

        authority::reactivate_issuer(&admin, a, b"ok");
        assert!(authority::is_active_issuer(a), 3);

        authority::revoke_issuer(&admin, a, b"fraud");
        let (_, _, _, _, _, _, _, _, status, reason, _) = authority::record_fields(&authority::issuer_record(a));
        assert!(status == t::role_revoked() && reason == b"fraud", 4);
    }

    #[test]
    fun suspended_issuer_can_be_revoked() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        assert!(authority::role_status(&authority::issuer_record(t::issuer1_addr())) == t::role_revoked(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun suspend_issuer_twice_fails() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_SUSPENDED, location = authority)]
    fun reactivate_active_issuer_fails() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::reactivate_issuer(&root, t::issuer1_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_ALREADY_REVOKED, location = authority)]
    fun revoked_issuer_cannot_be_reactivated_in_place() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        authority::reactivate_issuer(&root, t::issuer1_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_ALREADY_REVOKED, location = authority)]
    fun revoke_issuer_twice_fails() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_FOUND, location = authority)]
    fun issuer_status_change_requires_existing_issuer() {
        let root = t::setup();
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun stranger_cannot_change_issuer_status() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&t::user(t::random1_addr()), t::issuer1_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = authority)]
    fun caller_without_did_cannot_change_issuer_status() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&t::account(t::random1_addr()), t::issuer1_addr(), b"x");
    }

    #[test]
    fun delegator_can_suspend_and_revoke_own_sub_issuer() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&d, t::issuer2_addr(), b"check");
        assert!(authority::role_status(&authority::issuer_record(t::issuer2_addr())) == t::role_suspended(), 0);
        authority::revoke_issuer(&d, t::issuer2_addr(), b"done");
        assert!(authority::role_status(&authority::issuer_record(t::issuer2_addr())) == t::role_revoked(), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun delegator_cannot_reactivate_sub_issuer() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&d, t::issuer2_addr(), b"x");
        authority::reactivate_issuer(&d, t::issuer2_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun delegator_cannot_touch_another_delegators_sub_issuer() {
        let root = t::setup();
        let d1 = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        let d2 = t::delegator(&root, t::issuer3_addr(), t::bachelor(), 0);
        t::sub_issuer(&d1, t::issuer2_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&d2, t::issuer2_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun suspended_delegator_cannot_manage_sub_issuer() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        authority::revoke_issuer(&d, t::issuer2_addr(), b"x");
    }

    // ================= Kiem duyet DID: bao ve dich + thu hoi vai tro =================

    #[test]
    #[expected_failure(abort_code = errors::E_PROTECTED_TARGET, location = authority)]
    fun admin_cannot_moderate_root_did() {
        let root = t::setup();
        t::register(&root);
        let admin = t::admin(&root, t::admin1_addr());
        authority::admin_suspend_did(&admin, t::root_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_PROTECTED_TARGET, location = authority)]
    fun root_cannot_moderate_own_did() {
        let root = t::setup();
        t::register(&root);
        authority::admin_revoke_did(&root, t::root_addr(), b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_PROTECTED_TARGET, location = authority)]
    fun admin_cannot_moderate_another_admin_did() {
        let root = t::setup();
        let a1 = t::admin(&root, t::admin1_addr());
        t::admin(&root, t::admin2_addr());
        authority::admin_revoke_did(&a1, t::admin2_addr(), b"x");
    }

    #[test]
    fun admin_can_moderate_former_admin_did() {
        let root = t::setup();
        let a1 = t::admin(&root, t::admin1_addr());
        t::admin(&root, t::admin2_addr());
        authority::revoke_admin(&root, t::admin2_addr(), b"x");
        authority::admin_suspend_did(&a1, t::admin2_addr(), b"x");
        assert!(did_registry::status_of(t::admin2_addr()) == t::did_suspended(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun non_admin_cannot_moderate_did() {
        t::setup();
        t::user(t::holder1_addr());
        authority::admin_suspend_did(&t::user(t::random1_addr()), t::holder1_addr(), b"x");
    }

    #[test]
    fun revoking_admin_did_also_revokes_admin_role() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        authority::admin_revoke_did(&root, t::admin1_addr(), b"compromised");
        let (_, _, _, _, _, _, _, _, status, reason, _) = authority::record_fields(&authority::admin_record(t::admin1_addr()));
        assert!(status == t::role_revoked() && reason == b"compromised", 0);
        assert!(event::was_event_emitted(&authority::admin_revoked_event(t::admin1_addr(), t::root_addr(), b"compromised", t::t0())), 1);
    }

    #[test]
    fun revoking_issuer_did_also_revokes_issuer_role() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        authority::admin_revoke_did(&admin, t::issuer1_addr(), b"fraud");
        assert!(authority::role_status(&authority::issuer_record(t::issuer1_addr())) == t::role_revoked(), 0);
        assert!(event::was_event_emitted(&authority::issuer_status_changed_event(t::issuer1_addr(), t::admin1_addr(), t::role_revoked(), b"fraud", t::t0())), 1);
    }

    #[test]
    fun suspending_did_keeps_role_record_but_blocks_it() {
        let root = t::setup();
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::admin_suspend_did(&root, t::issuer1_addr(), b"x");
        assert!(authority::role_status(&authority::issuer_record(t::issuer1_addr())) == t::role_active(), 0);
        assert!(!authority::is_active_issuer(t::issuer1_addr()), 1);
        authority::admin_reactivate_did(&root, t::issuer1_addr(), b"x");
        assert!(authority::is_active_issuer(t::issuer1_addr()), 2);
    }

    // ================= Views =================

    #[test]
    fun is_active_issuer_reflects_every_condition() {
        let root = t::setup();
        assert!(!authority::is_active_issuer(t::issuer1_addr()), 0);
        t::user(t::issuer3_addr());
        assert!(!authority::is_active_issuer(t::issuer3_addr()), 1);
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 10);
        assert!(authority::is_active_issuer(t::issuer1_addr()), 2);
        t::advance(9);
        assert!(authority::is_active_issuer(t::issuer1_addr()), 3);
        t::advance(1);
        assert!(!authority::is_active_issuer(t::issuer1_addr()), 4);
    }

    #[test]
    fun is_active_admin_reflects_every_condition() {
        let root = t::setup();
        assert!(authority::is_active_admin(t::root_addr()), 0);
        assert!(!authority::is_active_admin(t::admin1_addr()), 1);
        t::user(t::random1_addr());
        assert!(!authority::is_active_admin(t::random1_addr()), 2);
        t::admin(&root, t::admin1_addr());
        assert!(authority::is_active_admin(t::admin1_addr()), 3);
    }

    #[test]
    fun can_delegate_matches_approve_issuer_rules() {
        let root = t::setup();
        assert!(authority::can_delegate(t::root_addr()), 0);
        t::admin(&root, t::admin1_addr());
        assert!(authority::can_delegate(t::admin1_addr()), 1);
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        assert!(!authority::can_delegate(t::issuer1_addr()), 2);
        t::delegator(&root, t::issuer2_addr(), t::bachelor(), t::t0() + 5);
        assert!(authority::can_delegate(t::issuer2_addr()), 3);
        t::user(t::random1_addr());
        assert!(!authority::can_delegate(t::random1_addr()), 4);
        t::advance(5);
        assert!(!authority::can_delegate(t::issuer2_addr()), 5);
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        assert!(!authority::can_delegate(t::admin1_addr()), 6);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = authority)]
    fun get_role_unknown_fails() {
        t::setup();
        authority::get_role(t::random1_addr());
    }

    #[test]
    fun get_role_of_plain_admin_and_plain_issuer() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        t::issuer(&root, t::issuer1_addr(), t::master(), 0);
        let (by, mask, _, _, _, status) = authority::get_info(t::admin1_addr());
        assert!(by == t::root_addr() && mask == 0 && status == t::role_active(), 0);
        let (_, mask2, _, _, _, _) = authority::get_info(t::issuer1_addr());
        assert!(mask2 == t::master(), 1);
    }

    #[test]
    fun get_role_prefers_the_live_role() {
        let root = t::setup();
        // issuer -> thu hoi -> admin: tra ve admin
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        authority::grant_admin(&root, t::issuer1_addr());
        let (_, _, _, _, _, status) = authority::get_info(t::issuer1_addr());
        assert!(status == t::role_active() && authority::role_owner(&authority::get_role(t::issuer1_addr())) == t::issuer1_addr(), 0);
        let (_, mask, _, _, _, _) = authority::get_info(t::issuer1_addr());
        assert!(mask == 0, 1);
        // admin -> thu hoi -> issuer: tra ve issuer
        t::admin(&root, t::admin1_addr());
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        authority::approve_issuer(&root, t::admin1_addr(), t::phd(), b"", b"", 0);
        let (_, mask2, _, _, _, status2) = authority::get_info(t::admin1_addr());
        assert!(mask2 == t::phd() && status2 == t::role_active(), 2);
        // ca hai da chet: tra ve ban issuer
        authority::revoke_issuer(&root, t::admin1_addr(), b"x");
        let (_, mask3, _, _, _, status3) = authority::get_info(t::admin1_addr());
        assert!(mask3 == t::phd() && status3 == t::role_revoked(), 3);
    }

    #[test]
    fun list_views_and_pagination() {
        let root = t::setup();
        t::admin(&root, t::admin1_addr());
        t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::issuer(&root, t::issuer2_addr(), t::bachelor(), 0);
        assert!(authority::get_admins() == vector[t::admin1_addr()], 0);
        let issuers = authority::get_issuers();
        assert!(vector::length(&issuers) == 2 && vector::contains(&issuers, &t::issuer2_addr()), 1);

        let page = authority::get_roles_paginated(1, 1);
        assert!(vector::length(&page) == 1 && authority::role_owner(vector::borrow(&page, 0)) == t::issuer1_addr(), 2);
        assert!(vector::length(&authority::get_roles_paginated(0, 200)) == 3, 3);
        assert!(vector::is_empty(&authority::get_roles_paginated(18446744073709551615, 200)), 4);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_RESULT_TOO_LARGE, location = authority)]
    fun get_admins_refuses_more_than_500_entries() {
        let root = t::setup();
        t::many_users(501);
        let n = 0;
        while (n < 501) { authority::grant_admin(&root, t::nth_addr(n)); n = n + 1; };
        assert!(vector::length(&authority::get_roles_paginated(300, 200)) == 200, 0);
        authority::get_admins();
    }

    #[test]
    #[expected_failure(abort_code = errors::E_RESULT_TOO_LARGE, location = authority)]
    fun get_issuers_refuses_more_than_500_entries() {
        let root = t::setup();
        t::many_users(501);
        let n = 0;
        while (n < 501) { authority::approve_issuer(&root, t::nth_addr(n), t::bachelor(), b"", b"", 0); n = n + 1; };
        authority::get_issuers();
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_PAGE, location = authority)]
    fun get_roles_paginated_rejects_zero_limit() {
        t::setup();
        authority::get_roles_paginated(0, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_PAGE, location = authority)]
    fun get_roles_paginated_rejects_limit_above_200() {
        t::setup();
        authority::get_roles_paginated(0, 201);
    }
}
