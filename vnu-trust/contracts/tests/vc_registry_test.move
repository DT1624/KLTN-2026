// Dac ta vong doi van bang (VC).
#[test_only]
module vnu::vc_registry_test {
    use std::vector;
    use aptos_framework::event;
    use vnu::authority;
    use vnu::did_registry;
    use vnu::errors;
    use vnu::vc_registry;
    use vnu::test_utils as t;

    /// root, issuer1 (cu nhan + thac si, vinh vien), holder1. Tra ve (root, issuer).
    fun world(): (signer, signer) {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor() | t::master(), 0);
        t::user(t::holder1_addr());
        (root, i)
    }

    fun status(id: u64): u8 { vc_registry::get_vc_status(id) }

    fun live(): (u64, u64) { vc_registry::get_live_counts(t::issuer1_addr(), t::holder1_addr()) }

    // ================= issue_vc =================

    #[test]
    fun issue_vc_stores_record_counts_and_event() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, t::t0() + 500);
        assert!(id == 0 && vc_registry::total_vcs() == 1, 0);

        let (rid, issuer, holder, vc_hash, cid, content, vc_type, st, issued, exp, revoked_at, reason) =
            vc_registry::record_fields(&vc_registry::get_vc_by_id(id));
        assert!(rid == 0 && issuer == t::issuer1_addr() && holder == t::holder1_addr(), 1);
        assert!(vc_hash == t::hash(1) && cid == t::cid() && content == t::content_hash(1), 2);
        assert!(vc_type == t::bachelor() && st == t::vc_active(), 3);
        assert!(issued == t::t0() && exp == t::t0() + 500 && revoked_at == 0 && reason == b"", 4);

        assert!(vc_registry::get_vc_id_by_hash(t::hash(1)) == 0, 5);
        let (ti, th) = vc_registry::get_counts(t::issuer1_addr(), t::holder1_addr());
        let (li, lh) = live();
        assert!(ti == 1 && th == 1 && li == 1 && lh == 1, 6);
        assert!(vc_registry::verify_integrity(id, t::content_hash(1)), 7);
        assert!(!vc_registry::verify_integrity(id, t::hash(77)), 8);
        assert!(event::was_event_emitted(&vc_registry::vc_issued_event(
            0, t::issuer1_addr(), t::did_for(t::issuer1_addr()), t::holder1_addr(), t::did_for(t::holder1_addr()),
            t::hash(1), t::cid(), t::bachelor(), t::t0(), t::t0() + 500)), 9);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_SELF_ISSUE, location = vc_registry)]
    fun issue_vc_rejects_self_issue() {
        let (_root, i) = world();
        t::issue(&i, t::issuer1_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_VC_TYPE, location = vc_registry)]
    fun issue_vc_rejects_type_zero() {
        let (_root, i) = world();
        t::issue(&i, t::holder1_addr(), 0, 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_VC_TYPE, location = vc_registry)]
    fun issue_vc_rejects_multi_bit_type_even_inside_mask() {
        let (_root, i) = world();
        t::issue(&i, t::holder1_addr(), t::bachelor() | t::master(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_VC_TYPE, location = vc_registry)]
    fun issue_vc_rejects_undefined_bit() {
        let (_root, i) = world();
        t::issue(&i, t::holder1_addr(), 64, 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_UNAUTHORIZED_VC_TYPE, location = authority)]
    fun issue_vc_rejects_type_outside_mask() {
        let (_root, i) = world();
        t::issue(&i, t::holder1_addr(), t::phd(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = vc_registry)]
    fun issue_vc_rejects_bad_vc_id_hash() {
        let (_root, i) = world();
        vc_registry::issue_vc(&i, t::holder1_addr(), t::bachelor(), t::bytes(31, 0), t::cid(), t::hash(2), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = vc_registry)]
    fun issue_vc_rejects_bad_content_hash() {
        let (_root, i) = world();
        vc_registry::issue_vc(&i, t::holder1_addr(), t::bachelor(), t::hash(1), t::cid(), t::bytes(33, 0), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = did_registry)]
    fun issue_vc_rejects_bad_cid() {
        let (_root, i) = world();
        vc_registry::issue_vc(&i, t::holder1_addr(), t::bachelor(), t::hash(1), b"", t::hash(2), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_EXPIRED, location = vc_registry)]
    fun issue_vc_rejects_expiry_now() {
        let (_root, i) = world();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, t::t0());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_FOUND, location = authority)]
    fun issue_vc_requires_issuer_role() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        t::user(t::holder1_addr());
        t::issue(&admin, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun issue_vc_rejects_suspended_issuer() {
        let (root, i) = world();
        authority::suspend_issuer(&root, t::issuer1_addr(), b"x");
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun issue_vc_rejects_revoked_issuer() {
        let (root, i) = world();
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_CAP_EXPIRED, location = authority)]
    fun issue_vc_rejects_expired_issuer() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 10);
        t::user(t::holder1_addr());
        t::advance(10);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = authority)]
    fun issue_vc_rejects_issuer_with_suspended_did() {
        let (_root, i) = world();
        did_registry::suspend_own_did(&i);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun issue_vc_requires_holder_did() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), 0);
        t::issue(&i, t::holder2_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun issue_vc_rejects_suspended_holder() {
        let (root, i) = world();
        authority::admin_suspend_did(&root, t::holder1_addr(), b"x");
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_EXISTS, location = vc_registry)]
    fun issue_vc_rejects_duplicate_vc_id_hash_across_issuers() {
        let (root, i) = world();
        let i2 = t::issuer(&root, t::issuer2_addr(), t::bachelor(), 0);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::issue(&i2, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    #[test]
    fun sub_issuer_issues_while_parent_is_valid() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        let s = t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        let id = t::issue(&s, t::holder1_addr(), t::bachelor(), 1, 0);
        assert!(status(id) == t::vc_active(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DELEGATOR_NOT_ACTIVE, location = authority)]
    fun sub_issuer_cannot_issue_after_parent_revoked() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        let s = t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        authority::revoke_issuer(&root, t::issuer1_addr(), b"fraud");
        t::issue(&s, t::holder1_addr(), t::bachelor(), 1, 0);
    }

    // ================= Issuer doi trang thai VC cua minh =================

    #[test]
    fun issuer_suspends_own_vc() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::advance(3);
        vc_registry::suspend_vc(&i, id, b"review");
        let (_, _, _, _, _, _, _, st, _, _, revoked_at, reason) = vc_registry::record_fields(&vc_registry::get_vc_by_id(id));
        assert!(st == t::vc_suspended() && reason == b"review" && revoked_at == 0, 0);
        let (li, lh) = live();
        assert!(li == 0 && lh == 0, 1);
        assert!(!vc_registry::verify_integrity(id, t::content_hash(1)), 2);
        assert!(event::was_event_emitted(&vc_registry::vc_status_changed_event(id, t::holder1_addr(), t::vc_suspended(), b"review", t::issuer1_addr(), t::t0() + 3)), 3);
    }

    #[test]
    fun issuer_revokes_own_vc() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::advance(7);
        vc_registry::revoke_vc(&i, id, b"error");
        let (_, _, _, _, _, _, _, st, _, _, revoked_at, reason) = vc_registry::record_fields(&vc_registry::get_vc_by_id(id));
        assert!(st == t::vc_revoked() && revoked_at == t::t0() + 7 && reason == b"error", 0);
        let (ti, th) = vc_registry::get_counts(t::issuer1_addr(), t::holder1_addr());
        let (li, lh) = live();
        assert!(ti == 1 && th == 1 && li == 0 && lh == 0, 1);
    }

    #[test]
    fun revoking_suspended_vc_does_not_double_decrement() {
        let (_root, i) = world();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        let id = t::issue(&i, t::holder1_addr(), t::master(), 2, 0);
        vc_registry::suspend_vc(&i, id, b"x");
        vc_registry::revoke_vc(&i, id, b"x");
        let (li, lh) = live();
        assert!(li == 1 && lh == 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_VC_ISSUER, location = vc_registry)]
    fun issuer_cannot_touch_another_issuers_vc() {
        let (root, i) = world();
        let i2 = t::issuer(&root, t::issuer2_addr(), t::bachelor(), 0);
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::revoke_vc(&i2, id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_VC_ISSUER, location = vc_registry)]
    fun holder_cannot_revoke_own_vc() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::revoke_vc(&t::signer_of(t::holder1_addr()), id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun issuer_status_change_on_missing_vc_fails() {
        let (_root, i) = world();
        vc_registry::suspend_vc(&i, 99, b"x");
    }

    #[test]
    fun expired_issuer_can_still_suspend_and_revoke_own_vcs() {
        let root = t::setup();
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 10);
        t::user(t::holder1_addr());
        let a = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        let b = t::issue(&i, t::holder1_addr(), t::bachelor(), 2, 0);
        t::advance(20);
        assert!(!authority::is_active_issuer(t::issuer1_addr()), 0);
        vc_registry::suspend_vc(&i, a, b"x");
        vc_registry::revoke_vc(&i, b, b"x");
        assert!(status(a) == t::vc_suspended() && status(b) == t::vc_revoked(), 1);
    }

    #[test]
    fun sub_issuer_can_revoke_own_vc_after_parent_revoked() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), 0);
        let s = t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        let id = t::issue(&s, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        vc_registry::revoke_vc(&s, id, b"cleanup");
        assert!(status(id) == t::vc_revoked(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun suspended_issuer_cannot_revoke_own_vc() {
        let (root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"key leak");
        vc_registry::revoke_vc(&i, id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun revoked_issuer_cannot_suspend_own_vc() {
        let (root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        vc_registry::suspend_vc(&i, id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun issuer_with_suspended_did_cannot_revoke_own_vc() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        did_registry::suspend_own_did(&i);
        vc_registry::revoke_vc(&i, id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun issuer_cannot_reinstate_own_vc() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::suspend_vc(&i, id, b"x");
        vc_registry::admin_reinstate_vc(&i, id, b"x");
    }

    // ================= Admin doi trang thai VC =================

    #[test]
    fun admin_suspend_reinstate_revoke_cycle() {
        let (root, i) = world();
        let admin = t::admin(&root, t::admin1_addr());
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);

        vc_registry::admin_suspend_vc(&admin, id, b"a");
        assert!(status(id) == t::vc_suspended(), 0);
        vc_registry::admin_reinstate_vc(&admin, id, b"b");
        assert!(status(id) == t::vc_active(), 1);
        let (li, lh) = live();
        assert!(li == 1 && lh == 1, 2);
        assert!(event::was_event_emitted(&vc_registry::vc_status_changed_event(id, t::holder1_addr(), t::vc_active(), b"b", t::admin1_addr(), t::t0())), 3);
        // Root khong co DID van la admin.
        vc_registry::admin_revoke_vc(&root, id, b"c");
        assert!(status(id) == t::vc_revoked(), 4);
    }

    #[test]
    fun admin_reinstates_vc_suspended_by_issuer() {
        let (root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::suspend_vc(&i, id, b"x");
        vc_registry::admin_reinstate_vc(&root, id, b"ok");
        assert!(status(id) == t::vc_active(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun non_admin_cannot_use_admin_path() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::admin_revoke_vc(&i, id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun admin_status_change_on_missing_vc_fails() {
        let (root, _i) = world();
        vc_registry::admin_revoke_vc(&root, 5, b"x");
    }

    // ================= Luat chuyen trang thai =================

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_ACTIVE, location = vc_registry)]
    fun suspend_already_suspended_fails() {
        let (root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::suspend_vc(&i, id, b"x");
        vc_registry::admin_suspend_vc(&root, id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_SUSPENDED, location = vc_registry)]
    fun reinstate_active_fails() {
        let (root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::admin_reinstate_vc(&root, id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_REVOKED, location = vc_registry)]
    fun revoke_twice_fails() {
        let (root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::revoke_vc(&i, id, b"x");
        vc_registry::admin_revoke_vc(&root, id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_REVOKED, location = vc_registry)]
    fun reinstate_revoked_fails() {
        let (root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::admin_revoke_vc(&root, id, b"x");
        vc_registry::admin_reinstate_vc(&root, id, b"x");
    }

    // ================= Het han =================

    #[test]
    fun vc_expires_exactly_at_expires_at() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, t::t0() + 100);
        t::advance(99);
        assert!(status(id) == t::vc_active() && vc_registry::verify_integrity(id, t::content_hash(1)), 0);
        t::advance(1);
        assert!(status(id) == t::vc_expired(), 1);
        assert!(vc_registry::record_status(&vc_registry::get_vc_by_id(id)) == t::vc_expired(), 2);
        assert!(!vc_registry::verify_integrity(id, t::content_hash(1)), 3);
        let page = vc_registry::get_vcs_paginated(0, 10);
        assert!(vc_registry::record_status(vector::borrow(&page, 0)) == t::vc_expired(), 4);
        // Het han khong duoc GHI vao storage.
        assert!(vc_registry::record_status(&vc_registry::stored_record(id)) == t::vc_active(), 5);
    }

    #[test]
    fun zero_expiry_never_expires() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::advance(3000000000);
        assert!(status(id) == t::vc_active(), 0);
    }

    #[test]
    fun suspended_vc_reports_expired_after_deadline() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, t::t0() + 10);
        vc_registry::suspend_vc(&i, id, b"x");
        t::advance(10);
        assert!(status(id) == t::vc_expired(), 0);
    }

    #[test]
    fun expired_vc_can_still_be_revoked_and_stays_revoked() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, t::t0() + 10);
        t::advance(20);
        vc_registry::revoke_vc(&i, id, b"fraud");
        assert!(status(id) == t::vc_revoked(), 0);
        t::advance(1000);
        assert!(status(id) == t::vc_revoked(), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_EXPIRED, location = vc_registry)]
    fun expired_vc_cannot_be_suspended() {
        let (_root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, t::t0() + 10);
        t::advance(10);
        vc_registry::suspend_vc(&i, id, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_EXPIRED, location = vc_registry)]
    fun expired_suspended_vc_cannot_be_reinstated() {
        let (root, i) = world();
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, t::t0() + 10);
        vc_registry::suspend_vc(&i, id, b"x");
        t::advance(10);
        vc_registry::admin_reinstate_vc(&root, id, b"x");
    }

    // ================= Views =================

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun get_vc_by_id_missing_fails() {
        world();
        vc_registry::get_vc_by_id(0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun get_vc_status_missing_fails() {
        world();
        vc_registry::get_vc_status(0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun get_vc_id_by_hash_missing_fails() {
        world();
        vc_registry::get_vc_id_by_hash(t::hash(1));
    }

    #[test]
    fun verify_integrity_false_for_missing_or_revoked() {
        let (root, i) = world();
        assert!(!vc_registry::verify_integrity(0, t::content_hash(1)), 0);
        let id = t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::admin_revoke_vc(&root, id, b"x");
        assert!(!vc_registry::verify_integrity(id, t::content_hash(1)), 1);
    }

    #[test]
    fun counts_are_zero_for_unknown_addresses() {
        world();
        let (a, b) = vc_registry::get_counts(t::random1_addr(), t::random1_addr());
        let (c, d) = vc_registry::get_live_counts(t::random1_addr(), t::random1_addr());
        assert!(a == 0 && b == 0 && c == 0 && d == 0, 0);
    }

    #[test]
    fun list_views_pagination_and_accessors() {
        let (_root, i) = world();
        t::user(t::holder2_addr());
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::issue(&i, t::holder2_addr(), t::master(), 2, t::t0() + 9);
        t::issue(&i, t::holder1_addr(), t::master(), 3, 0);

        let hashes = vc_registry::get_vcs();
        assert!(vector::length(&hashes) == 3 && vector::contains(&hashes, &t::hash(2)), 0);

        let page = vc_registry::get_vcs_paginated(1, 1);
        assert!(vector::length(&page) == 1, 1);
        let r = vector::borrow(&page, 0);
        assert!(vc_registry::record_id(r) == 1 && vc_registry::record_holder(r) == t::holder2_addr(), 2);
        assert!(vc_registry::record_issuer(r) == t::issuer1_addr() && vc_registry::record_expires_at(r) == t::t0() + 9, 3);
        assert!(vector::length(&vc_registry::get_vcs_paginated(0, 200)) == 3, 4);
        assert!(vector::is_empty(&vc_registry::get_vcs_paginated(18446744073709551615, 200)), 5);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_RESULT_TOO_LARGE, location = vc_registry)]
    fun get_vcs_refuses_more_than_500_entries() {
        let (_root, i) = world();
        let n = 0;
        while (n < 501) {
            vc_registry::issue_vc(&i, t::holder1_addr(), t::bachelor(), t::nth_hash(n), t::cid(), t::hash(1), 0);
            n = n + 1;
        };
        let (li, lh) = live();
        assert!(li == 501 && lh == 501, 0);
        vc_registry::get_vcs();
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_PAGE, location = vc_registry)]
    fun get_vcs_paginated_rejects_zero_limit() {
        world();
        vc_registry::get_vcs_paginated(0, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_PAGE, location = vc_registry)]
    fun get_vcs_paginated_rejects_limit_above_200() {
        world();
        vc_registry::get_vcs_paginated(0, 201);
    }
}
