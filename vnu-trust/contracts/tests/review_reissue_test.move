// Dac ta cho ban nang cap 13/11/2026 (C2, C3):
//   C2 - admin / issuer cha xem xet va xu ly VC theo lo;
//   C3 - cap lai VC co lien ket cu <-> moi (reissue_vc, admin_link_replacement).
// C1 (DID thu hoi la vinh vien) nam o did_registry_test va audit_findings_test.
#[test_only]
module vnu::review_reissue_test {
    use std::vector;
    use aptos_framework::event;
    use vnu::authority;
    use vnu::did_registry;
    use vnu::errors;
    use vnu::vc_registry;
    use vnu::test_utils as t;

    /// root, admin1, issuer1 (cu nhan + thac si, vinh vien), holder1, holder2.
    fun world(): (signer, signer, signer) {
        let root = t::setup();
        let a = t::admin(&root, t::admin1_addr());
        let i = t::issuer(&root, t::issuer1_addr(), t::bachelor() | t::master(), 0);
        t::user(t::holder1_addr());
        t::user(t::holder2_addr());
        (root, a, i)
    }

    /// Nhu world, them issuer1 la issuer UY QUYEN va issuer2 la sub-issuer cua no.
    fun family(): (signer, signer, signer, signer) {
        let root = t::setup();
        let a = t::admin(&root, t::admin1_addr());
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor() | t::master(), 0);
        let sub = t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), 0);
        t::user(t::holder1_addr());
        t::user(t::holder2_addr());
        (root, a, d, sub)
    }

    fun init_links() {
        vc_registry::init_replacement_for_test(&t::signer_of(t::deployer_addr()));
    }

    fun status(id: u64): u8 { vc_registry::get_vc_status(id) }

    fun reason(id: u64): vector<u8> {
        let (_, _, _, _, _, _, _, _, _, _, _, r) = vc_registry::record_fields(&vc_registry::stored_record(id));
        r
    }

    fun three(i: &signer): (u64, u64, u64) {
        (t::issue(i, t::holder1_addr(), t::bachelor(), 1, 0),
         t::issue(i, t::holder1_addr(), t::bachelor(), 2, 0),
         t::issue(i, t::holder2_addr(), t::master(), 3, 0))
    }

    fun reissue(i: &signer, old: u64, holder: address, vc_type: u64, seed: u8): u64 {
        vc_registry::reissue_vc(i, old, holder, vc_type, t::hash(seed), t::cid_v2(), t::content_hash(seed), 0);
        vc_registry::total_vcs() - 1
    }

    // ================= C2: admin theo lo =================

    #[test]
    fun admin_revoke_vcs_revokes_every_item_with_events() {
        let (_root, a, i) = world();
        three(&i);
        vc_registry::admin_revoke_vcs(&a, vector[0, 1, 2], b"issuer fraud");

        assert!(status(0) == t::vc_revoked() && status(1) == t::vc_revoked() && status(2) == t::vc_revoked(), 0);
        assert!(reason(1) == b"issuer fraud", 1);
        let (li, _) = vc_registry::get_live_counts(t::issuer1_addr(), t::holder1_addr());
        assert!(li == 0, 2);
        assert!(event::was_event_emitted(&vc_registry::vc_batch_processed_event(
            t::vc_revoked(), vector[0, 1, 2], vector[], t::admin1_addr(), t::t0())), 3);
        assert!(event::was_event_emitted(&vc_registry::vc_status_changed_event(
            2, t::holder2_addr(), t::vc_revoked(), b"issuer fraud", t::admin1_addr(), t::t0())), 4);
    }

    #[test]
    fun admin_revoke_vcs_skips_already_revoked_and_keeps_its_reason() {
        let (_root, a, i) = world();
        three(&i);
        vc_registry::revoke_vc(&i, 1, b"typo");
        vc_registry::admin_revoke_vcs(&a, vector[0, 1, 2], b"review");

        assert!(reason(1) == b"typo" && reason(0) == b"review", 0);
        assert!(event::was_event_emitted(&vc_registry::vc_batch_processed_event(
            t::vc_revoked(), vector[0, 2], vector[1], t::admin1_addr(), t::t0())), 1);
    }

    #[test]
    fun admin_revoke_vcs_revokes_suspended_and_expired() {
        let (_root, a, i) = world();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 2, t::t0() + 10);
        vc_registry::suspend_vc(&i, 0, b"check");
        t::advance(20);
        assert!(status(1) == t::vc_expired(), 0);

        vc_registry::admin_revoke_vcs(&a, vector[0, 1], b"review");
        assert!(status(0) == t::vc_revoked() && status(1) == t::vc_revoked(), 1);
    }

    #[test]
    fun admin_suspend_vcs_skips_suspended_revoked_and_expired() {
        let (_root, a, i) = world();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 2, 0);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 3, 0);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 4, t::t0() + 10);
        vc_registry::suspend_vc(&i, 1, b"x");
        vc_registry::revoke_vc(&i, 2, b"x");
        t::advance(20);

        vc_registry::admin_suspend_vcs(&a, vector[0, 1, 2, 3], b"review");
        assert!(status(0) == t::vc_suspended() && status(1) == t::vc_suspended(), 0);
        assert!(status(2) == t::vc_revoked() && status(3) == t::vc_expired(), 1);
        assert!(reason(1) == b"x", 2);
        assert!(event::was_event_emitted(&vc_registry::vc_batch_processed_event(
            t::vc_suspended(), vector[0], vector[1, 2, 3], t::admin1_addr(), t::t0() + 20)), 3);
    }

    #[test]
    fun root_can_use_batch_review() {
        let (root, _a, i) = world();
        three(&i);
        vc_registry::admin_suspend_vcs(&root, vector[2], b"r");
        assert!(status(2) == t::vc_suspended(), 0);
    }

    // Kich ban chinh cua C2: thu hoi issuer KHONG lam VC mat hieu luc; cap tren
    // xem xet roi thu hoi sau.
    #[test]
    fun revoked_issuer_vcs_stay_valid_until_admin_reviews_them() {
        let (root, a, i) = world();
        three(&i);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"left");
        assert!(status(0) == t::vc_active() && vc_registry::verify_integrity(0, t::content_hash(1)), 0);

        vc_registry::admin_revoke_vcs(&a, vector[0, 2], b"review after issuer revoked");
        assert!(!vc_registry::verify_integrity(0, t::content_hash(1)), 1);
        assert!(vc_registry::verify_integrity(1, t::content_hash(2)), 2);
    }

    #[test]
    fun batch_accepts_exactly_100_items() {
        let (_root, a, i) = world();
        let ids = vector::empty<u64>();
        let n: u8 = 0;
        while (n < 100) {
            vector::push_back(&mut ids, t::issue(&i, t::holder1_addr(), t::bachelor(), n + 1, 0));
            n = n + 1;
        };
        vc_registry::admin_revoke_vcs(&a, ids, b"bulk");
        assert!(status(0) == t::vc_revoked() && status(99) == t::vc_revoked(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_BATCH, location = vc_registry)]
    fun batch_rejects_more_than_100_items() {
        let (_root, a, i) = world();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        let ids = vector::empty<u64>();
        let n = 0;
        while (n < 101) { vector::push_back(&mut ids, n); n = n + 1; };
        vc_registry::admin_revoke_vcs(&a, ids, b"bulk");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_BATCH, location = vc_registry)]
    fun batch_rejects_empty_list() {
        let (_root, a, _i) = world();
        vc_registry::admin_revoke_vcs(&a, vector[], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_BATCH, location = vc_registry)]
    fun batch_rejects_duplicate_ids() {
        let (_root, a, i) = world();
        three(&i);
        vc_registry::admin_revoke_vcs(&a, vector[0, 0], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_BATCH, location = vc_registry)]
    fun batch_rejects_unsorted_ids() {
        let (_root, a, i) = world();
        three(&i);
        vc_registry::admin_suspend_vcs(&a, vector[1, 0], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun batch_rejects_unknown_id() {
        let (_root, a, i) = world();
        three(&i);
        vc_registry::admin_revoke_vcs(&a, vector[0, 9], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun admin_batch_rejects_non_admin() {
        let (_root, _a, i) = world();
        three(&i);
        vc_registry::admin_revoke_vcs(&t::signer_of(t::holder1_addr()), vector[0], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun admin_batch_rejects_revoked_admin() {
        let (root, a, i) = world();
        three(&i);
        authority::revoke_admin(&root, t::admin1_addr(), b"x");
        vc_registry::admin_suspend_vcs(&a, vector[0], b"r");
    }

    // ================= C2: issuer cha theo lo =================

    #[test]
    fun delegator_revokes_vcs_of_own_sub_issuer() {
        let (_root, _a, d, sub) = family();
        t::issue(&sub, t::holder1_addr(), t::bachelor(), 1, 0);
        t::issue(&sub, t::holder2_addr(), t::bachelor(), 2, 0);
        vc_registry::delegator_revoke_vcs(&d, vector[0, 1], b"parent review");
        assert!(status(0) == t::vc_revoked() && status(1) == t::vc_revoked(), 0);
        assert!(event::was_event_emitted(&vc_registry::vc_status_changed_event(
            1, t::holder2_addr(), t::vc_revoked(), b"parent review", t::issuer1_addr(), t::t0())), 1);
    }

    #[test]
    fun delegator_suspends_vcs_of_own_sub_issuer_even_after_own_cap_expired() {
        let root = t::setup();
        let d = t::delegator(&root, t::issuer1_addr(), t::bachelor(), t::t0() + 100);
        let sub = t::sub_issuer(&d, t::issuer2_addr(), t::bachelor(), t::t0() + 100);
        t::user(t::holder1_addr());
        t::issue(&sub, t::holder1_addr(), t::bachelor(), 1, 0);
        t::advance(200);
        // Thu hoi / tam ngung de hon cap (quyet dinh #12): het han uy quyen van xem xet duoc.
        vc_registry::delegator_suspend_vcs(&d, vector[0], b"r");
        assert!(status(0) == t::vc_suspended(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_PARENT_ISSUER, location = vc_registry)]
    fun delegator_cannot_touch_own_vcs_through_parent_path() {
        let (_root, _a, d, _sub) = family();
        t::issue(&d, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::delegator_revoke_vcs(&d, vector[0], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_PARENT_ISSUER, location = vc_registry)]
    fun delegator_cannot_touch_vcs_of_another_family() {
        let (root, _a, d, sub) = family();
        let d2 = t::delegator(&root, t::issuer3_addr(), t::bachelor(), 0);
        t::issue(&sub, t::holder1_addr(), t::bachelor(), 1, 0);
        let _ = d;
        vc_registry::delegator_revoke_vcs(&d2, vector[0], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_PARENT_ISSUER, location = vc_registry)]
    fun delegator_batch_aborts_whole_batch_on_one_foreign_item() {
        let (_root, _a, d, sub) = family();
        t::issue(&sub, t::holder1_addr(), t::bachelor(), 1, 0);
        t::issue(&d, t::holder1_addr(), t::bachelor(), 2, 0);
        vc_registry::delegator_revoke_vcs(&d, vector[0, 1], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_PARENT_ISSUER, location = vc_registry)]
    fun stranger_gets_clear_error_not_generic_abort() {
        let (_root, _a, _d, sub) = family();
        t::issue(&sub, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::delegator_revoke_vcs(&t::signer_of(t::holder2_addr()), vector[0], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun suspended_delegator_cannot_review() {
        let (root, _a, d, sub) = family();
        t::issue(&sub, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"audit");
        vc_registry::delegator_revoke_vcs(&d, vector[0], b"r");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun delegator_with_suspended_did_cannot_review() {
        let (root, _a, d, sub) = family();
        t::issue(&sub, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::admin_suspend_did(&root, t::issuer1_addr(), b"x");
        vc_registry::delegator_suspend_vcs(&d, vector[0], b"r");
    }

    // Cha bi thu hoi roi duoc root cap lai (ban ghi moi, khong bit uy quyen):
    // lien ket voi sub cu da het hieu luc nen mat quyen xem xet.
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_PARENT_ISSUER, location = vc_registry)]
    fun regranted_parent_loses_review_rights_over_old_subs() {
        let (root, _a, d, sub) = family();
        t::issue(&sub, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"x");
        authority::approve_issuer(&root, t::issuer1_addr(), t::bachelor(), b"", b"", 0);
        assert!(authority::get_delegator(t::issuer2_addr()) == t::issuer1_addr(), 0);
        vc_registry::delegator_revoke_vcs(&d, vector[0], b"r");
    }

    // ================= C3: khoi tao =================

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_INITIALIZED, location = vc_registry)]
    fun reissue_requires_replacement_registry() {
        let (_root, _a, i) = world();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        reissue(&i, 0, t::holder1_addr(), t::bachelor(), 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_INITIALIZED, location = vc_registry)]
    fun admin_link_requires_replacement_registry() {
        let (_root, a, i) = world();
        three(&i);
        vc_registry::admin_link_replacement(&a, 0, 1);
    }

    #[test]
    fun replacement_views_answer_false_before_init() {
        world();
        let (has, _) = vc_registry::get_replacement(0);
        let (is, _) = vc_registry::get_replaced(0);
        assert!(!has && !is, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_AUTHORIZED, location = vc_registry)]
    fun only_publisher_initializes_replacement_registry() {
        let (root, _a, _i) = world();
        vc_registry::init_replacement_registry(&root);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ALREADY_INITIALIZED, location = vc_registry)]
    fun replacement_registry_initializes_once() {
        world();
        init_links();
        init_links();
    }

    // ================= C3: reissue_vc =================

    #[test]
    fun reissue_same_holder_revokes_old_links_both_ways() {
        let (_root, _a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::advance(5);
        let new_id = reissue(&i, 0, t::holder1_addr(), t::bachelor(), 2);

        assert!(new_id == 1 && status(0) == t::vc_revoked() && status(1) == t::vc_active(), 0);
        assert!(reason(0) == b"replaced", 1);
        let (has, to) = vc_registry::get_replacement(0);
        let (is, from) = vc_registry::get_replaced(1);
        assert!(has && to == 1 && is && from == 0, 2);
        let (none, _) = vc_registry::get_replacement(1);
        assert!(!none, 3);
        assert!(!vc_registry::verify_integrity(0, t::content_hash(1)), 4);
        assert!(vc_registry::verify_integrity(1, t::content_hash(2)), 5);
        let (li, lh) = vc_registry::get_live_counts(t::issuer1_addr(), t::holder1_addr());
        assert!(li == 1 && lh == 1, 6);
        assert!(event::was_event_emitted(&vc_registry::vc_replaced_event(
            0, 1, t::holder1_addr(), t::holder1_addr(), t::issuer1_addr(), t::t0() + 5)), 7);
    }

    // Quy trinh cap lai khi holder mat khoa (P4.2): admin thu hoi DID cu, issuer
    // cap lai sang vi moi.
    #[test]
    fun reissue_to_new_wallet_after_old_did_revoked() {
        let (root, _a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::admin_revoke_did(&root, t::holder1_addr(), b"lost key");
        let new_id = reissue(&i, 0, t::holder2_addr(), t::bachelor(), 2);

        let (has, to) = vc_registry::get_replacement(0);
        assert!(has && to == new_id, 0);
        assert!(vc_registry::record_holder(&vc_registry::get_vc_by_id(new_id)) == t::holder2_addr(), 1);
        assert!(event::was_event_emitted(&vc_registry::vc_replaced_event(
            0, new_id, t::holder1_addr(), t::holder2_addr(), t::issuer1_addr(), t::t0())), 2);
    }

    #[test]
    fun reissue_to_new_wallet_after_old_did_suspended() {
        let (root, _a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::admin_suspend_did(&root, t::holder1_addr(), b"lost key");
        reissue(&i, 0, t::holder2_addr(), t::bachelor(), 2);
        assert!(status(0) == t::vc_revoked(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_HOLDER_STILL_ACTIVE, location = vc_registry)]
    fun reissue_cannot_move_vc_away_from_active_holder() {
        let (_root, _a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        reissue(&i, 0, t::holder2_addr(), t::bachelor(), 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun reissue_rejects_unknown_old_vc() {
        let (_root, _a, i) = world();
        init_links();
        reissue(&i, 7, t::holder1_addr(), t::bachelor(), 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun admin_link_rejects_unknown_replacement() {
        let (_root, a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::admin_link_replacement(&a, 0, 9);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_REISSUER, location = vc_registry)]
    fun unrelated_issuer_cannot_reissue() {
        let (root, _a, i) = world();
        init_links();
        let other = t::issuer(&root, t::issuer2_addr(), t::bachelor(), 0);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        reissue(&other, 0, t::holder1_addr(), t::bachelor(), 2);
    }

    #[test]
    fun parent_reissues_vc_of_revoked_sub_issuer() {
        let (_root, _a, d, sub) = family();
        init_links();
        t::issue(&sub, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::revoke_issuer(&d, t::issuer2_addr(), b"closed");
        let new_id = reissue(&d, 0, t::holder1_addr(), t::bachelor(), 2);
        assert!(vc_registry::record_issuer(&vc_registry::get_vc_by_id(new_id)) == t::issuer1_addr(), 0);
        assert!(status(0) == t::vc_revoked(), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_REISSUER, location = vc_registry)]
    fun sub_issuer_cannot_reissue_parent_vc() {
        let (_root, _a, d, sub) = family();
        init_links();
        t::issue(&d, t::holder1_addr(), t::bachelor(), 1, 0);
        reissue(&sub, 0, t::holder1_addr(), t::bachelor(), 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_REVOKED, location = vc_registry)]
    fun reissue_refuses_revoked_vc() {
        let (_root, a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::admin_revoke_vc(&a, 0, b"fraud");
        reissue(&i, 0, t::holder1_addr(), t::bachelor(), 2);
    }

    // Issuer khong duoc "lam mem" quyet dinh tam ngung cua admin bang cach cap lai.
    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_ACTIVE, location = vc_registry)]
    fun reissue_refuses_suspended_vc() {
        let (_root, a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::admin_suspend_vc(&a, 0, b"review");
        reissue(&i, 0, t::holder1_addr(), t::bachelor(), 2);
    }

    #[test]
    fun reissue_renews_expired_vc() {
        let (_root, _a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, t::t0() + 10);
        t::advance(20);
        let new_id = reissue(&i, 0, t::holder1_addr(), t::bachelor(), 2);
        assert!(status(0) == t::vc_revoked() && status(new_id) == t::vc_active(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_REPLACEMENT, location = vc_registry)]
    fun reissue_keeps_vc_type() {
        let (_root, _a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        reissue(&i, 0, t::holder1_addr(), t::master(), 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_EXISTS, location = vc_registry)]
    fun reissue_applies_issue_vc_rules() {
        let (_root, _a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        reissue(&i, 0, t::holder1_addr(), t::bachelor(), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun suspended_issuer_cannot_reissue() {
        let (root, _a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::suspend_issuer(&root, t::issuer1_addr(), b"audit");
        reissue(&i, 0, t::holder1_addr(), t::bachelor(), 2);
    }

    // ================= C3: admin_link_replacement =================

    // Issuer goc da bi thu hoi: issuer khac cap moi, admin noi lien ket.
    #[test]
    fun admin_links_replacement_issued_by_another_issuer() {
        let (root, a, i) = world();
        init_links();
        let other = t::issuer(&root, t::issuer2_addr(), t::bachelor(), 0);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::revoke_issuer(&root, t::issuer1_addr(), b"closed");
        authority::admin_revoke_did(&root, t::holder1_addr(), b"lost key");
        let new_id = t::issue(&other, t::holder2_addr(), t::bachelor(), 2, 0);

        vc_registry::admin_link_replacement(&a, 0, new_id);
        assert!(status(0) == t::vc_revoked() && reason(0) == b"replaced", 0);
        let (has, to) = vc_registry::get_replacement(0);
        assert!(has && to == new_id, 1);
        assert!(event::was_event_emitted(&vc_registry::vc_replaced_event(
            0, new_id, t::holder1_addr(), t::holder2_addr(), t::admin1_addr(), t::t0())), 2);
    }

    #[test]
    fun admin_link_keeps_reason_of_already_revoked_vc() {
        let (_root, a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        vc_registry::admin_revoke_vc(&a, 0, b"fraud");
        t::issue(&i, t::holder1_addr(), t::bachelor(), 2, 0);
        vc_registry::admin_link_replacement(&a, 0, 1);
        assert!(reason(0) == b"fraud", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_REPLACED, location = vc_registry)]
    fun vc_is_replaced_at_most_once() {
        let (_root, a, i) = world();
        init_links();
        three(&i);
        vc_registry::admin_link_replacement(&a, 0, 1);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 4, 0);
        vc_registry::admin_link_replacement(&a, 0, 3);
    }

    // Ba VC cung holder, cung loai; noi (0,2) roi (1,2). Moi rao khac deu dat
    // (2 > 1, VC 2 dang ACTIVE, cung loai, cung holder), nen CHI rao "VC moi da
    // thay cho VC khac" chan duoc. Ban dau test noi (0,1) roi (2,1) va PASS vi
    // rao "VC moi phai moi hon" chan truoc - kiem thu dot bien da bat duoc.
    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_REPLACEMENT, location = vc_registry)]
    fun replacement_replaces_at_most_one_vc() {
        let (_root, a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 2, 0);
        t::issue(&i, t::holder1_addr(), t::bachelor(), 3, 0);
        vc_registry::admin_link_replacement(&a, 0, 2);
        vc_registry::admin_link_replacement(&a, 1, 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_REPLACEMENT, location = vc_registry)]
    fun admin_link_requires_newer_vc() {
        let (_root, a, i) = world();
        init_links();
        three(&i);
        vc_registry::admin_link_replacement(&a, 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_REPLACEMENT, location = vc_registry)]
    fun admin_link_rejects_self_link() {
        let (_root, a, i) = world();
        init_links();
        three(&i);
        vc_registry::admin_link_replacement(&a, 1, 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_REPLACEMENT, location = vc_registry)]
    fun admin_link_requires_active_replacement() {
        let (_root, a, i) = world();
        init_links();
        three(&i);
        vc_registry::admin_suspend_vc(&a, 1, b"x");
        vc_registry::admin_link_replacement(&a, 0, 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_REPLACEMENT, location = vc_registry)]
    fun admin_link_requires_same_type() {
        let (_root, a, i) = world();
        init_links();
        three(&i);
        vc_registry::admin_link_replacement(&a, 0, 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_HOLDER_STILL_ACTIVE, location = vc_registry)]
    fun admin_link_cannot_move_vc_away_from_active_holder() {
        let (_root, a, i) = world();
        init_links();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        t::issue(&i, t::holder2_addr(), t::bachelor(), 2, 0);
        vc_registry::admin_link_replacement(&a, 0, 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun issuer_cannot_use_admin_link() {
        let (_root, _a, i) = world();
        init_links();
        three(&i);
        vc_registry::admin_link_replacement(&i, 0, 1);
    }

    #[test]
    fun c1_revoked_holder_keeps_vcs_until_reissued() {
        let (root, _a, i) = world();
        t::issue(&i, t::holder1_addr(), t::bachelor(), 1, 0);
        authority::admin_revoke_did(&root, t::holder1_addr(), b"lost key");
        // Thu hoi DID khong dong toi VC; viec xu ly VC la quyet dinh rieng.
        assert!(status(0) == t::vc_active() && !did_registry::has_active_did(t::holder1_addr()), 0);
    }
}
