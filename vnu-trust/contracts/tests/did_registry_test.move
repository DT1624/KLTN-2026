// Dac ta vong doi DID. Moi test la mot luat; ten test = <ham>_<dieu kien>.
#[test_only]
module vnu::did_registry_test {
    use std::vector;
    use aptos_framework::event;
    use vnu::authority;
    use vnu::did_registry;
    use vnu::errors;
    use vnu::test_utils as t;

    // ================= register_did =================

    #[test]
    fun register_did_creates_active_record_and_emits_event() {
        t::setup();
        let a = t::holder1_addr();
        let s = t::account(a);
        did_registry::register_did(&s, t::did_for(a), t::cid(), t::hash(1));

        let r = did_registry::get_did_by_owner(a);
        let (id, owner, did, cid, hash, status, created, updated, version, suspended_by) = did_registry::record_fields(&r);
        assert!(id == 0 && owner == a && did == t::did_for(a), 0);
        assert!(cid == t::cid() && hash == t::hash(1), 1);
        assert!(status == t::did_active() && version == 1 && suspended_by == @0x0, 2);
        assert!(created == t::t0() && updated == t::t0(), 3);
        assert!(did_registry::total_dids() == 1 && did_registry::has_active_did(a), 4);
        assert!(event::was_event_emitted(&did_registry::did_registered_event(0, a, t::did_for(a), t::cid(), t::t0())), 5);

        let (d1, c1, h1, s1, v1) = did_registry::resolve_did(t::did_for(a));
        let (d2, c2, h2, s2, v2) = did_registry::resolve_did_by_owner(a);
        assert!(d1 == d2 && c1 == c2 && h1 == h2 && s1 == s2 && v1 == v2, 6);
        assert!(d1 == t::did_for(a) && s1 == t::did_active() && v1 == 1, 7);
        assert!(did_registry::get_did(t::did_for(a)) == r, 8);
    }

    #[test]
    fun register_did_assigns_increasing_ids() {
        t::setup();
        t::user(t::holder1_addr());
        t::user(t::holder2_addr());
        assert!(did_registry::did_id_of(t::holder1_addr()) == 0, 0);
        assert!(did_registry::did_id_of(t::holder2_addr()) == 1, 1);
        assert!(did_registry::total_dids() == 2, 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = did_registry)]
    fun register_did_rejects_hash_shorter_than_32_bytes() {
        t::setup();
        let a = t::holder1_addr();
        did_registry::register_did(&t::account(a), t::did_for(a), t::cid(), t::bytes(31, 0));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = did_registry)]
    fun register_did_rejects_hash_longer_than_32_bytes() {
        t::setup();
        let a = t::holder1_addr();
        did_registry::register_did(&t::account(a), t::did_for(a), t::cid(), t::bytes(33, 0));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = did_registry)]
    fun register_did_rejects_cid_shorter_than_10() {
        t::setup();
        let a = t::holder1_addr();
        did_registry::register_did(&t::account(a), t::did_for(a), t::bytes(9, 97), t::hash(1));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = did_registry)]
    fun register_did_rejects_cid_longer_than_128() {
        t::setup();
        let a = t::holder1_addr();
        did_registry::register_did(&t::account(a), t::did_for(a), t::bytes(129, 97), t::hash(1));
    }

    #[test]
    fun register_did_accepts_cid_length_bounds() {
        t::setup();
        let a = t::holder1_addr();
        let b = t::holder2_addr();
        did_registry::register_did(&t::account(a), t::did_for(a), t::bytes(10, 97), t::hash(1));
        did_registry::register_did(&t::account(b), t::did_for(b), t::bytes(128, 97), t::hash(1));
        assert!(did_registry::has_active_did(a) && did_registry::has_active_did(b), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_BOUND_TO_OWNER, location = did_registry)]
    fun register_did_rejects_other_did_method() {
        t::setup();
        let a = t::holder1_addr();
        // Cung do dai voi "did:vnu:" de cham dung phep so tien to, khong bi
        // phep kiem do dai chan truoc.
        did_registry::register_did(&t::account(a), t::did_with(b"did:abc:", a), t::cid(), t::hash(1));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_BOUND_TO_OWNER, location = did_registry)]
    fun register_did_rejects_string_too_short_to_hold_prefix_and_address() {
        t::setup();
        let a = t::holder1_addr();
        did_registry::register_did(&t::account(a), t::did_with(b"did:x:", a), t::cid(), t::hash(1));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_BOUND_TO_OWNER, location = did_registry)]
    fun register_did_rejects_did_of_another_address() {
        t::setup();
        let s = t::account(t::holder1_addr());
        did_registry::register_did(&s, t::did_for(t::holder2_addr()), t::cid(), t::hash(1));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_BOUND_TO_OWNER, location = did_registry)]
    fun register_did_rejects_uppercase_address_suffix() {
        t::setup();
        let a = @0xABCD;
        let did = b"did:vnu:0x000000000000000000000000000000000000000000000000000000000000ABCD";
        did_registry::register_did(&t::account(a), did, t::cid(), t::hash(1));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_BOUND_TO_OWNER, location = did_registry)]
    fun register_did_rejects_empty_string() {
        t::setup();
        did_registry::register_did(&t::account(t::holder1_addr()), b"", t::cid(), t::hash(1));
    }

    #[test]
    fun register_did_accepts_minimal_and_128_byte_strings() {
        t::setup();
        let a = t::holder1_addr();
        let b = t::holder2_addr();
        // "did:vnu:" + dia chi = 8 + 66 = 74 byte
        did_registry::register_did(&t::account(a), t::did_with(b"did:vnu:", a), t::cid(), t::hash(1));
        // phan giua 54 byte -> tong 128
        let prefix = b"did:vnu:";
        vector::append(&mut prefix, t::bytes(54, 97));
        let long = t::did_with(prefix, b);
        assert!(vector::length(&long) == 128, 0);
        did_registry::register_did(&t::account(b), long, t::cid(), t::hash(1));
        assert!(did_registry::has_active_did(a) && did_registry::has_active_did(b), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_BOUND_TO_OWNER, location = did_registry)]
    fun register_did_rejects_string_longer_than_128() {
        t::setup();
        let a = t::holder1_addr();
        let prefix = b"did:vnu:";
        vector::append(&mut prefix, t::bytes(55, 97));
        did_registry::register_did(&t::account(a), t::did_with(prefix, a), t::cid(), t::hash(1));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_HAS_DID, location = did_registry)]
    fun register_did_rejects_second_did_while_active() {
        t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        did_registry::register_did(&s, t::did_with(b"did:vnu:v2:", a), t::cid(), t::hash(1));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_HAS_DID, location = did_registry)]
    fun register_did_rejects_new_did_while_suspended() {
        t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        did_registry::suspend_own_did(&s);
        did_registry::register_did(&s, t::did_with(b"did:vnu:v2:", a), t::cid(), t::hash(1));
    }

    #[test]
    fun register_did_after_revocation_creates_new_version_and_keeps_old_record() {
        let root = t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        authority::admin_revoke_did(&root, a, b"fraud");

        let new_did = t::did_with(b"did:vnu:v2:", a);
        did_registry::register_did(&s, new_did, t::cid_v2(), t::hash(2));

        assert!(did_registry::did_id_of(a) == 1 && did_registry::version_of(a) == 2, 0);
        assert!(did_registry::status_of(a) == t::did_active(), 1);
        let (_, _, _, old_status, old_version) = did_registry::resolve_did(t::did_for(a));
        assert!(old_status == t::did_revoked() && old_version == 1, 2);
        let (cur, _, _, _, _) = did_registry::resolve_did_by_owner(a);
        assert!(cur == new_did, 3);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_ALREADY_REGISTERED, location = did_registry)]
    fun register_did_rejects_reuse_of_revoked_did_string() {
        let root = t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        authority::admin_revoke_did(&root, a, b"fraud");
        did_registry::register_did(&s, t::did_for(a), t::cid(), t::hash(1));
    }

    // ================= update_did_document =================

    #[test]
    fun update_did_document_replaces_document_and_bumps_version() {
        t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        t::advance(50);
        did_registry::update_did_document(&s, t::cid_v2(), t::hash(2), 1);

        let (_, _, _, cid, hash, status, created, updated, version, _) =
            did_registry::record_fields(&did_registry::get_did_by_owner(a));
        assert!(cid == t::cid_v2() && hash == t::hash(2), 0);
        assert!(version == 2 && status == t::did_active(), 1);
        assert!(created == t::t0() && updated == t::t0() + 50, 2);
        assert!(event::was_event_emitted(&did_registry::did_document_updated_event(0, a, t::cid_v2(), 2, t::t0() + 50)), 3);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_STABLE_DID_VERSION, location = did_registry)]
    fun update_did_document_rejects_stale_version() {
        t::setup();
        let s = t::user(t::holder1_addr());
        did_registry::update_did_document(&s, t::cid_v2(), t::hash(2), 1);
        did_registry::update_did_document(&s, t::cid(), t::hash(3), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun update_did_document_requires_did() {
        t::setup();
        did_registry::update_did_document(&t::account(t::holder1_addr()), t::cid(), t::hash(2), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun update_did_document_rejects_suspended_did() {
        t::setup();
        let s = t::user(t::holder1_addr());
        did_registry::suspend_own_did(&s);
        did_registry::update_did_document(&s, t::cid_v2(), t::hash(2), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = did_registry)]
    fun update_did_document_rejects_bad_hash() {
        t::setup();
        let s = t::user(t::holder1_addr());
        did_registry::update_did_document(&s, t::cid_v2(), t::bytes(5, 0), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = did_registry)]
    fun update_did_document_rejects_bad_cid() {
        t::setup();
        let s = t::user(t::holder1_addr());
        did_registry::update_did_document(&s, b"", t::hash(2), 1);
    }

    // ================= suspend_own_did / deactivate_did =================

    #[test]
    fun suspend_own_did_marks_owner_as_locker() {
        t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        did_registry::suspend_own_did(&s);
        assert!(did_registry::status_of(a) == t::did_suspended(), 0);
        assert!(did_registry::suspended_by_of(a) == a, 1);
        assert!(!did_registry::has_active_did(a), 2);
        assert!(event::was_event_emitted(&did_registry::did_status_changed_event(0, a, a, t::did_suspended(), b"Other", t::t0())), 3);
    }

    #[test]
    fun deactivate_did_is_alias_of_suspend_own_did() {
        t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        did_registry::deactivate_did(&s);
        assert!(did_registry::status_of(a) == t::did_suspended(), 0);
        assert!(did_registry::suspended_by_of(a) == a, 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun suspend_own_did_twice_fails() {
        t::setup();
        let s = t::user(t::holder1_addr());
        did_registry::suspend_own_did(&s);
        did_registry::suspend_own_did(&s);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun suspend_own_did_cannot_override_admin_lock() {
        let root = t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        authority::admin_suspend_did(&root, a, b"x");
        did_registry::suspend_own_did(&s);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun suspend_own_did_requires_did() {
        t::setup();
        did_registry::suspend_own_did(&t::account(t::holder1_addr()));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_ALREADY_REVOKED, location = did_registry)]
    fun suspend_own_did_rejects_revoked_did() {
        let root = t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        authority::admin_revoke_did(&root, a, b"x");
        did_registry::suspend_own_did(&s);
    }

    // ================= reactivate_own_did =================

    #[test]
    fun reactivate_own_did_restores_self_locked_did() {
        t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        did_registry::suspend_own_did(&s);
        did_registry::reactivate_own_did(&s);
        assert!(did_registry::status_of(a) == t::did_active(), 0);
        assert!(did_registry::suspended_by_of(a) == @0x0, 1);
        assert!(event::was_event_emitted(&did_registry::did_status_changed_event(0, a, a, t::did_active(), b"Other", t::t0())), 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_SUSPENDED, location = did_registry)]
    fun reactivate_own_did_rejects_active_did() {
        t::setup();
        did_registry::reactivate_own_did(&t::user(t::holder1_addr()));
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_SELF_SUSPENDED, location = did_registry)]
    fun reactivate_own_did_cannot_undo_admin_lock() {
        let root = t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        authority::admin_suspend_did(&root, a, b"x");
        did_registry::reactivate_own_did(&s);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun reactivate_own_did_requires_did() {
        t::setup();
        did_registry::reactivate_own_did(&t::account(t::holder1_addr()));
    }

    // ================= Kiem duyet cua admin (qua authority) =================

    #[test]
    fun admin_suspend_did_records_admin_as_locker() {
        let root = t::setup();
        let admin = t::admin(&root, t::admin1_addr());
        let a = t::holder1_addr();
        t::user(a);
        authority::admin_suspend_did(&admin, a, b"policy");
        assert!(did_registry::status_of(a) == t::did_suspended(), 0);
        assert!(did_registry::suspended_by_of(a) == t::admin1_addr(), 1);
        let id = did_registry::did_id_of(a);
        assert!(event::was_event_emitted(&did_registry::did_status_changed_event(id, a, t::admin1_addr(), t::did_suspended(), b"policy", t::t0())), 2);
    }

    #[test]
    fun admin_suspend_did_takes_over_owner_lock() {
        let root = t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        did_registry::suspend_own_did(&s);
        authority::admin_suspend_did(&root, a, b"investigation");
        assert!(did_registry::status_of(a) == t::did_suspended(), 0);
        assert!(did_registry::suspended_by_of(a) == t::root_addr(), 1);
        // tu nay chi admin mo duoc
        authority::admin_reactivate_did(&root, a, b"cleared");
        assert!(did_registry::status_of(a) == t::did_active(), 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_NOT_SELF_SUSPENDED, location = did_registry)]
    fun owner_cannot_reopen_after_admin_takeover() {
        let root = t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        did_registry::suspend_own_did(&s);
        authority::admin_suspend_did(&root, a, b"investigation");
        did_registry::reactivate_own_did(&s);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun admin_suspend_did_twice_fails() {
        let root = t::setup();
        let a = t::holder1_addr();
        t::user(a);
        authority::admin_suspend_did(&root, a, b"x");
        authority::admin_suspend_did(&root, a, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_LOCKED, location = did_registry)]
    fun admin_reactivate_did_cannot_open_owner_lock() {
        let root = t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        did_registry::suspend_own_did(&s);
        authority::admin_reactivate_did(&root, a, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_SUSPENDED, location = did_registry)]
    fun admin_reactivate_did_rejects_active_did() {
        let root = t::setup();
        let a = t::holder1_addr();
        t::user(a);
        authority::admin_reactivate_did(&root, a, b"x");
    }

    #[test]
    fun admin_revoke_did_works_from_active_and_suspended() {
        let root = t::setup();
        let a = t::holder1_addr();
        let b = t::holder2_addr();
        t::user(a);
        let sb = t::user(b);
        did_registry::suspend_own_did(&sb);
        authority::admin_revoke_did(&root, a, b"fraud");
        authority::admin_revoke_did(&root, b, b"fraud");
        assert!(did_registry::status_of(a) == t::did_revoked(), 0);
        assert!(did_registry::status_of(b) == t::did_revoked(), 1);
        assert!(did_registry::suspended_by_of(b) == @0x0, 2);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_ALREADY_REVOKED, location = did_registry)]
    fun admin_revoke_did_twice_fails() {
        let root = t::setup();
        let a = t::holder1_addr();
        t::user(a);
        authority::admin_revoke_did(&root, a, b"x");
        authority::admin_revoke_did(&root, a, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_ALREADY_REVOKED, location = did_registry)]
    fun admin_suspend_did_rejects_revoked_did() {
        let root = t::setup();
        let a = t::holder1_addr();
        t::user(a);
        authority::admin_revoke_did(&root, a, b"x");
        authority::admin_suspend_did(&root, a, b"x");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun admin_moderation_requires_target_did() {
        let root = t::setup();
        authority::admin_suspend_did(&root, t::holder1_addr(), b"x");
    }

    // ================= Views =================

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_FOUND, location = did_registry)]
    fun resolve_did_unknown_string_fails() {
        t::setup();
        did_registry::resolve_did(b"did:vnu:nobody");
    }

    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun resolve_did_by_owner_unknown_fails() {
        t::setup();
        did_registry::resolve_did_by_owner(t::holder1_addr());
    }

    #[test]
    fun has_active_did_is_false_for_unknown_suspended_and_revoked() {
        let root = t::setup();
        assert!(!did_registry::has_active_did(t::holder1_addr()), 0);
        let s = t::user(t::holder1_addr());
        did_registry::suspend_own_did(&s);
        assert!(!did_registry::has_active_did(t::holder1_addr()), 1);
        t::user(t::holder2_addr());
        authority::admin_revoke_did(&root, t::holder2_addr(), b"x");
        assert!(!did_registry::has_active_did(t::holder2_addr()), 2);
    }

    #[test]
    fun list_views_include_every_did_string_and_owner() {
        let root = t::setup();
        let a = t::holder1_addr();
        let s = t::user(a);
        t::user(t::holder2_addr());
        authority::admin_revoke_did(&root, a, b"x");
        did_registry::register_did(&s, t::did_with(b"did:vnu:v2:", a), t::cid(), t::hash(1));

        let dids = did_registry::get_dids();
        assert!(vector::length(&dids) == 3, 0);
        assert!(vector::contains(&dids, &t::did_for(a)) && vector::contains(&dids, &t::did_with(b"did:vnu:v2:", a)), 1);
        let owners = did_registry::get_owners();
        assert!(vector::length(&owners) == 2, 2);
    }

    #[test]
    fun list_views_allow_exactly_500_entries() {
        t::setup();
        t::many_users(500);
        assert!(vector::length(&did_registry::get_dids()) == 500, 0);
        assert!(vector::length(&did_registry::get_owners()) == 500, 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_RESULT_TOO_LARGE, location = did_registry)]
    fun get_dids_refuses_more_than_500_entries() {
        t::setup();
        t::many_users(501);
        did_registry::get_dids();
    }

    #[test]
    #[expected_failure(abort_code = errors::E_RESULT_TOO_LARGE, location = did_registry)]
    fun get_owners_refuses_more_than_500_entries() {
        t::setup();
        t::many_users(501);
        did_registry::get_owners();
    }

    #[test]
    fun get_dids_paginated_returns_ordered_bounded_pages() {
        t::setup();
        t::user(@0x101);
        t::user(@0x102);
        t::user(@0x103);
        let page = did_registry::get_dids_paginated(1, 5);
        assert!(vector::length(&page) == 2, 0);
        let (id0, owner0, _, _, _, _, _, _, _, _) = did_registry::record_fields(vector::borrow(&page, 0));
        let (id1, owner1, _, _, _, _, _, _, _, _) = did_registry::record_fields(vector::borrow(&page, 1));
        assert!(id0 == 1 && owner0 == @0x102 && id1 == 2 && owner1 == @0x103, 1);
        assert!(vector::length(&did_registry::get_dids_paginated(0, 2)) == 2, 2);
        assert!(vector::is_empty(&did_registry::get_dids_paginated(3, 5)), 3);
        assert!(vector::is_empty(&did_registry::get_dids_paginated(18446744073709551615, 200)), 4);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_PAGE, location = did_registry)]
    fun get_dids_paginated_rejects_zero_limit() {
        t::setup();
        did_registry::get_dids_paginated(0, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_PAGE, location = did_registry)]
    fun get_dids_paginated_rejects_limit_above_200() {
        t::setup();
        did_registry::get_dids_paginated(0, 201);
    }
}
