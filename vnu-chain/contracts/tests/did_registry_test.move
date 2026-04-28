#[test_only]
module governance::did_registry_test {

    use aptos_framework::account;
    use aptos_framework::timestamp;
    use governance::errors;
    use governance::did_registry;
    use governance::test_utils;

    // ========== SETUP TEST = ==========

    // Setup: initialize DID module test environment
    #[test]
    fun setup_test_success() {
        setup_test();
    }

    // ========== REGISTER DID ==========

    // Fail: `register_did` aborts when document hash has wrong length
    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = did_registry)]
    fun test_register_did_fails_if_hash_short() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let short_document_hash = b"short";
        did_registry::register_did(h1, test_utils::did_for(owner), test_utils::mock_cid(), short_document_hash);
    }

    // Fail: `register_did` aborts when owner already has a DID
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_HAS_DID, location = did_registry)]
    fun test_register_did_fails_if_duplicate_owner() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        did_registry::register_did(h1, test_utils::did_for(owner), test_utils::mock_cid(), test_utils::mock_hash());
        did_registry::register_did(h1, test_utils::did_for(test_utils::random1_addr()), test_utils::mock_cid_v2(), test_utils::mock_hash_v2());
    }

    // Fail: `register_did` aborts when DID string already registered
    #[test]
    #[expected_failure(abort_code = errors::E_DID_ALREADY_REGISTERED, location = did_registry)]
    fun test_register_did_fails_if_duplicate_did() {
        setup_test();
        let owner1 = test_utils::holder1_addr();
        let owner2 = test_utils::holder2_addr();
        let h1 = &account::create_account_for_test(owner1);
        let h2 = &account::create_account_for_test(owner2);
        let same_did = test_utils::did_for(owner1);
        did_registry::register_did(h1, same_did, test_utils::mock_cid(), test_utils::mock_hash());
        did_registry::register_did(h2, same_did, test_utils::mock_cid_v2(), test_utils::mock_hash_v2());
    }

    // Success: `register_did` stores DID and document and emits event
    #[test]
    fun test_register_did_success() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let did = test_utils::did_for(owner);
        let cid = test_utils::mock_cid();
        let hash = test_utils::mock_hash();
        let now = timestamp::now_seconds();

        // Pre-state
        assert!(!did_registry::has_active_did(owner), 1);
        assert!(did_registry::total_dids() == 0, 2);

        did_registry::register_did(h1, did, cid, hash);
        did_registry::assert_did_registered_event_emitted(0, owner, did, cid, now);

        // Post-state
        assert!(did_registry::has_active_did(owner), 3);
        assert!(did_registry::total_dids() == 1, 4);

        let (did_str, doc_cid, doc_hash, status, version) = did_registry::resolve_did_by_owner(owner);
        assert!(did_str == did, 5);
        assert!(doc_cid == cid, 6);
        assert!(doc_hash == hash, 7);
        assert!(status == test_utils::did_status_active(), 8);
        assert!(version == 1, 9);

        let (record_id, record_owner, record_did, record_cid, record_hash, record_status, created_at, updated_at, record_version) = did_registry::get_did_details_by_owner(owner);
        assert!(record_id == 0, 10);
        assert!(record_owner == owner, 11);
        assert!(record_did == did, 12);
        assert!(record_cid == cid, 13);
        assert!(record_hash == hash, 14);
        assert!(record_status == test_utils::did_status_active(), 15);
        assert!(created_at == now, 16);
        assert!(updated_at == now, 17);
        assert!(record_version == 1, 18);
    }

    // ========== Update DID Document ==========

    // Fail: `update_did_document` aborts when owner does not exist
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun test_update_did_fails_if_owner_not_exists() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let new_cid = test_utils::mock_cid();
        let new_hash = test_utils::mock_hash();
        did_registry::update_did_document(h1, new_cid, new_hash, 1);
    }

    // Fail: `update_did_document` aborts when DID is not active
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun test_update_did_fails_if_did_not_active() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let did = test_utils::did_for(owner);
        let new_cid = test_utils::mock_cid();
        let new_hash = test_utils::mock_hash();

        did_registry::register_did(h1, did, new_cid, new_hash);
        did_registry::deactivate_did(h1);
        did_registry::update_did_document(h1, new_cid, new_hash, 1);
    }

    // Fail: `update_did_document` aborts on version mismatch (stable version)
    #[test]
    #[expected_failure(abort_code = errors::E_STABLE_DID_VERSION, location = did_registry)]
    fun test_update_did_fails_if_version_mismatch() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let did = test_utils::did_for(owner);
        let new_cid = test_utils::mock_cid();
        let new_hash = test_utils::mock_hash();

        did_registry::register_did(h1, did, new_cid, new_hash);
        did_registry::update_did_document(h1, new_cid, new_hash, 2);
    }

    // Fail: `update_did_document` aborts when provided hash length invalid
    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = did_registry)]
    fun test_update_did_fails_if_hash_short() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let did = test_utils::did_for(owner);
        let new_cid = test_utils::mock_cid();
        let new_hash = test_utils::mock_hash();

        did_registry::register_did(h1, did, new_cid, new_hash);
        let short_hash = b"short";
        did_registry::update_did_document(h1, new_cid, short_hash, 1);
    }

    // Success: owner can update DID document and event/state reflect changes
    #[test]
    fun test_update_did_document_success() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let did = test_utils::did_for(owner);
        let cid = test_utils::mock_cid();
        let hash = test_utils::mock_hash();
        let new_cid = test_utils::mock_cid_v2();
        let new_hash = test_utils::mock_hash_v2();
        let now = timestamp::now_seconds();

        did_registry::register_did(h1, did, cid, hash);
        let (did_str, doc_cid, doc_hash, status, version) = did_registry::resolve_did_by_owner(owner);
        assert!(did_str == did, 1);
        assert!(doc_cid == cid, 2);
        assert!(doc_hash == hash, 3);
        assert!(status == test_utils::did_status_active(), 4);
        assert!(version == 1, 5);

        did_registry::update_did_document(h1, new_cid, new_hash, 1);
        did_registry::assert_did_document_updated_event_emitted(0, owner, new_cid, 2, now);
        let (did_str, doc_cid, doc_hash, status, version) = did_registry::resolve_did_by_owner(owner);
        assert!(did_str == did, 6);
        assert!(doc_cid == new_cid, 7);
        assert!(doc_hash == new_hash, 8);
        assert!(status == test_utils::did_status_active(), 9);
        assert!(version == 2, 10);

        let (record_id, record_owner, record_did, record_cid, record_hash, record_status, created_at, updated_at, record_version) = did_registry::get_did_details_by_owner(owner);
        assert!(record_id == 0, 11);
        assert!(record_owner == owner, 12);
        assert!(record_did == did, 13);
        assert!(record_cid == new_cid, 14);
        assert!(record_hash == new_hash, 15);
        assert!(record_status == test_utils::did_status_active(), 16);
        assert!(created_at == now, 17);
        assert!(updated_at == now, 18);
        assert!(record_version == 2, 19);
    }

    // ========== Deactivate DID (owner only) ==========

    // Fail: `deactivate_did` aborts when owner not exists
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun test_deactivate_did_fails_if_owner_not_exists() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);

        did_registry::deactivate_did(h1);
    }

    // Fail: `deactivate_did` aborts when DID already suspended
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun test_deactivate_did_fails_if_did_is_suspending() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let did = test_utils::did_for(owner);
        let cid = test_utils::mock_cid();
        let hash = test_utils::mock_hash();

        did_registry::register_did(h1, did, cid, hash);
        did_registry::deactivate_did(h1);
        did_registry::deactivate_did(h1);
    }

    // Success: owner can deactivate DID and event/state updated accordingly
    #[test]
    fun test_deactivate_did_success() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let did = test_utils::did_for(owner);
        let cid = test_utils::mock_cid();
        let hash = test_utils::mock_hash();
        let now = timestamp::now_seconds();
        let reason = test_utils::reason_other();

        did_registry::register_did(h1, did, cid, hash);
        assert!(did_registry::has_active_did(owner), 1);
        did_registry::deactivate_did(h1);
        did_registry::assert_did_status_changed_event_emitted(0, owner, owner, test_utils::did_status_suspended(), reason, now);
        assert!(!did_registry::has_active_did(owner), 2);

        let (_, _, _, status, _) = did_registry::resolve_did_by_owner(owner);
        assert!(status == test_utils::did_status_suspended(), 43);

        let (record_id, record_owner, record_did, record_cid, record_hash, record_status, created_at, updated_at, record_version) = did_registry::get_did_details_by_owner(owner);
        assert!(record_id == 0, 3);
        assert!(record_owner == owner, 4);
        assert!(record_did == did, 5);
        assert!(record_cid == cid, 6);
        assert!(record_hash == hash, 7);
        assert!(record_status == test_utils::did_status_suspended(), 8);
        assert!(created_at == now, 9);
        assert!(updated_at == now, 10);
        assert!(record_version == 1, 11);
    }

    // ========== View DID ==========

    // Fail: `resolve_did` aborts when DID not registered
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_FOUND, location = did_registry)]
    fun test_resolve_did_fails_if_did_not_exists() {
        setup_test();
        let did = test_utils::did_for(test_utils::random1_addr());
        did_registry::resolve_did(did);
    }

    // Fail: `resolve_did_by_owner` aborts when owner not found
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun test_resolve_did_by_owner_fails_if_owner_not_exists() {
        setup_test();
        let owner = test_utils::holder1_addr();
        did_registry::resolve_did_by_owner(owner);
    }

    // Success: resolve_did and resolve_did_by_owner return correct active info
    #[test]
    fun test_resolve_did_active_success() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let did = test_utils::did_for(owner);
        let cid = test_utils::mock_cid();
        let hash = test_utils::mock_hash();

        did_registry::register_did(h1, did, cid, hash);

        let (did_str_1, doc_cid_1, doc_hash_1, status_1, version_1) = did_registry::resolve_did(did);
        assert!(did_str_1 == did, 1);
        assert!(doc_cid_1 == cid, 2);
        assert!(doc_hash_1 == hash, 3);
        assert!(status_1 == test_utils::did_status_active(), 4);
        assert!(version_1 == 1, 5);

        let (did_str_2, doc_cid_2, doc_hash_2, status_2, version_2) = did_registry::resolve_did_by_owner(owner);
        assert!(did_str_2 == did, 6);
        assert!(doc_cid_2 == cid, 7);
        assert!(doc_hash_2 == hash, 8);
        assert!(status_2 == test_utils::did_status_active(), 9);
        assert!(version_2 == 1, 10);
    }

    // Success: resolve_did returns suspended status after deactivation
    #[test]
    fun test_resolve_did_deactivated_success() {
        setup_test();
        let owner = test_utils::holder1_addr();
        let h1 = &account::create_account_for_test(owner);
        let did = test_utils::did_for(owner);
        let cid = test_utils::mock_cid();
        let hash = test_utils::mock_hash();

        did_registry::register_did(h1, did, cid, hash);
        did_registry::deactivate_did(h1);

        let (did_str_1, doc_cid_1, doc_hash_1, status_1, version_1) = did_registry::resolve_did(did);
        assert!(did_str_1 == did, 1);
        assert!(doc_cid_1 == cid, 2);
        assert!(doc_hash_1 == hash, 3);
        assert!(status_1 == test_utils::did_status_suspended(), 4);
        assert!(version_1 == 1, 5);
    }

    // ========== MULTIPLE ACTORS ==========

    // Success: multiple accounts can register DIDs independently
    #[test]
    fun test_multiple_actors_register_did_success() {
        setup_test();

        let h1 = &account::create_account_for_test(test_utils::holder1_addr());
        let h2 = &account::create_account_for_test(test_utils::holder2_addr());
        let i1 = &account::create_account_for_test(test_utils::issuer1_addr());

        did_registry::register_did(h1, test_utils::did_for(test_utils::holder1_addr()), test_utils::mock_cid(), test_utils::mock_hash());
        did_registry::register_did(h2, test_utils::did_for(test_utils::holder2_addr()), test_utils::mock_cid(), test_utils::mock_hash());
        did_registry::register_did(i1, test_utils::did_for(test_utils::issuer1_addr()), test_utils::mock_cid(), test_utils::mock_hash());

        assert!(did_registry::has_active_did(test_utils::holder1_addr()), 1);
        assert!(did_registry::has_active_did(test_utils::holder2_addr()), 2);
        assert!(did_registry::has_active_did(test_utils::issuer1_addr()), 3);
        assert!(did_registry::total_dids() == 3, 4);

        did_registry::deactivate_did(h2);
        assert!(did_registry::has_active_did(test_utils::holder1_addr()), 5);
        assert!(!did_registry::has_active_did(test_utils::holder2_addr()), 6);
        assert!(did_registry::has_active_did(test_utils::issuer1_addr()), 7);
    }

    // ========== Helpers ==========

    // Helper: initialize chain state for DID tests
    fun setup_test() {
        let aptos_framework = &account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(aptos_framework);
        test_utils::fast_forward_by(test_utils::initial_time_seconds());

        let root = &account::create_account_for_test(test_utils::root_addr());
        did_registry::initialize_for_test(root);
    }
}
