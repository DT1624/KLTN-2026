#[test_only]
module governance::vc_registry_test {
    
    use aptos_framework::account;
    use aptos_framework::timestamp;
    use governance::authority;
    use governance::did_registry;
    use governance::errors;
    use governance::test_utils;
    use governance::vc_registry;

    // ========== SETUP ========== 
    // Setup: initialize test environment and verify total VCs is zero
    #[test]
    fun setup_test_success() {
        let _root = setup_test();
        assert!(vc_registry::total_vcs() == 0, 1);
    }

    // ========== ISSUE VC ========== 
    // Fail: `issuer_vc` aborts when caller is not an approved issuer
    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_FOUND, location = authority)]
    fun test_issue_vc_fails_if_caller_not_approved_issuer() {
        setup_test();
        let caller = &register_did_for(test_utils::random1_addr());
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        vc_registry::issuer_vc(
            caller,
            holder,
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when caller has no DID registered
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun test_issue_vc_fails_if_caller_has_no_did() {
        setup_test();
        let issuer = &account::create_account_for_test(test_utils::issuer1_addr());
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        vc_registry::issuer_vc(
            issuer,
            holder,
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when issuer's DID is not active
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun test_issue_vc_fails_if_issuer_did_not_active() {
        let root = setup_test();
        let issuer_signer = &register_did_for(test_utils::issuer1_addr());
        authority::approve_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
            0,
        );
        did_registry::deactivate_did(issuer_signer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when holder's DID is not active
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun test_issue_vc_fails_if_holder_did_not_active() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder_signer = &register_did_for(test_utils::holder1_addr());
        did_registry::deactivate_did(holder_signer);

        vc_registry::issuer_vc(
            issuer_signer,
            test_utils::holder1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when holder has no DID registered
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun test_issue_vc_fails_if_holder_did_missing() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );

        vc_registry::issuer_vc(
            issuer_signer,
            test_utils::holder1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when content CID has invalid length
    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = vc_registry)]
    fun test_issue_vc_fails_if_content_cid_short() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            b"short",
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when vc_id_hash has invalid length
    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = vc_registry)]
    fun test_issue_vc_fails_if_vc_id_hash_short() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_bachelor(),
            b"short",
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when vc_type is not allowed for issuer
    #[test]
    #[expected_failure(abort_code = errors::E_UNAUTHORIZED_VC_TYPE, location = authority)]
    fun test_issue_vc_fails_if_vc_type_not_allowed() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_master(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when issuer is suspended
    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun test_issue_vc_fails_if_issuer_is_suspended() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        authority::suspend_issuer(&root, test_utils::issuer1_addr(), test_utils::reason_policy());
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when issuer's cap/permission has expired
    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_CAP_EXPIRED, location = authority)]
    fun test_issue_vc_fails_if_issuer_cap_expired() {
        setup_test();
        let issuer_signer = &register_did_for(test_utils::issuer1_addr());
        let expired_at = timestamp::now_seconds() - 1;
        authority::approve_issuer(
            &account::create_account_for_test(test_utils::root_addr()),
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
            expired_at,
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }

    // Fail: `issuer_vc` aborts when a VC with the same id hash already exists
    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_EXISTS, location = vc_registry)]
    fun test_issue_vc_fails_if_duplicate_vc_id_hash() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid_v2(),
            test_utils::mock_hash(),
        );
    }

    // Success: `issuer_vc` creates a valid VC and views/events return correct values
    #[test]
    fun test_issue_vc_success() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        let vc_id_hash = test_utils::mock_hash();
        let content_cid = test_utils::mock_vc_cid();
        let content_hash = test_utils::mock_hash_v2();
        let now = timestamp::now_seconds();

        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_bachelor(),
            vc_id_hash,
            content_cid,
            content_hash,
        );
        vc_registry::assert_vc_issued_event_emitted(
            0,
            test_utils::issuer1_addr(),
            test_utils::did_for(test_utils::issuer1_addr()),
            holder,
            test_utils::did_for(holder),
            vc_id_hash,
            content_cid,
            test_utils::vc_type_bachelor(),
            now,
            0,
        );

        assert!(vc_registry::total_vcs() == 1, 1);
        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_active(), 2);
        assert!(vc_registry::get_vc_id_by_hash(vc_id_hash) == 0, 3);
        let (issuer_count, holder_count) = vc_registry::get_counts(test_utils::issuer1_addr(), holder);
        assert!(issuer_count == 1, 4);
        assert!(holder_count == 1, 5);
        assert!(vc_registry::verify_integrity(0, content_hash), 6);

        let (id, issuer_addr, holder_addr, returned_hash, returned_cid, returned_content_hash, vc_type, status, issued_at, expires_at, revoked_at, status_reason) = vc_registry::get_vc_details_by_id(0);
        assert!(id == 0, 7);
        assert!(issuer_addr == test_utils::issuer1_addr(), 8);
        assert!(holder_addr == holder, 9);
        assert!(returned_hash == vc_id_hash, 10);
        assert!(returned_cid == content_cid, 11);
        assert!(returned_content_hash == content_hash, 12);
        assert!(vc_type == test_utils::vc_type_bachelor(), 13);
        assert!(status == test_utils::vc_status_active(), 14);
        assert!(issued_at == now, 15);
        assert!(expires_at == 0, 16);
        assert!(revoked_at == 0, 17);
        assert!(status_reason == b"", 18);
    }

    // View: `get_vc_status` should abort when vc id not found
    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_ID, location = vc_registry)]
    fun test_get_vc_status_fails_if_vc_not_found() {
        setup_test();
        vc_registry::get_vc_status(999);
    }

    // View: `verify_integrity` returns false when vc id not found
    #[test]
    fun test_verify_integrity_returns_false_if_vc_not_found() {
        setup_test();
        let res = vc_registry::verify_integrity(999, test_utils::mock_hash());
        assert!(!res, 1);
    }

    // ========== ISSUER STATUS ========== 

    // Fail: `suspend_vc` aborts when caller is not the VC issuer
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_VC_ISSUER, location = vc_registry)]
    fun test_suspend_vc_fails_if_caller_is_not_vc_issuer() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        let other_issuer = &register_did_for(test_utils::issuer2_addr());

        vc_registry::suspend_vc(other_issuer, 0, test_utils::reason_policy());
    }

    // Fail: `suspend_vc` aborts when vc id not found
    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_ID, location = vc_registry)]
    fun test_suspend_vc_fails_if_vc_not_found() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );

        vc_registry::suspend_vc(issuer_signer, 999, test_utils::reason_policy());
    }

    // Fail: `suspend_vc` aborts when VC already suspended
    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_ACTIVE, location = vc_registry)]
    fun test_suspend_vc_fails_if_vc_already_suspended() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        vc_registry::suspend_vc(issuer_signer, 0, test_utils::reason_policy());
        vc_registry::suspend_vc(issuer_signer, 0, test_utils::reason_policy());
    }

    // Success: issuer can suspend VC and event/state are updated
    #[test]
    fun test_suspend_vc_success() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        let reason = test_utils::reason_policy();
        let now = timestamp::now_seconds();

        vc_registry::suspend_vc(issuer_signer, 0, reason);
        vc_registry::assert_vc_status_changed_event_emitted(0, holder, test_utils::vc_status_suspended(), reason, test_utils::issuer1_addr(), now);

        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_suspended(), 1);
        assert!(!vc_registry::verify_integrity(0, test_utils::mock_hash_v2()), 2);
        let (_, issuer_addr, holder_addr, _, _, _, _, status, _, _, revoked_at, status_reason) = vc_registry::get_vc_details_by_id(0);
        assert!(issuer_addr == test_utils::issuer1_addr(), 3);
        assert!(holder_addr == holder, 4);
        assert!(status == test_utils::vc_status_suspended(), 5);
        assert!(revoked_at == 0, 6);
        assert!(status_reason == reason, 7);
    }

    // Success: issuer can revoke VC and event/state are updated
    #[test]
    fun test_revoke_vc_success() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        let reason = test_utils::reason_fraud();
        let now = timestamp::now_seconds();

        vc_registry::revoke_vc(issuer_signer, 0, reason);
        vc_registry::assert_vc_status_changed_event_emitted(0, holder, test_utils::vc_status_revoked(), reason, test_utils::issuer1_addr(), now);

        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_revoked(), 1);
        assert!(!vc_registry::verify_integrity(0, test_utils::mock_hash_v2()), 2);
        let (_, issuer_addr, holder_addr, _, _, _, _, status, _, _, revoked_at, status_reason) = vc_registry::get_vc_details_by_id(0);
        assert!(issuer_addr == test_utils::issuer1_addr(), 3);
        assert!(holder_addr == holder, 4);
        assert!(status == test_utils::vc_status_revoked(), 5);
        assert!(revoked_at == now, 6);
        assert!(status_reason == reason, 7);
    }

    // ========== ADMIN STATUS ========== 

    // Fail: `admin_suspend_vc` aborts when caller is not an active admin
    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun test_admin_suspend_vc_fails_if_caller_is_not_admin() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        let caller = &register_did_for(test_utils::random1_addr());

        vc_registry::admin_suspend_vc(caller, 0, test_utils::reason_policy());
    }

    // Fail: `admin_suspend_vc` aborts when vc id not found
    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun test_admin_suspend_vc_fails_if_vc_not_found() {
        let root = setup_test();
        let admin = &prepare_admin(&root);

        vc_registry::admin_suspend_vc(admin, 999, test_utils::reason_policy());
    }

    // Fail: `admin_reinstate_vc` aborts when vc id not found
    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun test_admin_reinstate_vc_fails_if_vc_not_found() {
        let root = setup_test();
        let admin = &prepare_admin(&root);

        vc_registry::admin_reinstate_vc(admin, 999, test_utils::reason_technical());
    }

    // Fail: `admin_revoke_vc` aborts when vc id not found
    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_FOUND, location = vc_registry)]
    fun test_admin_revoke_vc_fails_if_vc_not_found() {
        let root = setup_test();
        let admin = &prepare_admin(&root);

        vc_registry::admin_revoke_vc(admin, 999, test_utils::reason_fraud());
    }

    // Success: admin can suspend VC and event/state are updated
    #[test]
    fun test_admin_suspend_vc_success() {
        let root = setup_test();
        let admin = &prepare_admin(&root);
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        let reason = test_utils::reason_policy();
        let now = timestamp::now_seconds();

        vc_registry::admin_suspend_vc(admin, 0, reason);
        vc_registry::assert_vc_status_changed_event_emitted(0, holder, test_utils::vc_status_suspended(), reason, test_utils::admin1_addr(), now);

        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_suspended(), 1);
        let (_, issuer_addr, holder_addr, _, _, _, _, status, _, _, revoked_at, status_reason) = vc_registry::get_vc_details_by_id(0);
        assert!(issuer_addr == test_utils::issuer1_addr(), 2);
        assert!(holder_addr == holder, 3);
        assert!(status == test_utils::vc_status_suspended(), 4);
        assert!(revoked_at == 0, 5);
        assert!(status_reason == reason, 6);
    }

    // Fail: `admin_reinstate_vc` aborts when VC is not suspended
    #[test]
    #[expected_failure(abort_code = errors::E_VC_NOT_SUSPENDED, location = vc_registry)]
    fun test_admin_reinstate_vc_fails_if_vc_not_suspended() {
        let root = setup_test();
        let admin = &prepare_admin(&root);
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);

        vc_registry::admin_reinstate_vc(admin, 0, test_utils::reason_technical());
    }

    // Success: admin can reinstate suspended VC and integrity is restored
    #[test]
    fun test_admin_reinstate_vc_success() {
        let root = setup_test();
        let admin = &prepare_admin(&root);
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        vc_registry::admin_suspend_vc(admin, 0, test_utils::reason_policy());
        let reason = test_utils::reason_technical();
        let now = timestamp::now_seconds();

        vc_registry::admin_reinstate_vc(admin, 0, reason);
        vc_registry::assert_vc_status_changed_event_emitted(0, holder, test_utils::vc_status_active(), reason, test_utils::admin1_addr(), now);

        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_active(), 1);
        assert!(vc_registry::verify_integrity(0, test_utils::mock_hash_v2()), 2);
        let (_, issuer_addr, holder_addr, _, _, _, _, status, _, _, revoked_at, status_reason) = vc_registry::get_vc_details_by_id(0);
        assert!(issuer_addr == test_utils::issuer1_addr(), 3);
        assert!(holder_addr == holder, 4);
        assert!(status == test_utils::vc_status_active(), 5);
        assert!(revoked_at == 0, 6);
        assert!(status_reason == reason, 7);
    }

    // Fail: `admin_revoke_vc` aborts when VC already revoked
    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_REVOKED, location = vc_registry)]
    fun test_admin_revoke_vc_fails_if_vc_already_revoked() {
        let root = setup_test();
        let admin = &prepare_admin(&root);
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        vc_registry::admin_revoke_vc(admin, 0, test_utils::reason_fraud());
        vc_registry::admin_revoke_vc(admin, 0, test_utils::reason_error());
    }

    // Fail: `suspend_vc` aborts when VC already revoked
    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_REVOKED, location = vc_registry)]
    fun test_suspend_vc_fails_if_vc_already_revoked() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        vc_registry::revoke_vc(issuer_signer, 0, test_utils::reason_fraud());

        vc_registry::suspend_vc(issuer_signer, 0, test_utils::reason_policy());
    }

    // Fail: `revoke_vc` aborts when VC already revoked
    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_REVOKED, location = vc_registry)]
    fun test_revoke_vc_fails_if_vc_already_revoked() {
        let root = setup_test();
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        vc_registry::revoke_vc(issuer_signer, 0, test_utils::reason_fraud());

        vc_registry::revoke_vc(issuer_signer, 0, test_utils::reason_error());
    }

    // Success: admin can revoke VC and event/state are updated
    #[test]
    fun test_admin_revoke_vc_success() {
        let root = setup_test();
        let admin = &prepare_admin(&root);
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);
        let reason = test_utils::reason_fraud();
        let now = timestamp::now_seconds();

        vc_registry::admin_revoke_vc(admin, 0, reason);
        vc_registry::assert_vc_status_changed_event_emitted(0, holder, test_utils::vc_status_revoked(), reason, test_utils::admin1_addr(), now);

        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_revoked(), 1);
        assert!(!vc_registry::verify_integrity(0, test_utils::mock_hash_v2()), 2);
        let (_, issuer_addr, holder_addr, _, _, _, _, status, _, _, revoked_at, status_reason) = vc_registry::get_vc_details_by_id(0);
        assert!(issuer_addr == test_utils::issuer1_addr(), 3);
        assert!(holder_addr == holder, 4);
        assert!(status == test_utils::vc_status_revoked(), 5);
        assert!(revoked_at == now, 6);
        assert!(status_reason == reason, 7);
    }

    // Race: issuer suspends a VC, then admin reinstate it - state and events update correctly
    #[test]
    fun test_issuer_suspend_then_admin_reinstate_success() {
        let root = setup_test();
        let admin = &prepare_admin(&root);
        let issuer_signer = &prepare_approved_issuer(
            &root,
            test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
        );
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        issue_sample_vc(issuer_signer, holder);

        let reason_issuer = test_utils::reason_policy();
        vc_registry::suspend_vc(issuer_signer, 0, reason_issuer);
        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_suspended(), 1);

        let reason_admin = test_utils::reason_technical();
        let t2 = timestamp::now_seconds();
        vc_registry::admin_reinstate_vc(admin, 0, reason_admin);
        vc_registry::assert_vc_status_changed_event_emitted(0, holder, test_utils::vc_status_active(), reason_admin, test_utils::admin1_addr(), t2);

        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_active(), 2);
        assert!(vc_registry::verify_integrity(0, test_utils::mock_hash_v2()), 3);
    }

    // ========== HELPERS ========== 

    fun setup_test(): signer {
        let aptos_framework = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&aptos_framework);
        test_utils::fast_forward_by(test_utils::initial_time_seconds());

        let root = account::create_account_for_test(test_utils::root_addr());
        did_registry::initialize_for_test(&root);
        authority::initialize_for_test(&root);
        vc_registry::initialize_for_test(&root);
        register_did_for(test_utils::root_addr());
        root
    }

    fun register_did_for(addr: address): signer {
        let sig = account::create_account_for_test(addr);
        let did = test_utils::did_for(addr);
        let cid = test_utils::mock_cid();
        let hash = test_utils::mock_hash();
        did_registry::register_did(&sig, did, cid, hash);
        assert!(did_registry::has_active_did(addr), 1);
        sig
    }

    fun prepare_approved_issuer(
        root: &signer,
        issuer: address,
        vc_type_mask: u64,
        delegation_cid: vector<u8>,
        delegation_hash: vector<u8>,
    ): signer {
        let issuer_signer = register_did_for(issuer);
        authority::approve_issuer(root, issuer, vc_type_mask, delegation_cid, delegation_hash, 0);
        issuer_signer
    }

    fun prepare_admin(root: &signer): signer {
        let admin = test_utils::admin1_addr();
        register_did_for(admin);
        authority::grant_admin(root, admin);
        account::create_account_for_test(admin)
    }

    fun issue_sample_vc(issuer_signer: &signer, holder: address) {
        vc_registry::issuer_vc(
            issuer_signer,
            holder,
            test_utils::vc_type_bachelor(),
            test_utils::mock_hash(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash_v2(),
        );
    }
}