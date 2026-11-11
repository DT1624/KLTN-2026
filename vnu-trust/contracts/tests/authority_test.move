#[test_only]
module vnu::authority_test {

    use aptos_framework::account;
    use aptos_framework::timestamp;
    use vnu::authority::is_active_admin;
    use vnu::errors;
    use vnu::did_registry;
    use vnu::authority;
    use vnu::test_utils;

    // ========== SETUP TEST ==========

    // Setup: initialize module state and verify root/admin/issuer counts
    #[test]
    fun setup_test_success() {
        setup_test();
        assert!(authority::get_root_admin() == test_utils::root_addr(), 1);
        let (admin_count, issuer_count) = authority::stats();
        assert!(admin_count == 0, 2);
        assert!(issuer_count == 0, 3);
    }

    // ========== CHUYEN QUYEN ROOT (HAI BUOC) ==========
    // F-00: chuyen mot buoc la bay mot chieu. Nay phai co chu ky cua nguoi nhan.

    // Success: de cu roi nguoi nhan tu ky chap nhan -> quyen root moi doi
    #[test]
    fun test_transfer_root_two_step_success() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let new_root_addr = test_utils::random1_addr();
        let new_root = &account::create_account_for_test(new_root_addr);
        let now = timestamp::now_seconds();

        authority::propose_root(root, new_root_addr);
        authority::assert_root_transfer_proposed_event_emitted(test_utils::root_addr(), new_root_addr, now);
        // Buoc de cu CHUA doi quyen - day chinh la cho bao ve
        assert!(authority::get_root_admin() == test_utils::root_addr(), 1);
        assert!(authority::get_pending_root() == new_root_addr, 2);

        authority::accept_root(new_root);
        authority::assert_root_transferred_event_emitted(test_utils::root_addr(), new_root_addr, now);
        assert!(authority::get_root_admin() == new_root_addr, 3);
        assert!(authority::get_pending_root() == @0x0, 4);
    }

    // Fail: chi root moi duoc de cu
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun test_propose_root_fails_if_caller_not_root() {
        setup_test();
        let stranger = &account::create_account_for_test(test_utils::random2_addr());
        authority::propose_root(stranger, test_utils::random1_addr());
    }

    // Fail: nguoi KHAC nguoi duoc de cu khong the nhan quyen
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_PENDING_ROOT, location = authority)]
    fun test_accept_root_fails_if_not_the_proposed_address() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        authority::propose_root(root, test_utils::random1_addr());

        let impostor = &account::create_account_for_test(test_utils::random2_addr());
        authority::accept_root(impostor);
    }

    // Fail: khong co de cu nao thi khong nhan duoc
    #[test]
    #[expected_failure(abort_code = errors::E_NO_PENDING_ROOT, location = authority)]
    fun test_accept_root_fails_if_no_pending_proposal() {
        setup_test();
        let anyone = &account::create_account_for_test(test_utils::random1_addr());
        authority::accept_root(anyone);
    }

    // Success: root huy de cu -> nguoi duoc de cu khong the nhan nua
    #[test]
    #[expected_failure(abort_code = errors::E_NO_PENDING_ROOT, location = authority)]
    fun test_cancel_root_transfer_blocks_acceptance() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let new_root_addr = test_utils::random1_addr();
        let new_root = &account::create_account_for_test(new_root_addr);

        authority::propose_root(root, new_root_addr);
        authority::cancel_root_transfer(root);
        assert!(authority::get_pending_root() == @0x0, 1);

        authority::accept_root(new_root);
    }

    // ========== GRANT ADMIN ==========

    // Fail: `grant_admin` should abort when caller is not the root admin
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun test_grant_admin_fails_if_caller_not_root_admin() {
        setup_test();
        let caller = &account::create_account_for_test(test_utils::random1_addr());
        let admin = test_utils::admin1_addr();
        authority::grant_admin(caller, admin);
    }

    // Fail: `grant_admin` should abort when admin DID does not exist
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun test_grant_admin_fails_if_admin_not_exists() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin = test_utils::admin1_addr();
        authority::grant_admin(root, admin);
    }

    // Fail: `grant_admin` should abort when admin DID is not active
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun test_grant_admin_fails_if_admin_not_active() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin = test_utils::admin1_addr();
        let admin_signer = &register_did_for(admin);

        did_registry::deactivate_did(admin_signer);
        authority::grant_admin(root, admin);
    }

    // Success: root can grant admin and admin state/event updated accordingly
    #[test]
    fun test_grant_admin_success() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin = test_utils::admin1_addr();
        register_did_for(admin);
        let now = timestamp::now_seconds();

        assert!(!authority::is_active_admin(admin), 1);
        let (count_admin_befort, _) = authority::stats();
        assert!(count_admin_befort == 0, 2);

        authority::grant_admin(root, admin);
        authority::assert_admin_granted_event_emitted(admin, test_utils::root_addr(), now);

        assert!(authority::is_active_admin(admin), 3);
        let (count_admin_after, _) = authority::stats();
        assert!(count_admin_after == 1, 4);
        let (owner, approved_by, approved_at, version, vc_type_mask, delegation_cid, delegation_hash, expires_at, status, status_reason, status_updated_at) = authority::get_admin_details(admin);
        assert!(owner == admin, 5);
        assert!(approved_by == test_utils::root_addr(), 6);
        assert!(approved_at == now, 7);
        assert!(version == 1, 8);
        assert!(vc_type_mask == test_utils::vc_type_delegation(), 9);
        assert!(delegation_cid == b"", 10);
        assert!(delegation_hash == b"", 11);
        assert!(expires_at == 0, 12);
        assert!(status == test_utils::admin_status_active(), 13);
        assert!(status_reason == b"", 14);
        assert!(status_updated_at == now, 15);
    }

    // Fail: `grant_admin` should abort when admin already exists
    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_ALREADY_EXISTS, location = authority)]
    fun test_grant_admin_fails_if_admin_already_exists() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin = test_utils::admin1_addr();
        register_did_for(admin);

        authority::grant_admin(root, admin);
        authority::grant_admin(root, admin);
    }

    // Fail: `grant_admin` should abort when caller is an admin (not root)
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun test_grant_admin_fails_if_caller_is_admin() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin1 = test_utils::admin1_addr();
        let admin2 = test_utils::admin2_addr();
        register_did_for(admin1);
        register_did_for(admin2);

        authority::grant_admin(root, admin1);
        assert!(is_active_admin(admin1), 1);
        let admin1_signer = &account::create_account_for_test(admin1);
        authority::grant_admin(admin1_signer, admin2);
    }

    // ========== REVOKE ADMIN ==========

    // Fail: `revoke_admin` should abort when caller is not root admin
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun test_revoke_admin_fails_if_caller_not_root_admin() {
        setup_test();
        let caller = &account::create_account_for_test(test_utils::random1_addr());
        let admin = test_utils::admin1_addr();
        authority::revoke_admin(caller, admin, b"");
    }

    // Fail: `revoke_admin` should abort when caller is admin (not root)
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun test_revoke_admin_fails_if_caller_is_admin() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin1 = test_utils::admin1_addr();
        let admin2 = test_utils::admin2_addr();
        register_did_for(admin1);
        register_did_for(admin2);

        authority::grant_admin(root, admin1);
        authority::grant_admin(root, admin2);
        let admin1_signer = &account::create_account_for_test(admin1);
        authority::revoke_admin(admin1_signer, admin2, b"");
    }

    // Fail: `revoke_admin` should abort when the target is not an admin
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ADMIN, location = authority)]
    fun test_revoke_admin_fails_if_not_admin() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin1 = test_utils::admin1_addr();
        authority::revoke_admin(root, admin1, b"");
    }

    // Success: root can revoke admin and admin state/event updated accordingly
    #[test]
    fun test_revoke_admin_success() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin1 = test_utils::admin1_addr();
        register_did_for(admin1);

        authority::grant_admin(root, admin1);
        assert!(is_active_admin(admin1), 1);
        let now = timestamp::now_seconds();
        authority::revoke_admin(root, admin1, b"");
        authority::assert_admin_revoked_event_emitted(admin1, test_utils::root_addr(), b"", now);
        assert!(!is_active_admin(admin1), 2);
        let (owner, approved_by, approved_at, version, vc_type_mask, delegation_cid, delegation_hash, expires_at, status, status_reason, status_updated_at) = authority::get_admin_details(admin1);
        assert!(owner == admin1, 3);
        assert!(approved_by == test_utils::root_addr(), 4);
        assert!(approved_at < now + 1, 5);
        assert!(version == 1, 6);
        assert!(vc_type_mask == test_utils::vc_type_delegation(), 7);
        assert!(delegation_cid == b"", 8);
        assert!(delegation_hash == b"", 9);
        assert!(expires_at == 0, 10);
        assert!(status == test_utils::admin_status_revoked(), 11);
        assert!(status_reason == b"", 12);
        assert!(status_updated_at == now, 13);
    }

    // Fail: `revoke_admin` should abort when admin already revoked
    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_ALREADY_REVOKED, location = authority)]
    fun test_revoke_admin_fails_if_admin_already_revoked() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin1 = test_utils::admin1_addr();
        register_did_for(admin1);

        authority::grant_admin(root, admin1);
        assert!(is_active_admin(admin1), 1);
        authority::revoke_admin(root, admin1, b"");
        assert!(!is_active_admin(admin1), 1);
        authority::revoke_admin(root, admin1, b"");
    }

    // ========== ISSUER ========== 

    // Fail: `approve_issuer` should abort when caller has no DID
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun test_approve_issuer_fails_if_caller_has_no_did() {
        setup_test();
        let caller = &account::create_account_for_test(test_utils::random2_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(caller, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
    }

    // Fail: `approve_issuer` should abort when caller's DID is not active
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun test_approve_issuer_fails_if_caller_did_not_active() {
        setup_test();
        let caller = &register_did_for(test_utils::admin1_addr());
        did_registry::deactivate_did(caller);
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(caller, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
    }

    // Fail: `approve_issuer` should abort when caller is active DID but not an admin
    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun test_approve_issuer_fails_if_caller_is_active_did_but_not_admin() {
        setup_test();
        let caller = &register_did_for(test_utils::random1_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(caller, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
    }

    // Fail: `approve_issuer` should abort when issuer DID is missing
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_NOT_EXISTS, location = did_registry)]
    fun test_approve_issuer_fails_if_issuer_did_missing() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        authority::approve_issuer(root, test_utils::issuer1_addr(), test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
    }

    // Fail: `approve_issuer` should abort when issuer DID is not active
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun test_approve_issuer_fails_if_issuer_did_not_active() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer_signer = &register_did_for(test_utils::issuer1_addr());
        did_registry::deactivate_did(issuer_signer);
        authority::approve_issuer(root, test_utils::issuer1_addr(), test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
    }

    // Fail: `approve_issuer` should abort when issuer already exists
    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_ALREADY_EXISTS, location = authority)]
    fun test_approve_issuer_fails_if_issuer_already_exists() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);

        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
        authority::approve_issuer(root, issuer, test_utils::vc_type_master(), test_utils::mock_vc_cid_v2(), test_utils::mock_hash_v2(), 0);
    }

    // Fail: `approve_issuer` should abort when non-root tries to use delegation mask
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun test_approve_issuer_fails_if_delegation_mask_used_by_non_root() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin = test_utils::admin1_addr();
        register_did_for(admin);
        authority::grant_admin(root, admin);

        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        let admin_signer = &account::create_account_for_test(admin);
        authority::approve_issuer(admin_signer, issuer, test_utils::vc_type_delegation(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
    }

    // Fail: `approve_issuer` should abort when delegation hash length invalid
    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = authority)]
    fun test_approve_issuer_fails_if_hash_short() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), b"short", 0);
    }

    // Success: root approves issuer with delegation mask and event/state set
    #[test]
    fun test_approve_issuer_success_by_root_with_delegation() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        let now = timestamp::now_seconds();
        let vc_type_mask = test_utils::vc_type_bachelor() | test_utils::vc_type_delegation();
        let delegation_cid = test_utils::mock_vc_cid();
        let delegation_hash = test_utils::mock_hash();

        authority::approve_issuer(root, issuer, vc_type_mask, delegation_cid, delegation_hash, 0);
        authority::assert_issuer_approved_event_emitted(issuer, test_utils::root_addr(), vc_type_mask, delegation_cid, now, 0);

        assert!(authority::is_active_issuer(issuer), 1);
        let (approved_by, returned_mask, returned_cid, returned_hash, expires_at, status) = authority::get_info(issuer);
        assert!(approved_by == test_utils::root_addr(), 2);
        assert!(returned_mask == vc_type_mask, 3);
        assert!(returned_cid == delegation_cid, 4);
        assert!(returned_hash == delegation_hash, 5);
        assert!(expires_at == 0, 6);
        assert!(status == test_utils::issuer_status_active(), 7);

        let (owner, owner_approved_by, approved_at, version, owner_mask, owner_cid, owner_hash, owner_expires_at, owner_status, owner_reason, owner_status_updated_at) = authority::get_issuer_details(issuer);
        assert!(owner == issuer, 8);
        assert!(owner_approved_by == test_utils::root_addr(), 9);
        assert!(approved_at == now, 10);
        assert!(version == 1, 11);
        assert!(owner_mask == vc_type_mask, 12);
        assert!(owner_cid == delegation_cid, 13);
        assert!(owner_hash == delegation_hash, 14);
        assert!(owner_expires_at == 0, 15);
        assert!(owner_status == test_utils::issuer_status_active(), 16);
        assert!(owner_reason == b"", 17);
        assert!(owner_status_updated_at == now, 18);
    }

    #[test]
    fun test_approve_issuer_success_by_admin_without_delegation() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin = test_utils::admin1_addr();
        register_did_for(admin);
        authority::grant_admin(root, admin);

        let issuer = test_utils::issuer2_addr();
        register_did_for(issuer);
        let admin_signer = &account::create_account_for_test(admin);
        let now = timestamp::now_seconds();
        let vc_type_mask = test_utils::vc_type_bachelor() | test_utils::vc_type_transcript();
        let delegation_cid = b"";
        let delegation_hash = test_utils::mock_hash_v2();

        authority::approve_issuer(admin_signer, issuer, vc_type_mask, delegation_cid, delegation_hash, 0);
        authority::assert_issuer_approved_event_emitted(issuer, admin, vc_type_mask, delegation_cid, now, 0);

        assert!(authority::is_active_issuer(issuer), 1);
        let (approved_by, returned_mask, returned_cid, returned_hash, expires_at, status) = authority::get_info(issuer);
        assert!(approved_by == admin, 2);
        assert!(returned_mask == vc_type_mask, 3);
        assert!(returned_cid == delegation_cid, 4);
        assert!(returned_hash == delegation_hash, 5);
        assert!(expires_at == 0, 6);
        assert!(status == test_utils::issuer_status_active(), 7);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_FOUND, location = authority)]
    fun test_suspend_issuer_fails_if_issuer_not_found() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        authority::suspend_issuer(root, test_utils::issuer1_addr(), test_utils::reason_policy());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_ACTIVE, location = authority)]
    fun test_suspend_issuer_fails_if_issuer_already_suspended() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
        authority::suspend_issuer(root, issuer, test_utils::reason_policy());
        authority::suspend_issuer(root, issuer, test_utils::reason_policy());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_SUSPENDED, location = authority)]
    fun test_reactivate_issuer_fails_if_issuer_not_suspended() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
        authority::reactivate_issuer(root, issuer, test_utils::reason_technical());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_FOUND, location = authority)]
    fun test_reactivate_issuer_fails_if_issuer_not_found() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        authority::reactivate_issuer(root, test_utils::issuer1_addr(), test_utils::reason_technical());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun test_reactivate_issuer_fails_if_caller_active_did_but_not_admin() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let caller = &register_did_for(test_utils::random1_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
        authority::reactivate_issuer(caller, issuer, test_utils::reason_technical());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_ALREADY_REVOKED, location = authority)]
    fun test_revoke_issuer_fails_if_already_revoked() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
        authority::revoke_issuer(root, issuer, test_utils::reason_fraud());
        authority::revoke_issuer(root, issuer, test_utils::reason_error());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_NOT_FOUND, location = authority)]
    fun test_revoke_issuer_fails_if_issuer_not_found() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        authority::revoke_issuer(root, test_utils::issuer1_addr(), test_utils::reason_fraud());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun test_revoke_issuer_fails_if_caller_active_did_but_not_admin() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let caller = &register_did_for(test_utils::random1_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
        authority::revoke_issuer(caller, issuer, test_utils::reason_fraud());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_NOT_ACTIVE, location = authority)]
    fun test_suspend_issuer_fails_if_caller_active_did_but_not_admin() {
        setup_test();
        let caller = &register_did_for(test_utils::random1_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::suspend_issuer(caller, issuer, test_utils::reason_policy());
    }

    #[test]
    fun test_suspend_issuer_success() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);

        let reason = test_utils::reason_policy();
        let now = timestamp::now_seconds();
        authority::suspend_issuer(root, issuer, reason);
        authority::assert_issuer_status_changed_event_emitted(issuer, test_utils::root_addr(), test_utils::issuer_status_suspended(), reason, now);

        let (_, _, _, _, _, _, _, _, status, status_reason, status_updated_at) = authority::get_issuer_details(issuer);
        assert!(status == test_utils::issuer_status_suspended(), 1);
        assert!(status_reason == reason, 2);
        assert!(status_updated_at == now, 3);
    }

    #[test]
    fun test_reactivate_issuer_success() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
        authority::suspend_issuer(root, issuer, test_utils::reason_policy());

        let reason = test_utils::reason_technical();
        let now = timestamp::now_seconds();
        authority::reactivate_issuer(root, issuer, reason);
        authority::assert_issuer_status_changed_event_emitted(issuer, test_utils::root_addr(), test_utils::issuer_status_active(), reason, now);

        let (_, _, _, _, _, _, _, _, status, status_reason, status_updated_at) = authority::get_issuer_details(issuer);
        assert!(status == test_utils::issuer_status_active(), 1);
        assert!(status_reason == reason, 2);
        assert!(status_updated_at == now, 3);
    }

    #[test]
    fun test_revoke_issuer_success() {
        setup_test();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);

        let reason = test_utils::reason_fraud();
        let now = timestamp::now_seconds();
        authority::revoke_issuer(root, issuer, reason);
        authority::assert_issuer_status_changed_event_emitted(issuer, test_utils::root_addr(), test_utils::issuer_status_revoked(), reason, now);

        let (_, _, _, _, _, _, _, _, status, status_reason, status_updated_at) = authority::get_issuer_details(issuer);
        assert!(status == test_utils::issuer_status_revoked(), 1);
        assert!(status_reason == reason, 2);
        assert!(status_updated_at == now, 3);
    }

    // ========== HELPERS ==========

    fun setup_test() {
        let aptos_framework = &account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(aptos_framework);
        test_utils::fast_forward_by(test_utils::initial_time_seconds());

        let deployer = &account::create_account_for_test(test_utils::deployer_addr());
        did_registry::initialize_for_test(deployer);
        authority::initialize_for_test(deployer);
        register_did_for(test_utils::root_addr());
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
}
