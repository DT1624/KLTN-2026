// Bo test theo doi 10 phat hien trong docs/CONTRACT_AUDIT.md.
//
// LICH SU: truoc day moi test o day CHUNG MINH mot loi co that - test PASS
// nghia la loi ton tai. Sau khi sua contract, chung da duoc viet lai thanh test
// KHANG DINH HANH VI DUNG: PASS nghia la loi da duoc sua va khong quay lai.
//
// Moi test giu nguyen ma phat hien (f01_, f02_...) de doi chieu nguoc voi tai
// lieu ra soat.
#[test_only]
module vnu::audit_findings_test {

    use std::vector;
    use aptos_framework::account;
    use aptos_framework::timestamp;
    use vnu::errors;
    use vnu::did_registry;
    use vnu::authority;
    use vnu::vc_registry;
    use vnu::test_utils;

    // ===================================================================
    // F-01  approve_issuer chi doi delegation_vc_hash 32 byte khi THAT SU
    //       co uy quyen. Issuer thuong khong can VC uy quyen nao.
    // ===================================================================

    // Cap quyen cho mot issuer thuong voi cid/hash RONG - dung nhu ung dung that.
    #[test]
    fun f01_plain_issuer_approved_with_empty_delegation_proof() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);

        authority::approve_issuer(
            root, issuer,
            test_utils::vc_type_bachelor(),
            b"",    // delegation_vc_cid rong
            b"",    // delegation_vc_hash rong
            0
        );

        assert!(authority::is_active_issuer(issuer), 1);
        let (_by, mask, cid, hash, _exp, status) = authority::get_info(issuer);
        assert!(mask == test_utils::vc_type_bachelor(), 2);
        assert!(cid == b"", 3);
        assert!(hash == b"", 4);
        assert!(status == test_utils::issuer_status_active(), 5);
    }

    // Nhung hash SAI DO DAI thi van bi tu choi: nhan bua mot hash 5 byte roi im
    // lang la cach chac chan nhat de sau nay khong ai doi chieu duoc gi.
    #[test]
    #[expected_failure(abort_code = errors::E_HASH_WRONG_LENGTH, location = authority)]
    fun f01_malformed_delegation_hash_still_rejected() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(),
            b"", b"short", 0
        );
    }

    // Nguoc lai: co bit uy quyen thi BAT BUOC phai co VC uy quyen that.
    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = authority)]
    fun f01_delegation_bit_requires_real_proof_cid() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);

        authority::approve_issuer(
            root, issuer,
            test_utils::vc_type_bachelor() | test_utils::vc_type_delegation(),
            b"",                        // thieu CID cua VC uy quyen
            test_utils::mock_hash(),
            0
        );
    }

    // ===================================================================
    // F-02  Chuoi uy quyen da duoc noi day: issuer co bit VC_DELEGATION
    //       cap duoc sub-issuer, trong PHAM VI cua chinh minh.
    // ===================================================================

    #[test]
    fun f02_delegating_issuer_can_approve_sub_issuer() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());

        let issuer1 = test_utils::issuer1_addr();
        let issuer1_sig = register_did_for(issuer1);
        authority::approve_issuer(
            root, issuer1,
            test_utils::vc_type_bachelor() | test_utils::vc_type_master() | test_utils::vc_type_delegation(),
            test_utils::mock_vc_cid(),
            test_utils::mock_hash(),
            0
        );
        assert!(authority::can_delegate(issuer1), 1);

        // issuer1 cap cho issuer2 mot phan quyen cua minh
        let issuer2 = test_utils::issuer2_addr();
        register_did_for(issuer2);
        authority::approve_issuer(
            &issuer1_sig, issuer2,
            test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid_v2(),
            test_utils::mock_hash_v2(),
            0
        );

        assert!(authority::is_active_issuer(issuer2), 2);
        let (approved_by, mask, _cid, _hash, _exp, _st) = authority::get_info(issuer2);
        // Vet kiem toan chi ro ai da cap: issuer1, khong phai root
        assert!(approved_by == issuer1, 3);
        assert!(mask == test_utils::vc_type_bachelor(), 4);
        // Sub-issuer khong duoc thua ke quyen uy quyen lai
        assert!(!authority::can_delegate(issuer2), 5);
    }

    // Khong leo thang quyen: sub-issuer khong the nhan quyen ma nguoi cap khong co.
    #[test]
    #[expected_failure(abort_code = errors::E_UNAUTHORIZED_VC_TYPE, location = authority)]
    fun f02_sub_issuer_cannot_exceed_parent_mask() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());

        let issuer1 = test_utils::issuer1_addr();
        let issuer1_sig = register_did_for(issuer1);
        authority::approve_issuer(
            root, issuer1,
            test_utils::vc_type_bachelor() | test_utils::vc_type_delegation(),
            test_utils::mock_vc_cid(), test_utils::mock_hash(), 0
        );

        let issuer2 = test_utils::issuer2_addr();
        register_did_for(issuer2);
        // issuer1 chi co bang cu nhan, khong the cap quyen cap bang tien si
        authority::approve_issuer(
            &issuer1_sig, issuer2,
            test_utils::vc_type_phd(),
            test_utils::mock_vc_cid_v2(), test_utils::mock_hash_v2(), 0
        );
    }

    // Issuer KHONG co bit uy quyen thi van khong cap duoc cho ai.
    #[test]
    #[expected_failure(abort_code = errors::E_CANNOT_DELEGATE, location = authority)]
    fun f02_plain_issuer_cannot_approve_anyone() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());

        let issuer1 = test_utils::issuer1_addr();
        let issuer1_sig = register_did_for(issuer1);
        authority::approve_issuer(
            root, issuer1, test_utils::vc_type_bachelor(),
            b"", b"", 0
        );

        let issuer2 = test_utils::issuer2_addr();
        register_did_for(issuer2);
        authority::approve_issuer(
            &issuer1_sig, issuer2, test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid_v2(), test_utils::mock_hash_v2(), 0
        );
    }

    // Chi root moi phat duoc bit uy quyen - issuer uy quyen khong nhan ban duoc.
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_ROOT_ADMIN, location = authority)]
    fun f02_delegation_bit_cannot_be_passed_down() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());

        let issuer1 = test_utils::issuer1_addr();
        let issuer1_sig = register_did_for(issuer1);
        authority::approve_issuer(
            root, issuer1,
            test_utils::vc_type_bachelor() | test_utils::vc_type_delegation(),
            test_utils::mock_vc_cid(), test_utils::mock_hash(), 0
        );

        let issuer2 = test_utils::issuer2_addr();
        register_did_for(issuer2);
        authority::approve_issuer(
            &issuer1_sig, issuer2,
            test_utils::vc_type_bachelor() | test_utils::vc_type_delegation(),
            test_utils::mock_vc_cid_v2(), test_utils::mock_hash_v2(), 0
        );
    }

    // Han cua sub-issuer khong duoc vuot han cua nguoi cap.
    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_CAP_EXPIRED, location = authority)]
    fun f02_sub_issuer_cannot_outlive_parent() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let now = timestamp::now_seconds();

        let issuer1 = test_utils::issuer1_addr();
        let issuer1_sig = register_did_for(issuer1);
        authority::approve_issuer(
            root, issuer1,
            test_utils::vc_type_bachelor() | test_utils::vc_type_delegation(),
            test_utils::mock_vc_cid(), test_utils::mock_hash(), now + 1000
        );

        let issuer2 = test_utils::issuer2_addr();
        register_did_for(issuer2);
        authority::approve_issuer(
            &issuer1_sig, issuer2, test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid_v2(), test_utils::mock_hash_v2(), now + 5000
        );
    }

    // ===================================================================
    // F-03  Admin bi thu hoi PHAI cap lai duoc (thu hoi nham khong con la
    //       ban an chung than).
    // ===================================================================
    #[test]
    fun f03_revoked_admin_can_be_regranted() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin = test_utils::admin1_addr();
        register_did_for(admin);

        authority::grant_admin(root, admin);
        let first_role_id = authority::role_id_of_admin(admin);
        authority::revoke_admin(root, admin, test_utils::reason_error());
        assert!(!authority::is_active_admin(admin), 1);

        // Thu hoi nham -> cap lai duoc
        authority::grant_admin(root, admin);
        assert!(authority::is_active_admin(admin), 2);

        let (_o, _by, _at, version, _m, _c, _h, _e, status, _r, _u)
            = authority::get_admin_details(admin);
        // version tang -> biet day la lan cap thu hai
        assert!(version == 2, 3);
        assert!(status == test_utils::admin_status_active(), 4);
        // Ban ghi cu van con trong bang `roles` duoi id cu -> giu vet kiem toan
        assert!(authority::role_id_of_admin(admin) != first_role_id, 5);
        // ...va so admin RIENG BIET khong bi dem hai lan
        let (admin_count, _issuer_count) = authority::stats();
        assert!(admin_count == 1, 6);
    }

    // Nhung admin DANG HOAT DONG thi khong cap chong len duoc.
    #[test]
    #[expected_failure(abort_code = errors::E_ADMIN_ALREADY_EXISTS, location = authority)]
    fun f03_active_admin_cannot_be_granted_twice() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin = test_utils::admin1_addr();
        register_did_for(admin);

        authority::grant_admin(root, admin);
        authority::grant_admin(root, admin);
    }

    // ===================================================================
    // F-04  Issuer bi thu hoi PHAI approve lai duoc.
    // ===================================================================
    #[test]
    fun f04a_revoked_issuer_can_be_reapproved() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(), b"", b"", 0
        );
        authority::revoke_issuer(root, issuer, test_utils::reason_error());
        assert!(!authority::is_active_issuer(issuer), 1);

        // Cap lai voi pham vi khac
        authority::approve_issuer(
            root, issuer, test_utils::vc_type_master(), b"", b"", 0
        );
        assert!(authority::is_active_issuer(issuer), 2);

        let (_o, _by, _at, version, mask, _c, _h, _e, status, _r, _u)
            = authority::get_issuer_details(issuer);
        assert!(version == 2, 3);
        assert!(mask == test_utils::vc_type_master(), 4);
        assert!(status == test_utils::issuer_status_active(), 5);
        let (_admin_count, issuer_count) = authority::stats();
        assert!(issuer_count == 1, 6);
    }

    // CO Y GIU: `reactivate_issuer` chi hoi sinh tu SUSPENDED. Da THU HOI thi
    // phai di lai duong `approve_issuer` - de moi lan cap lai deu tao ra mot
    // ban ghi moi co version rieng, thay vi lang le bat lai ban ghi cu.
    #[test]
    #[expected_failure(abort_code = errors::E_ISSUER_ALREADY_REVOKED, location = authority)]
    fun f04b_revoked_issuer_is_not_reactivated_in_place() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(), b"", b"", 0
        );
        authority::revoke_issuer(root, issuer, test_utils::reason_error());
        authority::reactivate_issuer(root, issuer, test_utils::reason_error());
    }

    // ===================================================================
    // F-05  DID bi thu hoi -> chu so huu dang ky DID MOI duoc.
    //       Kich ban that: LO KHOA RIENG.
    // ===================================================================
    #[test]
    fun f05_revoked_did_owner_can_register_a_new_did() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let holder = test_utils::holder1_addr();
        let holder_sig = register_did_for(holder);
        let old_did = test_utils::did_for(holder);

        authority::admin_revoke_did(root, holder, test_utils::reason_key_compromise());
        assert!(!did_registry::has_active_did(holder), 1);

        // Lo khoa -> dang ky DID moi bang khoa moi, van dia chi do
        did_registry::register_did(
            &holder_sig,
            test_utils::did_with_prefix(b"did:vnu:v2:", holder),
            test_utils::mock_cid_v2(),
            test_utils::mock_hash_v2()
        );

        assert!(did_registry::has_active_did(holder), 2);
        let (did_str, _cid, _hash, status, version)
            = did_registry::resolve_did_by_owner(holder);
        assert!(did_str == test_utils::did_with_prefix(b"did:vnu:v2:", holder), 3);
        assert!(status == test_utils::did_status_active(), 4);
        assert!(version == 2, 5);

        // DID cu VAN tra cuu duoc va van bao la da thu hoi - vet kiem toan con nguyen
        let (_d2, _c2, _h2, old_status, _v2) = did_registry::resolve_did(old_did);
        assert!(old_status == test_utils::did_status_revoked(), 6);
    }

    // DID dang hoat dong thi van khong duoc dang ky chong.
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_HAS_DID, location = did_registry)]
    fun f05_active_did_still_blocks_a_second_registration() {
        setup();
        let holder = test_utils::holder1_addr();
        let holder_sig = register_did_for(holder);

        did_registry::register_did(
            &holder_sig, test_utils::did_with_prefix(b"did:vnu:v2:", holder),
            test_utils::mock_cid_v2(), test_utils::mock_hash_v2()
        );
    }

    // ===================================================================
    // F-06  CID rong bi tu choi - DID/VC "active" ma khong co tai lieu nao
    //       de resolve la vo nghia.
    // ===================================================================
    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = did_registry)]
    fun f06_register_did_rejects_empty_cid() {
        setup();
        let holder = test_utils::holder1_addr();
        let sig = account::create_account_for_test(holder);

        did_registry::register_did(&sig, b"did:vnu:empty", b"", test_utils::mock_hash());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_CID, location = vc_registry)]
    fun f06_issue_vc_rejects_empty_cid() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(), b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_bachelor(),
            test_utils::mock_hash(), b"", test_utils::mock_hash_v2(), 0
        );
    }

    // ===================================================================
    // F-07  Chu DID tu khoa thi TU MO LAI duoc - dung tinh than SSI.
    // ===================================================================
    #[test]
    fun f07_owner_can_reactivate_their_own_suspended_did() {
        setup();
        let holder = test_utils::holder1_addr();
        let sig = register_did_for(holder);

        did_registry::suspend_own_did(&sig);
        assert!(!did_registry::has_active_did(holder), 1);
        assert!(did_registry::suspended_by_of(holder) == holder, 2);

        did_registry::reactivate_own_did(&sig);
        assert!(did_registry::has_active_did(holder), 3);
        assert!(did_registry::suspended_by_of(holder) == @0x0, 4);
    }

    // Nhung DID bi ADMIN khoa thi van phai admin mo - neu khong thi ky luat
    // chang con nghia ly gi.
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_SELF_SUSPENDED, location = did_registry)]
    fun f07_owner_cannot_undo_an_admin_suspension() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let holder = test_utils::holder1_addr();
        let sig = register_did_for(holder);

        authority::admin_suspend_did(root, holder, test_utils::reason_policy());
        assert!(did_registry::suspended_by_of(holder) == test_utils::root_addr(), 1);

        did_registry::reactivate_own_did(&sig);
    }

    // Ten cu `deactivate_did` van chay - khong vo ABI da trien khai.
    #[test]
    fun f07_legacy_deactivate_did_alias_still_works() {
        setup();
        let holder = test_utils::holder1_addr();
        let sig = register_did_for(holder);

        did_registry::deactivate_did(&sig);
        assert!(!did_registry::has_active_did(holder), 1);
        did_registry::reactivate_own_did(&sig);
        assert!(did_registry::has_active_did(holder), 2);
    }

    // ===================================================================
    // F-08  Issuer het han uy quyen VAN thu hoi duoc VC minh da cap.
    //       Nguyen tac: cap moi can quyen con hieu luc, thu hoi thi khong.
    // ===================================================================
    #[test]
    fun f08_expired_issuer_can_still_revoke_own_vc() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        let expires_at = timestamp::now_seconds() + 1000;
        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(),
            b"", b"", expires_at
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_bachelor(),
            test_utils::mock_hash(), test_utils::mock_cid(), test_utils::mock_hash_v2(), 0
        );

        // Uy quyen het han
        test_utils::fast_forward_by(2000);
        assert!(!authority::is_active_issuer(issuer), 1);

        // Phat hien bang cap sai -> van thu hoi duoc
        vc_registry::revoke_vc(&issuer_sig, 0, test_utils::reason_error());
        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_revoked(), 2);
    }

    // Nhung nguoi KHAC van khong dong vao VC cua issuer duoc.
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_VC_ISSUER, location = vc_registry)]
    fun f08_stranger_still_cannot_revoke_someone_elses_vc() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);
        let stranger = test_utils::random1_addr();
        let stranger_sig = register_did_for(stranger);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(), b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_bachelor(),
            test_utils::mock_hash(), test_utils::mock_cid(), test_utils::mock_hash_v2(), 0
        );

        vc_registry::revoke_vc(&stranger_sig, 0, test_utils::reason_fraud());
    }

    // Issuer bi thu hoi DID thi khong con thao tac gi duoc nua.
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_ACTIVE, location = did_registry)]
    fun f08_issuer_with_revoked_did_cannot_revoke() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(), b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_bachelor(),
            test_utils::mock_hash(), test_utils::mock_cid(), test_utils::mock_hash_v2(), 0
        );

        authority::admin_revoke_did(root, issuer, test_utils::reason_fraud());
        vc_registry::revoke_vc(&issuer_sig, 0, test_utils::reason_error());
    }

    // ===================================================================
    // F-09  VC co han dung that. Nhanh xu ly het han khong con la ma chet.
    // ===================================================================
    #[test]
    fun f09_vc_expires_and_views_report_it() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_micro_cred(), b"", b"", 0
        );

        let expires_at = timestamp::now_seconds() + 3600;
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_micro_cred(),
            test_utils::mock_hash(), test_utils::mock_cid(),
            test_utils::mock_hash_v2(), expires_at
        );

        // Con han
        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_active(), 1);
        assert!(vc_registry::verify_integrity(0, test_utils::mock_hash_v2()), 2);

        // Qua han
        test_utils::fast_forward_by(3601);
        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_expired(), 3);
        // Het han thi khong con toan ven ve hieu luc nua
        assert!(!vc_registry::verify_integrity(0, test_utils::mock_hash_v2()), 4);

        // ...nhung view VAN tra ve ban ghi, khong abort: ben xac minh phai duoc
        // nhin thay du lieu de tu danh gia.
        let record = vc_registry::get_vc_by_id(0);
        assert!(vc_registry::record_status(&record) == test_utils::vc_status_expired(), 5);
        assert!(vc_registry::record_expires_at(&record) == expires_at, 6);
    }

    // VC khong co han (0) thi vinh vien - hop ly cho bang tot nghiep.
    #[test]
    fun f09_zero_expiry_means_permanent() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(), b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_bachelor(),
            test_utils::mock_hash(), test_utils::mock_cid(), test_utils::mock_hash_v2(), 0
        );

        test_utils::fast_forward_by(100 * 365 * 24 * 3600);
        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_active(), 1);
    }

    // Cap mot VC da het han ngay tu dau la vo nghia -> chan tu dau.
    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_EXPIRED, location = vc_registry)]
    fun f09_cannot_issue_an_already_expired_vc() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(), b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_bachelor(),
            test_utils::mock_hash(), test_utils::mock_cid(),
            test_utils::mock_hash_v2(), timestamp::now_seconds() - 1
        );
    }

    // VC het han van THU HOI duoc: thu hoi la loi tuyen bo vinh vien ve gian
    // lan, khong duoc phep het han truoc khi kip tuyen bo.
    #[test]
    fun f09_expired_vc_can_still_be_revoked() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_micro_cred(), b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_micro_cred(),
            test_utils::mock_hash(), test_utils::mock_cid(),
            test_utils::mock_hash_v2(), timestamp::now_seconds() + 100
        );

        test_utils::fast_forward_by(200);
        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_expired(), 1);

        vc_registry::revoke_vc(&issuer_sig, 0, test_utils::reason_fraud());
        assert!(vc_registry::get_vc_status(0) == test_utils::vc_status_revoked(), 2);
    }

    // ...nhung TAM NGUNG mot VC da het han thi vo nghia -> chan.
    #[test]
    #[expected_failure(abort_code = errors::E_VC_ALREADY_EXPIRED, location = vc_registry)]
    fun f09_expired_vc_cannot_be_suspended() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_micro_cred(), b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_micro_cred(),
            test_utils::mock_hash(), test_utils::mock_cid(),
            test_utils::mock_hash_v2(), timestamp::now_seconds() + 100
        );

        test_utils::fast_forward_by(200);
        vc_registry::suspend_vc(&issuer_sig, 0, test_utils::reason_technical());
    }

    // ===================================================================
    // F-10  View phan trang: khong bao gio nap ca bang vao bo nho.
    // ===================================================================
    #[test]
    fun f10_paginated_views_return_bounded_pages() {
        setup();
        // setup() da dang ky DID cho root -> id 0
        register_did_for(test_utils::holder1_addr());   // id 1
        register_did_for(test_utils::holder2_addr());   // id 2
        register_did_for(test_utils::issuer1_addr());   // id 3

        assert!(did_registry::total_dids() == 4, 1);

        let page1 = did_registry::get_dids_paginated(0, 2);
        assert!(vector::length(&page1) == 2, 2);

        let page2 = did_registry::get_dids_paginated(2, 2);
        assert!(vector::length(&page2) == 2, 3);

        // Xin qua so ban ghi hien co thi chi tra ve phan con lai, khong abort
        let page3 = did_registry::get_dids_paginated(3, 100);
        assert!(vector::length(&page3) == 1, 4);

        // Qua duoi cuoi bang -> trang rong
        let page4 = did_registry::get_dids_paginated(99, 10);
        assert!(vector::is_empty(&page4), 5);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_PAGE, location = did_registry)]
    fun f10_page_limit_zero_is_rejected() {
        setup();
        did_registry::get_dids_paginated(0, 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_INVALID_PAGE, location = vc_registry)]
    fun f10_page_limit_above_cap_is_rejected() {
        setup();
        vc_registry::get_vcs_paginated(0, 100000);
    }

    // ===================================================================
    // F-11c  Bo sinh id rieng: cap lai vai tro khong bao gio dung id.
    //        Truoc day id = admin_count + issuer_count, chi dung nho trung hop.
    // ===================================================================
    #[test]
    fun f11c_role_ids_never_collide_across_regrants() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let admin = test_utils::admin1_addr();
        let issuer = test_utils::issuer1_addr();
        register_did_for(admin);
        register_did_for(issuer);

        // Xen ke cap/thu hoi/cap lai - kich ban tung lam hai ban ghi dung id
        authority::grant_admin(root, admin);                                   // id 0
        authority::approve_issuer(root, issuer, test_utils::vc_type_bachelor(), b"", b"", 0);  // id 1
        authority::revoke_admin(root, admin, test_utils::reason_error());
        authority::grant_admin(root, admin);                                   // id 2
        authority::revoke_issuer(root, issuer, test_utils::reason_error());
        authority::approve_issuer(root, issuer, test_utils::vc_type_master(), b"", b"", 0);    // id 3

        assert!(authority::next_role_id_for_test() == 4, 1);
        assert!(authority::role_id_of_admin(admin) == 2, 2);
        assert!(authority::role_id_of_issuer(issuer) == 3, 3);
        // Ca hai deu dang hoat dong, khong ai de len ai
        assert!(authority::is_active_admin(admin), 4);
        assert!(authority::is_active_issuer(issuer), 5);
    }

    // ===================================================================
    // F-11d  Mot dia chi khong the vua la admin vua la issuer dang hoat dong -
    //        get_info se che mat mot trong hai vai tro.
    // ===================================================================
    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun f11d_active_admin_cannot_also_become_issuer() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let who = test_utils::admin1_addr();
        register_did_for(who);

        authority::grant_admin(root, who);
        authority::approve_issuer(root, who, test_utils::vc_type_bachelor(), b"", b"", 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_ROLE_CONFLICT, location = authority)]
    fun f11d_active_issuer_cannot_also_become_admin() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let who = test_utils::issuer1_addr();
        register_did_for(who);

        authority::approve_issuer(root, who, test_utils::vc_type_bachelor(), b"", b"", 0);
        authority::grant_admin(root, who);
    }

    // ...nhung doi vai tro SAU KHI thu hoi vai tro cu thi duoc.
    #[test]
    fun f11d_role_can_be_switched_after_revocation() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let who = test_utils::issuer1_addr();
        register_did_for(who);

        authority::approve_issuer(root, who, test_utils::vc_type_bachelor(), b"", b"", 0);
        authority::revoke_issuer(root, who, test_utils::reason_policy());
        authority::grant_admin(root, who);

        assert!(authority::is_active_admin(who), 1);
        assert!(!authority::is_active_issuer(who), 2);
    }

    // ===================================================================
    // F-11e  So VC dang co hieu luc giam khi thu hoi; tong da tung cap thi khong.
    // ===================================================================
    #[test]
    fun f11e_live_counts_drop_on_revocation_totals_do_not() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor() | test_utils::vc_type_master(),
            b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_bachelor(),
            test_utils::mock_hash_n(1), test_utils::mock_cid(), test_utils::mock_hash_n(2), 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_master(),
            test_utils::mock_hash_n(3), test_utils::mock_cid_v2(), test_utils::mock_hash_n(4), 0
        );

        let (total_i, total_h) = vc_registry::get_counts(issuer, holder);
        let (live_i, live_h) = vc_registry::get_live_counts(issuer, holder);
        assert!(total_i == 2 && total_h == 2, 1);
        assert!(live_i == 2 && live_h == 2, 2);

        vc_registry::revoke_vc(&issuer_sig, 0, test_utils::reason_fraud());

        let (total_i2, total_h2) = vc_registry::get_counts(issuer, holder);
        let (live_i2, live_h2) = vc_registry::get_live_counts(issuer, holder);
        // Tong da tung cap khong doi - do la su that lich su
        assert!(total_i2 == 2 && total_h2 == 2, 3);
        // ...nhung so dang co hieu luc thi giam
        assert!(live_i2 == 1 && live_h2 == 1, 4);
    }

    // Tam ngung cung lam giam so dang co hieu luc, va phuc hoi thi tang lai.
    // Mot van bang dang bi treo thi khong dung de chung minh dieu gi, nen dem
    // no vao "dang co hieu luc" la noi sai voi nguoi xem.
    #[test]
    fun f11e_suspending_also_drops_the_live_count() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor(), b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_bachelor(),
            test_utils::mock_hash_n(7), test_utils::mock_cid(), test_utils::mock_hash_n(8), 0
        );

        let (live_i, live_h) = vc_registry::get_live_counts(issuer, holder);
        assert!(live_i == 1 && live_h == 1, 1);

        vc_registry::suspend_vc(&issuer_sig, 0, test_utils::reason_technical());
        let (live_i2, live_h2) = vc_registry::get_live_counts(issuer, holder);
        assert!(live_i2 == 0 && live_h2 == 0, 2);

        // Chi admin moi phuc hoi duoc VC da tam ngung
        vc_registry::admin_reinstate_vc(root, 0, test_utils::reason_error());
        let (live_i3, live_h3) = vc_registry::get_live_counts(issuer, holder);
        assert!(live_i3 == 1 && live_h3 == 1, 3);

        // Thu hoi sau khi phuc hoi: giam dung mot lan, khong am
        vc_registry::revoke_vc(&issuer_sig, 0, test_utils::reason_fraud());
        let (live_i4, live_h4) = vc_registry::get_live_counts(issuer, holder);
        assert!(live_i4 == 0 && live_h4 == 0, 4);

        // Tong da tung cap van la 1 tu dau den cuoi
        let (total_i, total_h) = vc_registry::get_counts(issuer, holder);
        assert!(total_i == 1 && total_h == 1, 5);
    }

    // Thu hoi mot VC dang TAM NGUNG khong duoc giam bo dem lan thu hai -
    // no da duoc giam luc tam ngung roi. Bo dem u64 tru qua 0 se tran.
    #[test]
    fun f11e_revoking_a_suspended_vc_does_not_double_decrement() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        let issuer_sig = register_did_for(issuer);
        let holder = test_utils::holder1_addr();
        register_did_for(holder);

        authority::approve_issuer(
            root, issuer, test_utils::vc_type_bachelor() | test_utils::vc_type_master(),
            b"", b"", 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_bachelor(),
            test_utils::mock_hash_n(11), test_utils::mock_cid(), test_utils::mock_hash_n(12), 0
        );
        vc_registry::issue_vc(
            &issuer_sig, holder, test_utils::vc_type_master(),
            test_utils::mock_hash_n(13), test_utils::mock_cid_v2(), test_utils::mock_hash_n(14), 0
        );

        vc_registry::suspend_vc(&issuer_sig, 0, test_utils::reason_technical());
        vc_registry::revoke_vc(&issuer_sig, 0, test_utils::reason_fraud());

        // Con lai dung mot VC dang hoat dong, khong bi tru hai lan thanh tran so
        let (live_i, live_h) = vc_registry::get_live_counts(issuer, holder);
        assert!(live_i == 1 && live_h == 1, 1);
    }

    // Phan trang voi `start` cuc lon phai tra ve trang rong, khong duoc abort
    // vi tran so khi tinh start + limit.
    #[test]
    fun f10_huge_start_returns_empty_page_without_overflow() {
        setup();
        let page = did_registry::get_dids_paginated(18446744073709551615, 10);
        assert!(vector::is_empty(&page), 1);
        let vcs = vc_registry::get_vcs_paginated(18446744073709551615, 200);
        assert!(vector::is_empty(&vcs), 2);
    }

    // ===================================================================
    // F-12  Rà soát trước khi publish lại: chặn các quyền vượt mức.
    // ===================================================================

    fun approved_issuer(root: &signer, addr: address, mask: u64): signer {
        let sig = register_did_for(addr);
        authority::approve_issuer(root, addr, mask, b"", b"", 0);
        sig
    }

    // Issuer chi duoc cap cu nhan khong duoc cap "cu nhan + tien si".
    #[test]
    #[expected_failure(abort_code = errors::E_UNAUTHORIZED_VC_TYPE, location = authority)]
    fun f12_multibit_vc_type_cannot_exceed_mask() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = approved_issuer(root, test_utils::issuer1_addr(), test_utils::vc_type_bachelor());
        register_did_for(test_utils::holder1_addr());
        vc_registry::issue_vc(&issuer, test_utils::holder1_addr(),
            test_utils::vc_type_bachelor() | test_utils::vc_type_phd(),
            test_utils::mock_hash(), test_utils::mock_vc_cid(), test_utils::mock_hash_v2(), 0);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_UNAUTHORIZED_VC_TYPE, location = authority)]
    fun f12_vc_type_zero_rejected() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = approved_issuer(root, test_utils::issuer1_addr(), test_utils::vc_type_bachelor());
        register_did_for(test_utils::holder1_addr());
        vc_registry::issue_vc(&issuer, test_utils::holder1_addr(), 0,
            test_utils::mock_hash(), test_utils::mock_vc_cid(), test_utils::mock_hash_v2(), 0);
    }

    // Kieu nhieu bit van hop le khi nam tron trong mask.
    #[test]
    fun f12_multibit_vc_type_within_mask_allowed() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let mask = test_utils::vc_type_bachelor() | test_utils::vc_type_transcript();
        let issuer = approved_issuer(root, test_utils::issuer1_addr(), mask);
        register_did_for(test_utils::holder1_addr());
        vc_registry::issue_vc(&issuer, test_utils::holder1_addr(), mask,
            test_utils::mock_hash(), test_utils::mock_vc_cid(), test_utils::mock_hash_v2(), 0);
        assert!(vc_registry::total_vcs() == 1, 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_SELF_ISSUE, location = vc_registry)]
    fun f12_issuer_cannot_self_issue() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = approved_issuer(root, test_utils::issuer1_addr(), test_utils::vc_type_bachelor());
        vc_registry::issue_vc(&issuer, test_utils::issuer1_addr(), test_utils::vc_type_bachelor(),
            test_utils::mock_hash(), test_utils::mock_vc_cid(), test_utils::mock_hash_v2(), 0);
    }

    // Issuer uy quyen khong go duoc quyet dinh thu hoi cua admin.
    #[test]
    #[expected_failure(abort_code = errors::E_NOT_AUTHORIZED, location = authority)]
    fun f12_delegating_issuer_cannot_reapprove_revoked_issuer() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let parent = register_did_for(test_utils::issuer1_addr());
        authority::approve_issuer(root, test_utils::issuer1_addr(),
            test_utils::vc_type_bachelor() | test_utils::vc_type_delegation(),
            test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
        let child = test_utils::issuer2_addr();
        approved_issuer(root, child, test_utils::vc_type_bachelor());
        authority::revoke_issuer(root, child, test_utils::reason_fraud());

        authority::approve_issuer(&parent, child, test_utils::vc_type_bachelor(),
            test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
    }

    // Nhung admin/root van cap lai duoc (F-04 giu nguyen).
    #[test]
    fun f12_root_can_still_reapprove_revoked_issuer() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let child = test_utils::issuer2_addr();
        approved_issuer(root, child, test_utils::vc_type_bachelor());
        authority::revoke_issuer(root, child, test_utils::reason_fraud());
        authority::approve_issuer(root, child, test_utils::vc_type_bachelor(), b"", b"", 0);
        assert!(authority::is_active_issuer(child), 1);
    }

    #[test]
    #[expected_failure(abort_code = errors::E_PROTECTED_TARGET, location = authority)]
    fun f12_admin_cannot_revoke_another_admin_did() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let a1 = register_did_for(test_utils::admin1_addr());
        register_did_for(test_utils::admin2_addr());
        authority::grant_admin(root, test_utils::admin1_addr());
        authority::grant_admin(root, test_utils::admin2_addr());
        authority::admin_revoke_did(&a1, test_utils::admin2_addr(), test_utils::reason_other());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_PROTECTED_TARGET, location = authority)]
    fun f12_admin_cannot_suspend_root_did() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let a1 = register_did_for(test_utils::admin1_addr());
        authority::grant_admin(root, test_utils::admin1_addr());
        authority::admin_suspend_did(&a1, test_utils::root_addr(), test_utils::reason_other());
    }

    // Root van xu ly duoc DID cua admin; admin van xu ly duoc DID nguoi thuong.
    #[test]
    fun f12_root_and_admin_keep_legitimate_did_powers() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let a1 = register_did_for(test_utils::admin1_addr());
        register_did_for(test_utils::admin2_addr());
        register_did_for(test_utils::holder1_addr());
        authority::grant_admin(root, test_utils::admin1_addr());
        authority::grant_admin(root, test_utils::admin2_addr());

        authority::admin_suspend_did(root, test_utils::admin2_addr(), test_utils::reason_other());
        assert!(!authority::is_active_admin(test_utils::admin2_addr()), 1);

        authority::admin_suspend_did(&a1, test_utils::holder1_addr(), test_utils::reason_fraud());
        authority::admin_reactivate_did(&a1, test_utils::holder1_addr(), test_utils::reason_other());
        assert!(did_registry::has_active_did(test_utils::holder1_addr()), 2);
    }

    // DID chu tu khoa (nghi lo khoa) thi admin khong mo thay duoc.
    #[test]
    #[expected_failure(abort_code = errors::E_OWNER_LOCKED, location = did_registry)]
    fun f12_admin_cannot_reopen_self_locked_did() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let holder = register_did_for(test_utils::holder1_addr());
        did_registry::suspend_own_did(&holder);
        authority::admin_reactivate_did(root, test_utils::holder1_addr(), test_utils::reason_other());
    }

    // View tra loi giong assert: DID bi thu hoi thi khong con la issuer/admin tin cay.
    #[test]
    fun f12_views_respect_revoked_did() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let issuer = test_utils::issuer1_addr();
        register_did_for(issuer);
        authority::approve_issuer(root, issuer,
            test_utils::vc_type_bachelor() | test_utils::vc_type_delegation(),
            test_utils::mock_vc_cid(), test_utils::mock_hash(), 0);
        register_did_for(test_utils::admin1_addr());
        authority::grant_admin(root, test_utils::admin1_addr());
        assert!(authority::is_active_issuer(issuer) && authority::can_delegate(issuer), 1);
        assert!(authority::is_active_admin(test_utils::admin1_addr()), 2);

        authority::admin_revoke_did(root, issuer, test_utils::reason_key_compromise());
        authority::admin_revoke_did(root, test_utils::admin1_addr(), test_utils::reason_key_compromise());
        assert!(!authority::is_active_issuer(issuer), 3);
        assert!(!authority::can_delegate(issuer), 4);
        assert!(!authority::is_active_admin(test_utils::admin1_addr()), 5);
    }

    // Khong chiem truoc duoc DID mang dia chi nguoi khac.
    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_BOUND_TO_OWNER, location = did_registry)]
    fun f12_cannot_squat_someone_elses_did() {
        setup();
        let attacker = account::create_account_for_test(test_utils::random1_addr());
        did_registry::register_did(&attacker, test_utils::did_for(test_utils::holder1_addr()),
            test_utils::mock_cid(), test_utils::mock_hash());
    }

    #[test]
    #[expected_failure(abort_code = errors::E_DID_NOT_BOUND_TO_OWNER, location = did_registry)]
    fun f12_did_must_start_with_did_prefix() {
        setup();
        let h = account::create_account_for_test(test_utils::holder1_addr());
        did_registry::register_did(&h, test_utils::did_with_prefix(b"xyz:vnu:", test_utils::holder1_addr()),
            test_utils::mock_cid(), test_utils::mock_hash());
    }

    // Sau khi bi thu hoi, chuoi DID cu khong dung lai duoc - phai dung chuoi moi.
    #[test]
    #[expected_failure(abort_code = errors::E_DID_ALREADY_REGISTERED, location = did_registry)]
    fun f12_revoked_did_string_not_reusable() {
        setup();
        let root = &account::create_account_for_test(test_utils::root_addr());
        let h = register_did_for(test_utils::holder1_addr());
        authority::admin_revoke_did(root, test_utils::holder1_addr(), test_utils::reason_key_compromise());
        did_registry::register_did(&h, test_utils::did_for(test_utils::holder1_addr()),
            test_utils::mock_cid_v2(), test_utils::mock_hash_v2());
    }

    // ========== HELPERS ==========

    fun setup() {
        let aptos_framework = &account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(aptos_framework);
        test_utils::fast_forward_by(test_utils::initial_time_seconds());

        let deployer = &account::create_account_for_test(test_utils::deployer_addr());
        did_registry::initialize_for_test(deployer);
        authority::initialize_for_test(deployer);
        vc_registry::initialize_for_test(deployer);
        register_did_for(test_utils::root_addr());
    }

    fun register_did_for(addr: address): signer {
        let sig = account::create_account_for_test(addr);
        did_registry::register_did(
            &sig,
            test_utils::did_for(addr),
            test_utils::mock_cid(),
            test_utils::mock_hash()
        );
        sig
    }
}
