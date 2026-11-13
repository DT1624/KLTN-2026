// Fixture dung chung cho moi bo test.
//
// Quy uoc:
//   - `setup()` dung the gioi rong: dong ho o T0, ba module da khoi tao boi
//     DEPLOYER (@vnu), root = @root_admin (0x12345) va root CHUA co DID.
//   - `user(a)` = tai khoan + DID dang ACTIVE. Moi vai tro deu dung tren `user`.
//   - Hash duoc sinh tu `seed` de moi VC co hash rieng.
#[test_only]
module vnu::test_utils {
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::timestamp;
    use vnu::authority;
    use vnu::did_registry;
    use vnu::vc_registry;

    // === Dia chi ===
    const ADMIN_1:  address = @0xAA01;
    const ADMIN_2:  address = @0xAA02;
    const ISSUER_1: address = @0xBB01;
    const ISSUER_2: address = @0xBB02;
    const ISSUER_3: address = @0xBB03;
    const HOLDER_1: address = @0xCC01;
    const HOLDER_2: address = @0xCC02;
    const RANDOM_1: address = @0xDD01;

    const T0:       u64 = 100000000;

    public fun deployer_addr(): address { @vnu }
    public fun root_addr():     address { @root_admin }
    public fun admin1_addr():   address { ADMIN_1 }
    public fun admin2_addr():   address { ADMIN_2 }
    public fun issuer1_addr():  address { ISSUER_1 }
    public fun issuer2_addr():  address { ISSUER_2 }
    public fun issuer3_addr():  address { ISSUER_3 }
    public fun holder1_addr():  address { HOLDER_1 }
    public fun holder2_addr():  address { HOLDER_2 }
    public fun random1_addr():  address { RANDOM_1 }

    // === Trang thai (phai khop hang so trong module) ===
    public fun did_active():        u8 { 1 }
    public fun did_suspended():     u8 { 2 }
    public fun did_revoked():       u8 { 3 }
    public fun role_active():       u8 { 1 }
    public fun role_revoked():      u8 { 2 }
    public fun role_suspended():    u8 { 3 }
    public fun vc_active():         u8 { 1 }
    public fun vc_suspended():      u8 { 2 }
    public fun vc_expired():        u8 { 3 }
    public fun vc_revoked():        u8 { 4 }

    // === Loai van bang ===
    public fun bachelor():    u64 { 1 }
    public fun master():      u64 { 2 }
    public fun phd():         u64 { 4 }
    public fun transcript():  u64 { 8 }
    public fun micro():       u64 { 16 }
    public fun delegation():  u64 { 32 }

    // === Dong ho ===
    public fun t0(): u64 { T0 }
    public fun now(): u64 { timestamp::now_seconds() }
    public fun advance(seconds: u64) { timestamp::fast_forward_seconds(seconds) }

    // === Du lieu gia ===
    public fun cid(): vector<u8>    { b"bafkreicecff3ebjgtmmi2ddmqs4ytrswan44yqhmoctexyozenyzzofcom" }
    public fun cid_v2(): vector<u8> { b"bafkreihk7r6s7punqvyrwdblbsg2ixf45jbjtvla2ymfewgkuq5brwmxgy" }

    /// Hash 32 byte phu thuoc `seed`.
    public fun hash(seed: u8): vector<u8> { bytes(32, seed) }

    /// Vector `len` byte, byte thu i = (i + seed) mod 256.
    public fun bytes(len: u64, seed: u8): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < len) {
            vector::push_back(&mut v, (((i + (seed as u64)) % 256) as u8));
            i = i + 1;
        };
        v
    }

    /// Chuoi DID chuan cua mot dia chi.
    public fun did_for(addr: address): vector<u8> { did_with(b"did:vnu:test:", addr) }

    public fun did_with(prefix: vector<u8>, addr: address): vector<u8> {
        let did = prefix;
        vector::append(&mut did, did_registry::address_hex_for_test(addr));
        did
    }

    // === The gioi ===

    /// Khoi tao chuoi rong; tra ve signer cua root.
    public fun setup(): signer {
        let fx = account::create_account_for_test(@aptos_framework);
        timestamp::set_time_has_started_for_testing(&fx);
        timestamp::fast_forward_seconds(T0);
        let deployer = account::create_account_for_test(@vnu);
        did_registry::initialize_for_test(&deployer);
        authority::initialize_for_test(&deployer);
        vc_registry::initialize_for_test(&deployer);
        account::create_account_for_test(@root_admin)
    }

    /// Tai khoan chua co DID.
    public fun account(addr: address): signer {
        account::create_account_for_test(addr)
    }

    /// Tai khoan co DID ACTIVE.
    public fun user(addr: address): signer {
        let s = account::create_account_for_test(addr);
        did_registry::register_did(&s, did_for(addr), cid(), hash(1));
        s
    }

    /// Signer cua mot dia chi DA co tai khoan (khong tao lai tai khoan).
    public fun signer_of(addr: address): signer {
        account::create_signer_for_test(addr)
    }

    /// Dang ky DID cho mot signer da co (vd root).
    public fun register(s: &signer) {
        did_registry::register_did(s, did_for(std::signer::address_of(s)), cid(), hash(1));
    }

    public fun admin(root: &signer, addr: address): signer {
        let s = user(addr);
        authority::grant_admin(root, addr);
        s
    }

    /// Issuer thuong do root cap (mask khong co bit uy quyen, khong bang chung).
    public fun issuer(root: &signer, addr: address, mask: u64, expires_at: u64): signer {
        let s = user(addr);
        authority::approve_issuer(root, addr, mask, b"", b"", expires_at);
        s
    }

    /// Issuer co bit uy quyen do root cap (kem bang chung).
    public fun delegator(root: &signer, addr: address, mask: u64, expires_at: u64): signer {
        let s = user(addr);
        authority::approve_issuer(root, addr, mask | delegation(), cid(), hash(9), expires_at);
        s
    }

    /// Sub-issuer do `parent` cap qua uy quyen.
    public fun sub_issuer(parent: &signer, addr: address, mask: u64, expires_at: u64): signer {
        let s = user(addr);
        authority::approve_issuer(parent, addr, mask, cid(), hash(8), expires_at);
        s
    }

    /// Cap mot VC; tra ve id tren chuoi. vc_id_hash = hash(seed), content = hash(seed + 100).
    public fun issue(issuer: &signer, holder: address, vc_type: u64, seed: u8, expires_at: u64): u64 {
        vc_registry::issue_vc(issuer, holder, vc_type, hash(seed), cid(), hash(seed + 100), expires_at);
        vc_registry::total_vcs() - 1
    }

    public fun content_hash(seed: u8): vector<u8> { hash(seed + 100) }

    /// Dia chi thu `n` trong mot dai rieng (0xF000...0000 + n), cho test can nhieu dia chi.
    public fun nth_addr(n: u64): address {
        let b = bytes(32, 0);
        let i = 0;
        while (i < 32) { *vector::borrow_mut(&mut b, i) = 0; i = i + 1; };
        *vector::borrow_mut(&mut b, 0) = 0xF0;
        let k = 31;
        let v = n;
        while (v > 0) {
            *vector::borrow_mut(&mut b, k) = ((v % 256) as u8);
            v = v / 256;
            k = k - 1;
        };
        aptos_std::from_bcs::to_address(b)
    }

    /// Hash 32 byte rieng cho moi `n` (bcs cua nth_addr).
    public fun nth_hash(n: u64): vector<u8> { std::bcs::to_bytes(&nth_addr(n)) }

    /// Dang ky DID cho `count` dia chi nth_addr(0..count).
    public fun many_users(count: u64) {
        let n = 0;
        while (n < count) { user(nth_addr(n)); n = n + 1; };
    }
}
