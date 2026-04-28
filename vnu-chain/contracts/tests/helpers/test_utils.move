#[test_only]
module governance::test_utils {
    use std::vector;
    use aptos_framework::timestamp;

    // === Test address ===
    const ROOT:         address = @governance;
    const ADMIN_1:      address = @0xAA01;
    const ADMIN_2:      address = @0xAA02;
    const ISSUER_1:     address = @0xBB01;
    const ISSUER_2:     address = @0xBB02;
    const HOLDER_1:     address = @0xCC01;
    const HOLDER_2:     address = @0xCC02;
    const RANDOM_1:     address = @0xDD01;
    const RANDOM_2:     address = @0xDD02;

    // === DID Status ===
    const DID_STATUS_ACTIVE:        u8 = 1;
    const DID_STATUS_SUSPENDED:     u8 = 2;
    const DID_STATUS_REVOKED:       u8 = 3;

    // === Admin status ===
    const ADMIN_STATUS_ACTIVE:      u8 = 1;
    const ADMIN_STATUS_REVOKED:     u8 = 2;

    // === Issuer status ===
    const ISSUER_STATUS_ACTIVE:     u8 = 1;
    const ISSUER_STATUS_REVOKED:    u8 = 2;
    const ISSUER_STATUS_SUSPENDED:  u8 = 3;

    // === VC status ===
    const VC_STATUS_ACTIVE:         u8 = 1;
    const VC_STATUS_SUSPENDED:      u8 = 2;
    const VC_STATUS_EXPIRED:        u8 = 3;
    const VC_STATUS_REVOKED:        u8 = 4;

    // === VC type bits ===
    const VC_BACHELOR:              u64 = 1;    // 0b00000001
    const VC_MASTER:                u64 = 2;    // 0b00000010
    const VC_PHD:                   u64 = 4;    // 0b00000100
    const VC_TRANSCRIPT:            u64 = 8;    // 0b00001000
    const VC_MICRO_CRED:            u64 = 16;   // 0b00010000
    const VC_DELEGATION:            u64 = 32;   // 0b00100000

    // === Revocation reasons ===
    const REASON_FRAUD:             vector<u8> = b"fraud";
    const REASON_ERROR:             vector<u8> = b"error";
    const REASON_POLICY:            vector<u8> = b"policy";
    const REASON_KEY_COMPROMISE:    vector<u8> = b"key compromise";
    const REASON_TECHNICAL:         vector<u8> = b"technical";
    const REASON_OTHER:             vector<u8> = b"Other";

    public fun initial_time_seconds(): u64 {
        100000000
    }

    public fun fast_forward_by(amount_time: u64) {
        timestamp::fast_forward_seconds(amount_time);
    }

    public fun mock_cid(): vector<u8> {
        b"bafkreicecff3ebjgtmmi2ddmqs4ytrswan44yqhmoctexyozenyzzofcom"
    }

    public fun mock_cid_v2(): vector<u8> {
        b"bafkreihk7r6s7punqvyrwdblbsg2ixf45jbjtvla2ymfewgkuq5brwmxgy"
    }

    public fun mock_vc_cid(): vector<u8> {
        b"0123456789abcdef0123456789abcdef"
    }

    public fun mock_vc_cid_v2(): vector<u8> {
        b"fedcba9876543210fedcba9876543210"
    }

    public fun mock_hash(): vector<u8> {
        let h = vector::empty<u8>();
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut h, i + 10);
            i = i + 1;
        };
        h
    }

    public fun mock_hash_v2(): vector<u8> {
        let h = vector::empty<u8>();
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut h, i + 50);
            i = i + 1;
        };
        h
    }

    public fun did_for(addr: address): vector<u8> {
        let did = b"did:vnu:";
        if (addr == HOLDER_1) {
            vector::append(&mut did, b"0xcc01holder1");
        } else if (addr == HOLDER_2) {
            vector::append(&mut did, b"0xcc02holder2");
        } else if (addr == ISSUER_1) {
            vector::append(&mut did, b"0xbb01issuer1");
        } else if (addr == ISSUER_2) {
            vector::append(&mut did, b"0xbb02issuer2");
        } else if (addr == ADMIN_1) {
            vector::append(&mut did, b"0xaa01admin1");
        } else if (addr == ADMIN_2) {
            vector::append(&mut did, b"0xaa01admin2");
        } else if (addr == RANDOM_1) {
            vector::append(&mut did, b"0xdd01random1");
        } else if (addr == RANDOM_2) {
            vector::append(&mut did, b"0xdd02random2");
        } else {
            vector::append(&mut did, b"0xee01other");
        };
        did
    }

    public fun root_addr():     address { ROOT }
    public fun admin1_addr():   address { ADMIN_1 }
    public fun admin2_addr():   address { ADMIN_2 }
    public fun issuer1_addr():  address { ISSUER_1 }
    public fun issuer2_addr():  address { ISSUER_2 }
    public fun holder1_addr():  address { HOLDER_1 }
    public fun holder2_addr():  address { HOLDER_2 }
    public fun random1_addr():  address { RANDOM_1 }
    public fun random2_addr():  address { RANDOM_2 }

    public fun did_status_active():         u8 { DID_STATUS_ACTIVE }
    public fun did_status_suspended():      u8 { DID_STATUS_SUSPENDED }
    public fun did_status_revoked():        u8 { DID_STATUS_REVOKED }

    public fun admin_status_active():       u8 { ADMIN_STATUS_ACTIVE }
    public fun admin_status_revoked():      u8 { ADMIN_STATUS_REVOKED }

    public fun issuer_status_active():      u8 { ISSUER_STATUS_ACTIVE }
    public fun issuer_status_suspended():   u8 { ISSUER_STATUS_SUSPENDED }
    public fun issuer_status_revoked():     u8 { ISSUER_STATUS_REVOKED }

    public fun vc_status_active():          u8 { VC_STATUS_ACTIVE }
    public fun vc_status_suspended():       u8 { VC_STATUS_SUSPENDED }
    public fun vc_status_expired():         u8 { VC_STATUS_EXPIRED }
    public fun vc_status_revoked():         u8 { VC_STATUS_REVOKED }

    public fun vc_type_bachelor():          u64 { VC_BACHELOR }
    public fun vc_type_master():            u64 { VC_MASTER }
    public fun vc_type_phd():               u64 { VC_PHD }
    public fun vc_type_transcript():        u64 { VC_TRANSCRIPT }
    public fun vc_type_micro_cred():        u64 { VC_MICRO_CRED }
    public fun vc_type_delegation():        u64 { VC_DELEGATION }

    public fun reason_fraud():              vector<u8> { REASON_FRAUD }
    public fun reason_error():              vector<u8> { REASON_ERROR }
    public fun reason_policy():             vector<u8> { REASON_POLICY }
    public fun reason_key_compromise():     vector<u8> { REASON_KEY_COMPROMISE }
    public fun reason_technical():          vector<u8> { REASON_TECHNICAL }
    public fun reason_other():              vector<u8> { REASON_OTHER }
}