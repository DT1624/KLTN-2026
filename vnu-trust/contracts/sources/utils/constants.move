module vnu::constants {

    // VC Type bits
    // vc_type_mask = (vc_type_1) OR (vc_type_2) OR ...
    const VC_BACHELOR:             u64 = 1; // 0b00000001
    const VC_MASTER:               u64 = 2; //0b00000010
    const VC_PHD:                  u64 = 4; // 0b00000100
    const VC_TRANSCRIPT:           u64 = 8; //0b00001000
    const VC_MICRO_CRED:           u64 = 16; //0b00010000
    const VC_DELEGATION:           u64 = 32; //0b00100000

    // Revocation reasons
    const REASON_FRAUD:             vector<u8> = b"fraud";
    const REASON_ERROR:             vector<u8> = b"error";
    const REASON_POLICY:            vector<u8> = b"policy";
    const REASON_KEY_COMPROMISE:    vector<u8> = b"key compromise";
    const REASON_TECHNICAL:         vector<u8> = b"technical";
    const REASON_OTHER:             vector<u8> = b"Other";

    public inline fun VC_TYPE_BACHELOR():   u64 { 1 }
    public inline fun VC_TYPE_MASTER():     u64 { 2 }
    public inline fun VC_TYPE_PHD():        u64 { 4 }
    public inline fun VC_TYPE_TRANSCRIPT(): u64 { 8 }
    public inline fun VC_TYPE_MICRO_CRED(): u64 { 16 }
    public inline fun VC_TYPE_DELEGATION(): u64 { 32 }

    public inline fun REASON_TYPE_FRAUD():          vector<u8> { b"fraud" }
    public inline fun REASON_TYPE_ERROR():          vector<u8> { b"error" }
    public inline fun REASON_TYPE_POLICY():         vector<u8> { b"policy" }
    public inline fun REASON_TYPE_KEY_COMPROMISE(): vector<u8> { b"key compromise" }
    public inline fun REASON_TYPE_TECHNICAL():      vector<u8> { b"technical" }
    public inline fun REASON_TYPE_OTHER():          vector<u8> { b"Other" }
}
