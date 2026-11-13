/// Bit loai van bang. Mot issuer duoc cap mot MASK (hop cua nhieu bit);
/// moi VC mang DUNG MOT bit va bit do phai nam trong mask cua issuer.
module vnu::constants {

    public inline fun VC_TYPE_BACHELOR():   u64 { 1 }
    public inline fun VC_TYPE_MASTER():     u64 { 2 }
    public inline fun VC_TYPE_PHD():        u64 { 4 }
    public inline fun VC_TYPE_TRANSCRIPT(): u64 { 8 }
    public inline fun VC_TYPE_MICRO_CRED(): u64 { 16 }
    /// Quyen uy quyen: issuer co bit nay duoc cap sub-issuer. Chi root cap duoc.
    public inline fun VC_TYPE_DELEGATION(): u64 { 32 }
    /// Hop cua moi bit da dinh nghia.
    public inline fun ALL_VC_TYPES():       u64 { 63 }

    /// Ly do ghi vao su kien khi chu so huu tu khoa / tu mo DID.
    public inline fun REASON_TYPE_OTHER():  vector<u8> { b"Other" }

    /// Mask hop le: khac 0 va khong co bit la.
    public inline fun is_valid_mask(mask: u64): bool {
        mask != 0 && (mask & ALL_VC_TYPES()) == mask
    }

    /// Loai van bang hop le: dung MOT bit da dinh nghia.
    public inline fun is_single_vc_type(vc_type: u64): bool {
        is_valid_mask(vc_type) && (vc_type & (vc_type - 1)) == 0
    }
}
