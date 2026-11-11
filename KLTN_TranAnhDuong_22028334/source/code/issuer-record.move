struct RoleRecord has copy, drop, store {
    owner:              address,      // dia chi cua don vi duoc cap tham quyen
    version:            u64,          // tang moi lan duoc cap lai sau khi bi thu hoi
    approved_by:        address,      // ai da phe duyet: root, admin, hoac issuer uy quyen
    approved_at:        u64,          // dau thoi gian cua chuoi tai thoi diem phe duyet
    vc_type_mask:       u64,          // mat na bit: pham vi loai van bang duoc phep cap
    delegation_vc_cid:  vector<u8>,   // dinh danh noi dung cua chung thuc uy quyen
    delegation_vc_hash: vector<u8>,   // SHA3-256 cua chung thuc uy quyen, 32 byte
    expires_at:         u64,          // thoi han uy quyen; 0 = vinh vien
    status:             u8,           // 1 = dang hoat dong, 2 = da thu hoi, 3 = tam dinh chi
    status_reason:      vector<u8>,   // ly do cua lan doi trang thai gan nhat
    status_updated_at:  u64,          // dau thoi gian cua lan doi trang thai gan nhat
}
