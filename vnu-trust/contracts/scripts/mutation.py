#!/usr/bin/env python3
"""Kiem thu dot bien cho cac rao chan moi cua ban nang cap 13/11/2026 (C1-C3).

Moi dot bien go hoac lam yeu MOT rao, chay tren BAN SAO tam cua goi (ma that
khong bao gio bi sua), roi doi phai co it nhat mot test chuyen do. Rao nao
"song sot" nghia la chua co test that su kiem no (bai hoc #15, #29).

    python3 contracts/scripts/mutation.py              # chay het, TUAN TU
    python3 contracts/scripts/mutation.py C3-holder    # chay mot so dot bien
    python3 contracts/scripts/mutation.py --list

CHAY TUAN TU co chu y: may 3 GB RAM, moi `aptos move test` ~1 GB; chay song song
lam sap WSL (bai hoc #34).
"""
import os
import shutil
import subprocess
import sys
import tempfile

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V = "sources/vc_registry.move"
D = "sources/did_registry.move"
A = "sources/authority.move"
R = "review_reissue_test"

# (id, tep, nguyen van, thay bang, --filter cho aptos move test)
MUTATIONS = [
    ("C1-a", D, "assert!(prev.status != DID_STATUS_REVOKED, errors::did_permanently_revoked());", "", "register_did"),
    ("C1-b", D,
     "            assert!(prev.status != DID_STATUS_REVOKED, errors::did_permanently_revoked());\n"
     "            abort errors::owner_has_did()",
     "            assert!(prev.status == DID_STATUS_REVOKED, errors::owner_has_did());", "m01_"),
    ("C2-empty", V, "assert!(n > 0 && n <= MAX_BATCH, errors::invalid_batch());",
     "assert!(n <= MAX_BATCH, errors::invalid_batch());", R),
    ("C2-max", V, "assert!(n > 0 && n <= MAX_BATCH, errors::invalid_batch());",
     "assert!(n > 0, errors::invalid_batch());", R),
    ("C2-order", V, "assert!(i == 0 || id > *vector::borrow(&vc_ids, i - 1), errors::invalid_batch());", "", R),
    ("C2-admin", V, "if (mode == BY_ADMIN) authority::assert_is_active_admin(caller);", "", R),
    ("C2-parent", V, "assert!(authority::is_current_parent(caller, issuer), errors::not_parent_issuer());", "", R),
    ("C2-parent-state", V, "if (mode == BY_PARENT) authority::assert_can_manage_own_vcs(caller);", "", R),
    ("C2-skip-revoked", V, "if (record.status == VC_STATUS_REVOKED) return false;", "", R),
    ("C2-skip-expired", V,
     "record.status == VC_STATUS_ACTIVE && effective_status(record, now) != VC_STATUS_EXPIRED",
     "record.status == VC_STATUS_ACTIVE", R),
    ("C2-current-parent", A, "owner == parent && *smart_table::borrow(&a.issuers, owner) == id",
     "owner == parent", R),
    ("C3-init", V,
     "        let caller = signer::address_of(issuer);\n"
     "        assert!(exists<ReplacementRegistry>(@vnu), errors::not_initialized());",
     "        let caller = signer::address_of(issuer);", R),
    ("C3-reissuer", V,
     "assert!(caller == old.issuer_addr || authority::is_current_parent(caller, old.issuer_addr), errors::not_reissuer());",
     "", R),
    ("C3-reissuer-parent", V,
     "assert!(caller == old.issuer_addr || authority::is_current_parent(caller, old.issuer_addr), errors::not_reissuer());",
     "assert!(caller == old.issuer_addr, errors::not_reissuer());", R),
    ("C3-revoked", V, "        assert!(old.status != VC_STATUS_REVOKED, errors::vc_already_revoked());\n", "", R),
    ("C3-suspended", V, "        assert!(old.status == VC_STATUS_ACTIVE, errors::vc_not_active());\n", "", R),
    # Go han dong assert lam ham mat lan doc ReplacementRegistry duy nhat -> loi
    # "acquires thua", khong bien dich. Giu lan doc, cho dieu kien luon dung.
    ("C3-replaced-once", V,
     "assert!(!smart_table::contains(&borrow_global<ReplacementRegistry>(@vnu).replaced_by, old.id), errors::vc_already_replaced());",
     "assert!(smart_table::length(&borrow_global<ReplacementRegistry>(@vnu).replaced_by) < 18446744073709551615, errors::vc_already_replaced());",
     R),
    ("C3-same-type", V, "assert!(new_type == old.vc_type, errors::invalid_replacement());", "", R),
    ("C3-holder", V,
     "assert!(new_holder == old.holder_addr || !did_registry::has_active_did(old.holder_addr), errors::holder_still_active());",
     "", R),
    ("C3-link-newer", V, "assert!(new_vc_id > old_vc_id, errors::invalid_replacement());", "", R),
    ("C3-link-active", V,
     "assert!(effective_status(&new, timestamp::now_seconds()) == VC_STATUS_ACTIVE, errors::invalid_replacement());",
     "", R),
    ("C3-link-replaces", V,
     "assert!(!smart_table::contains(&borrow_global<ReplacementRegistry>(@vnu).replaces, new_vc_id), errors::invalid_replacement());",
     "", R),
    ("C3-link-admin", V,
     "        let caller = signer::address_of(admin);\n"
     "        authority::assert_is_active_admin(caller);\n"
     "        assert!(exists<ReplacementRegistry>(@vnu), errors::not_initialized());",
     "        let caller = signer::address_of(admin);\n"
     "        assert!(exists<ReplacementRegistry>(@vnu), errors::not_initialized());", R),
    ("C3-keep-reason", V,
     "        if (old.status != VC_STATUS_REVOKED) {\n            write_status(",
     "        if (true) {\n            write_status(", R),
    ("C3-init-signer", V,
     "    public entry fun init_replacement_registry(publisher: &signer) {\n"
     "        assert!(signer::address_of(publisher) == @vnu, errors::not_authorized());",
     "    public entry fun init_replacement_registry(publisher: &signer) {", R),
]


def run_one(mid, path, old, new, flt, base):
    d = os.path.join(base, mid)
    shutil.rmtree(d, ignore_errors=True)
    shutil.copytree(PKG, d, ignore=shutil.ignore_patterns("PROMPT_RA_SOAT.md", "scripts"))
    try:
        p = os.path.join(d, path)
        src = open(p, encoding="utf-8").read()
        if src.count(old) != 1:
            return "KHONG-AP-DUNG", f"nguyen van xuat hien {src.count(old)} lan"
        open(p, "w", encoding="utf-8").write(src.replace(old, new))
        r = subprocess.run(["aptos", "move", "test", "--skip-fetch-latest-git-deps", "--filter", flt],
                           cwd=d, capture_output=True, text=True)
        out = r.stdout + r.stderr
        fails = [l.split("::")[-1].strip() for l in out.splitlines() if l.startswith("[ FAIL")]
        if fails:
            return "BI-BAT", f"{len(fails)} test do: {', '.join(fails[:3])}"
        if "Test result" not in out:
            return "KHONG-BIEN-DICH", out.strip().splitlines()[-1][:120] if out.strip() else ""
        return "SONG-SOT", "khong test nao do"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    args = sys.argv[1:]
    if args == ["--list"]:
        print("\n".join(m[0] for m in MUTATIONS))
        return 0
    chosen = [m for m in MUTATIONS if not args or m[0] in args]
    base = tempfile.mkdtemp(prefix="vnu-mut-", dir=os.environ.get("MUT_TMP"))
    bad = 0
    try:
        for i, (mid, path, old, new, flt) in enumerate(chosen, 1):
            verdict, detail = run_one(mid, path, old, new, flt, base)
            bad += verdict != "BI-BAT"
            print(f"[{i}/{len(chosen)}] {mid:20} {verdict:16} {detail}", flush=True)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print(f"\n{len(chosen) - bad}/{len(chosen)} dot bien bi bat")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
