#!/usr/bin/env python3
"""Go tung rao chan MOI o hai backend roi doi phai co test chuyen do (rang buoc #5,
bai hoc #15/#29). Chay TUAN TU — may 3 GB RAM (bai hoc #34).

    GOFLAGS=-mod=mod GOPATH=... python3 scripts/backend-mutation.py          # tat ca
    python3 scripts/backend-mutation.py TS-batch-event G-self-recheck          # mot vai

Moi dot bien:
  1. ghi sha256 tep;  2. sua tep;  3. dung backend can thiet tren CSDL rieng
  (vnu_trust_mut);  4. chay bo test;  5. khoi phuc;  6. doi chieu sha256 = ban dau.
Truoc het chay MOT LUOT MOC chua sua: moc phai xanh thi "do" moi co nghia.

Loai test:
  mock-TS / mock-Go : backend nghiem ngat + fullnode GIA (tx-binding.mjs), mot phia.
  parity            : hai backend offline (parity.mjs) — sua mot phia thi phai LECH.
"""
import hashlib, os, signal, subprocess, sys, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = "vnu_trust_mut"
TS_REVIEW = "backend/src/services/review.service.ts"
TS_CLIENT = "backend/src/chain/client.ts"
GO_REVIEW = "backend-go/internal/handlers/review.go"
GO_CLIENT = "backend-go/internal/chain/client.go"

# (id, loai test, tep, nguyen van, thay bang)
MUTATIONS = [
    ("TS-batch-event", "mock-TS", TS_REVIEW,
     "const changedIds = OFFLINE ? null : batchChangedIds(tx);", "const changedIds = null;"),
    ("TS-u64s-arg", "mock-TS", TS_CLIENT,
     "      return Array.isArray(actual) && actual.length === spec.u64s.length\n"
     "        && actual.every((v, i) => String(v) === String(spec.u64s[i]));",
     "      return true;"),
    ("TS-batch-recheck", "mock-TS", TS_REVIEW,
     "if (!OFFLINE && (await getVcStatusOnChain(r.on_chain_vc_id as number)) !== target) {", "if (false) {"),
    ("TS-reissue-event", "mock-TS", TS_REVIEW,
     'throw badRequest("Giao dịch không phát VCReplacedEvent khớp văn bằng cũ và mới");', "void 0;"),
    ("TS-link-recheck", "mock-TS", TS_REVIEW,
     "  if (!OFFLINE) await assertLinkedOnChain(old.on_chain_vc_id as number, neu.on_chain_vc_id as number);\n", ""),
    ("TS-self-recheck", "mock-TS", TS_REVIEW,
     "    if (!onChain || onChain.status !== next) {", "    if (false) {"),
    ("G-batch-event", "mock-Go", GO_REVIEW,
     "\t\tif !a.Chain.Offline() {\n\t\t\tev := chain.FindEvent(tx, a.Chain.Module(\"vc_registry\")+\"::VCBatchProcessedEvent\")",
     "\t\tif false {\n\t\t\tev := chain.FindEvent(tx, a.Chain.Module(\"vc_registry\")+\"::VCBatchProcessedEvent\")"),
    ("G-u64s-arg", "mock-Go", GO_CLIENT,
     '\t\treturn strings.Join(got, ",") == want.Val', "\t\treturn true"),
    ("G-batch-recheck", "mock-Go", GO_REVIEW,
     "if !a.Chain.Offline() && a.Chain.VCStatus(ctx, *row.OnChainVCID) != target {", "if false {"),
    ("G-reissue-event", "mock-Go", GO_REVIEW,
     'return httpx.BadRequest("Giao dịch không phát VCReplacedEvent khớp văn bằng cũ và mới")', "_ = 0"),
    ("G-link-recheck", "mock-Go", GO_REVIEW,
     "a.assertLinkedOnChain(ctx, *old.OnChainVCID, *neu.OnChainVCID)", "error(nil)"),
    ("G-self-recheck", "mock-Go", GO_REVIEW,
     "\t\tif d == nil || d.Status != body.Status {", "\t\tif false {"),
    # Offline: sua MOT phia, phia kia giu dung -> doi chieu phai LECH.
    ("TS-reissue-holder", "parity", TS_REVIEW,
     "if (input.holderAddress !== old.holder_address && (await hasActiveDid(old.holder_address))) {", "if (false) {"),
    ("TS-migration-olddid", "parity", TS_REVIEW,
     "  if (await hasActiveDid(oldAddr)) {", "  if (false) {"),
    # Buoc 6 thanh CANH BAO (C2): hoan tac thi full-flow muc 5b phai do.
    ("TS-step6-advisory", "flow-TS", "backend/src/services/vp.service.ts",
     "overallValid: normalized.every((c) => c.passed || c.advisory),", "overallValid: normalized.every((c) => c.passed),"),
    ("G-step6-advisory", "flow-Go", "backend-go/internal/handlers/verify.go",
     "if !c.Passed && !c.Advisory {", "if !c.Passed {"),
    # P3: rao phong bi, rao gateway, buoc 7 dung van bang TRONG ban trinh bay.
    ("TS-envelope-issuer", "sec-TS", "backend/src/services/envelope.service.ts",
     '  if (issuers !== 1) throw badRequest("Phong bì không hợp lệ: issuer không nằm trong danh sách người nhận");\n', ""),
    ("TS-envelope-extra-keys", "sec-TS", "backend/src/services/envelope.service.ts",
     '  if (got !== [...keys].sort().join(",")) {', "  if (false) {"),
    ("TS-gateway-guard", "sec-TS", "backend/src/routes/public.routes.ts",
     '    if (!isPublicPinned(content)) throw notFound("Không có nội dung công khai tại CID này");\n', ""),
    ("TS-step7-presented", "tamper-TS", "backend/src/services/vp.service.ts",
     '      if (rec?.contentHash) return (OFFLINE || rec.status === "active") && rec.contentHash === sha3_256Hex(doc).toLowerCase();',
     "      if (rec?.contentHash) return true;"),
    ("G-envelope-issuer", "sec-Go", "backend-go/internal/handlers/envelope.go",
     '\tif issuers != 1 {\n\t\treturn httpx.BadRequest("Phong bì không hợp lệ: issuer không nằm trong danh sách người nhận")\n\t}\n', ""),
    ("G-envelope-extra-keys", "sec-Go", "backend-go/internal/handlers/envelope.go",
     '\tif strings.Join(got, ",") != strings.Join(want, ",") {', "\tif false {"),
    ("G-gateway-guard", "sec-Go", "backend-go/internal/handlers/handlers.go",
     "\tif !isPublicPinned(v) {", "\tif false {"),
    ("G-step7-presented", "tamper-Go", "backend-go/internal/handlers/verify.go",
     '\t\t\t\tintact[i] = (a.Chain.Offline() || rec.Status == "active") && rec.ContentHash == strings.ToLower(auth.SHA3256Hex(doc))',
     "\t\t\t\tintact[i] = doc != nil && strings.ToLower(\"\") == \"\""),
    ("G-batch-skip-revoked", "parity", GO_REVIEW,
     '\tif vc.Status == "revoked" {\n\t\treturn false\n\t}\n\tif target == "revoked" {',
     '\tif target == "revoked" {'),
]


def sha(path):
    return hashlib.sha256(open(os.path.join(ROOT, path), "rb").read()).hexdigest()


def psql(sql):
    subprocess.run(["docker", "exec", "-i", "vnu_trust_postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1",
                    "-U", "vnu_trust", "-d", "postgres", "-c", sql], check=True, capture_output=True)


def fresh_db():
    psql(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
    psql(f"CREATE DATABASE {DB}")
    with open(os.path.join(ROOT, "db/schema.sql"), "rb") as f:
        subprocess.run(["docker", "exec", "-i", "vnu_trust_postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1",
                        "-U", "vnu_trust", "-d", DB], stdin=f, check=True, capture_output=True)


def start(lang, port, strict_mock):
    env = dict(os.environ, DB_NAME=DB, PORT=str(port), LOG_LEVEL="warn",
               RATE_LIMIT_PER_MIN="100000", AUTH_RATE_LIMIT_PER_MIN="5000",
               VERIFY_ONCHAIN="true" if strict_mock else "false")
    if strict_mock:
        env["CHAIN_FULLNODE"] = "http://localhost:4099/v1"
    if lang == "TS":
        cmd, cwd = ["npx", "tsx", "src/server.ts"], os.path.join(ROOT, "backend")
    else:
        cmd, cwd = ["./run.sh"], os.path.join(ROOT, "backend-go")
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    for _ in range(240):
        try:
            urllib.request.urlopen(f"http://localhost:{port}/health", timeout=1)
            return p
        except Exception:
            if p.poll() is not None:
                return None  # khong bien dich / khong khoi dong duoc
            time.sleep(0.5)
    stop(p)
    return None


def stop(p):
    if p and p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)


def run_tests(kind):
    """True = bo test XANH."""
    fresh_db()
    procs = []
    try:
        if kind.split("-")[0] in ("flow", "sec", "tamper"):
            script = {"flow": "full-flow.mjs", "sec": "security-regression.mjs", "tamper": "tamper-check.mjs"}[kind.split("-")[0]]
            lang = kind.split("-")[1]
            port = 4010 if lang == "TS" else 4011
            p = start(lang, port, False)
            if not p:
                return None
            procs.append(p)
            r = subprocess.run(["node", f"scripts/{script}"], cwd=os.path.join(ROOT, "backend"),
                               env=dict(os.environ, API_BASE=f"http://localhost:{port}/api"),
                               capture_output=True, text=True)
        elif kind.startswith("mock-"):
            lang = kind[5:]
            port = 4095 if lang == "TS" else 4096
            p = start(lang, port, True)
            if not p:
                return None
            procs.append(p)
            env = dict(os.environ, MOCK_PORT="4099",
                       TS_BASE=f"http://localhost:4095/api" if lang == "TS" else "skip",
                       GO_BASE=f"http://localhost:4096/api" if lang == "Go" else "skip")
            r = subprocess.run(["node", "scripts/tx-binding.mjs"], cwd=os.path.join(ROOT, "backend"),
                               env=env, capture_output=True, text=True)
        else:
            for lang, port in (("TS", 4010), ("Go", 4011)):
                p = start(lang, port, False)
                if not p:
                    return None
                procs.append(p)
            r = subprocess.run(["bash", "-c", f". '{ROOT}/scripts/lib.sh' && TS_BASE=http://localhost:4010/api "
                                f"GO_BASE=http://localhost:4011/api node_noble '{ROOT}/scripts/parity.mjs'"],
                               capture_output=True, text=True)
        tail = [l for l in r.stdout.splitlines() if "FAIL" in l or "LỆCH" in l][:3]
        run_tests.last = (r.stdout.strip().splitlines() or ["?"])[-1] + (" | " + " | ".join(tail) if tail else "")
        return r.returncode == 0
    finally:
        for p in procs:
            stop(p)


def main():
    chosen = [m for m in MUTATIONS if len(sys.argv) < 2 or m[0] in sys.argv[1:]]
    kinds = sorted({m[1] for m in chosen})
    print("== Luot moc (chua sua) ==", flush=True)
    for k in kinds:
        ok = run_tests(k)
        print(f"  {k:8} {'XANH' if ok else 'DO/LOI'}  {run_tests.last if ok is not None else 'khong khoi dong'}", flush=True)
        if not ok:
            print("Moc khong xanh — dung lai, ket qua dot bien se vo nghia.")
            return 2
    bad = 0
    print("\n== Dot bien ==", flush=True)
    for i, (mid, kind, path, old, new) in enumerate(chosen, 1):
        full = os.path.join(ROOT, path)
        before = sha(path)
        src = open(full, encoding="utf-8").read()
        if src.count(old) != 1:
            print(f"[{i}/{len(chosen)}] {mid:22} KHONG-AP-DUNG (nguyen van xuat hien {src.count(old)} lan)", flush=True)
            bad += 1
            continue
        try:
            open(full, "w", encoding="utf-8").write(src.replace(old, new))
            ok = run_tests(kind)
        finally:
            open(full, "w", encoding="utf-8").write(src)
        restored = sha(path) == before
        verdict = "KHONG-KHOI-DONG" if ok is None else ("SONG-SOT" if ok else "BI-BAT")
        bad += verdict != "BI-BAT" or not restored
        print(f"[{i}/{len(chosen)}] {mid:22} {verdict:15} sha {before[:12]} {'= khoi phuc' if restored else '!= LOI KHOI PHUC'}"
              f"  {run_tests.last if ok is not None else ''}", flush=True)
    psql(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
    print(f"\n{len(chosen) - bad}/{len(chosen)} dot bien bi bat")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
