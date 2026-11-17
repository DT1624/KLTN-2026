// Duyệt giao diện bằng trình duyệt thật: chụp màn hình, đo cuộn ngang, gom lỗi console,
// tái hiện lỗi nhãn "Khoá khẩn cấp" (mục H) và kiểm giữ phiên ví qua F5 (mục R). KHÔNG sửa mã sản phẩm, KHÔNG gọi chuỗi thật.
//
// Cần sẵn: backend TS ở :4000 với VERIFY_ONCHAIN=false trên một CSDL RIÊNG (không phải
// CSDL dev), vite ở :5173. Chuỗi/faucet bị chặn ở tầng trình duyệt (route abort).
//
//   PLAYWRIGHT_CORE=<đường dẫn playwright-core/index.mjs> SHOT_DIR=<thư mục ảnh> \
//     node frontend/scripts/ui-shots.mjs
//
// Tuỳ chọn: BASE (mặc định http://localhost:5173), CHROME_PATH (mặc định binary
// chrome-headless-shell trong ~/.cache/ms-playwright).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const CORE = process.env.PLAYWRIGHT_CORE;
if (!CORE) { console.error("Thiếu PLAYWRIGHT_CORE (đường dẫn tới playwright-core/index.mjs)"); process.exit(2); }
const { chromium } = await import(pathToFileURL(path.resolve(CORE)).href);

const BASE = process.env.BASE ?? "http://localhost:5173";
const OUT = path.resolve(process.env.SHOT_DIR ?? path.join(os.tmpdir(), "vnu-shots"));
fs.mkdirSync(OUT, { recursive: true });

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const root = path.join(os.homedir(), ".cache", "ms-playwright");
  for (const d of fs.readdirSync(root).filter((x) => x.startsWith("chromium_headless_shell-"))) {
    const p = path.join(root, d, "chrome-headless-shell-linux64", "chrome-headless-shell");
    if (fs.existsSync(p)) return p;
  }
  for (const d of fs.readdirSync(root).filter((x) => x.startsWith("chromium-"))) {
    const p = path.join(root, d, "chrome-linux64", "chrome");
    if (fs.existsSync(p)) return p;
  }
  throw new Error("Không tìm thấy Chromium trong ~/.cache/ms-playwright");
}

const PASS = "Vnu-Trust!2026-xyz9";
const index = [];
const flows = [];
const allErrors = new Map(); // thông điệp -> số lần
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- tiện ích ----------
const pending = new WeakMap(); // page -> lỗi chưa gán vào ảnh nào
function watch(page) {
  pending.set(page, []);
  const add = (s) => { pending.get(page).push(s); allErrors.set(s, (allErrors.get(s) ?? 0) + 1); };
  page.on("console", (m) => { if (m.type() === "error") add("console.error: " + m.text().slice(0, 300)); });
  page.on("pageerror", (e) => add("pageerror: " + String(e.message).slice(0, 300)));
  page.on("requestfailed", (r) => {
    if (/movementnetwork\.xyz/.test(r.url())) return; // chặn có chủ ý
    add(`requestfailed: ${r.method()} ${r.url()} ${r.failure()?.errorText ?? ""}`);
  });
  page.on("response", (r) => {
    if (r.status() >= 400 && /\/api/.test(r.url())) add(`http ${r.status()}: ${r.request().method()} ${new URL(r.url()).pathname}`);
  });
}

async function newCtx(browser, vp = { width: 1280, height: 800 }) {
  const ctx = await browser.newContext({ viewport: vp, locale: "vi-VN" });
  await ctx.route(/movementnetwork\.xyz/, (r) => r.abort()); // rào chắn: không bao giờ chạm chuỗi/faucet thật
  const page = await ctx.newPage();
  page.on("dialog", (d) => d.accept());
  watch(page);
  return { ctx, page };
}

async function overflow(page) {
  return page.evaluate(() => {
    const iw = window.innerWidth;
    const px = document.documentElement.scrollWidth - iw;
    const off = [];
    if (px > 0) {
      for (const el of document.querySelectorAll("body *")) {
        const r = el.getBoundingClientRect();
        if (r.width > 0 && r.right > iw + 1) {
          off.push(`${el.tagName.toLowerCase()}${el.className && typeof el.className === "string" ? "." + el.className.trim().split(/\s+/).slice(0, 3).join(".") : ""} right=${Math.round(r.right)} "${(el.textContent ?? "").trim().slice(0, 30)}"`);
          if (off.length >= 5) break;
        }
      }
    }
    return { px, off };
  });
}

async function shot(page, flowName, name) {
  const vp = page.viewportSize();
  const file = `${flowName}-${name}-${vp.width}.png`;
  await sleep(350); // để hiệu ứng vào trang lắng xuống
  const ov = await overflow(page);
  await page.screenshot({ path: path.join(OUT, file), fullPage: true });
  const errs = pending.get(page).splice(0);
  index.push({ file, url: page.url(), viewport: `${vp.width}x${vp.height}`, overflowPx: ov.px, overflowEls: ov.off, consoleErrors: errs });
  fs.writeFileSync(path.join(OUT, "index.json"), JSON.stringify(index, null, 2));
}

// Đi tới đường dẫn mà KHÔNG tải lại trang (ví chỉ nằm trong bộ nhớ tab).
async function spa(page, p) {
  await page.evaluate((u) => { history.pushState({}, "", u); window.dispatchEvent(new PopStateEvent("popstate")); }, p);
  await page.waitForLoadState("networkidle").catch(() => {});
  await sleep(400);
}

async function banner(page) {
  await page.getByText("Chế độ thử, chưa nối chuỗi.").first().waitFor({ state: "visible", timeout: 15000 });
}

async function runFlow(name, fn, getPage) {
  const t0 = Date.now();
  try {
    const note = await fn();
    flows.push({ flow: name, ok: true, note: note ?? "", sec: Math.round((Date.now() - t0) / 1000) });
  } catch (e) {
    // Chụp trạng thái lỗi để biết trang đang hiện gì.
    try { const pg = getPage?.(); if (pg) await shot(pg, "LOI", name.split(".")[0]); } catch { /* bỏ qua */ }
    flows.push({ flow: name, ok: false, note: String(e.message).split("\n")[0].slice(0, 250), sec: Math.round((Date.now() - t0) / 1000) });
  }
  console.log(`[${flows.at(-1).ok ? "đạt " : "HỎNG"}] ${name}: ${flows.at(-1).note}`);
}

async function createWallet(page, { role, label }) {
  await page.goto(BASE + "/wallet", { waitUntil: "networkidle" });
  await page.getByRole("tab", { name: "Tạo ví mới" }).click();
  await page.getByRole("radio", { name: new RegExp(role) }).check();
  await page.getByLabel("Tên hiển thị").fill(label);
  await page.getByLabel("Mật khẩu ví", { exact: true }).fill(PASS);
  await page.getByLabel("Nhập lại mật khẩu").fill(PASS);
  await page.getByRole("button", { name: "Tạo ví", exact: true }).click();
  await page.getByText("Chép 12 từ này ra giấy ngay bây giờ").waitFor({ timeout: 30000 });
  return page;
}

async function mnemonicSteps(page, flowName, tag) {
  await page.getByRole("button", { name: "Bấm để hiện 12 từ" }).click();
  await shot(page, flowName, `${tag}-12-tu`);
  const words = await page.locator("ol.sheet li span.font-semibold").allTextContents();
  if (words.length !== 12) throw new Error(`đọc được ${words.length} từ, kỳ vọng 12`);
  await page.getByRole("button", { name: "Tôi đã chép xong" }).click();
  await page.getByText("Xác nhận bạn đã chép đúng").waitFor();
  const labels = await page.locator('label[for^="w"]').all();
  for (const l of labels) {
    const id = await l.getAttribute("for");
    await page.locator("#" + id).fill(words[Number(id.slice(1))]);
  }
  await shot(page, flowName, `${tag}-xac-nhan`);
  await page.getByRole("button", { name: "Xác nhận và vào hệ thống" }).click();
  await page.waitForURL((u) => !/\/wallet/.test(u.pathname), { timeout: 30000 });
  await page.waitForLoadState("networkidle").catch(() => {});
}

async function registerDid(page, flowName, tag) {
  await spa(page, "/account");
  await page.getByRole("heading", { name: "Tài khoản", exact: true }).waitFor();
  await banner(page);
  await shot(page, flowName, `${tag}-account-truoc`);
  await page.getByRole("button", { name: "Ký và đăng ký DID" }).click();
  await page.getByText("Đã đăng ký DID").first().waitFor({ timeout: 40000 });
  await shot(page, flowName, `${tag}-account-sau-did`);
}

async function accountIds(page) {
  await spa(page, "/account");
  await page.getByRole("heading", { name: "Tài khoản", exact: true }).waitFor();
  await sleep(500);
  const titles = await page.locator("span.hex[title]").evaluateAll((els) => els.map((e) => e.getAttribute("title")));
  const address = titles.find((t) => /^0x[0-9a-f]{64}$/i.test(t));
  const did = titles.find((t) => t.startsWith("did:"));
  if (!address || !did) throw new Error("không đọc được địa chỉ/DID: " + JSON.stringify(titles));
  return { address, did };
}

// ---------- chạy ----------
const browser = await chromium.launch({ executablePath: findChrome(), headless: true, args: ["--no-sandbox"] });
const S = {}; // trạng thái dùng chung giữa các luồng
let anon, issuer, holder, admin;

try {
  // A. Công khai
  await runFlow("A. công khai", async () => {
    anon = await newCtx(browser);
    const p = anon.page;
    await p.goto(BASE + "/", { waitUntil: "networkidle" });
    await banner(p);
    await shot(p, "A", "home");
    await p.goto(BASE + "/verify", { waitUntil: "networkidle" });
    await shot(p, "A", "verify");
    await p.goto(BASE + "/wallet", { waitUntil: "networkidle" });
    for (const [tab, key] of [["Mở ví", "mo-vi"], ["Tạo ví mới", "tao-vi"], ["Khôi phục ví", "khoi-phuc"]]) {
      await p.getByRole("tab", { name: tab }).click();
      await shot(p, "A", "wallet-" + key);
    }
    return "home, verify, wallet x3 tab";
  });

  // B. issuer
  await runFlow("B. issuer: tạo ví, DID, /issuer", async () => {
    issuer = await newCtx(browser);
    const p = issuer.page;
    await createWallet(p, { role: "Đơn vị cấp bằng", label: "Trường ĐH Công nghệ" });
    await mnemonicSteps(p, "B", "issuer");
    await registerDid(p, "B", "issuer");
    await spa(p, "/issuer");
    await p.getByRole("heading", { name: "Cấp văn bằng", exact: true }).waitFor({ timeout: 15000 });
    await shot(p, "B", "issuer-tab-cap");
    await p.getByRole("tab", { name: /Văn bằng đã cấp/ }).click();
    await shot(p, "B", "issuer-tab-da-cap");
    const tabs = await p.getByRole("tab").allTextContents();
    return "tab: " + tabs.join(" | ");
  });

  // C. holder
  await runFlow("C. holder: tạo ví, DID", async () => {
    holder = await newCtx(browser);
    const p = holder.page;
    await createWallet(p, { role: "Người học", label: "Lê Thu Hà" });
    await mnemonicSteps(p, "C", "holder");
    await registerDid(p, "C", "holder");
    Object.assign(S, await accountIds(p));
    return `address=${S.address.slice(0, 12)}… did=${S.did}`;
  });

  // D. cấp văn bằng
  await runFlow("D. issuer cấp văn bằng", async () => {
    if (!S.address) throw new Error("thiếu địa chỉ holder (luồng C hỏng)");
    const p = issuer.page;
    await spa(p, "/issuer");
    await p.getByRole("tab", { name: "Cấp văn bằng mới" }).click();
    await banner(p);
    await p.getByLabel(/^Địa chỉ ví người nhận/).fill(S.address);
    await p.getByLabel(/^DID người nhận/).fill(S.did);
    await p.getByLabel(/^Mã sinh viên/).fill("22028334");
    await p.getByLabel(/^Tên văn bằng/).fill("Cử nhân Khoa học Máy tính");
    await p.getByLabel(/^Khoa hoặc trường/).fill("Khoa Công nghệ thông tin");
    await p.getByLabel(/^Điểm trung bình/).fill("3.45");
    await p.getByLabel(/^Năm tốt nghiệp/).fill("2026");
    await shot(p, "D", "issuer-form-dien");
    const btn = p.getByRole("button", { name: "Ký và cấp văn bằng" });
    await btn.click();
    // Bắt tiến trình nếu còn kịp (chế độ thử ký cục bộ, rất nhanh).
    const prog = p.locator('ol[class*="space-y-1.5"]');
    if (await prog.first().isVisible().catch(() => false)) await shot(p, "D", "issuer-tien-trinh");
    await p.getByText("Đã cấp văn bằng").first().waitFor({ timeout: 60000 });
    await shot(p, "D", "issuer-ket-qua");
    await p.getByRole("tab", { name: /Văn bằng đã cấp/ }).click();
    await sleep(800);
    await shot(p, "D", "issuer-da-cap");
    return "đã cấp";
  }, () => issuer.page);

  // E. holder chia sẻ
  await runFlow("E. holder chia sẻ", async () => {
    const p = holder.page;
    // react-query giữ danh sách rỗng 10 s (staleTime) từ lần holder vào trang trước khi được cấp bằng:
    // chờ hết hạn rồi mới vào lại, nếu không trang cho kết quả cũ (không phải lỗi, chỉ là đệm).
    await sleep(11000);
    await spa(p, "/account");
    await spa(p, "/holder");
    await p.getByRole("heading", { name: "Văn bằng của tôi" }).waitFor();
    await p.locator("article.sheet").first().waitFor({ timeout: 20000 });
    await sleep(1500); // chờ giải mã + đối chiếu bản neo
    await shot(p, "E", "holder-co-van-bang");
    const cb = p.locator('article.sheet input[type="checkbox"]').first();
    if (await cb.isDisabled()) throw new Error("hộp chọn bị khoá: văn bằng chưa chia sẻ được (chưa giải mã/không active)");
    await cb.check();
    await p.getByRole("button", { name: "Tạo liên kết chia sẻ" }).click();
    await p.getByText("Liên kết đã sẵn sàng").waitFor({ timeout: 30000 });
    await shot(p, "E", "holder-lien-ket");
    S.link = await p.locator('span.hex[title*="/verify/"]').first().getAttribute("title");
    if (!S.link) throw new Error("không đọc được URL chia sẻ");
    return "link=" + S.link.slice(0, 70) + "…";
  }, () => holder.page);

  // F. người xác minh ẩn danh
  await runFlow("F. xác minh qua liên kết", async () => {
    if (!S.link) throw new Error("thiếu liên kết (luồng E hỏng)");
    const p = anon.page;
    await p.goto(S.link, { waitUntil: "networkidle" });
    await shot(p, "F", "verify-truoc");
    const btn = p.getByRole("button", { name: "Xác minh", exact: true });
    if (await btn.isEnabled().catch(() => false)) await btn.click();
    await p.getByText(/hợp lệ|không hợp lệ|Hợp lệ|Không hợp lệ/).first().waitFor({ timeout: 30000 }).catch(() => {});
    await sleep(1800 + 500);
    await shot(p, "F", "verify-ket-qua");
    // Ban 2: sau ket qua + 2 s hoa van phai hien du, con dau khong de chu thich.
    S.rosette = await p.evaluate(() => {
      const svg = document.querySelector('svg[aria-label="Hoa văn đối chiếu của văn bằng"]');
      if (!svg) return { err: "khong thay svg hoa van" };
      const paths = [...svg.querySelectorAll("path")];
      const offs = [...new Set(paths.map((x) => getComputedStyle(x).strokeDashoffset))];
      const note = [...document.querySelectorAll("main p")].find((x) => /đúng hoa văn này/.test(x.textContent ?? ""));
      const seal = [...document.querySelectorAll("main svg")].filter((x) => x !== svg && x.getBoundingClientRect().width > 100).pop();
      const hit = (a, b) => !(a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top);
      const nr = note?.getBoundingClientRect(), sr = seal?.getBoundingClientRect();
      return { paths: paths.length, offsets: offs, animClass: svg.getAttribute("class"), note: !!nr, seal: !!sr, overlap: nr && sr ? hit(nr, sr) : null };
    });
    if (S.rosette.err || S.rosette.paths < 5 || S.rosette.offsets.some((o) => o !== "0px" && o !== "0") || !S.rosette.seal || S.rosette.overlap !== false)
      throw new Error("hoa van/con dau sai: " + JSON.stringify(S.rosette));
    S.verifyText = (await p.locator("main").innerText()).replace(/\s+/g, " ").slice(0, 160);
    // Dán liên kết vào ô tra cứu ở trang chủ.
    await p.goto(BASE + "/", { waitUntil: "networkidle" });
    await p.getByPlaceholder("Dán liên kết hoặc mã cần tra").fill(S.link);
    await p.getByRole("button", { name: "Kiểm tra", exact: true }).click();
    await p.waitForURL(/\/verify\//, { timeout: 10000 });
    S.pasteDest = p.url();
    await shot(p, "F", "tra-cuu-chuyen-trang");
    return "dán link -> " + S.pasteDest.slice(0, 80) + "… | " + S.verifyText.slice(0, 80);
  });

  // G. admin
  await runFlow("G. admin", async () => {
    admin = await newCtx(browser);
    const p = admin.page;
    await createWallet(p, { role: "Quản trị viên", label: "Quản trị Thử nghiệm" });
    await mnemonicSteps(p, "G", "admin");
    await spa(p, "/admin");
    await p.getByRole("heading", { name: /Quản trị/ }).first().waitFor({ timeout: 15000 });
    const tabs = [["Tổng quan", "tong-quan"], ["Đơn vị cấp bằng", "cap-bang"], ["Danh tính", "danh-tinh"], ["Văn bằng", "van-bang"], ["Nhật ký và truy vết", "nhat-ky"]];
    for (const [t, k] of tabs) {
      await p.getByRole("tab", { name: new RegExp("^" + t) }).first().click();
      await sleep(900);
      await shot(p, "G", "admin-" + k);
    }
    await spa(p, "/root");
    await sleep(900);
    await shot(p, "G", "root");
    S.rootText = (await p.locator("main").innerText()).replace(/\s+/g, " ").slice(0, 140);
    await spa(p, "/verifier");
    await sleep(900);
    await shot(p, "G", "verifier");
    return "/root: " + S.rootText;
  });

  // H. tái hiện lỗi nhãn
  await runFlow("H. nhãn khoá khẩn cấp", async () => {
    const p = holder.page;
    await spa(p, "/account");
    await p.getByRole("heading", { name: "Khoá khẩn cấp" }).waitFor({ timeout: 15000 });
    await banner(p);
    const sheet = p.locator("div.rounded-sheet", { has: p.getByRole("heading", { name: "Khoá khẩn cấp" }) }) /* ban 2: khung ky la div.rounded-sheet (SignSheet), khong con class "sheet" */;
    const titleOf = async () => {
      // tiêu đề của Alert trong vùng [role=status] của thẻ này
      const st = sheet.locator('[role="status"]');
      await st.first().waitFor({ timeout: 40000 });
      await sleep(600);
      return (await st.allInnerTexts()).map((t) => t.replace(/\s+/g, " ").trim()).filter(Boolean);
    };
    await sheet.scrollIntoViewIfNeeded();
    await sheet.getByRole("button", { name: "Ký và khoá DID của tôi" }).click();
    const afterLock = await titleOf();
    S.afterLock = afterLock;
    await shot(p, "H", "sau-khoa");
    await sheet.getByRole("button", { name: "Ký và mở khoá DID" }).click();
    await sleep(1500);
    const afterUnlock = await titleOf();
    S.afterUnlock = afterUnlock;
    await shot(p, "H", "sau-mo-khoa");
    return `SAU KHOÁ: ${JSON.stringify(afterLock)} | SAU MỞ KHOÁ: ${JSON.stringify(afterUnlock)}`;
  });

  // I. di động 375x812
  await runFlow("I. di động 375x812", async () => {
    const vp = { width: 375, height: 812 };
    const a = anon.page, h = holder.page, i = issuer.page, ad = admin.page;
    for (const pg of [a, h, i, ad]) await pg.setViewportSize(vp);
    await a.goto(BASE + "/", { waitUntil: "networkidle" });
    await shot(a, "I", "home");
    await a.getByRole("button", { name: /Menu/ }).click();
    await shot(a, "I", "home-menu");
    await a.getByRole("button", { name: /Menu/ }).click().catch(() => {});
    if (S.link) {
      await a.goto(S.link, { waitUntil: "networkidle" });
      const btn = a.getByRole("button", { name: "Xác minh", exact: true });
      if (await btn.isEnabled().catch(() => false)) await btn.click();
      await sleep(2500);
      await shot(a, "I", "verify-ket-qua");
    }
    await a.goto(BASE + "/wallet", { waitUntil: "networkidle" });
    await shot(a, "I", "wallet");
    await spa(h, "/holder"); await sleep(1500); await shot(h, "I", "holder");
    await spa(h, "/account"); await sleep(800); await shot(h, "I", "account");
    await spa(i, "/issuer"); await i.getByRole("tab", { name: "Cấp văn bằng mới" }).click(); await sleep(600); await shot(i, "I", "issuer-cap");
    await spa(ad, "/admin"); await sleep(1000); await shot(ad, "I", "admin-tong-quan");
    // Ngan keo khi da mo vi (ban 2): khoa cuon nen, bay focus, Esc tra focus ve nut Menu.
    await spa(h, "/holder"); await sleep(600);
    const mb = h.locator('button[aria-controls="mobile-nav"]').first();
    await mb.click();
    await h.locator("#mobile-nav").waitFor({ state: "visible" });
    await sleep(500);
    await shot(h, "I", "drawer");
    const ovf = await h.evaluate(() => document.body.style.overflow);
    const info = () => h.evaluate(() => { const d = document.querySelector("#mobile-nav"); const f = [...d.querySelectorAll("a[href], button:not([disabled]), select, input, [tabindex]:not([tabindex='-1'])")]; const c = document.activeElement; return { n: f.length, idx: f.indexOf(c), inside: d.contains(c), tag: c.tagName + ":" + (c.textContent ?? "").trim().slice(0, 20) }; });
    const i0 = await info();
    // Tab tu phan tu cuoi: dua focus toi cuoi roi nhan Tab, ky vong ve dau.
    await h.evaluate(() => { const d = document.querySelector("#mobile-nav"); const f = d.querySelectorAll("a[href], button:not([disabled]), select, input, [tabindex]:not([tabindex='-1'])"); f[f.length - 1].focus(); });
    const before = await info();
    await h.keyboard.press("Tab");
    const after = await info();
    await h.keyboard.press("Escape");
    await sleep(400);
    const closed = !(await h.locator("#mobile-nav").isVisible().catch(() => false));
    const focusMenu = await h.evaluate(() => document.activeElement?.getAttribute("aria-controls") === "mobile-nav");
    const ovf2 = await h.evaluate(() => document.body.style.overflow);
    S.drawer = { ovf, ovfAfterClose: ovf2, initial: i0, before, after, closed, focusMenu };
    if (ovf !== "hidden" || before.idx !== before.n - 1 || after.idx !== 0 || !after.inside || !closed || !focusMenu || ovf2 === "hidden")
      throw new Error("ngan keo sai: " + JSON.stringify(S.drawer));
    return "7 trang + menu + ngan keo " + JSON.stringify(S.drawer);
  });
  // R. giữ phiên ví qua F5 (session.ts): tải lại giữ ví, tab mới thì không, "Khoá ví" xoá bản ghi
  await runFlow("R. phiên ví qua tải lại", async () => {
    const vp = { width: 1280, height: 800 };
    const p = holder.page;
    await p.setViewportSize(vp);
    await spa(p, "/holder");
    await p.getByRole("heading", { name: "Văn bằng của tôi" }).waitFor();
    await p.locator("article.sheet").first().waitFor({ timeout: 20000 });
    await sleep(1500);
    const title = async (pg) => (await pg.locator("article.sheet h3, article.sheet h2").first().innerText()).trim();
    const t0 = await title(p);
    const readIdb = (pg) => pg.evaluate(() => new Promise((res, rej) => {
      const rq = indexedDB.open("vnu-trust-session");
      rq.onerror = () => rej(rq.error);
      rq.onsuccess = () => {
        const db = rq.result;
        const names = [...db.objectStoreNames];
        if (!names.length) { db.close(); return res({ names, recs: [] }); }
        const g = db.transaction(names[0]).objectStore(names[0]).getAll();
        g.onerror = () => rej(g.error);
        g.onsuccess = () => {
          const recs = g.result.map((r) => ({
            fields: Object.keys(r).sort(),
            metaKeys: Object.keys(r.meta ?? {}),
            keyType: r.key?.constructor?.name, extractable: r.key?.extractable,
            keyAlg: r.key?.algorithm?.name,
          }));
          db.close(); res({ names, recs });
        };
      };
    }));
    // R2 trước khi tải lại: đúng 1 bản ghi, khoá không trích xuất được, không lộ bí mật
    const idb = await readIdb(p);
    const rec = idb.recs[0];
    const allowed = ["address", "expiresAt", "iv", "key", "meta", "publicKeyHex", "sessionId", "wrapped"];
    const bad = rec ? rec.fields.filter((f) => !allowed.includes(f)).concat(rec.metaKeys.filter((k) => /mnemonic|privateKey|password/i.test(k))) : ["khong co ban ghi"];
    if (idb.recs.length !== 1 || rec.extractable !== false || rec.keyType !== "CryptoKey" || bad.length)
      throw new Error("R2 sai: " + JSON.stringify({ n: idb.recs.length, rec, bad }));
    await p.reload({ waitUntil: "networkidle" });
    await sleep(2500);
    const path1 = new URL(p.url()).pathname;
    await p.locator("article.sheet").first().waitFor({ timeout: 20000 });
    const t1 = await title(p);
    await shot(p, "R", "r1-sau-f5");
    if (path1 !== "/holder" || t1 !== t0) throw new Error(`R1 sai: url=${path1} tieu de ${JSON.stringify(t0)} -> ${JSON.stringify(t1)}`);
    // R3: tab mới cùng context (không có sid) -> /wallet
    const p2 = await holder.ctx.newPage();
    watch(p2);
    await p2.goto(BASE + "/holder", { waitUntil: "networkidle" });
    await sleep(1500);
    const path3 = new URL(p2.url()).pathname;
    await shot(p2, "R", "r3-tab-moi");
    await p2.close();
    if (path3 !== "/wallet") throw new Error("R3 sai: tab moi o " + path3);
    // R4: khoá ví rồi F5 -> màn mở ví, IndexedDB rỗng
    await p.getByRole("button", { name: /Khoá ví/ }).first().click();
    await sleep(800);
    await p.reload({ waitUntil: "networkidle" });
    await sleep(1500);
    const path4 = new URL(p.url()).pathname;
    const idb4 = await readIdb(p);
    await shot(p, "R", "r4-sau-khoa");
    // Dac ta: "Khoa vi" dua nguoi dung ve trang chu (tra cuu cong khai, nut "Mo vi"), khong phai /wallet;
    // dieu can chung minh la ban ghi bi xoa va vao /holder trong CUNG tab van bi chuyen /wallet.
    const moVi = await p.getByRole("button", { name: /^Mở ví/ }).or(p.getByRole("link", { name: /^Mở ví/ })).first().isVisible().catch(() => false);
    await p.goto(BASE + "/holder", { waitUntil: "networkidle" });
    await sleep(1200);
    const path4b = new URL(p.url()).pathname;
    if (!["/", "/wallet"].includes(path4) || !moVi || idb4.recs.length !== 0 || path4b !== "/wallet")
      throw new Error(`R4 sai: url=${path4} moVi=${moVi} ban ghi=${idb4.recs.length} vao /holder -> ${path4b}`);
    return `R1 url=${path1} tieu de="${t1}" | R2 1 ban ghi ${rec.keyType} extractable=${rec.extractable} truong=${rec.fields.join(",")} meta=${rec.metaKeys.join(",")} | R3 tab moi -> ${path3} | R4 -> ${path4} (Mo vi hien), ban ghi=${idb4.recs.length}, /holder cung tab -> ${path4b}`;
  }, () => holder.page);
} finally {
  fs.writeFileSync(path.join(OUT, "index.json"), JSON.stringify(index, null, 2));
  fs.writeFileSync(path.join(OUT, "flows.json"), JSON.stringify({ flows, state: S, errors: [...allErrors] }, null, 2));
  await browser.close().catch(() => {});
}

console.log("\n== Tràn ngang (>0) ==");
for (const e of index.filter((x) => x.overflowPx > 0)) console.log(e.file, e.overflowPx + "px", e.overflowEls.join(" ; "));
console.log("\n== Lỗi gộp ==");
for (const [m, n] of allErrors) console.log(`${n}x ${m}`);
console.log("\nẢnh: " + index.length + " tệp trong " + OUT);
process.exit(flows.every((f) => f.ok) ? 0 : 1);
