// Dev-only purpose harness: drives the served /ui script's verify-attribution
// flow in Node and asserts user-visible outcomes (not code strings).
// Usage: node scripts/verify_attribution_stub.js <page-js-file>
// The page JS is eval'd AFTER these stubs (same pattern as login_dom_stub.js).
// Not shipped, not imported by prod code.
const fs = require("fs");
const assert = require("assert");

// --- compressed timers: 3s polls / 15s bars resolve in ~120ms ---
const __realSetTimeout = setTimeout;
global.setTimeout = (fn, ms, ...a) => __realSetTimeout(fn, Math.min(ms || 0, 120), ...a);

// --- minimal DOM: auto-vivifying elements that absorb any prop/method ---
function mkClassList() {
  const s = new Set();
  return {
    add: (...c) => c.forEach((x) => s.add(x)),
    remove: (...c) => c.forEach((x) => s.delete(x)),
    toggle: (c, f) => {
      const on = f === undefined ? !s.has(c) : !!f;
      if (on) s.add(c); else s.delete(c);
      return on;
    },
    contains: (c) => s.has(c),
  };
}
let __anon = 0;
function mkEl(id) {
  const el = {
    id, textContent: "", innerHTML: "", value: "", checked: false,
    disabled: false, hidden: false, title: "", className: "", type: "",
    dataset: {}, style: {}, children: [], parent: null,
    width: 1000, height: 64,
    classList: mkClassList(),
    appendChild(c) { c.parent = el; el.children.push(c); return c; },
    remove() {
      if (el.parent) {
        const i = el.parent.children.indexOf(el);
        if (i >= 0) el.parent.children.splice(i, 1);
        el.parent = null;
      }
    },
    setAttribute() {}, getAttribute() { return null; },
    addEventListener() {}, removeEventListener() {},
    focus() {}, select() {}, click() {},
    querySelector() { return null; },
    getContext() { return new Proxy({}, { get: () => () => {}, set: () => true }); },
  };
  Object.defineProperty(el, "firstChild", { get: () => el.children[0] || null });
  return el;
}
const els = {};
const probeBtns = {};
function probeBtn(tag) {
  if (!probeBtns[tag]) {
    const el = mkEl("probe-" + tag);
    el.getAttribute = (name) => {
      if (name === "data-probe") return tag;
      if (name === "aria-disabled") {
        const cur = (global.__busyProbeTag !== undefined)
          ? global.__busyProbeTag : (backend.probe.state === "running" ? backend.probe.tag : null);
        return cur === tag ? "true" : null;
      }
      return null;
    };
    el.closest = () => el;
    probeBtns[tag] = el;
  }
  return probeBtns[tag];
}
global.document = {
  getElementById: (id) => els[id] || (els[id] = mkEl(id)),
  querySelector: (sel) => {
    const m = /\[data-probe='([^']+)'\]/.exec(sel || "");
    if (m) return probeBtn(m[1]);
    return null;
  },
  querySelectorAll: () => [],
  createElement: () => mkEl("anon" + (__anon++)),
  activeElement: null,
  hidden: false,
  documentElement: { dataset: {} },
};
global.window = { addEventListener() {} };
global.location = { hostname: "preview.test" };
const store = {};
global.localStorage = {
  getItem: (k) => (k in store ? store[k] : null),
  setItem: (k, v) => { store[k] = String(v); },
  removeItem: (k) => { delete store[k]; },
};

// --- scripted backend mirroring production semantics ---
const IP_OF = { "vpngate-0": "9.9.9.11", "vpngate-1": "9.9.9.12" };
const backend = {
  calls: [],
  preferred_tag: "vpngate-1",
  verify: { state: "idle", exit_ip: null, ms: null, via_tag: null, error: null },
  probe: { state: "idle", tag: null, ms: null, error: null },
  probeDelayMs: 50,
  verifyDelayMs: 50,
  endpoints() {
    return ["vpngate-0", "vpngate-1"].map((tag, i) => ({
      tag, server: `203.0.113.1${1 + i}`, server_port: 443,
      country: "Japan", country_short: "JP",
      latency_ms: 100 + i * 50, real_latency_ms: 800 - i * 500,
      alive_seconds: 1200, first_seen: "2026-09-08T05:00:00Z",
    }));
  },
  statusDoc() {
    return {
      endpoints: this.endpoints(), countries: [],
      preferred_tag: this.preferred_tag, backup_tag: null, auto_pinned: true,
      refresh_ok: 1, refresh_fail: 0, uptime_seconds: 60, last_error: null,
      full_probe: { state: "idle", done: 0, total: 0 },
      probe: { ...this.probe },
      verify: { ...this.verify },
      refresh_history: [], traffic: {}, cpu: {}, memory: {},
    };
  },
};
function reply(status, obj) {
  const raw = JSON.stringify(obj);
  return { status, ok: status >= 200 && status < 300,
           text: async () => raw, json: async () => JSON.parse(raw) };
}
global.fetch = async (path, opts = {}) => {
  const method = (opts && opts.method) || "GET";
  const body = opts.body ? JSON.parse(opts.body) : undefined;
  backend.calls.push({ path, method, body });
  if (path === "/api/status" && method === "GET") return reply(200, backend.statusDoc());
  if (path === "/api/logs") return reply(200, { lines: [] });
  if (path === "/api/settings") return reply(200, { values: {
    refresh_seconds: 3600, dial_timeout: 20, real_topk: 10, dial_workers: 5,
    full_probe_workers: 5, probe_workers: 20, auto_repin: true, auto_rescue: true,
  } });
  if (path === "/api/switch" && method === "POST") {
    backend.preferred_tag = body.tag;
    backend.verify = { state: "idle", exit_ip: null, ms: null,
                       via_tag: null, error: null };
    return reply(200, { ok: true, preferred_tag: backend.preferred_tag, detail: "chain" });
  }
  if (path === "/api/probe" && method === "POST") {
    backend.probe = { state: "running", tag: body.tag, ms: null, error: null };
    setTimeout(() => {
      backend.probe = { state: "done", tag: body.tag, ms: 812, error: null };
    }, backend.probeDelayMs);
    return reply(202, { accepted: true, tag: body.tag });
  }
  if (path === "/api/verify" && method === "POST") {
    const via = backend.preferred_tag;
    backend.verify = { state: "running", exit_ip: null, ms: null,
                       via_tag: via, error: null };
    setTimeout(() => {
      backend.verify = { state: "done", exit_ip: IP_OF[via], ms: 42,
                         via_tag: via, error: null };
    }, backend.verifyDelayMs);
    return reply(202, { accepted: true, via_tag: via });
  }
  throw new Error("unexpected fetch " + method + " " + path);
};

// --- load the served page JS, then drive it ---
const pageJs = fs.readFileSync(process.argv[2], "utf-8");
eval(pageJs);

const sleep = (ms) => new Promise((r) => __realSetTimeout(r, ms));
const verifyPosts = () => backend.calls.filter((c) => c.path === "/api/verify").length;
// wrap toast to observe user-facing interruptions
const toastLog = [];
// eslint-disable-next-line no-undef
toast = ((orig) => (msg, isErr) => { toastLog.push(String(msg)); return orig(msg, isErr); })(toast);

(async () => {
  // Scenario A1: stale branch renders the hint when auto-verify is suppressed.
  autoVerifiedFor = "vpngate-1"; // pretend this pin was already auto-verified
  backend.preferred_tag = "vpngate-1";
  backend.verify = { state: "done", exit_ip: "9.9.9.11", ms: 100,
                     via_tag: "vpngate-0", error: null };
  lastStatus = backend.statusDoc();
  renderAll(lastStatus);
  assert.strictEqual(
    document.getElementById("verify-result").textContent,
    // Wording owned by renderVerify() in railway_manager.py: since 6ef76f2
    // the hint covers both a stale verify and a node switch.
    "验证已过期或已切换，出口待重新验证",
    "stale IP must be replaced by re-verify hint");
  assert.ok(!document.getElementById("verify-result").textContent.includes("9.9.9.11"),
    "old exit IP must not be displayed");
  console.log("PASS A1: stale exit IP hidden, re-verify hint shown");

  // Scenario A2: with the guard cleared, auto-verify fires and lands on the
  // NEW ip — the old IP is never displayed at any point.
  autoVerifiedFor = null;
  backend.calls.length = 0;
  renderAll(lastStatus);
  await sleep(600);
  assert.strictEqual(verifyPosts(), 1, "stale triggers exactly one auto verify");
  const afterStale = document.getElementById("verify-result").textContent;
  assert.ok(afterStale.includes("9.9.9.12"),
    "new exit shown after auto re-verify, got: " + afterStale);
  assert.ok(!afterStale.includes("9.9.9.11"), "old exit IP never shown");
  console.log("PASS A2: auto re-verify lands on new IP, old IP never shown");

  // Scenario B: idle verify + pin => exactly one auto verify, then done, no loop.
  autoVerifiedFor = null;
  backend.calls.length = 0;
  backend.verify = { state: "idle", exit_ip: null, ms: null, via_tag: null, error: null };
  lastStatus = backend.statusDoc();
  renderAll(lastStatus);
  await sleep(600);
  assert.strictEqual(verifyPosts(), 1, "exactly one auto verify POST");
  assert.ok(document.getElementById("verify-result").textContent.includes("9.9.9.12"),
    "auto verify result shown, got: " + document.getElementById("verify-result").textContent);
  renderAll(backend.statusDoc());
  renderAll(backend.statusDoc());
  await sleep(300);
  assert.strictEqual(verifyPosts(), 1, "no repeated auto verify (no loop)");
  console.log("PASS B: first identification automatic, once, no loop");

  // Scenario C: manual switch verifies the NEW node exactly once.
  backend.calls.length = 0;
  toastLog.length = 0;
  lastStatus = backend.statusDoc();
  renderAll(lastStatus);
  await switchTag("vpngate-0");
  await sleep(600);
  assert.strictEqual(verifyPosts(), 1, "switch triggers exactly one verify, got " + verifyPosts());
  assert.ok(document.getElementById("verify-result").textContent.includes("9.9.9.11"),
    "new node exit shown, got: " + document.getElementById("verify-result").textContent);
  assert.ok(!toastLog.some((m) => m.includes("已有验证进行中")),
    "no spurious 409 toast on switch, toasts: " + JSON.stringify(toastLog));
  console.log("PASS C: switch verifies new node once, no 409, correct IP");

  // No background verify loop: after everything settles, no new POSTs.
  await sleep(500);
  assert.strictEqual(verifyPosts(), 1, "no looping verify, got " + verifyPosts());
  console.log("PASS D: quiescent, no looping verify");

  // Scenario P1: a running single-probe is visible as a badge, and the
  // probe button stays operable (aria-disabled, not real disabled).
  backend.probe = { state: "running", tag: "vpngate-0", ms: null, error: null };
  lastStatus = backend.statusDoc();
  renderAll(lastStatus);
  const benchHtml = document.getElementById("bench-body").innerHTML;
  assert.ok(benchHtml.includes("测速中"), "probing badge rendered");
  assert.ok(benchHtml.includes("aria-disabled='true'"), "probe button aria-disabled");
  assert.ok(!benchHtml.includes("disabled title='测速中"),
    "no real disabled on probe button");
  console.log("PASS P1: running probe visible, button operable");

  // Scenario P2: activating the busy probe row explains itself.
  toastLog.length = 0;
  const busyBtn = probeBtn("vpngate-0");
  document.getElementById("bench-body").onclick({ target: busyBtn });
  assert.ok(toastLog.some((m) => m.includes("该节点测速中，请稍候")),
    "busy probe click toasts, got: " + JSON.stringify(toastLog));
  const probePostsBefore = backend.calls.filter((c) => c.path === "/api/probe").length;
  busyBtn.textContent = "测速";
  document.getElementById("bench-body").onkeydown(
    { key: "Enter", target: busyBtn, preventDefault() {} });
  assert.ok(toastLog.some((m) => m.includes("该节点测速中，请稍候")),
    "busy probe Enter toasts");
  assert.strictEqual(
    backend.calls.filter((c) => c.path === "/api/probe").length, probePostsBefore,
    "busy probe activation must not POST");
  console.log("PASS P2: busy probe row explains itself, no stray POST");

  // Scenario P3: Space defers to native click (no direct dispatch);
  // Enter on an idle row dispatches exactly one probe.
  let prevented = false;
  backend.probe = { state: "idle", tag: null, ms: null, error: null };
  const idleBtn = probeBtn("vpngate-1");
  document.getElementById("bench-body").onkeydown(
    { key: " ", target: idleBtn, preventDefault() { prevented = true; } });
  assert.ok(prevented, "Space preventDefault called");
  assert.strictEqual(
    backend.calls.filter((c) => c.path === "/api/probe").length, probePostsBefore,
    "Space must not dispatch directly");
  document.getElementById("bench-body").onkeydown(
    { key: "Enter", target: idleBtn, preventDefault() {} });
  await sleep(800);
  assert.strictEqual(
    backend.calls.filter((c) => c.path === "/api/probe").length, probePostsBefore + 1,
    "Enter dispatches exactly one probe");
  assert.strictEqual(idleBtn.textContent, "测速", "probe button text restored");
  console.log("PASS P3: Space defers, Enter probes once, button restored");

  console.log("ALL PASS: verify attribution serves the right IP at the right time");
  process.exit(0);
})().catch((e) => { console.error("HARNESS FAIL:", e); process.exit(1); });
