"use strict";
const { invoke } = window.__TAURI__.core;
const win = window.__TAURI__.window.getCurrentWindow();
const $ = (id) => document.getElementById(id);
const NS = "http://www.w3.org/2000/svg";

/* Every string reaches the page as text, never as HTML: names come from untrusted files. */
function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else if (k.startsWith("aria-") || k === "title" || k === "role") e.setAttribute(k, v);
    else e[k] = v;
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c);
  return e;
}
function ic(name, cls = "", filled = false) {
  const [size, ...ds] = ICONS[name][filled ? 1 : 0];
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", `0 0 ${size} ${size}`);
  s.setAttribute("class", "i " + cls);
  s.setAttribute("aria-hidden", "true");
  for (const d of ds) { const p = document.createElementNS(NS, "path"); p.setAttribute("d", d); s.append(p); }
  return s;
}
const btn = (c, g, t, f, o = {}) => el("button", { class: c, onclick: f, ...o }, g && ic(g), t && el("span", {}, t));
const icon = (g, t, f) => btn("s", g, "", f, { title: t, "aria-label": t });
const path = (p) => el("span", { class: "sub path", title: p }, p);
const badge = (k, t) => el("span", { class: "badge " + k }, t);
const base = (p) => p.split("\\").pop();
const sw = (t, on, f) => el("label", { class: "sw" }, el("input", { type: "checkbox", role: "switch", checked: on, onchange: (e) => f(e.target.checked), "aria-label": t }));
const row = (g, t, d, c) => el("div", { class: "row item" }, ic(g, "ic"), el("div", { class: "grow" }, el("div", { class: "t1" }, t), d && el("div", { class: "sub" }, d)), c);

let S = null, progs = [], evs = [], allowed = [], def, page = "home", toastT;
const open = new Set();
/* Expander that survives re-rendering. */
function exp(key, title, ...kids) {
  return el("details", { open: open.has(key), ontoggle: (e) => (e.target.open ? open.add(key) : open.delete(key)) },
    el("summary", {}, el("span", { class: "grow" }, title), ic("down", "chev")), el("div", { class: "body" }, ...kids));
}

function toast(t) {
  $("toast").textContent = t; $("toast").hidden = false;
  clearTimeout(toastT); toastT = setTimeout(() => ($("toast").hidden = true), 5000);
}
async function call(name, args, done) {
  try { const r = await invoke(name, args); if (done) toast(done); await refresh(); return r; }
  catch (e) { toast(String(e)); await refresh(); }
}
/* Safe choice focused; Esc means no. */
function ask(title, text, yes, danger) {
  return new Promise((ok) => {
    const d = $("dlg");
    d.querySelector("h3").textContent = title; d.querySelector("p").textContent = text;
    const no = btn("b", null, "إلغاء", () => d.close("no"));
    d.querySelector("footer").replaceChildren(btn(danger ? "p danger" : "p", null, yes, () => d.close("yes")), no);
    d.onclose = () => ok(d.returnValue === "yes");
    d.returnValue = ""; d.showModal(); no.focus();
  });
}
const tr = (r) => r.startsWith("Defender:") ? "كشفه Defender: " + r.slice(9).trim()
  : r.includes("double extension") ? "برنامج متنكر كمستند"
  : r.includes("downloaded") ? "بلا ناشر معروف ومحمّل من الإنترنت"
  : r.includes("modified after") ? "عُدّل بعد توقيعه الأصلي"
  : r.includes("replaces a Windows") ? "مكتبة تحل محل ملف من Windows (شائعة في الكراك والتعديلات، وفي الفيروسات)"
  : r.includes("unsigned") ? "بلا ناشر معروف"
  : r.includes("text-direction") ? "اسم فيه رموز خفية"
  : r.includes("rarely") ? "نوع ملف نادراً ما يكون سليماً" : r;

const pages = { home: ["الرئيسية", "home", home], apps: ["البرامج", "app", apps], act: ["النشاط", "lock", activity], set: ["الإعدادات", "set", settings] };
function nav() {
  $("nav").replaceChildren(...Object.entries(pages).map(([k, [t, g]]) => {
    const on = k === page;
    return el("button", { class: k === "set" ? "push" : "", "aria-label": t, title: t, "aria-current": on ? "page" : "false", onclick: () => go(k) }, ic(g, "", on), el("span", {}, t),
      k === "act" && S && S.quarantine.length > 0 && el("span", { class: "count" }, String(S.quarantine.length)));
  }));
}
async function go(p) {
  page = p; await refresh();
  document.querySelector("main").scrollTop = 0;
  const e = $("page"); e.classList.remove("in"); void e.offsetWidth; e.classList.add("in");
}
const empty = (g, t, s, ...k) => el("div", { class: "empty" }, ic(g), el("div", { class: "t1" }, t), el("div", { class: "sub" }, s), ...k);
const group = (...k) => el("div", { class: "card group" }, ...k);

function hero() {
  const bad = S.zones.reduce((n, z) => n + z.bad, 0), un = S.zones.some((z) => !z.scanned && !z.busy);
  const [k, g, t, s, b] =
    bad ? ["bad", "shieldbad", `وجدنا ${bad} ملف خبيث`, "تشغيل البرامج في مجلده متوقف حتى تحجره.", null]
    : def === false ? ["warn", "shieldbad", "حماية Windows مطفأة", "شغّل الحماية اللحظية في Defender، فحصن لا يعوّضها.", btn("p", null, "فتح أمان Windows", () => call("open_security"))]
    : !S.zones.length ? ["off", "shield", "أضف أول مجلد", "اختر مجلداً تضع فيه الملفات التي لا تثق بها.", null]
    : un ? ["warn", "shieldbad", "مجلد لم يُفحص", "افحصه لتقدر على تشغيل برامجه.", null]
    : !S.watching ? ["warn", "shieldbad", "المراقبة متوقفة", "الملفات الجديدة لا تُفحص تلقائياً.", btn("p", null, "الإعدادات", () => { open.add("adv"); go("set"); })]
    : allowed.length ? ["warn", "shieldbad", "تهديدات مسموحة في Defender", "سمحت سابقاً بـ: " + allowed.join("، ") + ". لن يكشفها الفحص.", btn("p", null, "مراجعة", () => call("open_security"))]
    : def == null ? ["off", "shield", "المراقبة تعمل", "لم نتأكد من حالة Defender.", null]
    : ["ok", "shield", "لا توجد تنبيهات", "مجلداتك مراقَبة. «لم نجد شيئاً» لا يعني أن الملف آمن تماماً.", null];
  return el("div", { class: "hero " + k }, el("div", { class: "disc" }, ic(g, "", true)), el("div", { class: "grow" }, el("h1", {}, t), el("div", { class: "sub big" }, s)), b);
}
async function addZone() {
  const z = await call("zone_add");
  if (z) call("zone_scan", { path: z });
}
/* One collapsed line per sub-folder, worst first. */
function groups(z, list, kind) {
  const g = new Map();
  for (const x of list) {
    const rel = x.path.slice(z.path.length + 1).split("\\");
    const k = rel.length > 1 ? rel[0] : "ملفات المجلد نفسه";
    if (!g.has(k)) g.set(k, []);
    g.get(k).push([x, rel.slice(rel.length > 1 ? 1 : 0)]);
  }
  const bad = (a) => a.filter(([x]) => x.bad).length;
  return [...g].sort((a, b) => bad(b[1]) - bad(a[1]) || b[1].length - a[1].length).map(([k, a]) => el("div", { class: "sect" }, exp(kind + z.path + k,
    el("span", { class: "row tight" }, ic("zone", "ic"), el("span", { class: "grow t1" }, k), badge(bad(a) ? "bad" : kind === "m" ? "warn" : "off", bad(a) ? bad(a) + " خبيث" : String(a.length))),
    ...a.map(([x, rel]) => el("div", { class: "row item" }, ic(x.bad ? "bad" : x.level ? "warn" : "file", "ic " + (x.bad ? "cbad" : x.level ? "cwarn" : "cdim"), x.level > 0),
      el("div", { class: "grow" }, el("div", { class: "t1" }, rel[rel.length - 1]), rel.length > 1 && path(rel.slice(0, -1).join("\\")), el("div", { class: "sub" }, x.reasons.map(tr).join("، "))),
      icon("open", "عرض في المجلد", () => call("reveal", { path: x.path })),
      icon("box", "نقل إلى الحجر", async () => { if (await ask("نقل إلى الحجر؟", rel[rel.length - 1] + "\nقد تتوقف اللعبة عن العمل. تقدر تسترجعه من «النشاط».", "حجر")) call("q_add", { path: x.path }, "نُقل إلى الحجر"); }))))));
}
function zoneRow(z) {
  const st = !z.exists ? badge("warn", "غير موجود") : z.busy ? badge("off", "جاري الفحص") : !z.scanned ? badge("warn", "لم يُفحص") : z.bad ? badge("bad", `${z.bad} خبيث`) : z.suspicious ? badge("warn", `${z.suspicious} للمراجعة`) : badge("ok", "لم نجد شيئاً");
  const main = z.findings.filter((x) => x.level > 0), quiet = z.findings.filter((x) => x.level === 0);
  return el("div", { class: "card" },
    el("div", { class: "row" }, ic("zone", "ic"), el("div", { class: "grow" }, el("div", { class: "t1" }, base(z.path)), path(z.path)), st,
      btn("b", "scan", "فحص", () => call("zone_scan", { path: z.path }, "انتهى الفحص"), { disabled: z.busy || !z.exists }),
      icon("close", "إزالة من الحماية", async () => { if (await ask("إزالة المجلد من الحماية؟", "تبقى ملفاتك في مكانها، لكن حصن لن يفحصها أو يراقبها.", "إزالة")) call("zone_remove", { path: z.path }); })),
    z.busy && el("div", { class: "prog" }),
    main.length > 0 && exp("z" + z.path, `${main.length} للمراجعة`, groups(z, main, "m")),
    quiet.length > 0 && exp("q" + z.path, `${quiet.length} بلا ناشر معروف · شائع في الألعاب`, groups(z, quiet, "n")));
}
function updateCard() {
  const u = S.update;
  return el("div", { class: "card" }, el("div", { class: "row" }, ic("scan", "ic"), el("div", { class: "grow" }, el("div", { class: "t1" }, "يتوفر تحديث " + u.version), el("div", { class: "sub" }, u.busy ? "جاري التنزيل والتحقق من التوقيع…" : "يستبدل النسخة الحالية ويحتفظ بإعداداتك.")),
    btn("p", "scan", "تحديث", async () => { if (await ask("تحديث حصن؟", "سيُغلق حصن ويعود بعد التثبيت.\n\n" + u.notes, "تحديث")) call("update_install"); }, { disabled: u.busy })), u.busy && el("div", { class: "prog" }));
}
function home() {
  const fact = (k, t, s) => row(k === "ok" ? "ok" : k === "warn" ? "warn" : "bad", t, s, badge(k, k === "ok" ? "محمي" : k === "warn" ? "جزئي" : "غير محمي"));
  return [hero(), S.update && updateCard(), S.running.length > 0 && el("h2", {}, "يعمل الآن"), ...S.running.map(running),
    el("div", { class: "h2" }, el("h2", {}, "المجلدات المحمية"), btn("p", "add", "إضافة مجلد", addZone)),
    S.zones.length === 0 && el("div", { class: "card" }, empty("zone", "لا توجد مجلدات", "يفحص حصن المجلد ويراقب كل ملف جديد فيه.")),
    ...S.zones.map(zoneRow),
    el("div", { class: "card only" }, exp("facts", "ماذا يحميك حصن؟",
      fact("ok", "ملفاتك الشخصية", "البرنامج المعزول لا يرى إلا مجلده."),
      fact("ok", "الإنترنت", "مقطوع إلا إذا سمحت."),
      fact("ok", "التشغيل التلقائي والمهام المجدولة", "ممنوعان."),
      fact("warn", "الكيبورد والشاشة والماوس", "مع «شاشة منفصلة» فقط. اختُبر منع فتح شاشتك، ولم تُختبر محاولات تجسس كاملة."),
      fact("bad", "الفتح من Explorer", "الضغط المزدوج لا يعزل. شغّل من صفحة البرامج.")))];
}
async function enter(r) {
  if (await ask("الانتقال لشاشة البرنامج؟", "للرجوع: Ctrl+Alt+Home أو الزر أعلى الشاشة.\n\nسترجع تلقائياً بعد 15 ثانية إن لم تضغط «ابقَ هنا».\n\nلا تكتب فيها كلمة مرور مهمة: البرنامج يرى ما تكتبه داخل شاشته.", "انتقال")) call("enter_screen", { id: r.id });
}
const running = (r) => el("div", { class: "card row" }, ic("shield", "ic", true), el("div", { class: "grow" }, el("div", { class: "t1" }, base(r.path)), el("div", { class: "sub" }, (r.private ? "شاشة منفصلة" : "على شاشتك") + " · " + (r.net ? "الإنترنت مسموح" : "بلا إنترنت"))),
  r.private && btn("p", "desk", "انتقال", () => enter(r)), btn("b", "stop", "إيقاف", () => call("stop", { id: r.id })));

function program(p) {
  const z = S.zones.find((z) => z.path === p.zone) || {};
  const save = async (c) => {
    const n = { path: p.path, net: p.net, write: p.write, strict: p.strict, screen: p.screen, ...c };
    if (c.net && !(await ask("السماح بالإنترنت؟", `سيقدر ${p.name} على إرسال أي شيء يراه.\n\nيُلغى السماح إذا تغيّر الملف.`, "السماح"))) return refresh();
    if (c.write && !(await ask("السماح بالحفظ في مجلده؟", `سيقدر ${p.name} على تعديل كل الملفات في مجلده. فعّلها إذا لم تُحفظ لعبتك.`, "السماح"))) return refresh();
    if (c.screen === false && !(await ask("إلغاء الشاشة المنفصلة؟", `قد يقدر ${p.name} على مراقبة ما تكتبه وتصوير شاشتك.`, "إلغاء الحماية", true))) return refresh();
    call("set_perm", n, "تُطبّق عند التشغيل القادم");
  };
  const why = p.bad ? "ملف خبيث" : !z.scanned ? "افحص مجلده أولاً" : z.bad ? "في مجلده ملف خبيث" : "";
  const start = async () => {
    toast("جاري الفحص ثم التشغيل…");
    const changed = await call("launch", { path: p.path });
    if (changed) toast("تغيّر الملف منذ آخر مرة، فأُلغيت صلاحياته المحفوظة.");
    else if (changed === false && p.screen) toast("يعمل في شاشة منفصلة. اضغط «انتقال» لرؤيته.");
  };
  return el("div", { class: "card" },
    el("div", { class: "row" }, ic("app", "ic"), el("div", { class: "grow" }, el("div", { class: "t1" }, p.name), el("div", { class: "sub" }, p.path.slice(p.zone.length + 1).split("\\").slice(0, -1).join(" ‹ ") || base(p.zone)), p.reasons.length > 0 && el("div", { class: "sub" }, p.reasons.map(tr).join("، "))),
      icon("open", "عرض في المجلد", () => call("reveal", { path: p.path })), why && badge(p.bad ? "bad" : "warn", why), btn("p", "play", "تشغيل", start, { disabled: !!why })),
    exp("p" + p.path, "الصلاحيات",
      row("net", "الإنترنت", null, sw("الإنترنت", p.net, (v) => save({ net: v }))),
      row("desk", "شاشة منفصلة", "تقلل خطر التجسس على الكيبورد والشاشة.", sw("شاشة منفصلة", p.screen, (v) => save({ screen: v }))),
      row("edit", "الحفظ في مجلده", null, sw("الحفظ في مجلده", p.write, (v) => save({ write: v }))),
      p.strict && row("shield", "عزل أشد", "قد يمنع البرنامج من العمل.", sw("عزل أشد", true, (v) => save({ strict: v })))));
}
/* Installers and crash reporters are rarely what the user wants to start. */
const helper = (p) => /\\_?(commonredist|redist|_redist|support)\\/i.test(p.path) || /(crash|handler|redist|unins|setup|dxweb|vc_|prereq|helper|ffmpeg|browser)/i.test(p.name);
function appGroups() {
  const g = new Map();
  for (const p of progs) {
    const rel = p.path.slice(p.zone.length + 1).split("\\");
    const k = p.zone + "|" + (rel.length > 1 ? rel[0] : "");
    if (!g.has(k)) g.set(k, []);
    g.get(k).push(p);
  }
  return [...g].sort((x, y) => x[0].localeCompare(y[0])).flatMap(([k, list]) => {
    const main = list.filter((p) => !helper(p)), more = list.filter(helper);
    return [el("h2", {}, k.split("|")[1] || base(k.split("|")[0])), ...main.map(program),
      more.length > 0 && el("div", { class: "card only tightcard" }, exp("h" + k, `أدوات مساعدة (${more.length})`, ...more.map(program)))];
  });
}
function apps() {
  return [el("h1", { class: "top" }, "البرامج"), ...S.running.map(running), 
    progs.length === 0 && el("div", { class: "card" }, empty("app", "لا توجد برامج بعد", "ضع البرنامج في مجلد محمي وسيظهر هنا.")),
    ...appGroups()];
}
function activity() {
  const when = (t) => new Date(t * 1000).toLocaleString("ar", { dateStyle: "short", timeStyle: "short" });
  return [el("h1", { class: "top" }, "النشاط"), el("h2", {}, "الحجر"),
    S.quarantine.length === 0 && el("div", { class: "card" }, empty("box", "الحجر فارغ", "الملفات الخبيثة تُنقل إلى هنا مشفّرة ولا يمكن تشغيلها.")),
    S.quarantine.length > 0 && group(...S.quarantine.map((q) => el("div", { class: "row item" }, ic("box", "ic"), el("div", { class: "grow" }, el("div", { class: "t1" }, base(q.original)), el("div", { class: "sub" }, tr(q.reason))),
      btn("b", "back", "استرجاع", async () => { if (await ask("استرجاع الملف؟", "يعود إلى مجلده ولن يُحجر تلقائياً. إن كان خبيثاً فسيبقى تشغيله من حصن ممنوعاً.\n\nانتبه: فتحه من Explorer ليس معزولاً.", "استرجاع", true)) call("q_restore", { id: q.id }, "استُرجع الملف"); }),
      icon("del", "حذف نهائي", async () => { if (await ask("حذف نهائي؟", base(q.original) + "\nلا يمكن التراجع.", "حذف", true)) call("q_delete", { id: q.id }, "حُذف نهائياً"); })))),
    el("h2", {}, "السجل"), evs.length === 0 && el("div", { class: "card" }, empty("lock", "لا توجد أحداث", "كل ما يفعله حصن يظهر هنا.")),
    evs.length > 0 && group(...evs.slice(0, 100).map((e) => el("div", { class: "row item" }, ic(e.level === "bad" ? "bad" : e.level === "warn" ? "warn" : "ok", "ic " + (e.level === "bad" ? "cbad" : e.level === "warn" ? "cwarn" : "cdim"), e.level !== "info"), el("div", { class: "grow" }, el("div", { class: "t1" }, e.text), e.path && el("div", { class: "sub path", title: e.path }, base(e.path))), el("span", { class: "sub" }, when(e.time)))))];
}
function settings() {
  const s = S.settings;
  const save = (c, auto = S.autostart) => call("save_settings", { value: { ...s, ...c }, autostart: auto });
  const tog = (t, k) => sw(t, s[k], (v) => save({ [k]: v }));
  return [el("h1", { class: "top" }, "الإعدادات"),
    group(row("power", "التشغيل مع Windows", "يبدأ بهدوء في الخلفية.", sw("التشغيل مع Windows", S.autostart, (v) => save({}, v))),
      row("bell", "الإشعارات", null, tog("الإشعارات", "notify")),
      row("theme", "المظهر", null, el("select", { "aria-label": "المظهر", onchange: (e) => save({ theme: e.target.value }) }, ...[["system", "حسب Windows"], ["light", "فاتح"], ["dark", "داكن"]].map(([v, t]) => el("option", { value: v, selected: s.theme === v }, t))))),
    el("h2", {}, "التحديثات"), S.update && updateCard(),
    group(row("scan", "الإصدار " + S.version, "البحث يتصل بـ GitHub مرتين يومياً.", btn("b", null, "بحث عن تحديث", async () => { const r = await call("update_check"); if (r === false) toast("عندك أحدث إصدار."); })),
      row("power", "التحديث التلقائي", "يثبّت عندما تكون النافذة مغلقة ولا يعمل برنامج معزول.", tog("التحديث التلقائي", "auto_update"))),
    el("div", { class: "card only" }, exp("adv", "خيارات متقدمة",
      row("bg", "البقاء في الخلفية عند الإغلاق", "للإنهاء: زر يمين على الأيقونة قرب الساعة.", tog("البقاء في الخلفية", "background")),
      row("eye", "مراقبة الملفات الجديدة", null, tog("المراقبة", "watch")),
      row("box", "حجر الخبيث تلقائياً", "ما يؤكده Defender فقط.", tog("الحجر التلقائي", "auto_quarantine")),
      row("del", "حذف بيانات البرامج المعزولة", "يشمل حفظ الألعاب داخل العزل.", btn("b", null, "حذف", async () => { if (await ask("حذف بيانات البرامج؟", "تُحذف إعداداتها وحفظ الألعاب داخل العزل نهائياً. ملفات مجلداتك تبقى.", "حذف", true)) call("clean", {}, "حُذفت البيانات"); }))))];
}

const media = matchMedia("(prefers-color-scheme: dark)");
function theme() {
  const t = S ? S.settings.theme : "system";
  document.documentElement.dataset.theme = t === "system" ? (media.matches ? "dark" : "light") : t;
  win.setTheme(t === "system" ? null : t).catch(() => {});
}
media.addEventListener("change", theme);

let seq = 0;
async function refresh() {
  const n = ++seq;
  try {
    const s = await invoke("snapshot");
    const p = page === "apps" ? await invoke("programs") : progs;
    const e = page === "act" ? await invoke("events") : evs;
    if (n !== seq) return;
    const old = S && S.settings.theme;
    S = s; progs = p; evs = e;
    if (old !== S.settings.theme) theme();
  } catch (e) {
    if (n === seq) $("page").replaceChildren(el("div", { class: "card row" }, ic("bad", "ic cbad", true), el("div", { class: "grow" }, "تعذّر قراءة بيانات حصن: " + e)));
    return;
  }
  nav();
  $("page").replaceChildren(...pages[page][2]().flat().filter(Boolean));
}
async function checkDefender() { try { def = await invoke("defender"); } catch { def = null; } try { allowed = await invoke("allowed_threats"); } catch {} if (page === "home") refresh(); }

const cap = (g, t, f, c = "") => el("button", { class: "cap " + c, title: t, "aria-label": t, tabIndex: -1, onclick: f }, ic(g));
$("caps").append(cap("close", "إغلاق", () => win.close(), "x"), cap("max", "تكبير", () => win.toggleMaximize()), cap("min", "تصغير", () => win.minimize()));
window.addEventListener("blur", () => document.body.classList.add("inactive"));
window.addEventListener("focus", () => { document.body.classList.remove("inactive"); checkDefender(); });
theme();
window.__TAURI__.event.listen("changed", refresh);
go("home");
checkDefender();
