#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod watch;

use hisn::{container, ops, screen::{self, Screen}, quarantine, scan::Verdict, util::*, zone};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::{AtomicBool, AtomicU32, Ordering}, Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, RunEvent, State,
};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;

const NO_WINDOW: u32 = 0x0800_0000;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Settings { pub watch: bool, pub auto_quarantine: bool, pub background: bool, pub notify: bool, pub theme: String }
impl Default for Settings {
    fn default() -> Self {
        Self { watch: true, auto_quarantine: true, background: true, notify: true, theme: "system".into() }
    }
}
/// Permissions belong to the exact file content; a changed program starts over with none.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
struct Perm { sha256: String, net: bool, write: bool, strict: bool, screen: Option<bool> }

#[derive(Serialize, Deserialize, Clone)]
struct Event { time: u64, level: String, text: String, path: String }

struct Running { id: u32, path: String, net: bool, cancel: Arc<AtomicBool>, screen: Option<Screen>, private: bool }

#[derive(Default)]
pub struct Core { running: Mutex<Vec<Running>>, next: AtomicU32, pub busy: Mutex<Vec<String>>, watcher: Mutex<Option<watch::Watch>>, quitting: AtomicBool, guard: AtomicBool }

pub fn settings() -> Res<Settings> {
    load_json(&state()?.join("settings.json"))
}
fn perms() -> Res<HashMap<String, Perm>> {
    load_json(&state()?.join("permissions.json"))
}
fn key(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}
/// Names come from untrusted files: drop control and text-direction characters.
pub fn safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control() && !matches!(*c as u32, 0x200E | 0x200F | 0x061C | 0x202A..=0x202E | 0x2066..=0x2069)).collect()
}
pub fn log(app: &AppHandle, level: &str, text: &str, path: &Path) {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let e = Event { time, level: level.into(), text: text.into(), path: safe(&path.to_string_lossy()) };
    if let (Ok(d), Ok(j)) = (state(), serde_json::to_string(&e)) {
        let _l = lock();
        let f = d.join("events.jsonl");
        if fs::metadata(&f).is_ok_and(|m| m.len() > 2 << 20) {
            let _ = fs::rename(&f, d.join("events.old.jsonl"));
        }
        if let Ok(mut f) = fs::OpenOptions::new().append(true).create(true).open(f) {
            let _ = writeln!(f, "{j}");
        }
    }
    if level != "info" && settings().map(|s| s.notify).unwrap_or(true) {
        let _ = app.notification().builder().title("حصن").body(format!("{text}\n{}", safe(&path.file_name().unwrap_or_default().to_string_lossy()))).show();
    }
    let _ = app.emit("changed", ());
}
/// Arabic text for errors that reach the user.
fn ar(e: String) -> String {
    let t = [
        ("scan the zone first", "افحص المنطقة أولاً قبل تشغيل أي برنامج منها."),
        ("still holds a malicious", "مرفوض: في المنطقة ملف خبيث. احجره أو احذفه أولاً."),
        ("refused: malicious program", "مرفوض: هذا البرنامج مصنّف خبيثاً."),
        ("Administrator rights", "مُنع: البرنامج يطلب صلاحيات المسؤول، وهذا غير مسموح داخل الحاوية."),
        ("anti-cheat is running", "نظام Anti-cheat يعمل الآن. رفضنا الشاشة المنفصلة حمايةً لحسابك. أغلق اللعبة ثم أعد المحاولة."),
        ("cannot be protected", "صلاحيات الشاشة على جهازك غير معتادة، فلا نقدر نحمي الكيبورد والشاشة. لم نشغّل البرنامج."),
        ("hotkey is taken", "زر الرجوع Ctrl+Alt+Home محجوز، فلم نشغّل البرنامج."),
        ("stopped by user", "أُوقف بطلبك."),
        ("elevated Hisn", "حصن يعمل كمسؤول. أغلقه وشغّله بشكل عادي."),
        ("game launcher or anti-cheat", "هذا مجلد ألعاب أو Anti-cheat. رفضناه حمايةً لحسابك."),
        ("protected location", "هذا مجلد نظام ولا يمكن أن يكون منطقة."),
        ("zone would contain", "هذا المجلد واسع جداً ويحتوي ملفاتك أو ملفات حصن. اختر مجلداً أصغر."),
        ("whole drive", "لا يمكن اختيار قرص كامل."),
        ("local drive paths", "مجلدات الشبكة غير مدعومة."),
        ("not inside a protected zone", "الملف ليس داخل منطقة محمية."),
        ("Defender", "تعذّر الفحص بواسطة Defender، لذلك لا نعتبر الملفات سليمة."),
        ("could not be verified", "تعذّر التحقق من العزل، فأُغلق البرنامج."),
    ];
    match t.iter().find(|x| e.contains(x.0)) {
        Some(x) => x.1.into(),
        None => format!("حدث خطأ: {}", safe(&e)),
    }
}

// ---------- views ----------
#[derive(Serialize)]
struct FindingView { path: String, bad: bool, level: u8, reasons: Vec<String> }
#[derive(Serialize)]
struct ZoneView { path: String, exists: bool, scanned: bool, files: usize, skipped: usize, bad: usize, suspicious: usize, busy: bool, findings: Vec<FindingView> }
#[derive(Serialize)]
struct RunView { id: u32, path: String, net: bool, private: bool }
#[derive(Serialize)]
struct Snapshot { zones: Vec<ZoneView>, quarantine: Vec<quarantine::Item>, running: Vec<RunView>, settings: Settings, autostart: bool, watching: bool }

#[tauri::command(async)]
fn snapshot(app: AppHandle, core: State<Core>) -> Res<Snapshot> {
    let busy = core.busy.lock().unwrap().clone();
    let mut zones = vec![];
    for z in zone::list()? {
        let r = ops::report(&z)?;
        let findings: Vec<FindingView> = r.iter().flat_map(|r| &r.findings).filter(|f| f.path.exists()).map(|f| FindingView { path: safe(&f.path.to_string_lossy()), bad: f.verdict == Verdict::Malicious, level: f.verdict as u8, reasons: f.reasons.clone() }).collect();
        let bad = findings.iter().filter(|f| f.bad).count();
        zones.push(ZoneView {
            exists: z.is_dir(),
            scanned: r.is_some(),
            files: r.as_ref().map_or(0, |r| r.files),
            skipped: r.as_ref().map_or(0, |r| r.skipped.len()),
            bad,
            suspicious: findings.iter().filter(|f| f.level == 1).count(),
            busy: busy.contains(&key(&z)),
            findings,
            path: z.to_string_lossy().into(),
        });
    }
    let running = core.running.lock().unwrap().iter().map(|r| RunView { id: r.id, path: r.path.clone(), net: r.net, private: r.private }).collect();
    let watching = core.watcher.lock().unwrap().is_some();
    Ok(Snapshot { zones, quarantine: quarantine::list()?, running, settings: settings()?, autostart: app.autolaunch().is_enabled().unwrap_or(false), watching })
}

/// None when Windows could not tell us.
#[tauri::command(async)]
fn defender() -> Option<bool> {
    let o = Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", "(Get-MpComputerStatus).RealTimeProtectionEnabled"]).creation_flags(NO_WINDOW).output().ok()?;
    match String::from_utf8_lossy(&o.stdout).trim() {
        "True" => Some(true),
        "False" => Some(false),
        _ => None,
    }
}
/// Threats the user told Defender to allow: scans stay silent about them everywhere.
#[tauri::command(async)]
fn allowed_threats() -> Vec<String> {
    let s = "$p=Get-MpPreference; $n=@{}; Get-MpThreat -EA SilentlyContinue | ForEach-Object { $n[[string]$_.ThreatID]=$_.ThreatName }; for($i=0;$i -lt @($p.ThreatIDDefaultAction_Ids).Count;$i++){ if(@($p.ThreatIDDefaultAction_Actions)[$i] -in 6,9){ $k=[string]@($p.ThreatIDDefaultAction_Ids)[$i]; if($n[$k]){$n[$k]}else{$k} } }";
    match Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", s]).creation_flags(NO_WINDOW).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).lines().map(|l| safe(l.trim())).filter(|l| !l.is_empty()).collect(),
        Err(_) => vec![],
    }
}
/// Opens Explorer with the file selected. The file itself is never opened.
#[tauri::command(async)]
fn reveal(path: String) -> Res<()> {
    let p = canon(Path::new(&path)).map_err(ar)?;
    zone::containing(&p).map_err(ar)?;
    let explorer = PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot")?).join("explorer.exe");
    Command::new(explorer).raw_arg(format!("/select,\"{}\"", p.display())).spawn().map_err(|e| e.to_string())?;
    Ok(())
}
#[tauri::command(async)]
fn open_security() {
    let _ = Command::new("explorer.exe").arg("windowsdefender://threat").spawn();
}

// ---------- zones ----------
#[tauri::command(async)]
fn zone_add(app: AppHandle) -> Res<Option<String>> {
    let Some(p) = app.dialog().file().blocking_pick_folder() else { return Ok(None) };
    let p = p.into_path().map_err(|e| e.to_string())?;
    let z = zone::add(&p).map_err(ar)?;
    log(&app, "info", "أُضيفت منطقة", &z);
    rewatch(&app);
    Ok(Some(z.to_string_lossy().into()))
}
#[tauri::command(async)]
fn zone_remove(app: AppHandle, path: String) -> Res<()> {
    zone::remove(Path::new(&path)).map_err(ar)?;
    log(&app, "info", "أُزيلت منطقة من الحماية", Path::new(&path));
    rewatch(&app);
    Ok(())
}
#[tauri::command(async)]
fn zone_scan(app: AppHandle, path: String) -> Res<()> {
    let p = canon(Path::new(&path)).map_err(ar)?;
    scan_and_log(&app, &p, true).map_err(ar)
}
/// Used by the button and by the watcher.
pub fn scan_and_log(app: &AppHandle, p: &Path, whole: bool) -> Res<()> {
    let core = app.state::<Core>();
    let z = zone::containing(p)?;
    {
        let mut b = core.busy.lock().unwrap();
        if whole && b.contains(&key(&z)) {
            return Ok(());
        }
        b.push(key(&z));
    }
    let _ = app.emit("changed", ());
    let r = settings().and_then(|s| if whole { ops::scan_zone(&z, s.auto_quarantine) } else { ops::scan_new(p, s.auto_quarantine) });
    {
        let mut b = core.busy.lock().unwrap();
        if let Some(i) = b.iter().position(|x| *x == key(&z)) {
            b.remove(i);
        }
    }
    match r {
        Ok((r, moved)) => {
            for m in &moved {
                match &m.result {
                    Ok(_) => log(app, "bad", "ملف خبيث نُقل إلى الحجر", &m.path),
                    Err(e) if e.contains("os error 225") => log(app, "bad", "ملف خبيث منعه Defender، راجعه في أمان Windows", &m.path),
                    Err(e) => log(app, "bad", &format!("ملف خبيث ولم يُحجر: {}", safe(e)), &m.path),
                }
            }
            for f in &r.findings {
                if f.verdict == Verdict::Malicious && !moved.iter().any(|m| m.path == f.path) {
                    log(app, "bad", "ملف خبيث في المنطقة، وتشغيله ممنوع", &f.path);
                }
            }
            let s = r.findings.iter().filter(|f| f.verdict == Verdict::Suspicious).count();
            log(app, if s > 0 && !whole { "warn" } else { "info" }, &format!("انتهى الفحص: {} ملف، {s} مشبوه", r.files), p);
            Ok(())
        }
        Err(e) => {
            log(app, "warn", "فشل الفحص، والملفات غير مؤكدة", p);
            Err(e)
        }
    }
}

// ---------- programs ----------
#[derive(Serialize)]
struct Program { path: String, name: String, zone: String, net: bool, write: bool, strict: bool, screen: bool, bad: bool, reasons: Vec<String> }

#[tauri::command(async)]
fn programs() -> Res<Vec<Program>> {
    let (perms, mut out) = (perms()?, vec![]);
    for z in zone::list()? {
        let r = ops::report(&z)?;
        let mut stack = vec![z.clone()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                let Ok(m) = fs::symlink_metadata(&p) else { continue };
                if is_reparse(&m) {
                    continue;
                }
                if m.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) && out.len() < 500 {
                    let f = r.as_ref().and_then(|r| r.findings.iter().find(|f| same(&f.path, &p)));
                    let q = perms.get(&key(&p)).cloned().unwrap_or_default();
                    out.push(Program {
                        name: safe(&p.file_name().unwrap_or_default().to_string_lossy()),
                        path: p.to_string_lossy().into(),
                        zone: z.to_string_lossy().into(),
                        net: q.net,
                        write: q.write,
                        strict: q.strict,
                        screen: q.screen.unwrap_or(f.is_some()),
                        bad: f.is_some_and(|f| f.verdict == Verdict::Malicious),
                        reasons: f.map(|f| f.reasons.clone()).unwrap_or_default(),
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(out)
}
#[tauri::command(async)]
fn set_perm(app: AppHandle, path: String, net: bool, write: bool, strict: bool, screen: bool) -> Res<()> {
    let p = canon(Path::new(&path)).map_err(ar)?;
    zone::containing(&p).map_err(ar)?;
    let sha = sha256(&p)?;
    {
        let _l = lock();
        let mut all = perms()?;
        all.insert(key(&p), Perm { sha256: sha, net, write, strict, screen: Some(screen) });
        save_json(&state()?.join("permissions.json"), &all)?;
    }
    log(&app, "info", &format!("تغيّرت الصلاحيات: الإنترنت {}، الكتابة {}", if net { "مسموح" } else { "ممنوع" }, if write { "مسموحة" } else { "ممنوعة" }), &p);
    Ok(())
}
/// Returns true when saved permissions were dropped because the file changed.
#[tauri::command(async)]
fn launch(app: AppHandle, core: State<Core>, path: String) -> Res<bool> {
    let exe = ops::check_launch(Path::new(&path)).map_err(|e| {
        let e = ar(e);
        log(&app, "warn", &e, Path::new(&path));
        e
    })?;
    let saved = perms()?.get(&key(&exe)).cloned().unwrap_or_default();
    let changed = !saved.sha256.is_empty() && saved.sha256 != sha256(&exe)?;
    if changed {
        let _l = lock();
        let mut all = perms()?;
        all.remove(&key(&exe));
        save_json(&state()?.join("permissions.json"), &all)?;
    }
    let q = if changed { Perm::default() } else { saved };
    // Anything with a warning gets its own screen unless the user chose otherwise.
    let flagged = ops::report(&zone::containing(&exe)?)?.is_some_and(|r| r.findings.iter().any(|f| same(&f.path, &exe)));
    let private = q.screen.unwrap_or(flagged);
    if private {
        if let Some(n) = screen::anti_cheat() {
            return Err(ar(format!("anti-cheat is running: {n}")));
        }
        start_guard(&core)?;
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let id = core.next.fetch_add(1, Ordering::Relaxed);
    core.running.lock().unwrap().push(Running { id, path: safe(&exe.to_string_lossy()), net: q.net, cancel: cancel.clone(), screen: None, private });
    log(&app, "info", if q.net { "تشغيل معزول مع الإنترنت" } else { "تشغيل معزول بلا إنترنت" }, &exe);
    let a = app.clone();
    std::thread::spawn(move || {
        let b = a.clone();
        let on_desktop: container::OnDesktop = Arc::new(move |d| {
            let s = screen::host(d)?;
            match b.state::<Core>().running.lock().unwrap().iter_mut().find(|r| r.id == id) {
                Some(r) => r.screen = Some(s),
                None => return Err("stopped by user".into()),
            }
            let _ = b.emit("changed", ());
            Ok(())
        });
        let o = container::Opts { private_desktop: private, on_desktop: Some(on_desktop), net: q.net, write: q.write, lpac: q.strict, cancel: Some(cancel), ..Default::default() };
        let r = container::run(&exe, &[], &o);
        // Dropping the screen brings the user back; not while holding the list.
        let done = {
            let core = a.state::<Core>();
            let mut l = core.running.lock().unwrap();
            l.iter().position(|x| x.id == id).map(|i| l.remove(i))
        };
        drop(done);
        match r {
            Ok(0) => log(&a, "info", "انتهى البرنامج", &exe),
            Ok(c) => log(&a, "info", &format!("انتهى البرنامج برمز 0x{c:X}، وقد لا يكون متوافقاً مع العزل"), &exe),
            Err(e) if e.contains("stopped by user") => log(&a, "info", "أُوقف البرنامج وكل عملياته", &exe),
            Err(e) => log(&a, "warn", &ar(e), &exe),
        }
    });
    Ok(changed)
}
#[tauri::command]
fn stop(core: State<Core>, id: u32) {
    if let Some(r) = core.running.lock().unwrap().iter().find(|r| r.id == id) {
        r.cancel.store(true, Ordering::Relaxed);
    }
}

#[tauri::command(async)]
fn enter_screen(core: State<Core>, id: u32) -> Res<()> {
    let l = core.running.lock().unwrap();
    let s = l.iter().find(|r| r.id == id).and_then(|r| r.screen.as_ref()).ok_or("الشاشة لم تجهز بعد.")?;
    s.enter().map_err(ar)
}
/// A helper that outlives a crash of Hisn and returns the user to their desktop.
fn start_guard(core: &Core) -> Res<()> {
    if core.guard.load(Ordering::Relaxed) {
        return Ok(());
    }
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    Command::new(me).args(["--guard", &std::process::id().to_string()]).creation_flags(NO_WINDOW).spawn().map_err(|e| e.to_string())?;
    core.guard.store(true, Ordering::Relaxed);
    Ok(())
}

// ---------- quarantine, log, settings ----------
#[tauri::command(async)]
fn q_restore(app: AppHandle, id: String) -> Res<()> {
    let p = ops::restore(&id).map_err(ar)?;
    log(&app, "info", "استُرجع ملف من الحجر، ويبقى تشغيله ممنوعاً", &p);
    Ok(())
}
#[tauri::command(async)]
fn q_delete(app: AppHandle, id: String) -> Res<()> {
    let i = quarantine::list()?.into_iter().find(|x| x.id == id).ok_or("غير موجود")?;
    quarantine::delete(&id).map_err(ar)?;
    log(&app, "info", "حُذف ملف نهائياً من الحجر", &i.original);
    Ok(())
}
#[tauri::command(async)]
fn q_add(app: AppHandle, path: String) -> Res<()> {
    let i = quarantine::add(Path::new(&path), "بطلب المستخدم").map_err(ar)?;
    log(&app, "info", "نُقل ملف إلى الحجر بطلبك", &i.original);
    Ok(())
}
#[tauri::command(async)]
fn events() -> Res<Vec<Event>> {
    let t = fs::read_to_string(state()?.join("events.jsonl")).unwrap_or_default();
    Ok(t.lines().rev().filter_map(|l| serde_json::from_str(l).ok()).take(300).collect())
}
#[tauri::command(async)]
fn save_settings(app: AppHandle, value: Settings, autostart: bool) -> Res<()> {
    save_json(&state()?.join("settings.json"), &value)?;
    let m = app.autolaunch();
    if m.is_enabled().unwrap_or(false) != autostart {
        if autostart { m.enable() } else { m.disable() }.map_err(|e| e.to_string())?;
    }
    rewatch(&app);
    let _ = app.emit("changed", ());
    Ok(())
}
#[tauri::command(async)]
fn clean(app: AppHandle, core: State<Core>) -> Res<usize> {
    if !core.running.lock().unwrap().is_empty() {
        return Err("أوقف البرامج المعزولة أولاً.".into());
    }
    let n = container::clean(None).map_err(ar)?;
    log(&app, "info", &format!("حُذفت {n} حاوية مع بياناتها"), Path::new(""));
    Ok(n)
}

fn rewatch(app: &AppHandle) {
    let core = app.state::<Core>();
    let on = settings().map(|s| s.watch).unwrap_or(true);
    let zones: Vec<PathBuf> = zone::list().unwrap_or_default();
    let mut w = core.watcher.lock().unwrap();
    *w = None;
    if on && !zones.is_empty() {
        match watch::start(app.clone(), &zones) {
            Ok(x) => *w = Some(x),
            Err(e) => {
                drop(w);
                log(app, "warn", &format!("تعذّرت مراقبة منطقة: {}", safe(&e)), Path::new(""));
            }
        }
    }
}
fn show(app: &AppHandle) {
    let app = app.clone();
    // Window creation must not run inside an event handler on Windows.
    std::thread::spawn(move || {
        let w = match app.get_webview_window("main") {
            Some(w) => w,
            None => {
                let Some(c) = app.config().app.windows.first().cloned() else { return };
                match tauri::WebviewWindowBuilder::from_config(&app, &c).and_then(|b| b.build()) {
                    Ok(w) => w,
                    Err(_) => return,
                }
            }
        };
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|a| a == "--guard") {
        if let Some(p) = args.get(2).and_then(|p| p.parse().ok()) {
            screen::guard(p);
        }
        return;
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| show(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec!["--background"])))
        .manage(Core::default())
        .invoke_handler(tauri::generate_handler![
            snapshot, defender, allowed_threats, reveal, open_security, zone_add, zone_remove, zone_scan, programs, set_perm, launch, stop, enter_screen,
            q_restore, q_delete, q_add, events, save_settings, clean
        ])
        .setup(|app| {
            let h = app.handle().clone();
            let open = MenuItem::with_id(app, "open", "فتح حصن", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "إنهاء حصن وإيقاف البرامج المعزولة", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            TrayIconBuilder::with_id("hisn")
                .icon(app.default_window_icon().ok_or("missing icon")?.clone())
                .tooltip("حصن")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, e| match e.id.as_ref() {
                    "open" => show(app),
                    "quit" => {
                        app.state::<Core>().quitting.store(true, Ordering::Relaxed);
                        app.exit(0)
                    }
                    _ => {}
                })
                .on_tray_icon_event(|t, e| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                        show(t.app_handle())
                    }
                })
                .build(app)?;
            if !std::env::args().any(|a| a == "--background") {
                show(&h);
            }
            rewatch(&h);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to start")
        .run(|app, e| {
            // Closing the window frees the whole web view; only the small watcher stays.
            if let RunEvent::ExitRequested { api, .. } = e {
                let core = app.state::<Core>();
                // A running container depends on Hisn, so closing never kills it silently.
                let keep = settings().map(|s| s.background).unwrap_or(true) || !core.running.lock().unwrap().is_empty();
                if keep && !core.quitting.load(Ordering::Relaxed) {
                    api.prevent_exit();
                }
            }
        });
}
