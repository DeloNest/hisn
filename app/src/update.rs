//! Updates from GitHub Releases. The updater only installs files signed with the project's key,
//! and only newer versions.
use crate::{ar, log, settings, Core};
use hisn::util::*;
use serde::Serialize;
use std::{path::Path, sync::atomic::{AtomicBool, Ordering}, sync::Mutex, time::Duration};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};

#[derive(Default)]
pub struct Updates { found: Mutex<Option<Update>>, busy: AtomicBool, told: Mutex<String> }

#[derive(Serialize)]
pub struct View { version: String, notes: String, busy: bool }

pub fn view(app: &AppHandle) -> Option<View> {
    let u = app.state::<Updates>();
    let f = u.found.lock().unwrap();
    f.as_ref().map(|x| View {
        version: crate::safe(&x.version),
        notes: x.body.as_deref().unwrap_or("").chars().filter(|c| *c == '\n' || !c.is_control()).take(1500).collect(),
        busy: u.busy.load(Ordering::Relaxed),
    })
}

async fn look(app: &AppHandle) -> Res<bool> {
    let found = app.updater().map_err(|e| e.to_string())?.check().await.map_err(|e| e.to_string())?;
    let u = app.state::<Updates>();
    let some = found.is_some();
    if let Some(v) = found.as_ref().map(|f| f.version.clone()) {
        let first = std::mem::replace(&mut *u.told.lock().unwrap(), v.clone()) != v;
        if first {
            log(app, "update", &format!("يتوفر تحديث {}", crate::safe(&v)), Path::new(""));
        }
    }
    *u.found.lock().unwrap() = found;
    let _ = app.emit("changed", ());
    Ok(some)
}
fn containers_running(app: &AppHandle) -> bool {
    !app.state::<Core>().running.lock().unwrap().is_empty()
}
async fn install(app: &AppHandle) -> Res<()> {
    if containers_running(app) {
        return Err("أوقف البرامج المعزولة أولاً، ثم حدّث.".into());
    }
    let u = app.state::<Updates>();
    let Some(up) = u.found.lock().unwrap().clone() else { return Err("لا يوجد تحديث.".into()) };
    if u.busy.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    let _ = app.emit("changed", ());
    // download() verifies the signature before returning any bytes.
    let r = match up.download(|_, _| {}, || {}).await {
        Err(e) => Err(format!("لم يُثبّت التحديث: {}", crate::safe(&e.to_string()))),
        // Something may have been started during the download.
        Ok(_) if containers_running(app) => Err("بدأ برنامج معزول أثناء التنزيل. أوقفه ثم حدّث.".into()),
        Ok(b) => up.install(b).map_err(|e| format!("لم يُثبّت التحديث: {}", crate::safe(&e.to_string()))),
    };
    u.busy.store(false, Ordering::Relaxed);
    let _ = app.emit("changed", ());
    r
}

#[tauri::command]
pub async fn update_check(app: AppHandle) -> Res<bool> {
    look(&app).await.map_err(|_| "تعذّر البحث عن تحديث. تأكد من الإنترنت.".into())
}
#[tauri::command]
pub async fn update_install(app: AppHandle, _u: State<'_, Updates>) -> Res<()> {
    install(&app).await.map_err(|e| if e.is_ascii() { ar(e) } else { e })
}

/// Shortly after start, then twice a day.
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        loop {
            if tauri::async_runtime::block_on(look(&app)).unwrap_or(false) {
                // Unattended installs wait until nobody is using Hisn.
                for _ in 0..144 {
                    let auto = settings().map(|s| s.auto_update).unwrap_or(false);
                    if auto && app.get_webview_window("main").is_none() && !containers_running(&app) && app.state::<Core>().busy.lock().unwrap().is_empty() {
                        if let Err(e) = tauri::async_runtime::block_on(install(&app)) {
                            log(&app, "warn", &e, Path::new(""));
                        }
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(300));
                }
            }
            std::thread::sleep(Duration::from_secs(12 * 3600));
        }
    });
}
