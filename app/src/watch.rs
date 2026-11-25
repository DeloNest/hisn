//! Event-driven folder watching: no polling, only the user's zones.
use crate::{log, scan_and_log};
use hisn::{util::*, zone};
use notify::{event::ModifyKind, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::mpsc::{channel, RecvTimeoutError},
    time::{Duration, Instant, SystemTime},
};
use tauri::AppHandle;

pub struct Watch(#[allow(dead_code)] RecommendedWatcher); // dropping it stops the worker

const QUIET: Duration = Duration::from_secs(3);
const MAX_WAIT: Duration = Duration::from_secs(60);

/// ACL edits (Hisn makes them itself) also arrive as modifications; a recent write time tells them apart.
fn relevant(e: &EventKind, p: &Path) -> bool {
    match e {
        EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(_)) => true,
        EventKind::Modify(_) => std::fs::metadata(p).is_ok_and(|m| {
            m.is_file() && m.modified().is_ok_and(|t| SystemTime::now().duration_since(t).map_or(true, |d| d < Duration::from_secs(120)))
        }),
        _ => false,
    }
}

pub fn start(app: AppHandle, zones: &[PathBuf]) -> Res<Watch> {
    let (tx, rx) = channel::<Option<PathBuf>>();
    let mut w = notify::recommended_watcher(move |r: notify::Result<Event>| match r {
        Ok(e) => {
            if e.need_rescan() {
                let _ = tx.send(None);
            }
            for p in e.paths {
                if relevant(&e.kind, &p) {
                    let _ = tx.send(Some(p));
                }
            }
        }
        Err(_) => {
            let _ = tx.send(None);
        }
    })
    .map_err(|e| e.to_string())?;
    for z in zones {
        if let Err(e) = w.watch(z, RecursiveMode::Recursive) {
            // One missing folder must not leave the other zones unwatched.
            log(&app, "warn", &format!("تعذّرت مراقبة المنطقة: {}", crate::safe(&e.to_string())), z);
        }
    }
    std::thread::spawn(move || {
        let mut pending: HashSet<PathBuf> = HashSet::new();
        let (mut overflow, mut first) = (false, None::<Instant>);
        loop {
            match rx.recv_timeout(QUIET) {
                Ok(x) => {
                    first.get_or_insert_with(Instant::now);
                    match x {
                        Some(p) => {
                            pending.insert(p);
                        }
                        None => overflow = true,
                    }
                    if first.is_some_and(|f| f.elapsed() < MAX_WAIT) {
                        continue;
                    }
                }
                Err(RecvTimeoutError::Timeout) if first.is_none() => continue,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            first = None;
            let items: Vec<PathBuf> = pending.drain().filter(|p| p.exists()).collect();
            if overflow || items.len() > 5 {
                // Many changes (an extracted archive): one scan of each affected zone.
                let mut zs: Vec<PathBuf> = if overflow { zone::list().unwrap_or_default() } else { items.iter().filter_map(|p| zone::containing(p).ok()).collect() };
                zs.sort();
                zs.dedup();
                for z in zs {
                    let _ = scan_and_log(&app, &z, true);
                }
            } else {
                for p in items {
                    if scan_and_log(&app, &p, false).is_err() {
                        // Often still locked by the program writing it: try once more.
                        std::thread::sleep(QUIET);
                        if p.exists() {
                            let _ = scan_and_log(&app, &p, false);
                        }
                    }
                }
            }
            overflow = false;
        }
    });
    Ok(Watch(w))
}
