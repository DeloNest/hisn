//! Operations shared by the command line and the desktop app.
use crate::{quarantine, scan::{self, Report, Verdict}, util::*, zone};
use std::path::{Path, PathBuf};

pub fn report(zone: &Path) -> Res<Option<Report>> {
    load_json(&scan::report_path(zone)?)
}
fn registered(p: &Path) -> Res<PathBuf> {
    let z = canon(p)?;
    if zone::list()?.iter().any(|x| same(x, &z)) {
        Ok(z)
    } else {
        Err("not a registered zone".into())
    }
}
/// Files the user restored on purpose: not auto-quarantined again, still refused at launch.
fn kept() -> Res<Vec<String>> {
    load_json(&state()?.join("kept.json"))
}
pub struct Moved {
    pub path: PathBuf,
    pub result: Res<quarantine::Item>,
}
fn isolate(r: &mut Report) -> Res<Vec<Moved>> {
    let kept = kept()?;
    let mut out = vec![];
    for f in r.findings.iter().filter(|f| f.verdict == Verdict::Malicious) {
        if sha256(&f.path).is_ok_and(|h| kept.contains(&h)) {
            continue;
        }
        out.push(Moved { path: f.path.clone(), result: quarantine::add(&f.path, &f.reasons.join("; ")) });
    }
    r.findings.retain(|f| f.path.exists());
    Ok(out)
}
/// Returns what was found (before quarantine) and what was moved.
pub fn scan_zone(p: &Path, quarantine: bool) -> Res<(Report, Vec<Moved>)> {
    let z = registered(p)?;
    let mut r = scan::scan(&z)?;
    let shown = r.clone();
    let moved = if quarantine { isolate(&mut r)? } else { vec![] };
    let _l = lock();
    save_json(&scan::report_path(&z)?, &r)?;
    Ok((shown, moved))
}
/// Scan one new file or folder and merge it into the zone's existing report.
pub fn scan_new(p: &Path, quarantine: bool) -> Res<(Report, Vec<Moved>)> {
    let p = canon(p)?;
    let z = zone::containing(&p)?;
    let mut r = scan::scan(&p)?;
    let shown = r.clone();
    let moved = if quarantine { isolate(&mut r)? } else { vec![] };
    let _l = lock();
    if let Some(mut all) = report(&z)? {
        all.findings.retain(|f| !is_within(&f.path, &p) && f.path.exists());
        all.findings.extend(r.findings);
        all.files += shown.files;
        save_json(&scan::report_path(&z)?, &all)?;
    }
    Ok((shown, moved))
}
/// Every launch passes through here.
pub fn check_launch(exe: &Path) -> Res<PathBuf> {
    let exe = canon(exe)?;
    let z = zone::validate(&zone::containing(&exe)?)?;
    let rep = report(&z)?.ok_or("scan the zone first")?;
    if rep.findings.iter().any(|f| f.verdict == Verdict::Malicious && f.path.exists()) {
        return Err("refused: the zone still holds a malicious file".into());
    }
    if scan::scan(&exe)?.findings.iter().any(|f| f.verdict == Verdict::Malicious) {
        return Err("refused: malicious program".into());
    }
    Ok(exe)
}
pub fn restore(id: &str) -> Res<PathBuf> {
    let i = quarantine::list()?.into_iter().find(|x| x.id == id).ok_or("no such quarantine id")?;
    let mut k = kept()?;
    if !k.contains(&i.sha256) {
        k.push(i.sha256);
        save_json(&state()?.join("kept.json"), &k)?; // before the file reappears, or the watcher re-takes it
    }
    let p = quarantine::restore(id)?;
    // The launch gate must know about it.
    scan_new(&p, false)?;
    Ok(p)
}
