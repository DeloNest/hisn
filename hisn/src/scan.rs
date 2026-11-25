use crate::util::*;
use serde::{Deserialize, Serialize};
use std::{fs, os::windows::process::CommandExt, path::{Path, PathBuf}, process::Command};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
/// Notice: common and weak (no signature). Suspicious: a specific warning sign.
pub enum Verdict { Notice, Suspicious, Malicious }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Finding { pub path: PathBuf, pub verdict: Verdict, pub reasons: Vec<String> }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Report { pub target: PathBuf, pub files: usize, pub skipped: Vec<PathBuf>, pub findings: Vec<Finding> }

pub fn report_path(zone: &Path) -> Res<PathBuf> {
    let d = state()?.join("reports");
    fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d.join(format!("{}.json", &hash_str(&zone.to_string_lossy().to_lowercase())[..32])))
}

/// Full Defender scan without remediation, plus cheap static signals.
/// Any scanner failure is an error: "could not scan" never becomes "clean".
pub fn scan(target: &Path) -> Res<Report> {
    let target = canon(target)?;
    let mut r = Report { target: target.clone(), files: 0, skipped: vec![], findings: vec![] };
    let files = walk(&target, &mut r.skipped);
    r.files = files.len();
    let hits = defender(&target)?;
    for (p, name) in &hits {
        r.findings.push(Finding { path: p.clone(), verdict: Verdict::Malicious, reasons: vec![format!("Defender: {name}")] });
    }
    for f in files {
        if hits.iter().any(|(p, _)| same(&f, p)) {
            continue;
        }
        let (verdict, reasons) = signals(&f);
        if !reasons.is_empty() {
            r.findings.push(Finding { path: f, verdict, reasons });
        }
    }
    r.findings.sort_by(|a, b| b.verdict.cmp(&a.verdict));
    Ok(r)
}

fn walk(root: &Path, skipped: &mut Vec<PathBuf>) -> Vec<PathBuf> {
    let (mut stack, mut out) = (vec![root.to_path_buf()], vec![]);
    while let Some(p) = stack.pop() {
        let Ok(m) = fs::symlink_metadata(&p) else {
            skipped.push(p);
            continue;
        };
        if is_reparse(&m) {
            skipped.push(p);
        } else if m.is_file() {
            out.push(p);
        } else {
            match fs::read_dir(&p) {
                Ok(d) => {
                    for e in d {
                        match e {
                            Ok(e) => stack.push(e.path()),
                            Err(_) => skipped.push(p.clone()),
                        }
                    }
                }
                Err(_) => skipped.push(p),
            }
        }
    }
    out
}

fn defender(target: &Path) -> Res<Vec<(PathBuf, String)>> {
    let exe = PathBuf::from(std::env::var_os("ProgramFiles").ok_or("ProgramFiles missing")?).join(r"Windows Defender\MpCmdRun.exe");
    let o = Command::new(exe)
        .args(["-Scan", "-ScanType", "3", "-File"])
        .arg(target)
        .arg("-DisableRemediation")
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| format!("Defender did not start: {e}"))?;
    let text = String::from_utf8_lossy(&o.stdout);
    let hits = parse_defender(&text);
    if hits.is_empty() && o.status.code() != Some(0) {
        return Err(format!("Defender scan failed ({:?}): {}", o.status.code(), text.trim().chars().take(400).collect::<String>()));
    }
    Ok(hits)
}

pub fn parse_defender(t: &str) -> Vec<(PathBuf, String)> {
    let (mut name, mut out): (String, Vec<(PathBuf, String)>) = ("threat".into(), vec![]);
    for l in t.lines() {
        let Some((k, v)) = l.split_once(':') else { continue };
        match k.trim().to_lowercase().as_str() {
            "threat" => name = v.trim().into(),
            "file" | "containerfile" => {
                // archive members appear as outer.zip->inner.exe
                let outer = PathBuf::from(v.trim().split("->").next().unwrap_or("").trim());
                if !outer.as_os_str().is_empty() && !out.iter().any(|(p, _)| *p == outer) {
                    out.push((outer, name.clone()));
                }
            }
            _ => {}
        }
    }
    out
}

/// Windows libraries that programs load by name: a local copy runs inside the program.
const PROXY: &[&str] = &["winmm.dll", "version.dll", "winhttp.dll", "dinput8.dll", "dsound.dll", "dxgi.dll", "d3d9.dll", "d3d11.dll", "wininet.dll", "userenv.dll", "cryptbase.dll"];

fn signals(p: &Path) -> (Verdict, Vec<String>) {
    const RUNNABLE: &[&str] = &["exe", "scr", "com", "pif", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk"];
    let name = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
    let ext = p.extension().unwrap_or_default().to_string_lossy().to_lowercase();
    let mut r = vec![];
    let sig = if ["exe", "scr", "msi", "dll"].contains(&ext.as_str()) { trust(p) } else { 0 };
    if sig == BAD_DIGEST {
        r.push("modified after it was signed".into());
    }
    if ext == "dll" {
        if sig != 0 && PROXY.contains(&name.as_str()) {
            r.push("replaces a Windows library".into());
        }
        return (Verdict::Suspicious, r);
    }
    if !RUNNABLE.contains(&ext.as_str()) {
        return (Verdict::Notice, r);
    }
    let stem = name.rsplit_once('.').map(|x| x.0).unwrap_or("").trim_end();
    if [".pdf", ".jpg", ".png", ".docx", ".xlsx", ".mp4", ".txt", ".zip"].iter().any(|x| stem.ends_with(x)) {
        r.push("double extension disguises a program".into());
    }
    if ["scr", "pif", "vbe", "jse", "wsf", "hta"].contains(&ext.as_str()) {
        r.push(format!(".{ext} is rarely legitimate"));
    }
    if name.chars().any(|c| matches!(c as u32, 0x202A..=0x202E | 0x2066..=0x2069)) {
        r.push("hidden text-direction characters in the name".into());
    }
    let verdict = if r.is_empty() { Verdict::Notice } else { Verdict::Suspicious };
    if sig != 0 && sig != BAD_DIGEST {
        let mut ads = p.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        let motw = fs::read_to_string(ads).is_ok_and(|s| s.contains("ZoneId=3") || s.contains("ZoneId=4"));
        r.push(if motw { "unsigned and downloaded from the internet".into() } else { "unsigned program".into() });
    }
    (verdict, r)
}

const BAD_DIGEST: i32 = 0x8009_6010_u32 as i32;

/// 0 means a valid, trusted signature.
fn trust(p: &Path) -> i32 {
    use windows_sys::Win32::Security::WinTrust::*;
    let w = wide(p);
    unsafe {
        let mut f: WINTRUST_FILE_INFO = std::mem::zeroed();
        f.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        f.pcwszFilePath = w.as_ptr();
        let mut d: WINTRUST_DATA = std::mem::zeroed();
        d.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        d.dwUIChoice = WTD_UI_NONE;
        d.fdwRevocationChecks = WTD_REVOKE_NONE;
        d.dwUnionChoice = WTD_CHOICE_FILE;
        d.Anonymous.pFile = &mut f;
        d.dwStateAction = WTD_STATEACTION_VERIFY;
        d.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        let mut g = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let none = -1isize;
        let rc = WinVerifyTrust(none as _, &mut g, &mut d as *mut _ as _);
        d.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(none as _, &mut g, &mut d as *mut _ as _);
        rc
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    #[test]
    fn parses_threat_and_archive() {
        let t = "Threat                  : Virus:DOS/X\r\nResources : 1 total\r\n    file                : C:\\a b\\e.zip->x.exe\r\n";
        assert_eq!(super::parse_defender(t), vec![(PathBuf::from("C:\\a b\\e.zip"), "Virus:DOS/X".to_string())]);
    }
    #[test]
    fn signature_check_works() {
        assert_eq!(super::trust(std::path::Path::new(r"C:\Windows\explorer.exe")), 0);
        assert_ne!(super::trust(&std::env::current_exe().unwrap()), 0);
    }
}
