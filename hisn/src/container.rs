//! Kernel-enforced launch: AppContainer/LPAC token and job, both set at process creation.
use crate::util::*;
use serde::{Deserialize, Serialize};
use std::{ffi::{c_void, OsStr}, fs, mem::{size_of, size_of_val, zeroed}, os::windows::{fs::OpenOptionsExt, process::CommandExt}, path::{Path, PathBuf}, process::Command, ptr::{null, null_mut}};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Isolation::*, *},
    System::{Com::CoTaskMemFree, JobObjects::*, Threading::*},
};

/// Called with the private desktop before the program's first instruction; an error kills it.
pub type OnDesktop = std::sync::Arc<dyn Fn(std::sync::Arc<crate::desktop::Private>) -> Res<()> + Send + Sync>;

#[derive(Clone, Default)]
pub struct Opts { pub private_desktop: bool, pub on_desktop: Option<OnDesktop>, pub net: bool, pub write: bool, pub lpac: bool, pub hidden: bool, pub timeout_ms: Option<u32>, pub cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>> }

#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct Grant { path: PathBuf, sid: String, profile: String }

struct Owned(HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}
struct Sid(PSID);
impl Drop for Sid {
    fn drop(&mut self) {
        unsafe { FreeSid(self.0) };
    }
}
/// SIDs and arrays allocated with LocalAlloc.
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
unsafe fn from_wide(p: *const u16) -> String {
    let n = (0..).take_while(|&i| *p.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

pub fn profile_name(exe: &Path) -> String {
    format!("Hisn.{}", &hash_str(&exe.to_string_lossy().to_lowercase())[..32])
}
fn journal() -> Res<PathBuf> {
    Ok(state()?.join("grants.json"))
}
fn icacls(args: &[&OsStr]) -> Res<()> {
    let exe = PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot missing")?).join(r"System32\icacls.exe");
    let o = Command::new(exe).args(args).creation_flags(CREATE_NO_WINDOW).output().map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!("icacls: {}", String::from_utf8_lossy(&o.stdout).trim()))
    }
}
fn grant(dir: &Path, sid: &str, profile: &str, write: bool) -> Res<()> {
    let _l = lock();
    let mut j: Vec<Grant> = load_json(&journal()?)?;
    let g = Grant { path: dir.into(), sid: sid.into(), profile: profile.into() };
    if !j.contains(&g) {
        j.push(g);
        save_json(&journal()?, &j)?; // journal before touching the ACL
    }
    let r = format!("*{sid}:(OI)(CI){}", if write { "M" } else { "RX" });
    icacls(&[dir.as_os_str(), "/grant:r".as_ref(), r.as_ref(), "/Q".as_ref()])
}
/// Undo every ACL entry and container profile Hisn created. `only` limits it to one profile.
pub fn clean(only: Option<&str>) -> Res<usize> {
    let _l = lock();
    let (mut left, mut n) = (vec![], 0);
    for g in load_json::<Vec<Grant>>(&journal()?)? {
        if only.is_some_and(|o| o != g.profile) {
            left.push(g);
            continue;
        }
        let who = format!("*{}", g.sid);
        if g.path.exists() && icacls(&[g.path.as_os_str(), "/remove:g".as_ref(), who.as_ref(), "/Q".as_ref()]).is_err() {
            left.push(g);
            continue;
        }
        unsafe { DeleteAppContainerProfile(wide(&g.profile).as_ptr()) };
        n += 1;
    }
    save_json(&journal()?, &left)?;
    if only.is_none() && !left.is_empty() {
        return Err(format!("{} entries could not be cleaned", left.len()));
    }
    Ok(n)
}
fn sid_str(s: PSID) -> Res<String> {
    unsafe {
        let mut p = null_mut();
        if ConvertSidToStringSidW(s, &mut p) == 0 {
            return Err(err("ConvertSid"));
        }
        let r = from_wide(p);
        LocalFree(p as _);
        Ok(r)
    }
}
fn make_profile(name: &str) -> Res<Sid> {
    unsafe {
        let (w, d) = (wide(name), wide("Hisn container"));
        let mut s = null_mut();
        if CreateAppContainerProfile(w.as_ptr(), w.as_ptr(), d.as_ptr(), null(), 0, &mut s) < 0 {
            let hr = DeriveAppContainerSidFromAppContainerName(w.as_ptr(), &mut s);
            if hr < 0 {
                return Err(format!("AppContainer profile failed: 0x{hr:08x}"));
            }
        }
        Ok(Sid(s))
    }
}
fn folder(sid: &str) -> Res<PathBuf> {
    unsafe {
        let mut p = null_mut();
        let hr = GetAppContainerFolderPath(wide(sid).as_ptr(), &mut p);
        if hr < 0 {
            return Err(format!("container folder: 0x{hr:08x}"));
        }
        let r = PathBuf::from(from_wide(p));
        CoTaskMemFree(p as _);
        Ok(r)
    }
}
pub fn data_dir(exe: &Path) -> Res<PathBuf> {
    let s = make_profile(&profile_name(exe))?;
    folder(&sid_str(s.0)?)
}

pub fn sid_of(exe: &Path) -> Res<String> {
    sid_str(make_profile(&profile_name(exe))?.0)
}

/// Allow-list only: user environment variables often hold API keys.
fn environment(data: &Path) -> Vec<u16> {
    let get = |k: &str| std::env::var(k).unwrap_or_default();
    let root = get("SystemRoot");
    let d = data.to_string_lossy().to_string();
    let mut v: Vec<(String, String)> = [
        "SystemRoot", "SystemDrive", "ComSpec", "ProgramData", "ProgramFiles", "ProgramFiles(x86)",
        "CommonProgramFiles", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "PATHEXT",
    ]
    .iter()
    .map(|k| (k.to_string(), get(k)))
    .filter(|x| !x.1.is_empty())
    .collect();
    v.push(("windir".into(), root.clone()));
    v.push(("PATH".into(), format!("{root}\\System32;{root};{root}\\System32\\WindowsPowerShell\\v1.0")));
    for k in ["USERPROFILE", "LOCALAPPDATA", "APPDATA"] {
        v.push((k.into(), d.clone()));
    }
    for k in ["TEMP", "TMP"] {
        v.push((k.into(), format!("{d}\\Temp")));
    }
    v.sort_by_key(|x| x.0.to_uppercase());
    let mut o: Vec<u16> = vec![];
    for (k, x) in v {
        o.extend(format!("{k}={x}\0").encode_utf16());
    }
    o.push(0);
    o
}
/// CommandLineToArgvW-compatible quoting.
pub fn quote(a: &str) -> String {
    let (mut o, mut b) = (String::from("\""), 0);
    for c in a.chars() {
        if c == '\\' {
            b += 1;
            continue;
        }
        o.push_str(&"\\".repeat(if c == '"' { b * 2 + 1 } else { b }));
        b = 0;
        o.push(c);
    }
    o.push_str(&"\\".repeat(b * 2));
    o.push('"');
    o
}
/// None when the token could not be queried.
unsafe fn token_flag(t: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<bool> {
    let (mut v, mut n) = (0u32, 0u32);
    (GetTokenInformation(t, class, &mut v as *mut _ as _, 4, &mut n) != 0).then_some(v != 0)
}
fn self_elevated() -> bool {
    unsafe {
        let mut t = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) == 0 {
            return true;
        }
        let t = Owned(t);
        token_flag(t.0, TokenElevation) != Some(false)
    }
}

/// Runs to completion of the whole process tree. Closing Hisn kills the tree.
pub fn run(exe: &Path, args: &[String], o: &Opts) -> Res<u32> {
    if self_elevated() {
        return Err("refusing to launch from an elevated Hisn".into());
    }
    let exe = canon(exe)?;
    if !exe.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
        return Err("only .exe files can be launched".into());
    }
    // Hold the image against replacement until it exits.
    let _pin = fs::OpenOptions::new().read(true).share_mode(1).open(&exe).map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or("no parent folder")?;
    let name = profile_name(&exe);
    let sid = make_profile(&name)?;
    let ss = sid_str(sid.0)?;
    let data = folder(&ss)?;
    fs::create_dir_all(data.join("Temp")).map_err(|e| e.to_string())?;
    grant(dir, &ss, &name, o.write)?;

    unsafe {
        let mut caps: Vec<SID_AND_ATTRIBUTES> = vec![];
        let mut _keep: Vec<Local> = vec![];
        if o.net {
            let mut s = null_mut();
            if ConvertStringSidToSidW(wide("S-1-15-3-1").as_ptr(), &mut s) == 0 {
                return Err(err("internetClient"));
            }
            caps.push(SID_AND_ATTRIBUTES { Sid: s, Attributes: 4 });
            _keep.push(Local(s));
        }
        if o.lpac {
            let (mut gs, mut gn, mut cs, mut cn) = (null_mut(), 0, null_mut(), 0);
            if DeriveCapabilitySidsFromName(wide("registryRead").as_ptr(), &mut gs, &mut gn, &mut cs, &mut cn) == 0 {
                return Err(err("registryRead"));
            }
            for i in 0..cn as usize {
                let s = *cs.add(i);
                caps.push(SID_AND_ATTRIBUTES { Sid: s, Attributes: 4 });
                _keep.push(Local(s));
            }
            for i in 0..gn as usize {
                _keep.push(Local(*gs.add(i)));
            }
            _keep.push(Local(gs as _));
            _keep.push(Local(cs as _));
        }
        let sc = SECURITY_CAPABILITIES {
            AppContainerSid: sid.0,
            Capabilities: if caps.is_empty() { null_mut() } else { caps.as_mut_ptr() },
            CapabilityCount: caps.len() as u32,
            Reserved: 0,
        };

        let job = Owned(CreateJobObjectW(null(), null()));
        if job.0.is_null() {
            return Err(err("job"));
        }
        let mut li: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        li.BasicLimitInformation.ActiveProcessLimit = 64;
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_EXITWINDOWS,
        };
        if SetInformationJobObject(job.0, JobObjectExtendedLimitInformation, &li as *const _ as _, size_of_val(&li) as u32) == 0
            || SetInformationJobObject(job.0, JobObjectBasicUIRestrictions, &ui as *const _ as _, size_of_val(&ui) as u32) == 0
        {
            return Err(err("job limits"));
        }

        let mut sz = 0;
        InitializeProcThreadAttributeList(null_mut(), 4, 0, &mut sz);
        let mut buf = vec![0u64; sz / 8 + 1];
        let al = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if InitializeProcThreadAttributeList(al, 4, 0, &mut sz) == 0 {
            return Err(err("attributes"));
        }
        let jobs = [job.0];
        let mitigations: u64 = (1 << 32) | (1 << 52); // no legacy extension points, no remote images
        let optout: u32 = 1;
        let set = |k: usize, p: *const c_void, n: usize| -> Res<()> {
            if UpdateProcThreadAttribute(al, 0, k, p, n, null_mut(), null()) == 0 {
                return Err(err("attribute"));
            }
            Ok(())
        };
        set(0x20009, &sc as *const _ as _, size_of_val(&sc))?; // SECURITY_CAPABILITIES
        set(0x2000D, jobs.as_ptr() as _, size_of::<HANDLE>())?; // JOB_LIST
        set(0x20007, &mitigations as *const _ as _, 8)?; // MITIGATION_POLICY
        if o.lpac {
            set(0x2000F, &optout as *const _ as _, 4)?; // ALL_APPLICATION_PACKAGES opt-out
        }

        let mut si: STARTUPINFOEXW = zeroed();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = al;
        let private = if o.private_desktop { Some((std::sync::Arc::new(crate::desktop::create(&ss)?), crate::desktop::token()?)) } else { None };
        let mut desk_name = private.as_ref().map(|p| wide(format!("WinSta0\\{}", p.0.name)));
        if let Some(d) = desk_name.as_mut() {
            si.StartupInfo.lpDesktop = d.as_mut_ptr();
        }
        let mut pi: PROCESS_INFORMATION = zeroed();
        let env = environment(&data);
        let mut line = quote(&exe.to_string_lossy());
        for a in args {
            line.push(' ');
            line.push_str(&quote(a));
        }
        let (image, cwd, mut line) = (wide(&exe), wide(dir), wide(line));
        let flags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT
            | if o.hidden { CREATE_NO_WINDOW } else { CREATE_NEW_CONSOLE };
        let ok = match &private {
            Some((_, t)) => CreateProcessAsUserW(t.0, image.as_ptr(), line.as_mut_ptr(), null(), null(), 0, flags, env.as_ptr() as _, cwd.as_ptr(), &si.StartupInfo, &mut pi),
            None => CreateProcessW(image.as_ptr(), line.as_mut_ptr(), null(), null(), 0, flags, env.as_ptr() as _, cwd.as_ptr(), &si.StartupInfo, &mut pi),
        };
        let e = GetLastError();
        DeleteProcThreadAttributeList(al);
        if ok == 0 {
            return Err(if e == ERROR_ELEVATION_REQUIRED {
                "blocked: program demands Administrator rights".into()
            } else {
                format!("launch failed: {}", std::io::Error::from_raw_os_error(e as i32))
            });
        }
        let (proc, thread) = (Owned(pi.hProcess), Owned(pi.hThread));
        let kill = |m: String| -> Res<u32> {
            TerminateJobObject(job.0, 1);
            TerminateProcess(proc.0, 1);
            Err(m)
        };

        // Confirm confinement before the first instruction runs.
        let (mut t, mut inside) = (null_mut(), 0);
        let opened = OpenProcessToken(proc.0, TOKEN_QUERY, &mut t) != 0;
        let t = Owned(t);
        if !opened
            || token_flag(t.0, TokenIsAppContainer) != Some(true)
            || token_flag(t.0, TokenElevation) != Some(false)
            || IsProcessInJob(proc.0, job.0, &mut inside) == 0
            || inside == 0
            || (private.is_some() && !crate::desktop::logon_disabled(t.0))
        {
            return kill("confinement could not be verified; process killed".into());
        }
        if let (Some((d, _)), Some(f)) = (&private, &o.on_desktop) {
            if let Err(e) = f(d.clone()) {
                return kill(e);
            }
        }
        if ResumeThread(thread.0) == u32::MAX {
            return kill(err("resume"));
        }
        let start = std::time::Instant::now();
        loop {
            let mut a: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = zeroed();
            if QueryInformationJobObject(job.0, JobObjectBasicAccountingInformation, &mut a as *mut _ as _, size_of_val(&a) as u32, null_mut()) == 0 {
                return kill(err("job query"));
            }
            if a.ActiveProcesses == 0 {
                break;
            }
            if o.cancel.as_ref().is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                return kill("stopped by user".into());
            }
            if o.timeout_ms.is_some_and(|m| start.elapsed().as_millis() > m as u128) {
                return kill("timed out; killed".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        let mut code = 0;
        GetExitCodeProcess(proc.0, &mut code);
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::quote;
    #[test]
    fn quoting() {
        assert_eq!(quote("a b"), r#""a b""#);
        assert_eq!(quote(r"a\"), r#""a\\""#);
        assert_eq!(quote(r#"a\"b"#), r#""a\\\"b""#);
    }
}
