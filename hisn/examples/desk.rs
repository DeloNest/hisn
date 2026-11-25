//! Can a contained process open a desktop it was not given? Opens and closes handles only:
//! no capture, no hooks, no switching, and the real desktop is never modified.
use hisn::{container::{self, Opts}, util::*};
use std::{fs, ptr::{null, null_mut}};
use windows_sys::Win32::{
    Security::{Authorization::*, *},
    System::StationsAndDesktops::*,
};

fn can_open(name: &str, access: u32) -> bool {
    unsafe {
        let h = OpenDesktopW(wide(name).as_ptr(), 0, 0, access);
        if !h.is_null() {
            CloseDesktop(h);
        }
        !h.is_null()
    }
}
fn sddl(name: &str) -> Res<String> {
    unsafe {
        let h = OpenDesktopW(wide(name).as_ptr(), 0, 0, 0x20000);
        if h.is_null() {
            return Err(err("open"));
        }
        let info = DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
        let (mut sd, mut s) = (null_mut(), null_mut());
        let rc = GetSecurityInfo(h as _, SE_WINDOW_OBJECT, info, null_mut(), null_mut(), null_mut(), null_mut(), &mut sd);
        if rc != 0 {
            return Err(format!("GetSecurityInfo {rc}"));
        }
        ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, info, &mut s, null_mut());
        let n = (0..).take_while(|&i| *s.add(i) != 0).count();
        Ok(String::from_utf16_lossy(std::slice::from_raw_parts(s, n)))
    }
}
fn create(name: &str, sd: &str) -> Res<HDESK> {
    unsafe {
        let mut p = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sd).as_ptr(), 1, &mut p, null_mut()) == 0 {
            return Err(err("sddl"));
        }
        let sa = SECURITY_ATTRIBUTES { nLength: 24, lpSecurityDescriptor: p, bInheritHandle: 0 };
        let h = CreateDesktopW(wide(name).as_ptr(), null(), null(), 0, 0x10000000, &sa);
        if h.is_null() { Err(err("CreateDesktop")) } else { Ok(h) }
    }
}
const NAMES: [&str; 5] = ["Default", "HisnT_copy", "HisnT_deny", "HisnT_userOnly", "HisnT_mine"];

fn main() -> Res<()> {
    let a: Vec<String> = std::env::args().collect();
    if let Some(out) = a.get(1) {
        let mut s = String::new();
        for n in NAMES {
            s += &format!("{n:<16} read={} write={} hook={} enumerate={}\n", can_open(n, 0x1), can_open(n, 0x80), can_open(n, 0x8), can_open(n, 0x40));
        }
        s += &format!("open current={} clipboard_lock={}", can_open(a.get(2).map(|x| x.as_str()).unwrap_or(""), 1), unsafe { let o = windows_sys::Win32::System::DataExchange::OpenClipboard(null_mut()); if o != 0 { windows_sys::Win32::System::DataExchange::CloseClipboard(); } o != 0 });
        fs::write(out, s).map_err(|e| e.to_string())?;
        return Ok(());
    }
    let exe = canon(&std::env::current_exe().unwrap())?;
    let data = container::data_dir(&exe)?;
    let sid = container::sid_of(&exe)?;
    let real = sddl("Default")?;
    println!("Default: {real}\ncontainer: {sid}");
    let dacl = real[real.find("D:").unwrap()..].to_string();
    let (d, sacl) = dacl.split_once("S:").map(|(a, b)| (a.to_string(), format!("S:{b}"))).unwrap_or((dacl.clone(), "S:(ML;;NW;;;LW)".into()));
    let aces = &d[d.find('(').unwrap()..];
    let _h = [
        create("HisnT_copy", &format!("D:{aces}{sacl}"))?,
        create("HisnT_deny", &format!("D:(D;;GA;;;{sid}){aces}{sacl}"))?,
        create("HisnT_userOnly", "D:(A;;GA;;;OW)S:(ML;;NW;;;LW)")?,
        create("HisnT_mine", &format!("D:{aces}(A;;0x200c7;;;{sid})S:(ML;;NW;;;LW)"))?,
    ];
    println!("station: {:?}", hisn::desktop::describe()?.0);
    for (label, lpac, pd) in [("AppContainer", false, false), ("AppContainer+private", false, true), ("LPAC+private", true, true)] {
        let out = data.join(format!("desk{lpac}{pd}.txt"));
        let o = Opts { hidden: true, lpac, private_desktop: pd, timeout_ms: Some(20000), ..Default::default() };
        let r = container::run(&exe, &[out.display().to_string()], &o);
        println!("== {label}: {r:?}\n{}", fs::read_to_string(&out).unwrap_or_default());
    }
    container::clean(Some(&container::profile_name(&exe)))?;
    Ok(())
}
