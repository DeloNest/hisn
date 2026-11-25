//! A private desktop plus a token without the logon SID.
//!
//! A separate desktop alone is NOT isolation: the user's desktop admits every AppContainer, and deny
//! entries for a package SID are ignored. It admits the user only through the logon SID, so a token
//! where that SID is deny-only can no longer open it.
use crate::util::*;
use std::ptr::{null, null_mut};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{StationsAndDesktops::*, Threading::*},
};

const LOGON_ID: u32 = 0xC000_0000;
// Measured minimum: READ_CONTROL, next to the global-atom right Windows already gives the user.
const WINSTA: u32 = 0x20 | 0x2_0000;
// Create windows and menus, read and write. No hooks control, journaling, enumeration of others or switching.
const DESK: u32 = 0x1 | 0x2 | 0x4 | 0x40 | 0x80 | 0x2_0000;

pub struct Token(pub HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
/// HDESK is only used from calls that are safe on any thread.
pub struct Private { handle: HDESK, pub name: String }
unsafe impl Send for Private {}
unsafe impl Sync for Private {}
impl Drop for Private {
    fn drop(&mut self) {
        unsafe { CloseDesktop(self.handle) };
    }
}
impl Private {
    pub fn raw(&self) -> HDESK {
        self.handle
    }
}

unsafe fn info(t: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Res<Vec<u64>> {
    let mut n = 0;
    GetTokenInformation(t, class, null_mut(), 0, &mut n);
    let mut b = vec![0u64; n as usize / 8 + 1];
    if GetTokenInformation(t, class, b.as_mut_ptr() as _, n, &mut n) == 0 {
        return Err(err("token query"));
    }
    Ok(b)
}
unsafe fn own_token() -> Res<Token> {
    let mut t = null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &mut t) == 0 {
        return Err(err("own token"));
    }
    Ok(Token(t))
}
fn text(s: PSID) -> Res<String> {
    unsafe {
        let mut p = null_mut();
        if ConvertSidToStringSidW(s, &mut p) == 0 {
            return Err(err("sid"));
        }
        let n = (0..).take_while(|&i| *p.add(i) != 0).count();
        let r = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        LocalFree(p as _);
        Ok(r)
    }
}
pub fn user_sid() -> Res<String> {
    unsafe {
        let t = own_token()?;
        let b = info(t.0, TokenUser)?;
        text((*(b.as_ptr() as *const TOKEN_USER)).User.Sid)
    }
}
/// The caller's token with the logon SID deny-only and privileges dropped.
pub fn token() -> Res<Token> {
    unsafe {
        let t = own_token()?;
        let b = info(t.0, TokenGroups)?;
        let g = &*(b.as_ptr() as *const TOKEN_GROUPS);
        let all = std::slice::from_raw_parts(g.Groups.as_ptr(), g.GroupCount as usize);
        let off: Vec<SID_AND_ATTRIBUTES> = all.iter().filter(|x| x.Attributes & LOGON_ID == LOGON_ID).map(|x| SID_AND_ATTRIBUTES { Sid: x.Sid, Attributes: 0 }).collect();
        if off.is_empty() {
            return Err("no logon SID in the token".into());
        }
        let mut r = null_mut();
        if CreateRestrictedToken(t.0, DISABLE_MAX_PRIVILEGE, off.len() as u32, off.as_ptr(), 0, null(), 0, null(), &mut r) == 0 {
            return Err(err("restricted token"));
        }
        Ok(Token(r))
    }
}
/// True only when every logon SID is deny-only in this token.
pub fn logon_disabled(t: HANDLE) -> bool {
    unsafe {
        let Ok(b) = info(t, TokenGroups) else { return false };
        let g = &*(b.as_ptr() as *const TOKEN_GROUPS);
        let l: Vec<_> = std::slice::from_raw_parts(g.Groups.as_ptr(), g.GroupCount as usize).iter().filter(|x| x.Attributes & LOGON_ID == LOGON_ID).collect();
        !l.is_empty() && l.iter().all(|x| x.Attributes & 0x10 != 0 && x.Attributes & 0x4 == 0)
    }
}

unsafe fn sd_text(h: HANDLE) -> Res<String> {
    let (mut sd, mut s) = (null_mut(), null_mut());
    let rc = GetSecurityInfo(h, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), null_mut(), null_mut(), &mut sd);
    if rc != 0 {
        return Err(format!("GetSecurityInfo {rc}"));
    }
    ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, DACL_SECURITY_INFORMATION, &mut s, null_mut());
    LocalFree(sd as _);
    if s.is_null() {
        return Err(err("sddl"));
    }
    let n = (0..).take_while(|&i| *s.add(i) != 0).count();
    let r = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
    LocalFree(s as _);
    Ok(r)
}
pub fn describe() -> Res<(String, String)> {
    unsafe {
        let d = OpenDesktopW(wide("Default").as_ptr(), 0, 0, 0x2_0000);
        if d.is_null() {
            return Err(err("open Default"));
        }
        let r = (sd_text(GetProcessWindowStation())?, sd_text(d)?);
        CloseDesktop(d);
        Ok(r)
    }
}
/// The protection rests on the user's desktop not admitting the user SID or a broad group directly.
pub fn default_is_closed() -> Res<()> {
    let (_, d) = describe()?;
    for bad in [user_sid()?.as_str(), "WD", "AU", "IU", "BU", "S-1-5-4", "S-1-1-0", "S-1-5-11", "S-1-5-32-545"] {
        if d.contains(&format!(";;;{bad})")) {
            return Err(format!("this PC's desktop admits {bad}; keyboard and screen cannot be protected"));
        }
    }
    Ok(())
}

/// Lets the weakened token attach to the window station at all. Lasts until sign-out.
fn admit_user_to_station() -> Res<()> {
    unsafe {
        let h = GetProcessWindowStation();
        let user = user_sid()?;
        let mut sid = null_mut();
        if ConvertStringSidToSidW(wide(&user).as_ptr(), &mut sid) == 0 {
            return Err(err("sid"));
        }
        let (mut sd, mut old, mut new) = (null_mut(), null_mut(), null_mut());
        let mut rc = GetSecurityInfo(h, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), &mut old, null_mut(), &mut sd);
        if rc == 0 {
            let mut e: EXPLICIT_ACCESS_W = std::mem::zeroed();
            e.grfAccessPermissions = WINSTA;
            e.grfAccessMode = GRANT_ACCESS;
            e.grfInheritance = 4; // no-propagate, so it merges with the entry Windows made
            e.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            e.Trustee.ptstrName = sid as _;
            rc = SetEntriesInAclW(1, &e, old, &mut new);
        }
        if rc == 0 {
            rc = SetSecurityInfo(h, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), new, null());
        }
        LocalFree(new as _);
        LocalFree(sd as _);
        LocalFree(sid);
        if rc == 0 { Ok(()) } else { Err(format!("window station: {}", std::io::Error::from_raw_os_error(rc as i32))) }
    }
}

pub fn create(container: &str) -> Res<Private> {
    default_is_closed()?;
    admit_user_to_station()?;
    let user = user_sid()?;
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
    let name = format!("Hisn_{}", &hash_str(&format!("{container}{t}"))[..16]);
    unsafe {
        let mut sd = null_mut();
        // The user entry serves both Hisn and the user half of the container's access check;
        // only this one container SID passes the other half.
        let s = format!("D:P(A;;0xf01ff;;;{user})(A;;0x{:x};;;{container})S:(ML;;NW;;;LW)", DESK);
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(&s).as_ptr(), 1, &mut sd, null_mut()) == 0 {
            return Err(err("sddl"));
        }
        let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
        let h = CreateDesktopW(wide(&name).as_ptr(), null(), null(), 0, 0xf01ff, &sa);
        let e = err("CreateDesktop");
        LocalFree(sd as _);
        if h.is_null() { Err(e) } else { Ok(Private { handle: h, name }) }
    }
}
