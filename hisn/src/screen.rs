//! Switching to a private desktop and, above all, always getting back:
//! a hotkey, a button, an automatic return unless the user confirms, a return when the program ends,
//! and a separate guard process for when Hisn itself dies.
use crate::{desktop::Private, util::*};
use std::{
    ptr::{null, null_mut},
    sync::{mpsc, Arc},
    thread::JoinHandle,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{LibraryLoader::GetModuleHandleW, Services::*, StationsAndDesktops::*, Threading::*},
    UI::{Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
};

const ARM: u32 = WM_APP + 1;
const BACK: usize = 1;
const STAY: usize = 2;
const TIMER: usize = 3;
const AUTO_RETURN_MS: u32 = 15_000;

pub struct Screen { desk: Arc<Private>, thread: u32, join: Option<JoinHandle<()>> }

pub fn current() -> String {
    unsafe {
        let h = OpenInputDesktop(0, 0, 0x1);
        if h.is_null() {
            return String::new();
        }
        let (mut b, mut n) = ([0u16; 128], 0);
        GetUserObjectInformationW(h as _, UOI_NAME, b.as_mut_ptr() as _, 256, &mut n);
        CloseDesktop(h);
        String::from_utf16_lossy(&b).trim_end_matches('\0').to_string()
    }
}
pub fn go_home() -> bool {
    unsafe {
        let d = OpenDesktopW(wide("Default").as_ptr(), 0, 0, DESKTOP_SWITCHDESKTOP);
        if d.is_null() {
            return false;
        }
        let ok = SwitchDesktop(d) != 0;
        CloseDesktop(d);
        ok
    }
}
/// Runs as a separate process: if Hisn dies while its desktop is showing, bring the user back.
pub fn guard(pid: u32) {
    unsafe {
        let p = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if !p.is_null() {
            WaitForSingleObject(p, INFINITE);
            CloseHandle(p);
        }
    }
    for _ in 0..10 {
        if !current().starts_with("Hisn_") || go_home() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}
/// Name of a running anti-cheat component, if any. Read-only query.
pub fn anti_cheat() -> Option<&'static str> {
    const NAMES: &[&str] = &[
        "vgk", "vgc", "EasyAntiCheat", "EasyAntiCheat_EOS", "EasyAntiCheatSys", "EasyAntiCheat_EOSSys", "BEService", "BEDaisy",
        "atvi-brynhildr", "FACEIT", "FACEITService", "EAAntiCheat", "EAAntiCheatService", "mhyprot2", "mhyprot3", "ACE-BASE", "ACE-GAME", "xhunter1",
    ];
    unsafe {
        let m = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if m.is_null() {
            return Some("unknown (service query failed)");
        }
        let mut found = None;
        for n in NAMES {
            let s = OpenServiceW(m, wide(n).as_ptr(), SERVICE_QUERY_STATUS);
            if s.is_null() {
                continue;
            }
            let mut st: SERVICE_STATUS = std::mem::zeroed();
            if QueryServiceStatus(s, &mut st) != 0 && st.dwCurrentState != SERVICE_STOPPED {
                found = Some(*n);
            }
            CloseServiceHandle(s);
        }
        CloseServiceHandle(m);
        found
    }
}

/// Puts the trusted return bar on the desktop. Call before the program's first instruction,
/// so it cannot take the hotkey first.
pub fn host(desk: Arc<Private>) -> Res<Screen> {
    let (tx, rx) = mpsc::channel::<Res<u32>>();
    let d = desk.clone();
    let join = std::thread::spawn(move || unsafe { bar(&d, tx) });
    let thread = rx.recv().map_err(|_| "return bar failed".to_string())??;
    Ok(Screen { desk, thread, join: Some(join) })
}

unsafe fn bar(d: &Private, tx: mpsc::Sender<Res<u32>>) {
    let fail = |m: &str| {
        let _ = tx.send(Err(err(m)));
    };
    if SetThreadDesktop(d.raw()) == 0 {
        return fail("SetThreadDesktop");
    }
    let class = wide("HisnReturnBar");
    let inst = GetModuleHandleW(null());
    let mut wc: WNDCLASSW = std::mem::zeroed();
    wc.lpfnWndProc = Some(proc_);
    wc.hInstance = inst;
    wc.lpszClassName = class.as_ptr();
    wc.hbrBackground = 6 as _; // COLOR_WINDOW + 1
    wc.hCursor = LoadCursorW(null_mut(), IDC_ARROW);
    RegisterClassW(&wc); // already registered on later launches
    let (w, h) = (430, 48);
    let x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    let win = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, class.as_ptr(), wide("حصن").as_ptr(), WS_POPUP | WS_BORDER | WS_VISIBLE, x, 0, w, h, null_mut(), null_mut(), inst, null());
    if win.is_null() {
        return fail("return bar");
    }
    let button = |t: &str, x: i32, w: i32, id: usize| CreateWindowExW(0, wide("BUTTON").as_ptr(), wide(t).as_ptr(), WS_CHILD | WS_VISIBLE, x, 8, w, 30, win, id as _, inst, null());
    if button("رجوع لشاشتي (Ctrl+Alt+Home)", 8, 250, BACK).is_null() || button("ابقَ هنا", 266, 150, STAY).is_null() {
        return fail("return buttons");
    }
    if RegisterHotKey(null_mut(), 1, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, VK_HOME as u32) == 0 {
        DestroyWindow(win);
        return fail("return hotkey is taken by another program");
    }
    let mut confirmed = false;
    let mut m: MSG = std::mem::zeroed();
    PeekMessageW(&mut m, null_mut(), WM_USER, WM_USER, PM_NOREMOVE); // create the queue
    let _ = tx.send(Ok(GetCurrentThreadId()));
    while GetMessageW(&mut m, null_mut(), 0, 0) > 0 {
        match m.message {
            WM_HOTKEY => {
                go_home();
            }
            // Posted by the window procedure; the program cannot post to a higher-integrity thread.
            WM_COMMAND if m.wParam == BACK => {
                go_home();
            }
            WM_COMMAND if m.wParam == STAY => {
                confirmed = true;
                KillTimer(win, TIMER);
            }
            ARM if !confirmed => {
                SetTimer(win, TIMER, AUTO_RETURN_MS, None);
            }
            WM_TIMER if m.wParam == TIMER => {
                KillTimer(win, TIMER);
                if current() == d.name {
                    go_home();
                }
            }
            _ => {
                TranslateMessage(&m);
                DispatchMessageW(&m);
            }
        }
    }
    if current() == d.name {
        go_home();
    }
    UnregisterHotKey(null_mut(), 1);
    DestroyWindow(win);
}
unsafe extern "system" fn proc_(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match m {
        WM_COMMAND => {
            PostThreadMessageW(GetCurrentThreadId(), WM_COMMAND, w & 0xffff, 0);
            0
        }
        WM_CLOSE => 0,
        _ => DefWindowProcW(h, m, w, l),
    }
}

impl Screen {
    pub fn enter(&self) -> Res<()> {
        if let Some(n) = anti_cheat() {
            return Err(format!("anti-cheat is running: {n}"));
        }
        // The timer is armed first: a switch can never happen without a way back.
        if unsafe { PostThreadMessageW(self.thread, ARM, 0, 0) } == 0 {
            return Err(err("return bar is gone"));
        }
        if unsafe { SwitchDesktop(self.desk.raw()) } == 0 {
            return Err(err("SwitchDesktop"));
        }
        Ok(())
    }
    pub fn name(&self) -> &str {
        &self.desk.name
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        unsafe { PostThreadMessageW(self.thread, WM_QUIT, 0, 0) };
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}
