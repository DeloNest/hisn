//! Harmless escape probe. Each entry is true when the attempt SUCCEEDED.
//! It never reads personal content: only a canary, or yes/no on whether an object can be opened.
use std::{collections::BTreeMap, fs, net::*, os::windows::process::CommandExt, path::Path, process::Command, ptr::{null, null_mut}, time::Duration};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::{DataExchange::*, LibraryLoader::GetModuleHandleW, Registry::*, Threading::*},
    UI::WindowsAndMessaging::*,
};

const NO_WINDOW: u32 = 0x0800_0000;

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn canary(p: &str) -> bool {
    fs::read_to_string(p).is_ok_and(|s| s == "CANARY")
}
fn tcp(a: &str) -> bool {
    TcpStream::connect_timeout(&a.parse().unwrap(), Duration::from_secs(4)).is_ok()
}
fn ps(s: &str) -> bool {
    Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", s]).creation_flags(NO_WINDOW).status().is_ok_and(|s| s.success())
}
fn schtasks(x: &[&str]) -> bool {
    Command::new("schtasks.exe").args(x).creation_flags(NO_WINDOW).output().is_ok_and(|o| o.status.success())
}
unsafe fn hkcu(key: &str, access: u32) -> bool {
    let mut h = null_mut();
    let ok = RegOpenKeyExW(HKEY_CURRENT_USER, w(key).as_ptr(), 0, access, &mut h) == 0;
    if ok {
        RegCloseKey(h);
    }
    ok
}
unsafe extern "system" fn hook(c: i32, a: WPARAM, b: LPARAM) -> LRESULT {
    CallNextHookEx(null_mut(), c, a, b)
}

fn main() {
    // Only where lab/inside.ps1 (or the owner of a VM) placed this marker.
    if !std::path::Path::new("C:/hisn-disposable-vm.marker").exists() {
        eprintln!("refused: hisn-probe runs only in a disposable VM (lab/run.ps1)");
        std::process::exit(2);
    }
    let a: Vec<String> = std::env::args().collect();
    if a.get(1).is_some_and(|x| x == "--child") {
        std::process::exit(if canary(&a[2]) { 77 } else { 0 })
    }
    let (out, secret, port, pid) = (&a[1], &a[2], &a[3], a[4].parse::<u32>().unwrap());
    let c = format!("{secret}\\canary.txt");
    let mut r: BTreeMap<&str, bool> = BTreeMap::new();

    r.insert("file_read", canary(&c));
    r.insert("file_read_verbatim", canary(&format!("\\\\?\\{c}")));
    r.insert("file_read_unc", canary(&format!("\\\\localhost\\{}$\\{}", &c[..1], &c[3..])));
    r.insert("file_read_globalroot", canary(&format!("\\\\?\\GLOBALROOT\\??\\{c}")));
    r.insert("file_write", fs::write(format!("{secret}\\written.txt"), "x").is_ok());
    r.insert("file_list_folder", fs::read_dir(secret).is_ok());
    let here = Path::new(out).parent().unwrap();
    let link = here.join(format!("j{}", std::process::id()));
    let _ = Command::new("cmd.exe").args(["/c", "mklink", "/J"]).arg(&link).arg(secret).creation_flags(NO_WINDOW).output();
    r.insert("file_read_junction", canary(&link.join("canary.txt").to_string_lossy()));
    let _ = fs::remove_dir(&link);
    let hl = here.join("hard.txt");
    r.insert("file_read_hardlink", fs::hard_link(&c, &hl).is_ok() && canary(&hl.to_string_lossy()));
    let _ = fs::remove_file(&hl);
    r.insert("child_read", Command::new(&a[0]).args(["--child", &c]).creation_flags(NO_WINDOW).status().is_ok_and(|s| s.code() == Some(77)));
    r.insert("self_modify_folder", {
        let f = Path::new(&a[0]).with_file_name("planted.tmp");
        let ok = fs::write(&f, "x").is_ok();
        let _ = fs::remove_file(f);
        ok
    });

    r.insert("net_tcp", tcp("1.1.1.1:443"));
    r.insert("net_loopback", tcp(&format!("127.0.0.1:{port}")));
    r.insert("net_dns", ("example.com", 443).to_socket_addrs().is_ok_and(|mut x| x.next().is_some()));
    r.insert("net_udp", UdpSocket::bind("0.0.0.0:0").is_ok_and(|u| {
        let q = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01";
        let _ = u.set_read_timeout(Some(Duration::from_secs(4)));
        u.send_to(q, "1.1.1.1:53").is_ok() && u.recv_from(&mut [0; 512]).is_ok()
    }));

    unsafe {
        // Opened for write and closed again: nothing is stored.
        r.insert("reg_run_key", hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_SET_VALUE));
        r.insert("reg_com_hijack", hkcu("Software\\Classes", KEY_CREATE_SUB_KEY));
        for (n, acc) in [("proc_inject_open", PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD), ("proc_memory_read", PROCESS_VM_READ)] {
            let h = OpenProcess(acc, 0, pid);
            r.insert(n, !h.is_null());
            if !h.is_null() {
                CloseHandle(h);
            }
        }
        let cb = OpenClipboard(null_mut()) != 0;
        r.insert("clipboard_read", cb && !GetClipboardData(13).is_null());
        if cb {
            CloseClipboard();
        }
        let h = SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook), GetModuleHandleW(null()), 0);
        r.insert("keyboard_hook", !h.is_null());
        if !h.is_null() {
            UnhookWindowsHookEx(h);
        }
        // Pixels are only checked for "not all the same colour", then discarded.
        let dc = GetDC(null_mut());
        let mem = CreateCompatibleDC(dc);
        let bmp = CreateCompatibleBitmap(dc, 1200, 800);
        SelectObject(mem, bmp as _);
        let ok = BitBlt(mem, 0, 0, 1200, 800, dc, 0, 0, SRCCOPY) != 0;
        let first = GetPixel(mem, 0, 0);
        let varied = (0..1200).step_by(13).any(|x| (0..800).step_by(13).any(|y| GetPixel(mem, x, y) != first));
        r.insert("screen_capture", ok && varied);
        DeleteDC(mem);
        DeleteObject(bmp as _);
        ReleaseDC(null_mut(), dc);
    }

    let mark = |n: &str| format!("cmd.exe /c echo x> \"{secret}\\{n}.txt\"");
    let _ = Command::new("cmd.exe").raw_arg(format!("/c echo x> \"{secret}\\breakaway.txt\"")).creation_flags(0x0100_0000 | NO_WINDOW).status();
    r.insert("info_powershell", ps("exit 0"));
    ps(&format!("Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine='{}'}}", mark("wmi")));
    ps(&format!("$o=[activator]::CreateInstance([type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39'));$o.Item().Document.Application.ShellExecute('cmd.exe','/c echo x> \"\"{secret}\\com.txt\"\"','','open',0)").replace("\"\"", "\\\""));
    // The task is created, run once, and deleted.
    let t = format!("HisnProbe{}", std::process::id());
    let created = schtasks(&["/Create", "/F", "/TN", &t, "/SC", "ONCE", "/ST", "23:59", "/TR", &mark("task")]);
    r.insert("task_create", created);
    if created {
        schtasks(&["/Run", "/TN", &t]);
        std::thread::sleep(Duration::from_secs(3));
        schtasks(&["/Delete", "/F", "/TN", &t]);
    }
    fs::write(out, serde_json::to_vec(&r).unwrap()).unwrap();
}
