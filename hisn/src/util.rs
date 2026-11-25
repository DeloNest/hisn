use sha2::{Digest, Sha256};
use std::{fs, io::Read, os::windows::ffi::OsStrExt, os::windows::fs::MetadataExt, path::{Path, PathBuf}};

pub type Res<T> = Result<T, String>;

pub fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
pub fn err(ctx: &str) -> String {
    format!("{ctx}: {}", std::io::Error::last_os_error())
}
/// Per-user state directory.
pub fn state() -> Res<PathBuf> {
    let p = PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing")?).join("Hisn");
    fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    Ok(p)
}
/// Canonical path without the \\?\ prefix. UNC and device paths are refused.
pub fn canon(p: &Path) -> Res<PathBuf> {
    let c = fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let s = c.to_str().ok_or("path is not valid Unicode")?;
    let s = s.strip_prefix(r"\\?\").unwrap_or(s);
    if s.as_bytes().get(1) != Some(&b':') {
        return Err("only local drive paths are supported".into());
    }
    Ok(PathBuf::from(s))
}
pub fn is_within(child: &Path, parent: &Path) -> bool {
    let (c, p) = (child.to_string_lossy().to_lowercase(), parent.to_string_lossy().to_lowercase());
    Path::new(&c).starts_with(Path::new(&p))
}
pub fn same(a: &Path, b: &Path) -> bool {
    is_within(a, b) && is_within(b, a)
}
pub fn is_reparse(m: &fs::Metadata) -> bool {
    m.file_attributes() & 0x400 != 0
}
pub fn sha256(p: &Path) -> Res<String> {
    let mut f = fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut h = Sha256::new();
    let mut b = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(hex(&h.finalize()))
}
pub fn hash_bytes(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
pub fn hash_str(s: &str) -> String {
    hash_bytes(s.as_bytes())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Write through a temp file so an interrupted save never truncates state.
pub fn save_json<T: serde::Serialize>(p: &Path, v: &T) -> Res<()> {
    let t = p.with_extension("tmp");
    fs::write(&t, serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    fs::rename(&t, p).map_err(|e| e.to_string())
}
/// Missing file means default; a damaged file is an error, never "empty".
pub fn load_json<T: serde::de::DeserializeOwned + Default>(p: &Path) -> Res<T> {
    match fs::read(p) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{} is damaged: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e.to_string()),
    }
}

/// Serializes read-modify-write of state files inside this process.
pub fn lock() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}
