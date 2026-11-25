use crate::util::*;
use std::path::{Path, PathBuf};

const GAME_DIRS: &[&str] = &[
    "steam", "steamapps", "steamlibrary", "riot games", "epic games", "battle.net", "easyanticheat",
    "easyanticheat_eos", "battleye", "ea games", "xboxgames", "ubisoft", "faceit",
];

fn file() -> Res<PathBuf> {
    Ok(state()?.join("zones.json"))
}
pub fn list() -> Res<Vec<PathBuf>> {
    load_json(&file()?)
}
pub fn validate(p: &Path) -> Res<PathBuf> {
    let z = canon(p)?;
    if !z.is_dir() {
        return Err("a zone must be a folder".into());
    }
    if z.parent().is_none() {
        return Err("a whole drive cannot be a zone".into());
    }
    for v in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "APPDATA"] {
        if let Some(d) = std::env::var_os(v) {
            let d = PathBuf::from(d);
            if is_within(&z, &d) || is_within(&d, &z) {
                return Err(format!("protected location: {}", d.display()));
            }
        }
    }
    for d in [PathBuf::from(std::env::var_os("USERPROFILE").ok_or("USERPROFILE missing")?), state()?] {
        if is_within(&d, &z) {
            return Err(format!("zone would contain {}", d.display()));
        }
    }
    for c in z.components() {
        let n = c.as_os_str().to_string_lossy().to_lowercase();
        if GAME_DIRS.contains(&n.as_str()) {
            return Err(format!("\"{n}\" belongs to a game launcher or anti-cheat; refused to protect your account"));
        }
    }
    Ok(z)
}
pub fn add(p: &Path) -> Res<PathBuf> {
    let _l = lock();
    let z = validate(p)?;
    let mut l = list()?;
    if !l.iter().any(|x| same(x, &z)) {
        l.push(z.clone());
        save_json(&file()?, &l)?;
    }
    Ok(z)
}
pub fn remove(p: &Path) -> Res<()> {
    let _l = lock();
    let key = canon(p).unwrap_or_else(|_| p.to_path_buf());
    let mut l = list()?;
    let n = l.len();
    l.retain(|x| !same(x, &key));
    if l.len() == n {
        return Err("not a registered zone".into());
    }
    save_json(&file()?, &l)
}
pub fn containing(p: &Path) -> Res<PathBuf> {
    list()?.into_iter().find(|z| is_within(p, z)).ok_or_else(|| "file is not inside a protected zone".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_dangerous_zones() {
        for p in [r"C:\", r"C:\Windows", r"C:\Windows\System32", r"C:\Users"] {
            assert!(validate(Path::new(p)).is_err(), "{p}");
        }
        assert!(validate(Path::new(&std::env::var("USERPROFILE").unwrap())).is_err());
    }
    #[test]
    fn prefix_is_not_containment() {
        assert!(!is_within(Path::new(r"C:\zone2\a"), Path::new(r"C:\zone")));
        assert!(is_within(Path::new(r"C:\ZONE\a"), Path::new(r"c:\zone")));
    }
}
