//! Harmless escape attempts. The uncontained control must succeed, or "blocked" proves nothing.
use crate::{container::{self, Opts}, util::*};
use std::{collections::BTreeMap, fs, net::TcpListener, path::Path, process::Command};

type R = BTreeMap<String, bool>;

fn read(p: &Path) -> Res<R> {
    let b = fs::read(p).map_err(|e| format!("probe produced no result: {e}"))?;
    serde_json::from_slice(&b).map_err(|e| e.to_string())
}

pub fn run(probe: &Path) -> Res<()> {
    let root = state()?.join("selftest");
    let _ = fs::remove_dir_all(&root);
    let (zone, secret) = (root.join("zone"), root.join("secret"));
    fs::create_dir_all(&zone).map_err(|e| e.to_string())?;
    fs::create_dir_all(&secret).map_err(|e| e.to_string())?;
    let exe = zone.join("hisn-probe.exe");
    fs::copy(probe, &exe).map_err(|e| e.to_string())?;
    let exe = canon(&exe)?;
    fs::write(secret.join("canary.txt"), "CANARY").map_err(|e| e.to_string())?;
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    std::thread::spawn(move || for s in l.incoming() { drop(s) });
    let args = |out: &Path| vec![out.display().to_string(), secret.display().to_string(), port.to_string(), std::process::id().to_string()];
    // Effects carried out by other processes are judged by what appeared on disk.
    let effects = |r: &mut R| {
        std::thread::sleep(std::time::Duration::from_secs(2));
        for n in ["wmi", "com", "breakaway", "task"] {
            let f = secret.join(format!("{n}.txt"));
            r.insert(format!("escape_{n}"), f.exists());
            let _ = fs::remove_file(f);
        }
        let _ = fs::remove_file(secret.join("written.txt"));
    };

    let out = root.join("control.json");
    Command::new(&exe).args(args(&out)).status().map_err(|e| e.to_string())?;
    let mut ctl = read(&out)?;
    effects(&mut ctl);

    let mut cols: Vec<(&str, R)> = vec![];
    for (n, lpac, net) in [("AppContainer", false, false), ("LPAC", true, false), ("AC+net", false, true)] {
        let out = container::data_dir(&exe)?.join(format!("{n}.json"));
        let o = Opts { lpac, net, hidden: true, timeout_ms: Some(120_000), ..Default::default() };
        match container::run(&exe, &args(&out), &o).and_then(|c| read(&out).map_err(|e| format!("{e} (exit 0x{c:x})"))) {
            Ok(mut r) => {
                effects(&mut r);
                cols.push((n, r));
            }
            Err(e) => println!("{n}: {e}"),
        }
    }
    println!("{:<24}{:>10}{:>14}{:>10}{:>10}", "attempt", "control", "AppContainer", "LPAC", "AC+net");
    for (k, c) in &ctl {
        let cell = |n: &str| match cols.iter().find(|x| x.0 == n).and_then(|x| x.1.get(k)) {
            None => "no data",
            Some(true) => "POSSIBLE",
            Some(false) if *c => "blocked",
            Some(false) => "unproven",
        };
        println!("{k:<24}{:>10}{:>14}{:>10}{:>10}", if *c { "possible" } else { "no" }, cell("AppContainer"), cell("LPAC"), cell("AC+net"));
    }
    println!("\n\"unproven\": the control failed too, so nothing is shown.");
    container::clean(Some(&container::profile_name(&exe)))?;
    fs::remove_dir_all(&root).map_err(|e| e.to_string())
}
