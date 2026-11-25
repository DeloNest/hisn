use hisn::{container, ops, quarantine, scan::Verdict, selftest, util::*, zone};
use std::path::Path;

const HELP: &str = "hisn zone add|remove <folder>   |   hisn zone list
hisn scan <zone> [--quarantine]
hisn run <exe> [--net] [--write] [--lpac] [-- args...]
hisn quarantine list | restore <id> | delete <id>
hisn clean              undo all permissions; DELETES data saved inside containers
hisn selftest <probe.exe>";

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = go(&a) {
        eprintln!("error: {e}");
        std::process::exit(1)
    }
}
fn go(a: &[String]) -> Res<()> {
    let s: Vec<&str> = a.iter().map(|x| x.as_str()).collect();
    match s.as_slice() {
        ["zone", "add", p] => {
            println!("zone added: {}", zone::add(Path::new(p))?.display());
            println!("Note: opening a file directly from Explorer is NOT contained yet; use `hisn run`.");
        }
        ["zone", "remove", p] => zone::remove(Path::new(p))?,
        ["zone", "list"] => {
            for z in zone::list()? {
                println!("{}", z.display())
            }
        }
        ["scan", p] => do_scan(p, false)?,
        ["scan", p, "--quarantine"] => do_scan(p, true)?,
        ["quarantine", "list"] => {
            for i in quarantine::list()? {
                println!("{}  {}  {}", i.id, i.original.display(), i.reason)
            }
        }
        ["quarantine", "restore", id] => println!("restored: {}", ops::restore(id)?.display()),
        ["quarantine", "delete", id] => quarantine::delete(id)?,
        ["clean"] => println!("cleaned {}", container::clean(None)?),
        ["selftest", p] => selftest::run(Path::new(p))?,
        ["run", exe, rest @ ..] => do_run(exe, rest)?,
        _ => println!("{HELP}"),
    }
    Ok(())
}
fn do_scan(p: &str, quarantine: bool) -> Res<()> {
    let (r, moved) = ops::scan_zone(Path::new(p), quarantine)?;
    for f in &r.findings {
        let tag = match f.verdict { Verdict::Malicious => "MALICIOUS", Verdict::Suspicious => "SUSPICIOUS", Verdict::Notice => "notice" };
        println!("[{tag}] {}\n    {}", f.path.display(), f.reasons.join("; "));
    }
    for m in moved {
        match m.result {
            Ok(i) => println!("quarantined {} as {}", m.path.display(), i.id),
            Err(e) => println!("NOT quarantined {}: {e}", m.path.display()),
        }
    }
    println!("{} files, {} findings, {} skipped. \"Nothing found\" is not proof of safety.", r.files, r.findings.len(), r.skipped.len());
    Ok(())
}
fn do_run(exe: &str, rest: &[&str]) -> Res<()> {
    let mut o = container::Opts::default();
    let cut = rest.iter().position(|x| *x == "--").unwrap_or(rest.len());
    for f in &rest[..cut] {
        match *f {
            "--net" => o.net = true,
            "--write" => o.write = true,
            "--lpac" => o.lpac = true,
            x => return Err(format!("unknown option {x}")),
        }
    }
    let args: Vec<String> = rest.get(cut + 1..).unwrap_or(&[]).iter().map(|x| x.to_string()).collect();
    let exe = ops::check_launch(Path::new(exe))?;
    println!("running contained; network {}; personal files hidden", if o.net { "ON" } else { "off" });
    println!("exit code {}", container::run(&exe, &args, &o)?);
    Ok(())
}
