use std::{fs, path::Path, process::ExitCode};
use tf_guard::{scan, Severity};

fn collect(path: &Path, out: &mut Vec<std::path::PathBuf>) {
    if path.is_dir() {
        if let Ok(rd) = fs::read_dir(path) {
            let mut entries: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
            entries.sort();
            for e in entries {
                if e.file_name()
                    .is_some_and(|n| n == ".terraform" || n == ".git")
                {
                    continue;
                }
                collect(&e, out);
            }
        }
    } else if path.extension().is_some_and(|x| x == "tf") {
        out.push(path.to_path_buf());
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("usage: tf-guard <file.tf|dir>...   (exit 1 on high findings, 2 on usage error)");
        return ExitCode::from(2);
    }
    let mut files = Vec::new();
    for a in &args {
        let p = Path::new(a);
        if !p.exists() {
            eprintln!("not found: {a}");
            return ExitCode::from(2);
        }
        collect(p, &mut files);
    }
    let (mut high, mut total) = (0, 0);
    for f in &files {
        let Ok(src) = fs::read_to_string(f) else {
            eprintln!("cannot read {}", f.display());
            continue;
        };
        for x in scan(&src) {
            total += 1;
            if x.severity == Severity::High {
                high += 1;
            }
            println!(
                "{}:{}: [{}] {} {} ({})",
                f.display(),
                x.line,
                if x.severity == Severity::High {
                    "HIGH"
                } else {
                    "MEDIUM"
                },
                x.rule,
                x.message,
                x.resource
            );
        }
    }
    println!(
        "{} file(s) scanned, {} finding(s), {} high",
        files.len(),
        total,
        high
    );
    if high > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
