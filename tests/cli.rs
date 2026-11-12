use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_tf-guard"))
        .args(args)
        .output()
        .unwrap();
    (
        o.status.code().unwrap(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
    )
}

#[test]
fn exit_codes_and_output() {
    let (code, out) = run(&["samples/bad.tf"]);
    assert_eq!(code, 1);
    assert!(out.contains("samples/bad.tf:8: [HIGH] TF001"), "{out}");
    let (code, out) = run(&["samples/good.tf"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("0 finding(s)"));
    assert_eq!(run(&[]).0, 2);
    assert_eq!(run(&["nope.tf"]).0, 2);
}

#[test]
fn directories_are_walked() {
    let (code, out) = run(&["samples"]);
    assert_eq!(code, 1);
    assert!(out.contains("2 file(s) scanned"), "{out}");
}
