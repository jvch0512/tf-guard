use tf_guard::*;

fn rules(src: &str) -> Vec<&'static str> {
    scan(src).iter().map(|f| f.rule).collect()
}

#[test]
fn open_ssh_is_high_and_egress_is_not_flagged() {
    let src = include_str!("../samples/bad.tf");
    let f = scan(src);
    let sg: Vec<_> = f.iter().filter(|x| x.rule == "TF001").collect();
    assert_eq!(
        sg.len(),
        1,
        "ingress 22 only, the all-ports egress block must not count twice"
    );
    assert_eq!(sg[0].line, 8, "points at the 0.0.0.0/0 line");
    assert_eq!(sg[0].severity, Severity::High);
}

#[test]
fn bad_sample_hits_every_family() {
    let r = rules(include_str!("../samples/bad.tf"));
    for rule in ["TF001", "TF002", "TF003", "TF005", "TF006", "TF007"] {
        assert!(r.contains(&rule), "missing {rule} in {r:?}");
    }
}

#[test]
fn good_sample_has_no_high_findings() {
    let f = scan(include_str!("../samples/good.tf"));
    assert!(f.iter().all(|x| x.severity != Severity::High), "{f:?}");
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn comments_and_braces_in_strings_do_not_confuse_blocks() {
    let src = "# resource \"aws_db_instance\" \"fake\" {\n}\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"a{b}c\" // }\n  acl = \"public-read\"\n}\nresource \"aws_ebs_volume\" \"v\" {\n  encrypted = true\n}\n";
    let blocks = parse_blocks(src);
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].name, "b");
    let r = rules(src);
    assert!(r.contains(&"TF002"));
    assert!(!r.contains(&"TF005"));
}

#[test]
fn spacing_variants_are_handled() {
    assert!(
        rules("resource \"aws_db_instance\" \"d\" {\n storage_encrypted=false\n}")
            .contains(&"TF005")
    );
    assert!(rules("resource \"aws_ebs_volume\" \"v\" {\n encrypted    =   true\n}").is_empty());
    assert!(rules("resource \"aws_security_group_rule\" \"r\" {\n type = \"ingress\"\n from_port=3389\n to_port=3389\n cidr_blocks=[\"::/0\"]\n}").contains(&"TF001"));
}

#[test]
fn security_group_rule_egress_is_ignored() {
    assert!(rules("resource \"aws_security_group_rule\" \"r\" {\n type = \"egress\"\n from_port=0\n to_port=0\n cidr_blocks=[\"0.0.0.0/0\"]\n}").is_empty());
}

#[test]
fn public_access_block_flags_each_disabled_setting() {
    let r = rules("resource \"aws_s3_bucket_public_access_block\" \"p\" {\n block_public_acls = false\n block_public_policy = true\n ignore_public_acls = false\n}");
    assert_eq!(r.iter().filter(|x| **x == "TF004").count(), 2);
}

#[test]
fn clean_keeps_line_numbers() {
    let src = "a /* x\ny */ b # c\nd";
    assert_eq!(clean(src).lines().count(), 3);
}

#[test]
fn findings_sorted_high_first_and_empty_input_ok() {
    let f = scan(include_str!("../samples/bad.tf"));
    assert!(f.windows(2).all(|w| w[0].severity >= w[1].severity));
    assert!(scan("").is_empty());
    assert!(
        scan("resource \"aws_db_instance\"").is_empty(),
        "malformed header must not panic"
    );
}
