//! A deliberately small Terraform (HCL) scanner. It extracts `resource "type" "name" { ... }` blocks
//! with a brace-aware tokenizer (comments and strings respected) and applies AWS misconfiguration rules.
//! It is a fast pre-commit check, not a replacement for `terraform plan` based tools.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub resource: String,
    pub line: usize,
    pub message: String,
}

#[derive(Debug)]
pub struct Block {
    pub kind: String,
    pub name: String,
    pub line: usize,
    pub body: String,
    pub body_line: usize,
}

/// Remove comments (#, //, /* */) and blank out string contents' braces so brace counting is safe.
/// Line structure is preserved so line numbers stay correct. Returns the cleaned text.
pub fn clean(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let (mut i, mut in_str, mut block) = (0, false, false);
    while i < c.len() {
        let ch = c[i];
        if block {
            if ch == '*' && c.get(i + 1) == Some(&'/') {
                block = false;
                i += 2;
                continue;
            }
            if ch == '\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if in_str {
            if ch == '\\' && i + 1 < c.len() {
                out.push(ch);
                out.push(c[i + 1]);
                i += 2;
                continue;
            }
            if ch == '"' {
                in_str = false;
            }
            out.push(if ch == '{' || ch == '}' { '_' } else { ch });
            i += 1;
            continue;
        }
        match ch {
            '"' => {
                in_str = true;
                out.push(ch);
            }
            '#' => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            '/' if c.get(i + 1) == Some(&'/') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                block = true;
                i += 2;
                continue;
            }
            _ => out.push(ch),
        }
        i += 1;
    }
    out
}

pub fn parse_blocks(src: &str) -> Vec<Block> {
    let text = clean(src);
    let mut blocks = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut idx = 0;
    while idx < lines.len() {
        let t = lines[idx].trim_start();
        if let Some(rest) = t.strip_prefix("resource") {
            let q: Vec<&str> = rest.split('"').collect();
            if q.len() >= 4 && lines[idx].contains('{') {
                let (kind, name) = (q[1].to_string(), q[3].to_string());
                let start = idx;
                let mut depth = 0i32;
                let mut body = String::new();
                let mut j = idx;
                'scan: while j < lines.len() {
                    for ch in lines[j].chars() {
                        if ch == '{' {
                            depth += 1;
                        }
                        if ch == '}' {
                            depth -= 1;
                        }
                    }
                    body.push_str(lines[j]);
                    body.push('\n');
                    if depth <= 0 {
                        break 'scan;
                    }
                    j += 1;
                }
                blocks.push(Block {
                    kind,
                    name,
                    line: start + 1,
                    body,
                    body_line: start + 1,
                });
                idx = j + 1;
                continue;
            }
        }
        idx += 1;
    }
    blocks
}

fn has(body: &str, needle: &str) -> bool {
    body.lines().any(|l| compact(l).contains(&compact(needle)))
}

fn compact(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Line (1-based, in the file) of the first body line containing the needle, falling back to the block line.
fn line_of(b: &Block, needle: &str) -> usize {
    b.body
        .lines()
        .position(|l| compact(l).contains(&compact(needle)))
        .map(|p| b.body_line + p)
        .unwrap_or(b.line)
}

fn sensitive_port(body: &str) -> Option<&'static str> {
    let flat = compact(body);
    let ports = [
        ("22", "SSH"),
        ("3389", "RDP"),
        ("3306", "MySQL"),
        ("5432", "PostgreSQL"),
        ("1433", "MSSQL"),
        ("27017", "MongoDB"),
        ("6379", "Redis"),
    ];
    let from = flat.split("from_port=").nth(1).map(|s| {
        s.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
    });
    let to = flat.split("to_port=").nth(1).map(|s| {
        s.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
    });
    if from.as_deref() == Some("0") && matches!(to.as_deref(), Some("0") | Some("65535")) {
        return Some("all ports");
    }
    for (p, name) in ports {
        if from.as_deref() == Some(p) || to.as_deref() == Some(p) {
            return Some(name);
        }
    }
    None
}

pub fn scan(src: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for b in parse_blocks(src) {
        let id = format!("{}.{}", b.kind, b.name);
        let mut add = |rule: &'static str, severity: Severity, line: usize, message: &str| {
            out.push(Finding {
                rule,
                severity,
                resource: id.clone(),
                line,
                message: message.to_string(),
            });
        };
        match b.kind.as_str() {
            "aws_security_group"
            | "aws_security_group_rule"
            | "aws_vpc_security_group_ingress_rule" => {
                let world = has(&b.body, "0.0.0.0/0") || has(&b.body, "::/0");
                let egress_only =
                    b.kind == "aws_security_group_rule" && has(&b.body, "type=\"egress\"");
                if world && !egress_only {
                    if let Some(what) = sensitive_port(&b.body) {
                        let needle = if has(&b.body, "0.0.0.0/0") {
                            "0.0.0.0/0"
                        } else {
                            "::/0"
                        };
                        add(
                            "TF001",
                            Severity::High,
                            line_of(&b, needle),
                            &format!("{what} is reachable from the whole internet"),
                        );
                    }
                }
            }
            "aws_s3_bucket" => {
                if has(&b.body, "acl=\"public-read\"") || has(&b.body, "acl=\"public-read-write\"")
                {
                    add(
                        "TF002",
                        Severity::High,
                        line_of(&b, "acl"),
                        "S3 bucket has a public ACL",
                    );
                }
                if !has(&b.body, "server_side_encryption_configuration") {
                    add("TF003", Severity::Medium, b.line, "S3 bucket has no inline encryption configuration (check for a separate aws_s3_bucket_server_side_encryption_configuration)");
                }
            }
            "aws_s3_bucket_public_access_block" => {
                for k in [
                    "block_public_acls",
                    "block_public_policy",
                    "ignore_public_acls",
                    "restrict_public_buckets",
                ] {
                    if has(&b.body, &format!("{k}=false")) {
                        add(
                            "TF004",
                            Severity::High,
                            line_of(&b, &format!("{k}=false")),
                            &format!("public access block disables {k}"),
                        );
                    }
                }
            }
            "aws_db_instance" => {
                if has(&b.body, "storage_encrypted=false") || !has(&b.body, "storage_encrypted") {
                    add(
                        "TF005",
                        Severity::High,
                        b.line,
                        "RDS storage is not encrypted",
                    );
                }
                if has(&b.body, "publicly_accessible=true") {
                    add(
                        "TF006",
                        Severity::High,
                        line_of(&b, "publicly_accessible"),
                        "RDS instance is publicly accessible",
                    );
                }
            }
            "aws_ebs_volume" => {
                if !has(&b.body, "encrypted=true") {
                    add(
                        "TF005",
                        Severity::Medium,
                        b.line,
                        "EBS volume is not encrypted",
                    );
                }
            }
            "aws_iam_policy" | "aws_iam_role_policy" | "aws_iam_user_policy" => {
                let flat = compact(&b.body).to_lowercase();
                let patterns = [
                    "action=\"*\"",
                    "\"action\":\"*\"",
                    "\\\"action\\\":\\\"*\\\"",
                    "\"*:*\"",
                    "actions=[\"*\"]",
                    "action=[\"*\"]",
                ];
                if patterns.iter().any(|p| flat.contains(p)) {
                    add(
                        "TF007",
                        Severity::High,
                        line_of(&b, "*"),
                        "IAM policy allows all actions",
                    );
                }
            }
            _ => {}
        }
    }
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.resource.cmp(&b.resource))
            .then(a.rule.cmp(b.rule))
    });
    out
}
