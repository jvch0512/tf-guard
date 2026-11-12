# tf-guard

Dependency-free Terraform scanner for AWS misconfigurations, written in Rust. It is a fast pre-commit and CI check that reads `.tf` files directly (no `terraform init`, no cloud credentials, no network).

> Built with AI assistance (Claude) as part of a security portfolio. Samples are intentionally insecure examples.

## Usage

```bash
cargo build --release
./target/release/tf-guard samples/bad.tf
./target/release/tf-guard infra/            # walks directories, skips .terraform and .git
```

Output is one line per finding: `file:line: [HIGH] TF001 message (resource)`. Exit codes: 0 no high finding, 1 at least one high finding, 2 usage error.

## Rules

| ID | Severity | Check |
|---|---|---|
| TF001 | High | Security group allows 0.0.0.0/0 or ::/0 on SSH, RDP, database ports or all ports (egress rules are ignored) |
| TF002 | High | S3 bucket with a public ACL |
| TF003 | Medium | S3 bucket without inline encryption configuration |
| TF004 | High | S3 public access block with a protection set to false |
| TF005 | High/Medium | RDS or EBS storage not encrypted |
| TF006 | High | RDS publicly accessible |
| TF007 | High | IAM policy allowing all actions |

## How it parses

A brace-aware pass removes `#`, `//` and `/* */` comments and neutralises braces inside strings while keeping line numbers intact, then extracts `resource` blocks. Whitespace around `=` does not matter.

## Limits

This is pattern based. It does not resolve variables, modules or `count`, and TF003 cannot see a separate encryption resource, so treat it as a first line of defence next to plan-based scanners.

## Tests

`cargo test` covers comment and string handling, spacing variants, egress exclusion, each rule family, malformed input and the CLI contract. CI runs on Linux, macOS and Windows with clippy `-D warnings`.

MIT licensed.
