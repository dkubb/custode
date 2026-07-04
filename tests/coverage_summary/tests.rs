use axum as _;
use blake3 as _;
use clap as _;
use custode as _;
use futures_util as _;
use getrandom as _;
use http as _;
use http_body_util as _;
use humantime as _;
use non_empty_string as _;
use pretty_assertions as _;
use proptest as _;
use reqwest as _;
use serde as _;
use serde_json as _;
use thiserror as _;
use tokio as _;
use tokio_stream as _;
use tower as _;
use tracing as _;
use tracing_subscriber as _;
use url as _;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

const FIXTURE_FILENAME: &str = "/tmp/custode-no-such-source.rs";
const ZERO_TOTALS: &str = r#""totals":{"regions":{"count":0,"covered":0},"functions":{"count":0,"covered":0},"lines":{"count":0,"covered":0},"branches":{"count":0,"covered":0}}"#;

fn run_coverage_summary(branches: &str, max_missed_branches: u32) -> Output {
    let directory = tempdir().expect("temporary directory should be created");
    let summary = directory.path().join("coverage.json");
    let fixture = format!(
        r#"{{"data":[{{{ZERO_TOTALS},"functions":[],"files":[{{"filename":"{FIXTURE_FILENAME}","segments":[],"branches":{branches}}}]}}]}}"#
    );
    fs::write(&summary, fixture).expect("coverage fixture should be written");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-coverage-summary.sh");
    Command::new(script)
        .arg("--exclude-test-mods")
        .arg("--max-missed-branches")
        .arg(max_missed_branches.to_string())
        .arg(summary)
        .output()
        .expect("coverage script should run")
}

fn run_coverage_summary_for_source(
    source_text: &str,
    segments: &str,
    max_missed_lines: u32,
) -> Output {
    let directory = tempdir().expect("temporary directory should be created");
    let source = directory.path().join("fixture.rs");
    let summary = directory.path().join("coverage.json");
    fs::write(&source, source_text).expect("source fixture should be written");
    let filename = serde_json::to_string(&source.to_string_lossy())
        .expect("source path should serialize as JSON");
    let fixture = format!(
        r#"{{"data":[{{{ZERO_TOTALS},"functions":[],"files":[{{"filename":{filename},"segments":{segments},"branches":[]}}]}}]}}"#
    );
    fs::write(&summary, fixture).expect("coverage fixture should be written");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-coverage-summary.sh");
    Command::new(script)
        .arg("--exclude-test-mods")
        .arg("--max-missed-lines")
        .arg(max_missed_lines.to_string())
        .arg(summary)
        .output()
        .expect("coverage script should run")
}

fn run_file_ratchet_for_source(
    source_relative_path: &Path,
    source_text: &str,
    segments: &str,
    ratchet: &str,
) -> Output {
    let directory = tempdir().expect("temporary directory should be created");
    let source = directory.path().join(source_relative_path);
    let summary = directory.path().join("coverage.json");
    let ratchet_path = directory.path().join("ratchet.tsv");
    if let Some(parent) = source.parent() {
        fs::create_dir_all(parent).expect("source parent should be created");
    }
    fs::write(&source, source_text).expect("source fixture should be written");
    fs::write(&ratchet_path, ratchet).expect("ratchet fixture should be written");
    let filename = serde_json::to_string(&source.to_string_lossy())
        .expect("source path should serialize as JSON");
    let fixture = format!(
        r#"{{"data":[{{{ZERO_TOTALS},"functions":[],"files":[{{"filename":{filename},"segments":{segments},"branches":[]}}]}}]}}"#
    );
    fs::write(&summary, fixture).expect("coverage fixture should be written");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-coverage-summary.sh");
    Command::new(script)
        .arg("--exclude-test-mods")
        .arg("--max-missed-lines")
        .arg("1")
        .arg("--per-file-ratchet")
        .arg(ratchet_path)
        .arg(summary)
        .output()
        .expect("coverage script should run")
}

fn run_summary_fixture(fixture: &str) -> Output {
    let directory = tempdir().expect("temporary directory should be created");
    let summary = directory.path().join("coverage.json");
    fs::write(&summary, fixture).expect("coverage fixture should be written");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-coverage-summary.sh");
    Command::new(script)
        .arg(summary)
        .output()
        .expect("coverage script should run")
}

fn run_excluded_summary_fixture(fixture: &str) -> Output {
    let directory = tempdir().expect("temporary directory should be created");
    let summary = directory.path().join("coverage.json");
    fs::write(&summary, fixture).expect("coverage fixture should be written");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-coverage-summary.sh");
    Command::new(script)
        .arg("--exclude-test-mods")
        .arg(summary)
        .output()
        .expect("coverage script should run")
}

fn assert_branch_failure(output: Output, missed: u32, maximum: u32) {
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_eq!(output.status.code(), Some(1_i32));
    assert!(
        stderr.contains(&format!(
            "coverage metric branches has {missed} missed states; max is {maximum}"
        )),
        "{stderr}"
    );
}

fn assert_line_failure(output: Output, missed: u32, maximum: u32) {
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_eq!(output.status.code(), Some(1_i32));
    assert!(
        stderr.contains(&format!(
            "coverage metric lines has {missed} missed states; max is {maximum}"
        )),
        "{stderr}"
    );
}

fn assert_file_line_failure(output: Output, missed: u32, maximum: u32) {
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_eq!(output.status.code(), Some(1_i32));
    assert!(
        stderr.contains(&format!(
            "coverage file fixture.rs metric lines has {missed} missed states; max is {maximum}"
        )),
        "{stderr}"
    );
}

fn assert_file_line_ratchet_failure(output: Output, missed: u32, ratchet: u32) {
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_eq!(output.status.code(), Some(1_i32));
    assert!(
        stderr.contains(&format!(
            "coverage file fixture.rs metric lines has {missed} missed states; ratchet is {ratchet}"
        )),
        "{stderr}"
    );
}

#[test]
fn summary_requires_numeric_totals() {
    let output = run_summary_fixture(r#"{"data":[{"totals":{}}]}"#);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_ne!(output.status.code(), Some(0_i32));
    assert!(
        stderr.contains("coverage summary missing numeric field: regions."),
        "{stderr}"
    );
}

#[test]
fn summary_rejects_covered_totals_above_counts() {
    let output = run_summary_fixture(
        r#"{"data":[{"totals":{"regions":{"count":0,"covered":1},"functions":{"count":0,"covered":0},"lines":{"count":0,"covered":0},"branches":{"count":0,"covered":0}}}]}"#,
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_ne!(output.status.code(), Some(0_i32));
    assert!(
        stderr.contains(
            "coverage summary has impossible covered count: regions.covered > regions.count"
        ),
        "{stderr}"
    );
}

#[test]
fn exclude_test_modules_rejects_covered_totals_above_counts() {
    let output = run_excluded_summary_fixture(
        r#"{"data":[{"totals":{"regions":{"count":0,"covered":1},"functions":{"count":0,"covered":0},"lines":{"count":0,"covered":0},"branches":{"count":0,"covered":0}},"functions":[],"files":[{"filename":"/tmp/custode-no-such-source.rs","segments":[],"branches":[]}]}]}"#,
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_ne!(output.status.code(), Some(0_i32));
    assert!(
        stderr.contains(
            "coverage summary has impossible covered count: regions.covered > regions.count"
        ),
        "{stderr}"
    );
}

#[test]
fn exclude_test_modules_requires_detailed_events_for_summary_misses() {
    let output = run_excluded_summary_fixture(
        r#"{"data":[{"totals":{"regions":{"count":0,"covered":0},"functions":{"count":1,"covered":0},"lines":{"count":0,"covered":0},"branches":{"count":0,"covered":0}},"functions":[],"files":[]}]}"#,
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_ne!(output.status.code(), Some(0_i32));
    assert!(
        stderr
            .contains("coverage detail missing uncovered functions events despite summary misses"),
        "{stderr}"
    );
}

#[test]
fn exclude_test_modules_counts_each_uncovered_branch_arm() {
    let output = run_coverage_summary("[[1,0,1,10,1,0]]", 0);

    assert_branch_failure(output, 1, 0);
}

#[test]
fn exclude_test_modules_counts_both_uncovered_branch_arms() {
    let output = run_coverage_summary("[[1,0,1,10,0,0]]", 0);

    assert_branch_failure(output, 2, 0);
}

#[test]
fn exclude_test_modules_counts_missed_lines_after_test_module() {
    let output = run_coverage_summary_for_source(
        "fn before() {}\nmod tests {\n    #[test]\n    fn it_works() {}\n}\nfn after() {}\n",
        "[[6,1,0,true,false]]",
        0,
    );

    assert_line_failure(output, 1, 0);
}

#[test]
fn exclude_test_modules_deduplicates_repeated_branch_rows() {
    let output = run_coverage_summary("[[1,0,1,10,0,0],[1,0,1,10,0,0]]", 1);

    assert_branch_failure(output, 2, 1);
}

#[test]
fn exclude_test_modules_ignores_missed_lines_inside_test_module() {
    let output = run_coverage_summary_for_source(
        "fn before() {}\nmod tests {\n    #[test]\n    fn it_works() {}\n}\nfn after() {}\n",
        "[[4,5,0,true,false]]",
        0,
    );

    assert!(
        output.status.success(),
        "test module line should be excluded"
    );
}

#[test]
fn exclude_test_modules_ignores_braces_inside_raw_strings() {
    let output = run_coverage_summary_for_source(
        "fn before() {}\nmod tests {\n    const RAW: &str = r#\"{\"#;\n}\nfn after() {}\n",
        "[[5,1,0,true,false]]",
        0,
    );

    assert_line_failure(output, 1, 0);
}

#[test]
fn exclude_test_modules_ignores_alphabetic_char_literals() {
    let output = run_coverage_summary_for_source(
        "fn before() {}\nmod tests {\n    const LETTER: char = 'a';\n}\nfn after() {}\n",
        "[[5,1,0,true,false]]",
        0,
    );

    assert_line_failure(output, 1, 0);
}

#[test]
fn file_ratchet_allows_known_missed_lines_outside_test_modules() {
    let output = run_file_ratchet_for_source(
        Path::new("fixture.rs"),
        "fn before() {}\nmod tests {\n    #[test]\n    fn it_works() {}\n}\nfn after() {}\n",
        "[[6,1,0,true,false]]",
        "fixture.rs\t0\t0\t1\t0\n",
    );

    assert!(output.status.success(), "known file miss should pass");
}

#[test]
fn file_ratchet_rejects_new_missed_lines_outside_test_modules() {
    let output = run_file_ratchet_for_source(
        Path::new("fixture.rs"),
        "fn before() {}\nmod tests {\n    #[test]\n    fn it_works() {}\n}\nfn after() {}\n",
        "[[6,1,0,true,false]]",
        "fixture.rs\t0\t0\t0\t0\n",
    );

    assert_file_line_failure(output, 1, 0);
}

#[test]
fn file_ratchet_rejects_improved_missed_lines_until_updated() {
    let output = run_file_ratchet_for_source(
        Path::new("fixture.rs"),
        "fn before() {}\nmod tests {\n    #[test]\n    fn it_works() {}\n}\nfn after() {}\n",
        "[]",
        "fixture.rs\t0\t0\t1\t0\n",
    );

    assert_file_line_ratchet_failure(output, 0, 1);
}

#[test]
fn file_ratchet_uses_last_source_directory_component() {
    let output = run_file_ratchet_for_source(
        Path::new("src/checkout/src/fixture.rs"),
        "fn before() {}\nmod tests {\n    #[test]\n    fn it_works() {}\n}\nfn after() {}\n",
        "[[6,1,0,true,false]]",
        "src/fixture.rs\t0\t0\t1\t0\n",
    );

    assert!(
        output.status.success(),
        "parent source directories should not change ratchet key"
    );
}
