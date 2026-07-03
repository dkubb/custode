use axum as _;
use blake3 as _;
use clap as _;
use custode as _;
use futures_util as _;
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

fn run_coverage_summary(branches: &str, max_missed_branches: u32) -> Output {
    let directory = tempdir().expect("temporary directory should be created");
    let summary = directory.path().join("coverage.json");
    let fixture = format!(
        r#"{{"data":[{{"functions":[],"files":[{{"filename":"{FIXTURE_FILENAME}","segments":[],"branches":{branches}}}]}}]}}"#
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
fn exclude_test_modules_deduplicates_repeated_branch_rows() {
    let output = run_coverage_summary("[[1,0,1,10,0,0],[1,0,1,10,0,0]]", 1);

    assert_branch_failure(output, 2, 1);
}
