use core::fmt;

use crate::prelude::*;

const COV_IGNORE_REGEX: &str =
    r#"(crates/ironrdp-(session|.+generators|.+glutin.+|replay|client|fuzzing|tokio|web|futures|tls)|xtask|testsuite)"#;

pub fn install(sh: &Shell) -> anyhow::Result<()> {
    let _s = Section::new("COV-INSTALL");

    if !is_installed(sh, "cargo-llvm-cov") {
        cmd!(
            sh,
            "{CARGO} install --locked --root {LOCAL_CARGO_ROOT} cargo-llvm-cov@{CARGO_LLVM_COV_VERSION}"
        )
        .run()?;
    }

    Ok(())
}

pub fn update(sh: &Shell) -> anyhow::Result<()> {
    let _s = Section::new("COV-UPDATE");

    let report = CoverageReport::generate(sh)?;
    println!("New:\n{report}");

    let initial_branch = cmd!(sh, "git rev-parse --abbrev-ref HEAD").read()?;

    println!("Switch branch");
    let _ = cmd!(sh, "git branch -D cov-data").run();
    cmd!(sh, "git checkout --orphan cov-data").run()?;

    let result = || -> anyhow::Result<()> {
        cmd!(sh, "git rm --cached -r .").run()?;

        sh.write_file("./report.json", report.original_json_data)?;

        cmd!(sh, "git add ./report.json").run()?;
        cmd!(sh, "git commit -m 'cov: update report data'").run()?;
        cmd!(sh, "git push --force --set-upstream origin cov-data").run()?;

        Ok(())
    }();

    println!("Clean working tree");
    cmd!(sh, "git clean -df").run()?;

    println!("Switch back to initial branch");
    cmd!(sh, "git checkout {initial_branch}").run()?;

    result?;

    Ok(())
}

pub fn report(sh: &Shell, html_report: bool) -> anyhow::Result<()> {
    let _s = Section::new("COV-REPORT");

    if html_report {
        cmd!(sh, "{CARGO} llvm-cov --html")
            .arg("--ignore-filename-regex")
            .arg(COV_IGNORE_REGEX)
            .run()?;
    } else {
        let report = CoverageReport::generate(sh)?;
        let past_report = CoverageReport::past_report(sh)?;

        println!("Past:\n{past_report}");
        println!("New:\n{report}");
        println!(
            "Diff: {:+.2}%",
            report.covered_lines_percent - past_report.covered_lines_percent
        );
    }

    Ok(())
}

pub fn report_github(sh: &Shell, repo: &str, pr_id: u32) -> anyhow::Result<()> {
    use std::fmt::Write as _;

    const COMMENT_HEADER: &str = "## Coverage Report :robot: :gear:";
    const DIFF_THRESHOLD: f64 = 0.005;

    let _s = Section::new("COV-REPORT");

    let report = CoverageReport::generate(sh)?;
    let past_report = CoverageReport::past_report(sh)?;

    let diff = report.covered_lines_percent - past_report.covered_lines_percent;

    println!("Past:\n{past_report}");
    println!("New:\n{report}");
    println!("Diff: {:+}%", diff);

    let comments = cmd!(sh, "gh api")
        .arg("-H")
        .arg("Accept: application/vnd.github.v3+json")
        .arg(format!("/repos/{repo}/issues/{pr_id}/comments"))
        .read()?;

    let comments: tinyjson::JsonValue = comments.parse().context("GitHub comments")?;
    let comments = comments.get::<Vec<_>>().context("comments list")?;

    let mut prev_comment_id = None;

    for comment in comments {
        let body = comment["body"].get::<String>().context("comment body")?;

        if body.starts_with(COMMENT_HEADER) {
            let comment_id = *comment["id"].get::<f64>().context("id")? as u64;
            prev_comment_id = Some(comment_id);
            break;
        }
    }

    let mut body = String::new();

    writeln!(body, "{COMMENT_HEADER}")?;
    writeln!(body, "**Past**:\n{past_report}")?;
    writeln!(body, "**New**:\n{report}")?;
    writeln!(body, "**Diff**: {:+.2}%", diff)?;
    writeln!(body, "\n[this comment will be updated automatically]")?;

    let command = cmd!(sh, "gh api")
        .arg("-H")
        .arg("Accept: application/vnd.github.v3+json")
        .arg("-f")
        .arg(format!("body={body}"));

    if let Some(comment_id) = prev_comment_id {
        println!("Update existing comment");

        command
            .arg("--method")
            .arg("PATCH")
            .arg(format!("/repos/{repo}/issues/comments/{comment_id}"))
            .ignore_stdout()
            .run()?;
    } else if diff.abs() > DIFF_THRESHOLD {
        trace!("Diff ({diff}) is greater than threshold ({DIFF_THRESHOLD})");
        println!("Create new comment");

        command
            .arg("--method")
            .arg("POST")
            .arg(format!("/repos/{repo}/issues/{pr_id}/comments"))
            .ignore_stdout()
            .run()?;
    } else {
        println!("Coverage didn’t change, skip GitHub comment");
    }

    Ok(())
}

pub fn grcov(sh: &Shell) -> anyhow::Result<()> {
    let _s = Section::new("COV-GRCOV");

    cmd!(sh, "rustup install nightly --profile=minimal").run()?;
    cmd!(sh, "rustup component add --toolchain nightly llvm-tools-preview").run()?;
    cmd!(sh, "rustup component add llvm-tools-preview").run()?;

    if !is_installed(sh, "cargo-fuzz") {
        cmd!(
            sh,
            "{CARGO} install --debug --locked --root {LOCAL_CARGO_ROOT} cargo-fuzz@{CARGO_FUZZ_VERSION}"
        )
        .run()?;
    }

    if !is_installed(sh, "grcov") {
        cmd!(
            sh,
            "{CARGO} install --debug --locked --root {LOCAL_CARGO_ROOT} grcov@{GRCOV_VERSION}"
        )
        .run()?;
    }

    println!("Remove leftovers");
    sh.remove_path("./fuzz/coverage/")?;
    sh.remove_path("./coverage/")?;

    sh.create_dir("./coverage/binaries")?;

    if cfg!(not(target_os = "windows")) {
        // Fuzz coverage

        let _guard = sh.push_dir("./fuzz");

        cmd!(sh, "{CARGO} clean").run()?;

        for target in FUZZ_TARGETS {
            cmd!(sh, "rustup run nightly cargo fuzz coverage {target}").run()?;
        }

        cmd!(sh, "cp -r ./target ../coverage/binaries/").run()?;
    }

    {
        // Test coverage

        cmd!(sh, "{CARGO} clean").run()?;

        cmd!(sh, "rustup run nightly cargo test --workspace")
            .env("CARGO_INCREMENTAL", "0")
            .env("RUSTFLAGS", "-C instrument-coverage")
            .env("LLVM_PROFILE_FILE", "./coverage/default-%m-%p.profraw")
            .run()?;

        cmd!(sh, "cp -r ./target/debug ./coverage/binaries/").run()?;
    }

    sh.create_dir("./docs")?;

    cmd!(
        sh,
        "grcov . ./fuzz
        --source-dir .
        --binary-path ./coverage/binaries/
        --output-type html
        --branch
        --ignore-not-existing
        --ignore xtask/*
        --ignore src/*
        --ignore **/tests/*
        --ignore crates/*-generators/*
        --ignore crates/web/*
        --ignore crates/client/*
        --ignore crates/glutin-renderer/*
        --ignore crates/glutin-client/*
        --ignore crates/replay-client/*
        --ignore crates/tls/*
        --ignore fuzz/fuzz_targets/*
        --ignore target/*
        --ignore fuzz/target/*
        --excl-start begin-no-coverage
        --excl-stop end-no-coverage
        -o ./docs/coverage"
    )
    .run()?;

    println!("Code coverage report available in `./docs/coverage` folder");

    println!("Clean up");

    sh.remove_path("./coverage/")?;
    sh.remove_path("./fuzz/coverage/")?;
    sh.remove_path("./xtask/coverage/")?;

    sh.read_dir("./crates")?
        .into_iter()
        .try_for_each(|crate_path| -> xshell::Result<()> {
            for path in sh.read_dir(crate_path)? {
                if path.ends_with("coverage") {
                    sh.remove_path(path)?;
                }
            }
            Ok(())
        })?;

    Ok(())
}

struct CoverageReport {
    total_lines: u64,
    covered_lines: u64,
    covered_lines_percent: f64,
    original_json_data: String,
}

impl CoverageReport {
    fn from_json_value(lines: &tinyjson::JsonValue) -> anyhow::Result<Self> {
        let total_lines = *lines["count"].get::<f64>().context("invalid value for `count`")? as u64;
        let covered_lines = *lines["covered"].get::<f64>().context("invalid value for `covered`")? as u64;
        let covered_lines_percent = *lines["percent"].get::<f64>().context("invalid value for `covered`")?;

        let original_json_data = lines.stringify().context("original json data")?;

        Ok(Self {
            total_lines,
            covered_lines,
            covered_lines_percent,
            original_json_data,
        })
    }

    fn generate(sh: &Shell) -> anyhow::Result<Self> {
        let output = cmd!(
            sh,
            "{CARGO} llvm-cov
            --ignore-filename-regex {COV_IGNORE_REGEX}
            --json"
        )
        .read()?;

        let report: tinyjson::JsonValue = output.parse().context("invalid JSON from cargo-llvm-cov")?;

        let lines = &report["data"][0]["totals"]["lines"];

        Self::from_json_value(lines)
    }

    fn past_report(sh: &Shell) -> anyhow::Result<Self> {
        cmd!(sh, "git fetch origin cov-data").run()?;

        let output = cmd!(sh, "git show origin/cov-data:report.json").read()?;

        let lines: tinyjson::JsonValue = output
            .parse()
            .context("invalid JSON from origin/cov-data:report.json")?;

        Self::from_json_value(&lines)
    }
}

impl fmt::Display for CoverageReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Total lines: {}", self.total_lines)?;
        writeln!(
            f,
            "Covered lines: {} ({:.2}%)",
            self.covered_lines, self.covered_lines_percent
        )?;
        Ok(())
    }
}
