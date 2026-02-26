use std::process::{Command, Stdio};
use std::time::Duration;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Local, Utc};

pub mod cipher;
pub mod net;
pub mod allocator;
pub mod hook;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod privilege;

macro_rules! ternary {
    ($condition: expr, $_true: expr, $_false: expr) => {
        if $condition { $_true } else { $_false }
    };
}

/// Format optional duration for TUI display (e.g. "12 ms" or "—").
pub fn format_elapsed(elapsed: Option<&Duration>) -> String {
    elapsed
        .map(|d| format!("{} ms", d.as_millis()))
        .unwrap_or_else(|| "—".to_string())
}

/// Format packet loss as percentage for TUI display.
pub fn format_loss_percent(packet_loss_count: u64, send_count: u64) -> String {
    if send_count == 0 {
        "—".to_string()
    } else {
        let rate = packet_loss_count as f32 / send_count as f32 * 100f32;
        format!("{:.2}%", rate)
    }
}

pub fn utc_to_str(t: i64) -> Result<String> {
    let utc: DateTime<Utc> = DateTime::from_timestamp(t, 0).ok_or_else(|| anyhow!("Failed to convert timestamp {} to UTC DateTime. Invalid timestamp value.", t))?;
    let local_time: DateTime<Local> = DateTime::from(utc);
    let str = local_time.format("%Y-%m-%d %H:%M:%S").to_string();

    Ok(str)
}

#[cfg(windows)]
pub fn cmd_exists<T: AsRef<str>>(program: T) -> Result<()> {
    let output = Command::new("powershell")
        .args([
            "Get-Command", program.as_ref()
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("Command '{}' not found in PowerShell. Please ensure it is installed and in your PATH.", program.as_ref()));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn cmd_exists<T: AsRef<str>>(program: T) -> Result<()> {
    let output = Command::new("which")
        .arg(program.as_ref())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("Command '{}' not found in system PATH. Please ensure it is installed and accessible.", program.as_ref()));
    }
    Ok(())
}