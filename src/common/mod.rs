use anyhow::{anyhow, Result};
use chrono::{DateTime, Local, Utc};

pub mod cipher;
pub mod net;
pub mod allocator;
pub mod hook;

macro_rules! ternary {
    ($condition: expr, $_true: expr, $_false: expr) => {
        if $condition { $_true } else { $_false }
    };
}

pub fn utc_to_str(t: i64) -> Result<String> {
    let utc: DateTime<Utc> = DateTime::from_timestamp(t, 0).ok_or_else(|| anyhow!("can't convert timestamp"))?;
    let local_time: DateTime<Local> = DateTime::from(utc);
    let str = local_time.format("%Y-%m-%d %H:%M:%S").to_string();

    Ok(str)
}