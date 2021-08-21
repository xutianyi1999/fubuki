#[macro_use]
extern crate log;

mod tun;
mod server;
mod client;
pub mod common;


fn main() -> () {}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use chrono::{DateTime, Utc};

    struct User {
        name: String,
        age: i32,
    }

    #[test]
    fn a1() {
        let user = User { name: "abc".to_string(), age: 10 };
        let arr = [0u8; 32];
        let p = &arr[..];

        let a = Box::<[u8]>::from(p);
    }
}