use std::io::Result;

use serde::Serialize;

pub trait ToJson: Serialize {
    fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    fn to_json_string_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn to_json_vec(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

impl<T> ToJson for T where T: Serialize {}
