use serde::Serialize;
use tokio::io::Result;

pub trait ToJson {
    fn to_json_string(&self) -> Result<String>;

    fn to_json_string_pretty(&self) -> Result<String>;

    fn to_json_vec(&self) -> Result<Vec<u8>>;
}

impl<T> ToJson for T
    where T: Serialize
{
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
