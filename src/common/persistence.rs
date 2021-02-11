use serde::Serialize;
use tokio::io::Result;

use crate::common::res::StdResAutoConvert;

pub trait ToJson {
    fn to_json_string(&self) -> Result<String>;

    fn to_json_string_pretty(&self) -> Result<String>;

    fn to_json_vec(&self) -> Result<Vec<u8>>;
}

impl<T> ToJson for T
    where T: Serialize
{
    fn to_json_string(&self) -> Result<String> {
        serde_json::to_string(self).res_auto_convert()
    }

    fn to_json_string_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).res_auto_convert()
    }

    fn to_json_vec(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).res_auto_convert()
    }
}
