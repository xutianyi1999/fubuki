use std::collections::HashMap;
use std::sync::LazyLock;

use http_body_util::Full;
use hyper::{http, Response};
use hyper::body::Bytes;
use static_files::Resource;

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

const INDEX_PATH: &str = "index.html";
static FILES_MAP: LazyLock<HashMap<&'static str, Resource>> = LazyLock::new(|| generate());

pub fn static_files(path: &str) -> Result<Response<Full<Bytes>>, http::Error> {
    let resource = FILES_MAP
        .get(path)
        .or_else(|| FILES_MAP.get(INDEX_PATH));

    match resource {
        None => {
            Response::builder()
                .status(404)
                .body(Full::new(Bytes::new()))
        }
        Some(resource) => {
            Response::builder()
                .header("Content-Type", resource.mime_type)
                .status(200)
                .body(Full::new(Bytes::from(resource.data)))
        }
    }
}