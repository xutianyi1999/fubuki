use std::collections::HashMap;
use std::sync::LazyLock;

use hyper::{Body, http, Response};
use static_files::Resource;

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

const INDEX_PATH: &str = "index.html";
static FILES_MAP: LazyLock<HashMap<&'static str, Resource>> = LazyLock::new(|| generate());

pub fn static_files(path: &str) -> Result<Response<Body>, http::Error> {
    let resource = FILES_MAP
        .get(path)
        .or_else(|| FILES_MAP.get(INDEX_PATH));

    match resource {
        None => {
            Response::builder()
                .status(404)
                .body(Body::empty())
        }
        Some(resource) => {
            Response::builder()
                .header("Content-Type", resource.mime_type)
                .status(200)
                .body(Body::from(resource.data))
        }
    }
}