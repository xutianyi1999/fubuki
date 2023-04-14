use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use hyper::{Body, http, Request, Response};
use hyper::service::{make_service_fn, service_fn};

use crate::client::{Interface, InterfaceInfo};

#[cfg(feature = "web")]
use std::str::pattern::Pattern;

#[cfg(feature = "web")]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

fn info<K>(
    _req: Request<Body>,
    interfaces: &[Arc<Interface<K>>],
) -> Result<Response<Body>, http::Error> {
    let mut list = Vec::with_capacity(interfaces.len());

    for inter in interfaces {
        list.push(InterfaceInfo::from(&**inter));
    }
    
    let resp = match serde_json::to_vec(&list) {
        Ok(v) => Response::new(Body::from(v)),
        Err(e) => {
            error!("API server error: {}", e);

            Response::builder()
                .status(500)
                .body(Body::from(e.to_string()))?
        }
    };
    Ok(resp)
}

fn router<K>(
    interfaces: Vec<Arc<Interface<K>>>,
    req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
    match req.uri().path() {
        "/info" => info(req, &interfaces),
        #[cfg(feature = "web")]
        path if path.is_prefix_of("/static") => {
            let map: std::collections::HashMap<&str, static_files::Resource> = generate();
            let k = path.trim_start_matches("/");

            match map.get(k) {
                None =>  {
                    Response::builder()
                        .status(404)
                        .body(Body::empty())
                }
                Some(resource) => {
                    Ok(Response::new(Body::from(resource.data)))
                }
            }
        }
        _ => {
            Response::builder()
                .status(404)
                .body(Body::empty())
        }
    }
}

pub(super) async fn api_start<K: Send + Sync + 'static>(
    bind: SocketAddr,
    interfaces: Vec<Arc<Interface<K>>>
) -> Result<()> {
    let make_svc = make_service_fn(move |_conn|  {
        let interfaces = interfaces.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let interfaces = interfaces.clone();

                async move {
                    router(interfaces, req)
                }
            }))
        }
    });

    tokio::spawn(hyper::server::Server::bind(&bind)
            .serve(make_svc)).await??;

    Ok(())
}