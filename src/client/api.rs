use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use hyper::{Body, http, Request, Response};
use hyper::service::{make_service_fn, service_fn};

use crate::client::{Interface, InterfaceInfo};

#[cfg(feature = "web")]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

struct Context<K> {
    interfaces: Vec<Arc<Interface<K>>>,
    #[cfg(feature = "web")]
    static_files: std::collections::HashMap<&'static str, static_files::Resource>
}

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
    ctx: Arc<Context<K>>,
    req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
    let path = req.uri()
        .path()
        .trim_start_matches('/');

    match path {
        "info" => info(req, ctx.interfaces.as_slice()),
        #[cfg(feature = "web")]
        path if path.starts_with("static") => {
            match ctx.static_files.get(path) {
                None =>  {
                    Response::builder()
                        .status(404)
                        .body(Body::empty())
                }
                Some(resource) => {
                    Response::builder()
                        .header("Content-Type", resource.mime_type)
                        .status(200)
                        .body(Body::empty())
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
    let ctx = Context {
        interfaces,
        #[cfg(feature = "web")]
        static_files: generate()
    };

    let ctx = Arc::new(ctx);

    let make_svc = make_service_fn(move |_conn|  {
        let ctx = ctx.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let ctx = ctx.clone();

                async {
                    router(ctx, req)
                }
            }))
        }
    });

    tokio::spawn(hyper::server::Server::try_bind(&bind)?
            .serve(make_svc)).await??;

    Ok(())
}