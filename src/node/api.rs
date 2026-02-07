use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use http_body_util::Full;
use hyper::{http, Request, Response};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use tokio::net::TcpListener;

use crate::node::{Interface, InterfaceInfo};

struct Context<K> {
    interfaces: Vec<Arc<Interface<K>>>,
}

fn info<K>(
    _req: Request<Incoming>,
    interfaces: &[Arc<Interface<K>>],
) -> Result<Response<Full<Bytes>>, http::Error> {
    let mut list = Vec::with_capacity(interfaces.len());

    for inter in interfaces {
        list.push(InterfaceInfo::from(&**inter));
    }

    let resp = match serde_json::to_vec(&list) {
        Ok(v) => Response::new(Full::new(Bytes::from(v))),
        Err(e) => {
            error!("API server failed: {}", e);

            Response::builder()
                .status(500)
                .body(Full::new(Bytes::from(e.to_string())))?
        }
    };
    Ok(resp)
}

fn router<K>(
    ctx: &Context<K>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, http::Error> {
    let path = req.uri().path();

    match path {
        "/info" => info(req, ctx.interfaces.as_slice()),
        "/type" => Ok(Response::new(Full::new(Bytes::from("node")))),
        #[cfg(feature = "web")]
        path => crate::web::static_files(path.trim_start_matches('/')),
        #[cfg(not(feature = "web"))]
        _ => Response::builder()
            .status(404)
            .body(Full::new(Bytes::new())),
    }
}

pub(super) async fn api_start<K: Send + Sync + 'static>(
    bind: SocketAddr,
    interfaces: Vec<Arc<Interface<K>>>,
) -> Result<()> {
    let ctx = Context { interfaces };
    let ctx = Arc::new(ctx);

    let listener = TcpListener::bind(bind).await?;
    info!("API server listening on http://{}", bind);

    loop {
        let (stream, _) = listener.accept().await?;
        let stream = hyper_util::rt::TokioIo::new(stream);
        let ctx = ctx.clone();

        tokio::spawn(async move {
            let ctx = &ctx;
            let res = http1::Builder::new()
                .serve_connection(
                    stream,
                    service_fn(move |req| {
                        std::future::ready(router(ctx, req))
                    }),
                )
                .await;

            if let Err(e) = res {
                warn!("Failed to serve API request: {:?}", e);
            }
        });
    }
}
