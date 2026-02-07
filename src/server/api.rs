use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use http_body_util::Full;
use hyper::{http, Request, Response};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use tokio::net::TcpListener;

use crate::server::{GroupHandle, GroupInfo};

struct Context {
    group_handles: Vec<Arc<GroupHandle>>,
}

fn info(
    _req: Request<Incoming>,
    group_handles: &[Arc<GroupHandle>],
) -> Result<Response<Full<Bytes>>, http::Error> {
    let mut list = Vec::with_capacity(group_handles.len());

    for gh in group_handles {
        list.push(GroupInfo::from(&**gh));
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

fn router(ctx: &Context, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, http::Error> {
    let path = req.uri().path();

    match path {
        "/info" => info(req, ctx.group_handles.as_slice()),
        "/type" => Ok(Response::new(Full::new(Bytes::from("server")))),
        #[cfg(feature = "web")]
        path => crate::web::static_files(path.trim_start_matches('/')),
        #[cfg(not(feature = "web"))]
        _ => Response::builder()
            .status(404)
            .body(Full::new(Bytes::new())),
    }
}

pub(super) async fn api_start(bind: SocketAddr, ghs: Vec<Arc<GroupHandle>>) -> Result<()> {
    let ctx = Context { group_handles: ghs };
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
