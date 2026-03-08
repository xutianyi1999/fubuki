use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use http_body_util::Full;
use hyper::{http, Method, Request, Response};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use tokio::net::TcpListener;
use tokio::sync::Notify;

use crate::node::{Interface, InterfaceInfo};

struct Context<K> {
    interfaces: Vec<Arc<Interface<K>>>,
    restart_notify: Arc<Notify>,
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

fn restart(
    _req: Request<Incoming>,
    restart_notify: &Arc<Notify>,
) -> Result<Response<Full<Bytes>>, http::Error> {
    info!("Restart request received via API, will restart in 3 seconds");
    let notify = restart_notify.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        notify.notify_one();
    });
    Ok(Response::new(Full::new(Bytes::new())))
}

fn router<K>(
    ctx: &Context<K>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, http::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    match path.as_str() {
        "/info" => info(req, ctx.interfaces.as_slice()),
        "/type" => Ok(Response::new(Full::new(Bytes::from("node")))),
        "/restart" if method == Method::POST => restart(req, &ctx.restart_notify),
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
    restart_notify: Arc<Notify>,
) -> Result<()> {
    let ctx = Context { interfaces, restart_notify };
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
