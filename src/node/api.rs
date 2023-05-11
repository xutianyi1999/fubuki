use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use hyper::{Body, http, Request, Response};
use hyper::service::{make_service_fn, service_fn};

use crate::node::{Interface, InterfaceInfo};

struct Context<K> {
    interfaces: Vec<Arc<Interface<K>>>,
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
            error!("api server error: {}", e);

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
    let path = req.uri().path();

    match path {
        "/info" => info(req, ctx.interfaces.as_slice()),
        "/type" => Ok(Response::new(Body::from("node"))),
        #[cfg(feature = "web")]
        path => crate::web::static_files(path.trim_start_matches('/')),
        #[cfg(not(feature = "web"))]
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

    info!("api listening on http://{}", bind);

    tokio::spawn(hyper::server::Server::try_bind(&bind)?
            .serve(make_svc)).await??;

    Ok(())
}