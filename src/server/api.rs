use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use hyper::{Body, http, Request, Response};
use hyper::service::{make_service_fn, service_fn};

use crate::server::{GroupHandle, GroupInfo};

struct Context {
    group_handles: Vec<Arc<GroupHandle>>,
}

fn info(
    _req: Request<Body>,
    group_handles: &[Arc<GroupHandle>],
) -> Result<Response<Body>, http::Error> {
    let mut list = Vec::with_capacity(group_handles.len());

    for gh in group_handles {
        list.push(GroupInfo::from(&**gh));
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

fn router(
    ctx: Arc<Context>,
    req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
    let path = req.uri().path();

    match path {
        "/info" => info(req, ctx.group_handles.as_slice()),
        _ => {
            Response::builder()
                .status(404)
                .body(Body::empty())
        }
    }
}

pub(super) async fn api_start(
    bind: SocketAddr,
    ghs: Vec<Arc<GroupHandle>>
) -> Result<()> {
    let ctx = Context {
        group_handles: ghs,
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