use std::pin::pin;

use anyhow::Result;
use net_route::{Handle, Route};
use futures_util::stream::StreamExt;

pub struct SystemRouteHandle {
    handle: Handle,
    routes: Vec<Route>,
    rt: tokio::runtime::Handle,
}

impl SystemRouteHandle {
    pub fn new() -> Result<Self> {
        let handle = Handle::new()?;
        let stream = handle.route_listen_stream();

        tokio::spawn(async move {
            let mut stream = pin!(stream);

            while let Some(v) = stream.next().await {
                info!("Route change: {:?}", v)
            }
        });

        let this = SystemRouteHandle {
            handle,
            routes: Vec::new(),
            rt: tokio::runtime::Handle::current(),
        };
        Ok(this)
    }

    pub async fn add(&mut self, routes: &[Route]) -> Result<()> {
        self.routes.extend(routes.iter().cloned().collect::<Vec<Route>>());

        for x in &self.routes {
            self.handle.add(x).await?;
        }
        Ok(())
    }

    pub async fn clear(&mut self) -> Result<()> {
        for x in &self.routes {
            self.handle.delete(x).await?;
        }
        Ok(())
    }
}

impl Drop for SystemRouteHandle {
    fn drop(&mut self) {
        if !self.routes.is_empty() {
            info!("Clear route");

            let rt= self.rt.clone();

            std::thread::scope(|scope| {
                scope.spawn(|| {
                    if let Err(e) = rt.block_on(self.clear()) {
                        error!("delete route failure: {}", e)
                    }
                });
            });
        }
    }
}