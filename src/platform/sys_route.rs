use std::pin::pin;

use anyhow::Result;
use futures_util::stream::StreamExt;
use net_route::Handle;

pub use net_route::Route;

/// Owns OS route operations and remembers routes added by this process for teardown.
pub struct SystemRouteHandle {
    /// Platform `net_route` handle (add/list/delete).
    handle: Handle,
    /// Routes successfully installed by [`Self::add`] (used by [`Self::clear`]).
    routes: Vec<Route>,
    /// Handle to the runtime that created this struct (for spawn safety on some paths).
    rt: tokio::runtime::Handle,
}

impl SystemRouteHandle {
    pub fn new() -> Result<Self> {
        let handle = Handle::new()?;
        let stream = handle.route_listen_stream();

        tokio::spawn(async move {
            let mut stream = pin!(stream);

            while let Some(v) = stream.next().await {
                debug!("route change: {:?}", v)
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
        for x in routes {
            #[cfg(target_os = "macos")]
            {
                use anyhow::anyhow;
                use std::process::Stdio;
                use tokio::process::Command;

                let gateway = x.gateway.ok_or_else(|| anyhow!("Cannot add route: gateway is required but not provided for destination '{}'.", x.destination))?;

                let status = Command::new("route")
                    .args([
                        "-n",
                        "add",
                        "-net",
                        x.destination.to_string().as_str(),
                        "-netmask",
                        x.mask().to_string().as_str(),
                        gateway.to_string().as_str(),
                    ])
                    .stderr(Stdio::inherit())
                    .output()
                    .await?
                    .status;

                if !status.success() {
                    return Err(anyhow!("Failed to add route for destination '{}' via gateway '{}'. Command failed.", x.destination, gateway));
                }
            }

            #[cfg(target_os = "windows")]
            self.handle.add(x).await?;

            #[cfg(target_os = "linux")]
            self.handle.add(x).await?;

            self.routes.push(x.clone());
        }
        Ok(())
    }

    pub async fn clear(&mut self) -> Result<()> {
        let list = self.handle.list().await?;

        for a in &self.routes {
            for b in &list {
                if a.destination == b.destination
                    && a.prefix == b.prefix
                    && a.gateway == b.gateway
                    && a.ifindex == b.ifindex
                {
                    self.handle.delete(a).await?;
                    debug!("delete route: {:?}", a);
                }
            }
        }

        self.routes = Vec::new();
        Ok(())
    }
}

impl Drop for SystemRouteHandle {
    fn drop(&mut self) {
        if !self.routes.is_empty() {
            info!("Clearing all network routes managed by Fubuki.");

            let rt = self.rt.clone();

            std::thread::scope(|scope| {
                scope.spawn(|| {
                    if let Err(e) = rt.block_on(self.clear()) {
                        warn!("Failed to clear all managed system routes: {}", e)
                    }
                });
            });
        }
    }
}
